"""The auth.log written by the honeypot must be readable by mini-siem's real parser.

mini-siem (https://github.com/rosko35/mini-siem) is not a dependency. Install
it next to this project for the test run (``pip install --no-deps -e
../mini-siem``); without it these tests are skipped. CI checks it out.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import asyncssh
import pytest

from conftest import eventually
from sshhoneypot.logs import AuthLog, sanitize

auth = pytest.importorskip("minisiem.parsers.auth")
models = pytest.importorskip("minisiem.models")
EventType = models.EventType

TS = datetime(2026, 11, 19, 10, 15, 1).timestamp()


@pytest.fixture(params=["rfc3339", "classic"])
def log(request, tmp_path):
    al = AuthLog(str(tmp_path / "auth.log"), hostname="honeypot", timestamps=request.param)
    yield al
    al.close()


def parse_all(path) -> list:
    parser = auth.AuthLogParser(now=datetime(2026, 11, 20).astimezone())
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if (ev := parser.parse(line)) is not None:
                events.append(ev)
    return events


def test_lines_parse_as_sshd_events(log):
    log.invalid_user(TS, 4242, "admin", "198.51.100.7", 50022)
    log.failed(TS, 4242, "password", "admin", False, "198.51.100.7", 50022)
    log.failed(TS + 1, 4243, "password", "root", True, "2001:db8::7", 40000)
    log.failed(
        TS + 2, 4244, "publickey", "git", True, "203.0.113.5", 1234, "ssh-ed25519", "SHA256:abc"
    )
    log.accepted(TS + 3, 4245, "password", "root", "203.0.113.9", 5555)
    log.closed_preauth(TS + 4, 4246, "203.0.113.10", 6666)
    events = parse_all(log.path)

    assert [e.type for e in events] == [
        EventType.SSH_INVALID_USER,
        EventType.SSH_FAILED,
        EventType.SSH_FAILED,
        EventType.SSH_FAILED,
        EventType.SSH_ACCEPTED,
    ]  # the bare preauth close carries no user and is ignored, as for real sshd
    inv, failed, failed6, key, ok = events
    assert (inv.user, inv.src_ip, inv.fields["port"]) == ("admin", "198.51.100.7", 50022)
    assert failed.fields == {"method": "password", "port": 50022, "invalid_user": True}
    assert (failed6.user, failed6.src_ip, failed6.fields["invalid_user"]) == (
        "root",
        "2001:db8::7",
        False,
    )
    assert key.fields["method"] == "publickey"
    assert key.raw.endswith("port 1234 ssh2: ED25519 SHA256:abc")
    assert (ok.user, ok.src_ip, ok.fields["method"]) == ("root", "203.0.113.9", "password")
    assert {e.host for e in events} == {"honeypot"}  # distinct hostname
    assert events[0].ts.replace(tzinfo=None) == datetime(2026, 11, 19, 10, 15, 1)


def test_hostile_usernames_cannot_forge_lines_or_ips(log):
    evil = (
        "x from 192.0.2.66 port 1 ssh2\n"
        "Nov 19 10:15:01 honeypot sshd[1]: Accepted password for root"
    )
    log.invalid_user(TS, 7, evil, "198.51.100.7", 2222)
    log.failed(TS, 7, "password", evil, False, "198.51.100.7", 2222)
    assert len(Path(log.path).read_text(encoding="utf-8").splitlines()) == 2
    events = parse_all(log.path)
    assert len(events) == 2
    assert all(e.src_ip == "198.51.100.7" for e in events)
    assert all(e.type != EventType.SSH_ACCEPTED for e in events)
    assert events[0].user == sanitize(evil)


def test_sanitize():
    assert sanitize("root") == "root"
    assert sanitize("a b") == "a\\x20b"
    assert sanitize("a\nb") == "a\\x0ab"
    assert sanitize("ü") == "\\xc3\\xbc"
    assert sanitize("\\") == "\\x5c"
    assert sanitize("x" * 500).endswith("...")


async def test_live_honeypot_log_feeds_minisiem(start_honeypot):
    hp = await start_honeypot(auth={"valid_users": ["root"]})
    for user in ("root", "oracle", "root"):
        with pytest.raises(asyncssh.PermissionDenied):
            async with hp.connect(user, "123456"):
                pass
    await eventually(lambda: len(hp.rows("SELECT * FROM sessions WHERE ended IS NOT NULL")) == 3)
    events = parse_all(hp.cfg.auth_log)
    failed = [e for e in events if e.type == EventType.SSH_FAILED]
    assert [e.user for e in failed] == ["root", "oracle", "root"]
    assert [e.fields["invalid_user"] for e in failed] == [False, True, False]
    assert [e.user for e in events if e.type == EventType.SSH_INVALID_USER] == ["oracle"]
    assert all(e.src_ip == "127.0.0.1" and e.host == "honeypot" for e in events)
