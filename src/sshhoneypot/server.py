"""The SSH side of the honeypot, built on asyncssh.

Isolation rules this module enforces (see also README "Safety model"):

* Authentication never touches real accounts. The policy decides in memory.
* After a (fake) login the client only ever talks to :class:`FakeShell`,
  which is pure string processing. No process is spawned, no PTY is
  allocated on the host, nothing is read from or written to the real
  filesystem on the attacker's behalf.
* Port forwarding (local, remote, UNIX socket, tun/tap), agent and X11
  forwarding, SFTP, SCP and every subsystem are refused and recorded.
* Reverse DNS lookups and GSSAPI are disabled: an incoming connection never
  causes an outgoing one.
* Every connection is bounded: global and per-IP concurrency, login timeout,
  idle timeout, maximum duration, maximum input bytes, maximum commands,
  maximum line length and maximum queued output.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

import asyncssh

from .config import Config
from .fingerprint import connection_fingerprint
from .geoip import GeoIP
from .notifiers import LoginEvent
from .recorder import Recorder
from .shell import FakeShell

log = logging.getLogger(__name__)

MAX_WRITE_BACKLOG = 256 * 1024  # bytes of unsent output before we hang up
MAX_RECORDS_PER_CONNECTION = 100  # stored side requests / download URLs per connection
_MEMORY = 10_000  # remembered source IPs for the after_attempts policy


class _LRU(OrderedDict):
    def __init__(self, size: int) -> None:
        super().__init__()
        self.size = size

    def touch(self, key: Any, default: Callable[[], Any]) -> Any:
        if key not in self:
            self[key] = default()
        self.move_to_end(key)
        while len(self) > self.size:
            self.popitem(last=False)
        return self[key]


class AuthPolicy:
    """Decides whether a username/password pair "works". Never consults real accounts."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg.auth
        self._attempts: _LRU = _LRU(_MEMORY)  # ip -> failed password attempts
        self._granted: _LRU = _LRU(_MEMORY)  # ip -> {(user, password)} that worked before

    def check(self, ip: str, username: str, password: str) -> bool:
        policy = self.cfg.policy
        if policy == "reject":
            return False
        if policy == "credentials":
            return any(
                c.username in ("*", username) and c.password in ("*", password)
                for c in self.cfg.credentials
            )
        granted: set = self._granted.touch(ip, set)
        if (username, password) in granted:
            return True
        count = self._attempts.touch(ip, int) + 1
        if count >= self.cfg.accept_after:
            self._attempts[ip] = 0
            granted.add((username, password))
            return True
        self._attempts[ip] = count
        return False


class Honeypot:
    """Owns the listener, the connection accounting and shared state."""

    def __init__(
        self,
        cfg: Config,
        recorder: Recorder,
        host_keys: list[asyncssh.SSHKey],
        *,
        geoip: GeoIP | None = None,
    ) -> None:
        self.cfg = cfg
        self.recorder = recorder
        self.host_keys = host_keys
        self.geoip = geoip
        self.policy = AuthPolicy(cfg)
        self.active: dict[str, int] = {}
        self.total_active = 0
        self.refused = 0
        self._last_refusal_log = 0.0
        self._server: asyncssh.SSHAcceptor | None = None
        self.connections: set[HoneypotServer] = set()

    @property
    def port(self) -> int:
        assert self._server is not None
        return self._server.get_port()

    async def start(self) -> None:
        lim = self.cfg.limits
        self._server = await asyncssh.create_server(
            lambda: HoneypotServer(self),
            self.cfg.listen.host,
            self.cfg.listen.port,
            server_host_keys=self.host_keys,
            server_version=self.cfg.banner,
            config=None,  # never read /etc/ssh/sshd_config or similar
            login_timeout=lim.login_timeout,
            keepalive_interval=30,
            keepalive_count_max=3,
            # Authentication methods we pretend to offer.
            password_auth=True,
            public_key_auth=True,
            kbdint_auth=True,  # mapped onto validate_password by asyncssh
            host_based_auth=False,
            gss_host=None,
            # Never resolve or connect anywhere because of a client.
            rdns_lookup=False,
            agent_forwarding=False,
            x11_forwarding=False,
            allow_scp=False,
            sftp_factory=None,
            # The fake shell gets decoded text; invalid UTF-8 is replaced, not fatal.
            encoding="utf-8",
            errors="replace",
            utf8_decode_errors="replace",
            line_editor=True,
            line_history=0,
            max_line_length=lim.max_line_length,
            reuse_address=True,
        )
        log.info(
            "SSH honeypot listening on %s:%d (policy=%s, banner=%r)",
            self.cfg.listen.host,
            self.port,
            self.cfg.auth.policy,
            self.cfg.banner,
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for conn in list(self.connections):
            conn.close("shutdown")
        for _ in range(50):  # give connection_lost a moment to record the end
            if not self.connections:
                break
            await asyncio.sleep(0.02)
        await self.recorder.drain()

    # -- connection accounting --------------------------------------------------

    def admit(self, ip: str) -> bool:
        lim = self.cfg.limits
        if self.total_active >= lim.max_connections or (
            self.active.get(ip, 0) >= lim.max_connections_per_ip
        ):
            self.refused += 1
            now = time.monotonic()
            if now - self._last_refusal_log > 60:
                self._last_refusal_log = now
                log.warning(
                    "connection limit reached, refusing connections (%d refused so far)",
                    self.refused,
                )
            return False
        self.total_active += 1
        self.active[ip] = self.active.get(ip, 0) + 1
        return True

    def release(self, ip: str) -> None:
        self.total_active -= 1
        n = self.active.get(ip, 0) - 1
        if n <= 0:
            self.active.pop(ip, None)
        else:
            self.active[ip] = n


class HoneypotServer(asyncssh.SSHServer):
    """One instance per TCP connection."""

    def __init__(self, hp: Honeypot) -> None:
        self.hp = hp
        self.cfg = hp.cfg
        self.rec = hp.recorder
        self.conn: asyncssh.SSHServerConnection | None = None
        self.admitted = False
        self.sid = secrets.token_hex(6)
        self.pid = 1000 + secrets.randbelow(64000)  # sshd[pid] in auth.log lines
        self.ip = ""
        self.port = 0
        self.started = time.monotonic()
        self.last_activity = self.started
        self.auth_attempts = 0
        self.bytes_in = 0
        self.commands = 0
        self.channels = 0
        self.requests = 0
        self.downloads = 0
        self.username: str | None = None
        self.password: str | None = None
        self.fingerprinted = False
        self.end_reason = "client closed"
        self.shell: FakeShell | None = None
        self.country: str | None = None
        self._invalid_logged: set[str] = set()
        self._watchdog: asyncio.Task | None = None
        self._closing = False

    # -- lifecycle --------------------------------------------------------------

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.conn = conn
        peer = conn.get_extra_info("peername") or ("?", 0)
        sock = conn.get_extra_info("sockname") or ("?", 0)
        self.ip, self.port = str(peer[0]), int(peer[1])
        if self.ip.startswith("::ffff:"):  # IPv4-mapped on a dual-stack socket
            self.ip = self.ip[7:]
        if not self.hp.admit(self.ip):
            conn.abort()
            return
        self.admitted = True
        self.hp.connections.add(self)
        country = self.hp.geoip.lookup(self.ip) if self.hp.geoip else None
        self.country = country
        self.rec.session_started(
            self.sid, src_ip=self.ip, src_port=self.port, dst_port=int(sock[1]), country=country
        )
        self._watchdog = asyncio.get_running_loop().create_task(self._watch())

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.admitted:
            return
        self.admitted = False
        self.hp.release(self.ip)
        self.hp.connections.discard(self)
        if self._watchdog is not None:
            self._watchdog.cancel()
        self._fingerprint()  # scanners that only grab the host key never reach begin_auth
        if not self._closing and exc is not None and not isinstance(exc, asyncssh.ConnectionLost):
            self.end_reason = f"error: {type(exc).__name__}"
        self.rec.session_closed(
            self.sid,
            reason=self.end_reason,
            bytes_in=self.bytes_in,
            auth_attempts=self.auth_attempts,
            pid=self.pid,
            src_ip=self.ip,
            src_port=self.port,
            duration=time.monotonic() - self.started,
        )

    def close(self, reason: str) -> None:
        if self._closing or self.conn is None:
            return
        self._closing = True
        self.end_reason = reason
        self.conn.close()

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    async def _watch(self) -> None:
        lim = self.cfg.limits
        hard = self.started + lim.max_session_duration
        while True:
            now = time.monotonic()
            idle_at = self.last_activity + lim.idle_timeout
            if now >= hard:
                self.close("max duration")
                return
            if now >= idle_at:
                self.close("idle timeout")
                return
            await asyncio.sleep(min(hard, idle_at) - now + 0.01)

    def _fingerprint(self) -> None:
        if self.fingerprinted or self.conn is None:
            return
        self.fingerprinted = True
        self.rec.client_info(self.sid, **connection_fingerprint(self.conn))

    # -- authentication ---------------------------------------------------------

    def begin_auth(self, username: str) -> bool:
        self.touch()
        self._fingerprint()
        return True  # authentication is always required

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def _note_user(self, username: str) -> bool:
        valid = username in self.cfg.auth.valid_users
        if not valid and username not in self._invalid_logged and len(self._invalid_logged) < 20:
            self._invalid_logged.add(username)
            self.rec.invalid_user(
                self.sid, pid=self.pid, username=username, src_ip=self.ip, src_port=self.port
            )
        return valid

    def _after_failure(self) -> None:
        if self.auth_attempts >= self.cfg.auth.max_attempts_per_connection:
            self.close("too many auth attempts")

    async def validate_password(self, username: str, password: str) -> bool:
        self.touch()
        self.auth_attempts += 1
        valid = self._note_user(username)
        ok = self.hp.policy.check(self.ip, username, password)
        self.rec.auth_attempt(
            self.sid,
            pid=self.pid,
            src_ip=self.ip,
            src_port=self.port,
            username=username,
            method="password",
            valid_user=valid,
            success=ok,
            password=password,
        )
        if ok:
            self.username, self.password = username, password
            return True
        if self.cfg.auth.failure_delay:
            await asyncio.sleep(self.cfg.auth.failure_delay)
        self._after_failure()
        return False

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        self.touch()
        self.auth_attempts += 1
        valid = self._note_user(username)
        try:
            key_type, fp = key.get_algorithm(), key.get_fingerprint("sha256")
        except Exception:
            key_type, fp = "unknown", None
        self.rec.auth_attempt(
            self.sid,
            pid=self.pid,
            src_ip=self.ip,
            src_port=self.port,
            username=username,
            method="publickey",
            valid_user=valid,
            success=False,
            key_type=key_type,
            key_fingerprint=fp,
        )
        self._after_failure()
        return False  # keys are logged, never accepted

    def auth_completed(self) -> None:
        self.touch()
        user = self.username or "root"
        self.shell = FakeShell(
            hostname=self.cfg.hostname,
            username=user,
            src_ip=self.ip,
            on_download=self._download,
        )
        event = LoginEvent(
            session_id=self.sid,
            ts=time.time(),
            src_ip=self.ip,
            src_port=self.port,
            username=user,
            country=self.country,
            client_version=self.conn.get_extra_info("client_version") if self.conn else None,
        )
        self.rec.login(self.sid, event, self.password)

    def _download(self, tool: str, url: str) -> None:
        self.downloads += 1
        if self.downloads <= MAX_RECORDS_PER_CONNECTION:
            self.rec.download(self.sid, tool=tool, url=url)

    def record_request(self, kind: str, detail: str | None, accepted: bool = False) -> None:
        """Record a side request. A client that spams them is cut off."""
        self.requests += 1
        if self.requests > MAX_RECORDS_PER_CONNECTION:
            self.close("request limit")
            return
        self.rec.request(self.sid, kind=kind, detail=detail, accepted=accepted)

    # -- channels and forwarding (refused, recorded) --------------------------------

    def session_requested(self) -> asyncssh.SSHServerSession | bool:
        self.touch()
        if self.shell is None or self.channels >= self.cfg.limits.max_channels:
            self.record_request(kind="session", detail="channel limit reached")
            return False
        self.channels += 1
        return HoneypotSession(self)

    def connection_requested(
        self, dest_host: str, dest_port: int, orig_host: str, orig_port: int
    ) -> bool:
        self.touch()
        self.record_request(
            kind="direct-tcpip",
            detail=f"{dest_host}:{dest_port} from {orig_host}:{orig_port}",
        )
        return False

    def server_requested(self, listen_host: str, listen_port: int) -> bool:
        self.touch()
        self.record_request(kind="tcpip-forward", detail=f"{listen_host}:{listen_port}")
        return False

    def unix_connection_requested(self, dest_path: str) -> bool:
        self.touch()
        self.record_request(kind="direct-streamlocal", detail=dest_path)
        return False

    def unix_server_requested(self, listen_path: str) -> bool:
        self.touch()
        self.record_request(kind="streamlocal-forward", detail=listen_path)
        return False

    def tun_requested(self, unit: int | None) -> bool:
        self.touch()
        self.record_request(kind="tun", detail=str(unit))
        return False

    def tap_requested(self, unit: int | None) -> bool:
        self.touch()
        self.record_request(kind="tap", detail=str(unit))
        return False


class HoneypotSession(asyncssh.SSHServerSession):
    """A session channel: interactive fake shell or a single exec command."""

    def __init__(self, server: HoneypotServer) -> None:
        self.server = server
        self.chan: asyncssh.SSHServerChannel | None = None
        self.mode: str | None = None
        self.command: str | None = None
        self.pty = False
        self.buffer = ""
        self.done = False

    @property
    def shell(self) -> FakeShell:
        assert self.server.shell is not None
        return self.server.shell

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:
        self.chan = chan

    def pty_requested(self, term_type: str, term_size: tuple, term_modes: dict) -> bool:
        self.pty = True
        self.server.rec.terminal(self.server.sid, term_type[:64])
        return True

    def shell_requested(self) -> bool:
        self.mode = "shell"
        return True

    def exec_requested(self, command: str) -> bool:
        self.mode = "exec"
        self.command = command
        return True

    def subsystem_requested(self, subsystem: str) -> bool:
        self.server.record_request(kind="subsystem", detail=subsystem)
        return False  # sftp and everything else is refused

    def session_started(self) -> None:
        if self.mode == "shell":
            self._write(self.shell.motd() + self.shell.prompt())
        elif self.mode == "exec" and self.command is not None:
            self.server.record_request(kind="exec", detail=self.command, accepted=True)
            result = self._run(self.command, kind="exec")
            if result is not None:
                self._write(result.output)
            self._finish(0 if result is None else result.status)

    # -- input --------------------------------------------------------------------

    def data_received(self, data: str, datatype: Any) -> None:
        srv = self.server
        srv.touch()
        if self.done:
            return
        srv.bytes_in += len(data.encode("utf-8", "replace"))
        if srv.bytes_in > srv.cfg.limits.max_input_bytes:
            self._write("\n")
            self._finish(1)
            srv.close("input limit")
            return
        if self.mode != "shell":
            return  # input to an exec command is ignored (and counted)
        self.buffer += data
        max_line = srv.cfg.limits.max_line_length
        while not self.done:
            idx = min((i for i in (self.buffer.find("\n"), self.buffer.find("\r")) if i >= 0),
                      default=-1)  # fmt: skip
            if idx < 0:
                if len(self.buffer) > max_line:  # no newline in sight: treat as one line
                    line, self.buffer = self.buffer[:max_line], ""
                    self._line(line)
                break
            line = self.buffer[:idx]
            rest = self.buffer[idx + 1 :]
            self.buffer = rest[1:] if self.buffer[idx] == "\r" and rest[:1] == "\n" else rest
            self._line(line[:max_line])

    def _line(self, line: str) -> None:
        if not line.strip():
            self._write(self.shell.prompt())
            return
        result = self._run(line, kind="shell")
        if result is None:
            return
        self._write(result.output)
        if result.exit:
            self._write("logout\n")
            self._finish(0)
        else:
            self._write(self.shell.prompt())

    def _run(self, line: str, kind: str):
        srv = self.server
        if srv.commands >= srv.cfg.limits.max_commands:
            self._finish(1)
            srv.close("command limit")
            return None
        srv.commands += 1
        result = self.shell.run_line(line)
        srv.rec.command(
            srv.sid,
            kind=kind,
            command=line,
            known=result.known,
            elapsed=time.monotonic() - srv.started,
        )
        return result

    def _write(self, text: str) -> None:
        if not text or self.chan is None or self.done:
            return
        self.chan.write(text)
        if self.chan.get_write_buffer_size() > MAX_WRITE_BACKLOG:
            self.server.close("output backlog")

    def _finish(self, status: int) -> None:
        if self.done or self.chan is None:
            return
        self.done = True
        with contextlib.suppress(Exception):
            self.chan.exit(status)

    def eof_received(self) -> bool:
        if self.mode == "shell" and self.buffer.strip() and not self.done:
            line, self.buffer = self.buffer, ""
            self._line(line)
        self._finish(0)
        return False

    def break_received(self, msec: int) -> bool:
        self._interrupt()
        return True

    def signal_received(self, signal: str) -> None:
        self._interrupt()

    def _interrupt(self) -> None:
        if self.mode == "shell" and not self.done:
            self.buffer = ""
            self._write("^C\n" + self.shell.prompt())

    def connection_lost(self, exc: Exception | None) -> None:
        self.done = True
