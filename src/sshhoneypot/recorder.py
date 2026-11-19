"""One place that turns honeypot events into database rows, log lines and notifications.

The SSH server and the fake shell only call :class:`Recorder` methods; they
never know where data ends up. Every sink is wrapped so that a full disk or a
broken log file is reported once in the service log but never takes the
honeypot down or leaks an exception to the attacker.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

from .logs import AuthLog, JsonLog
from .notifiers import LoginEvent, NotifierHub
from .storage import SQLiteStorage

log = logging.getLogger(__name__)


class Recorder:
    def __init__(
        self,
        storage: SQLiteStorage,
        *,
        auth_log: AuthLog | None = None,
        json_log: JsonLog | None = None,
        notifier: NotifierHub | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.storage = storage
        self.auth_log = auth_log
        self.json_log = json_log
        self.notifier = notifier
        self.clock = clock
        self._tasks: set[asyncio.Task] = set()
        self._failures: set[str] = set()

    def _safe(self, what: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        try:
            fn(*args, **kwargs)
        except Exception:
            if what not in self._failures:  # do not flood the journal
                self._failures.add(what)
                log.exception("recording %s failed (further errors of this kind are hidden)", what)

    def _json(self, event: str, ts: float, **fields: Any) -> None:
        if self.json_log is not None:
            self._safe("json log", self.json_log.write, event, ts, **fields)

    # -- connection lifecycle ---------------------------------------------------

    def session_started(
        self, sid: str, *, src_ip: str, src_port: int, dst_port: int, country: str | None
    ) -> float:
        ts = self.clock()
        self._safe(
            "session",
            self.storage.create_session,
            sid,
            started=ts,
            src_ip=src_ip,
            src_port=src_port,
            dst_port=dst_port,
            country=country,
        )
        self._json(
            "session.connect",
            ts,
            session=sid,
            src_ip=src_ip,
            src_port=src_port,
            dst_port=dst_port,
            country=country,
        )
        return ts

    def client_info(self, sid: str, **fields: Any) -> None:
        """Client version string and key-exchange fingerprint (HASSH)."""
        self._safe("session", self.storage.update_session, sid, **fields)
        self._json("session.client", self.clock(), session=sid, **fields)

    def session_closed(
        self,
        sid: str,
        *,
        reason: str,
        bytes_in: int,
        auth_attempts: int,
        pid: int,
        src_ip: str,
        src_port: int,
        duration: float,
    ) -> None:
        ts = self.clock()
        self._safe(
            "session", self.storage.update_session, sid, ended=ts, end_reason=reason,
            bytes_in=bytes_in,
        )  # fmt: skip
        if self.auth_log is not None and auth_attempts == 0:
            self._safe("auth log", self.auth_log.closed_preauth, ts, pid, src_ip, src_port)
        self._json(
            "session.closed", ts, session=sid, reason=reason, duration=round(duration, 3),
            bytes_in=bytes_in,
        )  # fmt: skip

    # -- authentication ---------------------------------------------------------

    def invalid_user(
        self, sid: str, *, pid: int, username: str, src_ip: str, src_port: int
    ) -> None:
        if self.auth_log is not None:
            self._safe(
                "auth log", self.auth_log.invalid_user, self.clock(), pid, username, src_ip,
                src_port,
            )  # fmt: skip

    def auth_attempt(
        self,
        sid: str,
        *,
        pid: int,
        src_ip: str,
        src_port: int,
        username: str,
        method: str,
        valid_user: bool,
        success: bool,
        password: str | None = None,
        key_type: str | None = None,
        key_fingerprint: str | None = None,
    ) -> None:
        ts = self.clock()
        self._safe(
            "auth attempt",
            self.storage.add_auth_attempt,
            sid,
            ts=ts,
            src_ip=src_ip,
            username=username,
            method=method,
            password=password,
            key_type=key_type,
            key_fingerprint=key_fingerprint,
            success=success,
        )
        if self.auth_log is not None:
            if success:
                self._safe(
                    "auth log", self.auth_log.accepted, ts, pid, method, username, src_ip, src_port
                )
            else:
                key_info = f"{key_type} {key_fingerprint}" if key_fingerprint else None
                self._safe(
                    "auth log", self.auth_log.failed, ts, pid, method, username, valid_user,
                    src_ip, src_port, key_info,
                )  # fmt: skip
        self._json(
            "auth.success" if success else "auth.failed",
            ts,
            session=sid,
            src_ip=src_ip,
            username=username,
            method=method,
            password=password,
            key_type=key_type,
            key_fingerprint=key_fingerprint,
        )

    def login(self, sid: str, event: LoginEvent, password: str | None) -> None:
        self._safe(
            "session", self.storage.update_session, sid, logged_in=1, login_user=event.username,
            login_password=password, login_at=event.ts,
        )  # fmt: skip
        if self.notifier is not None:
            try:
                task = asyncio.get_running_loop().create_task(self.notifier.login(event))
            except RuntimeError:
                return
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    # -- inside the session -----------------------------------------------------

    def command(self, sid: str, *, kind: str, command: str, known: bool, elapsed: float) -> None:
        ts = self.clock()
        self._safe(
            "command", self.storage.add_command, sid, ts=ts, elapsed=elapsed, kind=kind,
            command=command, known=known,
        )  # fmt: skip
        self._json("command", ts, session=sid, kind=kind, command=command, known=known)

    def request(self, sid: str, *, kind: str, detail: str | None, accepted: bool = False) -> None:
        ts = self.clock()
        self._safe(
            "request", self.storage.add_request, sid, ts=ts, kind=kind, detail=detail,
            accepted=accepted,
        )  # fmt: skip
        self._json("request", ts, session=sid, kind=kind, detail=detail, accepted=accepted)

    def download(self, sid: str, *, tool: str, url: str) -> None:
        """A URL the attacker asked wget/curl to fetch. It is recorded, never fetched."""
        ts = self.clock()
        self._safe("download", self.storage.add_download, sid, ts=ts, tool=tool, url=url)
        self._json("download", ts, session=sid, tool=tool, url=url)

    def terminal(self, sid: str, term: str) -> None:
        self._safe("session", self.storage.update_session, sid, term=term)

    async def drain(self) -> None:
        """Wait for pending notifications (used on shutdown and in tests)."""
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
