"""Text logs written next to the database.

* :class:`AuthLog` writes sshd-style lines ("Failed password for ... from IP
  port N ssh2") that mini-siem's ``auth`` parser (or fail2ban, or a human
  with grep) can read. Passwords are never written there, exactly like sshd.
* :class:`JsonLog` writes one JSON object per event, for jq or a log shipper.

Both rotate themselves by size (rename to ``.1``, ``.2``, ...) so a flood
cannot fill the disk even without logrotate. Rotation by rename is the
"create" mode that mini-siem's tailer follows.

Usernames are attacker-controlled. Before they go into a line-oriented log,
everything outside printable ASCII *and the space character* is escaped as
``\\xNN``. That stops two log-injection tricks: a newline that forges a whole
extra line, and a username like ``x from 198.51.100.7 port 1`` that would
make a parser blame a different IP.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Any


def sanitize(value: str, limit: int = 128) -> str:
    """Escape a value for a single-token position in a syslog-style line."""
    out: list[str] = []
    for ch in value[:limit]:
        if "!" <= ch <= "~" and ch != "\\":
            out.append(ch)
        else:
            out.extend(f"\\x{b:02x}" for b in ch.encode("utf-8", "replace"))
    if len(value) > limit:
        out.append("...")
    return "".join(out)


def _key_label(algorithm: str) -> str:
    """ssh-ed25519 -> ED25519, rsa-sha2-512 -> RSA, ecdsa-sha2-nistp256 -> ECDSA (sshd's labels)."""
    for prefix, label in (
        ("ssh-ed25519", "ED25519"),
        ("sk-ssh-ed25519", "ED25519-SK"),
        ("ecdsa-", "ECDSA"),
        ("sk-ecdsa-", "ECDSA-SK"),
        ("ssh-rsa", "RSA"),
        ("rsa-sha2-", "RSA"),
        ("ssh-dss", "DSA"),
    ):
        if algorithm.startswith(prefix):
            return label
    return algorithm.upper() or "UNKNOWN"


def _rotating_logger(name: str, path: str, max_bytes: int, backups: int) -> logging.Logger:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(f"sshhoneypot.file.{name}.{path}")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(
        path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


def _close(logger: logging.Logger) -> None:
    for h in list(logger.handlers):
        h.close()
        logger.removeHandler(h)


class AuthLog:
    """sshd-compatible authentication log."""

    def __init__(
        self,
        path: str,
        *,
        hostname: str = "honeypot",
        timestamps: str = "rfc3339",
        max_bytes: int = 20 * 1024 * 1024,
        backups: int = 3,
    ) -> None:
        self.path = path
        self.hostname = hostname
        self.timestamps = timestamps
        self._log = _rotating_logger("auth", path, max_bytes, backups)

    def _stamp(self, ts: float) -> str:
        dt = datetime.fromtimestamp(ts).astimezone()
        if self.timestamps == "classic":
            return f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S}"
        return dt.isoformat(timespec="microseconds")

    def line(self, ts: float, pid: int, message: str) -> str:
        return f"{self._stamp(ts)} {self.hostname} sshd[{pid}]: {message}"

    def write(self, ts: float, pid: int, message: str) -> None:
        self._log.info(self.line(ts, pid, message))

    # The messages below follow OpenSSH's wording (auth.c / auth2.c).

    def invalid_user(self, ts: float, pid: int, user: str, ip: str, port: int) -> None:
        self.write(ts, pid, f"Invalid user {sanitize(user)} from {ip} port {port}")

    def failed(
        self,
        ts: float,
        pid: int,
        method: str,
        user: str,
        valid: bool,
        ip: str,
        port: int,
        key_type: str | None = None,
        key_fingerprint: str | None = None,
    ) -> None:
        who = sanitize(user) if valid else f"invalid user {sanitize(user)}"
        extra = ""
        if key_fingerprint:  # sshd style: "ssh2: ED25519 SHA256:..."
            extra = f": {sanitize(_key_label(key_type or ''))} {sanitize(key_fingerprint, 200)}"
        self.write(ts, pid, f"Failed {method} for {who} from {ip} port {port} ssh2{extra}")

    def accepted(self, ts: float, pid: int, method: str, user: str, ip: str, port: int) -> None:
        self.write(ts, pid, f"Accepted {method} for {sanitize(user)} from {ip} port {port} ssh2")

    def closed_preauth(self, ts: float, pid: int, ip: str, port: int) -> None:
        self.write(ts, pid, f"Connection closed by {ip} port {port} [preauth]")

    def close(self) -> None:
        _close(self._log)


class JsonLog:
    """One JSON object per line. ``json.dumps`` escapes control characters."""

    def __init__(self, path: str, *, max_bytes: int = 50 * 1024 * 1024, backups: int = 3) -> None:
        self.path = path
        self._log = _rotating_logger("json", path, max_bytes, backups)

    def write(self, event: str, ts: float, **fields: Any) -> None:
        record = {
            "ts": datetime.fromtimestamp(ts).astimezone().isoformat(timespec="microseconds"),
            "event": event,
            **fields,
        }
        self._log.info(json.dumps(record, ensure_ascii=True, default=str))

    def close(self) -> None:
        _close(self._log)
