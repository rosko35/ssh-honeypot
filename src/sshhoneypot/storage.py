"""SQLite storage: sessions, authentication attempts, commands and side requests.

Every TCP connection is a *session* row. Everything an attacker sends is
stored as plain data (bound SQL parameters, never string formatting), and
long values are truncated before they reach the database so a hostile client
cannot grow it with a single huge packet.

Timestamps are UNIX epoch seconds (UTC) as REAL.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id               TEXT PRIMARY KEY,
    started          REAL NOT NULL,
    ended            REAL,
    src_ip           TEXT NOT NULL,
    src_port         INTEGER,
    dst_port         INTEGER,
    country          TEXT,
    client_version   TEXT,
    hassh            TEXT,
    hassh_algorithms TEXT,
    kex              TEXT,
    cipher           TEXT,
    mac              TEXT,
    auth_attempts    INTEGER NOT NULL DEFAULT 0,
    logged_in        INTEGER NOT NULL DEFAULT 0,
    login_user       TEXT,
    login_password   TEXT,
    login_at         REAL,
    term             TEXT,
    commands         INTEGER NOT NULL DEFAULT 0,
    bytes_in         INTEGER NOT NULL DEFAULT 0,
    end_reason       TEXT
);
CREATE INDEX IF NOT EXISTS ix_sessions_started ON sessions(started);
CREATE INDEX IF NOT EXISTS ix_sessions_ip ON sessions(src_ip);

CREATE TABLE IF NOT EXISTS auth_attempts (
    id               INTEGER PRIMARY KEY,
    session_id       TEXT NOT NULL,
    ts               REAL NOT NULL,
    src_ip           TEXT NOT NULL,
    username         TEXT NOT NULL,
    method           TEXT NOT NULL,
    password         TEXT,
    key_type         TEXT,
    key_fingerprint  TEXT,
    success          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_auth_ts ON auth_attempts(ts);
CREATE INDEX IF NOT EXISTS ix_auth_session ON auth_attempts(session_id);

CREATE TABLE IF NOT EXISTS commands (
    id               INTEGER PRIMARY KEY,
    session_id       TEXT NOT NULL,
    ts               REAL NOT NULL,
    elapsed          REAL NOT NULL,
    kind             TEXT NOT NULL,
    command          TEXT NOT NULL,
    known            INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_commands_session ON commands(session_id, ts);
CREATE INDEX IF NOT EXISTS ix_commands_ts ON commands(ts);

CREATE TABLE IF NOT EXISTS requests (
    id               INTEGER PRIMARY KEY,
    session_id       TEXT NOT NULL,
    ts               REAL NOT NULL,
    kind             TEXT NOT NULL,
    detail          TEXT,
    accepted         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_requests_session ON requests(session_id);
CREATE INDEX IF NOT EXISTS ix_requests_ts ON requests(ts);

CREATE TABLE IF NOT EXISTS downloads (
    id               INTEGER PRIMARY KEY,
    session_id       TEXT NOT NULL,
    ts               REAL NOT NULL,
    tool             TEXT NOT NULL,
    url              TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_downloads_session ON downloads(session_id);
CREATE INDEX IF NOT EXISTS ix_downloads_ts ON downloads(ts);
"""

MAX_FIELD = 1024  # usernames, passwords, URLs, details
MAX_COMMAND = 4096

_SESSION_FIELDS = frozenset(
    {
        "ended", "country", "client_version", "hassh", "hassh_algorithms", "kex", "cipher",
        "mac", "auth_attempts", "logged_in", "login_user", "login_password", "login_at",
        "term", "commands", "bytes_in", "end_reason",
    }
)  # fmt: skip


def clip(value: str | None, limit: int = MAX_FIELD) -> str | None:
    if value is None:
        return None
    return value if len(value) <= limit else value[:limit] + "…"


def _rows(cur: sqlite3.Cursor) -> list[dict[str, Any]]:
    return [dict(r) for r in cur.fetchall()]


class SQLiteStorage:
    def __init__(self, path: str, *, readonly: bool = False) -> None:
        self.path = path
        if readonly:
            uri = Path(path).resolve().as_uri() + "?mode=ro"
            self.conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        else:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(path, check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.executescript(SCHEMA)
            self.conn.commit()
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=5000")

    def close(self) -> None:
        self.conn.close()

    # -- writes ---------------------------------------------------------------

    def create_session(
        self,
        session_id: str,
        *,
        started: float,
        src_ip: str,
        src_port: int | None,
        dst_port: int | None,
        country: str | None = None,
    ) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO sessions (id, started, src_ip, src_port, dst_port, country) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, started, src_ip, src_port, dst_port, country),
            )

    def update_session(self, session_id: str, **fields: Any) -> None:
        unknown = set(fields) - _SESSION_FIELDS
        if unknown:
            raise ValueError(f"unknown session fields: {sorted(unknown)}")
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields)  # keys are whitelisted above
        values = [clip(v) if isinstance(v, str) else v for v in fields.values()]
        with self.conn:
            self.conn.execute(f"UPDATE sessions SET {cols} WHERE id = ?", (*values, session_id))

    def add_auth_attempt(
        self,
        session_id: str,
        *,
        ts: float,
        src_ip: str,
        username: str,
        method: str,
        password: str | None = None,
        key_type: str | None = None,
        key_fingerprint: str | None = None,
        success: bool = False,
    ) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO auth_attempts (session_id, ts, src_ip, username, method, password, "
                "key_type, key_fingerprint, success) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session_id, ts, src_ip, clip(username), method, clip(password),
                    clip(key_type), clip(key_fingerprint), int(success),
                ),
            )  # fmt: skip
            self.conn.execute(
                "UPDATE sessions SET auth_attempts = auth_attempts + 1 WHERE id = ?",
                (session_id,),
            )

    def add_command(
        self, session_id: str, *, ts: float, elapsed: float, kind: str, command: str, known: bool
    ) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO commands (session_id, ts, elapsed, kind, command, known) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, ts, elapsed, kind, clip(command, MAX_COMMAND), int(known)),
            )
            self.conn.execute(
                "UPDATE sessions SET commands = commands + 1 WHERE id = ?", (session_id,)
            )

    def add_request(
        self, session_id: str, *, ts: float, kind: str, detail: str | None, accepted: bool = False
    ) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO requests (session_id, ts, kind, detail, accepted) "
                "VALUES (?, ?, ?, ?, ?)",
                (session_id, ts, kind, clip(detail), int(accepted)),
            )

    def add_download(self, session_id: str, *, ts: float, tool: str, url: str) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO downloads (session_id, ts, tool, url) VALUES (?, ?, ?, ?)",
                (session_id, ts, tool, clip(url)),
            )

    def prune(self, days: int) -> int:
        """Delete sessions (and everything that belongs to them) older than ``days``."""
        cutoff = time.time() - days * 86400
        with self.conn:
            old = "SELECT id FROM sessions WHERE started < ?"
            for table in ("auth_attempts", "commands", "requests", "downloads"):
                self.conn.execute(
                    f"DELETE FROM {table} WHERE session_id IN ({old}) OR ts < ?", (cutoff, cutoff)
                )
            n = self.conn.execute("DELETE FROM sessions WHERE started < ?", (cutoff,)).rowcount
        return n

    # -- reads ----------------------------------------------------------------

    def summary(self, since: float) -> dict[str, Any]:
        q = self.conn.execute
        s = q(
            "SELECT COUNT(*) AS sessions, COUNT(DISTINCT src_ip) AS ips, "
            "COALESCE(SUM(logged_in), 0) AS shell_sessions, MIN(started) AS first "
            "FROM sessions WHERE started >= ?",
            (since,),
        ).fetchone()
        a = q(
            "SELECT COUNT(*) AS attempts, COUNT(DISTINCT username) AS usernames, "
            "COUNT(DISTINCT password) AS passwords, "
            "COALESCE(SUM(method = 'publickey'), 0) AS key_attempts "
            "FROM auth_attempts WHERE ts >= ?",
            (since,),
        ).fetchone()
        c = q("SELECT COUNT(*) FROM commands WHERE ts >= ?", (since,)).fetchone()[0]
        d = q("SELECT COUNT(DISTINCT url) FROM downloads WHERE ts >= ?", (since,)).fetchone()[0]
        return {
            "sessions": s["sessions"],
            "unique_ips": s["ips"],
            "shell_sessions": s["shell_sessions"],
            "auth_attempts": a["attempts"],
            "key_attempts": a["key_attempts"],
            "usernames": a["usernames"],
            "passwords": a["passwords"],
            "commands": c,
            "download_urls": d,
            "first_seen": s["first"],
        }

    def top_usernames(self, since: float, limit: int = 10) -> list[dict]:
        return _rows(
            self.conn.execute(
                "SELECT username, COUNT(*) AS count, COUNT(DISTINCT src_ip) AS ips "
                "FROM auth_attempts WHERE ts >= ? GROUP BY username "
                "ORDER BY count DESC, username LIMIT ?",
                (since, limit),
            )
        )

    def top_passwords(self, since: float, limit: int = 10, min_sources: int = 1) -> list[dict]:
        return _rows(
            self.conn.execute(
                "SELECT password, COUNT(*) AS count, COUNT(DISTINCT src_ip) AS ips "
                "FROM auth_attempts WHERE ts >= ? AND method = 'password' "
                "GROUP BY password HAVING ips >= ? ORDER BY count DESC, password LIMIT ?",
                (since, min_sources, limit),
            )
        )

    def top_pairs(self, since: float, limit: int = 10, min_sources: int = 1) -> list[dict]:
        return _rows(
            self.conn.execute(
                "SELECT username, password, COUNT(*) AS count, COUNT(DISTINCT src_ip) AS ips "
                "FROM auth_attempts WHERE ts >= ? AND method = 'password' "
                "GROUP BY username, password HAVING ips >= ? "
                "ORDER BY count DESC, username, password LIMIT ?",
                (since, min_sources, limit),
            )
        )

    def top_ips(self, since: float, limit: int = 10) -> list[dict]:
        return _rows(
            self.conn.execute(
                "SELECT s.src_ip AS ip, MAX(s.country) AS country, COUNT(*) AS sessions, "
                "COALESCE(SUM(s.auth_attempts), 0) AS attempts, "
                "COALESCE(SUM(s.logged_in), 0) AS shells, "
                "MIN(s.started) AS first_seen, MAX(s.started) AS last_seen "
                "FROM sessions s WHERE s.started >= ? GROUP BY s.src_ip "
                "ORDER BY attempts DESC, sessions DESC, ip LIMIT ?",
                (since, limit),
            )
        )

    def countries(self, since: float) -> list[dict]:
        return _rows(
            self.conn.execute(
                "SELECT COALESCE(country, '??') AS country, COUNT(*) AS sessions, "
                "COALESCE(SUM(auth_attempts), 0) AS attempts, COUNT(DISTINCT src_ip) AS ips "
                "FROM sessions WHERE started >= ? GROUP BY 1 ORDER BY attempts DESC, sessions DESC",
                (since,),
            )
        )

    def client_versions(self, since: float, limit: int = 10) -> list[dict]:
        return _rows(
            self.conn.execute(
                "SELECT COALESCE(client_version, '(none)') AS client_version, "
                "COUNT(*) AS sessions, COUNT(DISTINCT src_ip) AS ips "
                "FROM sessions WHERE started >= ? "
                "GROUP BY 1 ORDER BY sessions DESC, client_version LIMIT ?",
                (since, limit),
            )
        )

    def top_hassh(self, since: float, limit: int = 10) -> list[dict]:
        return _rows(
            self.conn.execute(
                "SELECT hassh, MAX(client_version) AS client_version, COUNT(*) AS sessions, "
                "COUNT(DISTINCT src_ip) AS ips FROM sessions "
                "WHERE started >= ? AND hassh IS NOT NULL "
                "GROUP BY hassh ORDER BY sessions DESC, hassh LIMIT ?",
                (since, limit),
            )
        )

    def first_commands(self, since: float, limit: int = 10) -> list[dict]:
        """The first command line of each session, counted."""
        return _rows(
            self.conn.execute(
                "WITH firsts AS ("
                "  SELECT c.session_id, c.command, s.src_ip FROM commands c "
                "  JOIN sessions s ON s.id = c.session_id "
                "  WHERE c.ts >= ? AND c.id = ("
                "    SELECT MIN(id) FROM commands WHERE session_id = c.session_id)"
                ") SELECT command, COUNT(*) AS sessions, COUNT(DISTINCT src_ip) AS ips "
                "FROM firsts GROUP BY command ORDER BY sessions DESC, command LIMIT ?",
                (since, limit),
            )
        )

    def top_commands(self, since: float, limit: int = 10) -> list[dict]:
        return _rows(
            self.conn.execute(
                "SELECT command, COUNT(*) AS count, COUNT(DISTINCT session_id) AS sessions "
                "FROM commands WHERE ts >= ? GROUP BY command "
                "ORDER BY count DESC, command LIMIT ?",
                (since, limit),
            )
        )

    def top_downloads(self, since: float, limit: int = 10) -> list[dict]:
        return _rows(
            self.conn.execute(
                "SELECT url, COUNT(*) AS count, COUNT(DISTINCT session_id) AS sessions "
                "FROM downloads WHERE ts >= ? GROUP BY url ORDER BY count DESC, url LIMIT ?",
                (since, limit),
            )
        )

    def timeline(self, since: float, bucket: int = 3600) -> list[dict]:
        """Attempts, sessions and shell logins per time bucket (epoch seconds)."""
        q = self.conn.execute
        out: dict[int, dict] = {}

        def slot(b: int) -> dict:
            return out.setdefault(b, {"ts": b, "attempts": 0, "sessions": 0, "shells": 0})

        for b, n in q(
            "SELECT CAST(ts / ? AS INTEGER) * ?, COUNT(*) FROM auth_attempts "
            "WHERE ts >= ? GROUP BY 1",
            (bucket, bucket, since),
        ):
            slot(b)["attempts"] = n
        for b, n, shells in q(
            "SELECT CAST(started / ? AS INTEGER) * ?, COUNT(*), COALESCE(SUM(logged_in), 0) "
            "FROM sessions WHERE started >= ? GROUP BY 1",
            (bucket, bucket, since),
        ):
            slot(b)["sessions"] = n
            slot(b)["shells"] = shells
        start = int(since // bucket) * bucket
        end = int(time.time() // bucket) * bucket
        for b in range(start, end + 1, bucket):
            slot(b)
        return [out[k] for k in sorted(out)]

    def recent_sessions(self, limit: int = 50, *, shell_only: bool = False) -> list[dict]:
        where = "WHERE logged_in = 1" if shell_only else ""
        return _rows(
            self.conn.execute(
                "SELECT id, started, ended, src_ip, src_port, country, client_version, hassh, "
                "auth_attempts, logged_in, login_user, login_password, commands, end_reason "
                f"FROM sessions {where} ORDER BY started DESC LIMIT ?",
                (limit,),
            )
        )

    def session(self, session_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if row is None:
            return None
        q = self.conn.execute
        out = dict(row)
        out["auth"] = _rows(
            q(
                "SELECT ts, username, method, password, key_type, key_fingerprint, success "
                "FROM auth_attempts WHERE session_id = ? ORDER BY id",
                (session_id,),
            )
        )
        out["transcript"] = _rows(
            q(
                "SELECT ts, elapsed, kind, command, known FROM commands "
                "WHERE session_id = ? ORDER BY id",
                (session_id,),
            )
        )
        out["requests"] = _rows(
            q(
                "SELECT ts, kind, detail, accepted FROM requests WHERE session_id = ? ORDER BY id",
                (session_id,),
            )
        )
        out["downloads"] = _rows(
            q(
                "SELECT ts, tool, url FROM downloads WHERE session_id = ? ORDER BY id",
                (session_id,),
            )
        )
        return out
