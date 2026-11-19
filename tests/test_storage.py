from __future__ import annotations

import sqlite3
import time

import pytest

from conftest import HOSTILE, populate
from sshhoneypot.storage import MAX_FIELD, SQLiteStorage


@pytest.fixture
def db(tmp_path):
    s = SQLiteStorage(str(tmp_path / "hp.db"))
    populate(s)
    yield s
    s.close()


def test_summary(db):
    s = db.summary(time.time() - 86400)
    assert s["sessions"] == 4
    assert s["unique_ips"] == 3
    assert s["auth_attempts"] == 6
    assert s["usernames"] == 4
    assert s["passwords"] == 3
    assert s["shell_sessions"] == 1
    assert s["commands"] == 4
    assert s["download_urls"] == 1


def test_top_queries(db):
    since = time.time() - 86400
    assert db.top_usernames(since, 1) == [{"username": "root", "count": 3, "ips": 2}]
    pw = db.top_passwords(since, 10)
    assert pw[0] == {"password": "123456", "count": 3, "ips": 3}
    assert {"password": "my-real-Passw0rd", "count": 1, "ips": 1} in pw
    # min_sources hides credentials tried from a single address
    assert [p["password"] for p in db.top_passwords(since, 10, min_sources=2)] == ["123456"]
    pairs = db.top_pairs(since, 10, min_sources=2)
    assert pairs == [{"username": "root", "password": "123456", "count": 2, "ips": 2}]
    ips = db.top_ips(since)
    assert ips[0]["ip"] == "198.51.100.7" and ips[0]["attempts"] == 3 and ips[0]["sessions"] == 2
    assert {c["country"] for c in db.countries(since)} == {"CN", "US", "??"}
    assert db.client_versions(since)[0] == {
        "client_version": "SSH-2.0-libssh_0.9.6", "sessions": 2, "ips": 1,
    }  # fmt: skip
    firsts = {f["command"]: f["sessions"] for f in db.first_commands(since)}
    assert firsts == {"uname -a": 2}
    assert {h["hassh"]: h["sessions"] for h in db.top_hassh(since)} == {"f" * 32: 2, "e" * 32: 2}


def test_session_detail(db):
    s = db.session("aaaaaaaaaaa4")
    assert s["login_user"] == HOSTILE
    assert [c["command"] for c in s["transcript"]][1] == HOSTILE
    assert s["downloads"][0]["url"] == "http://malware.example/x.sh"
    assert s["requests"][0]["kind"] == "direct-tcpip"
    assert db.session("000000000000") is None
    assert [r["id"] for r in db.recent_sessions(10, shell_only=True)] == ["aaaaaaaaaaa4"]


def test_timeline_buckets(db):
    rows = db.timeline(time.time() - 3 * 3600)
    assert sum(r["attempts"] for r in rows) == 6
    assert sum(r["sessions"] for r in rows) == 4
    assert len(rows) in (3, 4)
    assert [r["ts"] for r in rows] == sorted(r["ts"] for r in rows)


def test_long_values_are_clipped(tmp_path):
    db = SQLiteStorage(str(tmp_path / "x.db"))
    db.create_session(
        "bbbbbbbbbbbb", started=time.time(), src_ip="192.0.2.1", src_port=1, dst_port=2
    )
    db.add_auth_attempt("bbbbbbbbbbbb", ts=time.time(), src_ip="192.0.2.1", username="u" * 50000,
                        method="password", password="p" * 50000)  # fmt: skip
    row = db.conn.execute("SELECT username, password FROM auth_attempts").fetchone()
    assert len(row["username"]) == MAX_FIELD + 1 and len(row["password"]) == MAX_FIELD + 1
    with pytest.raises(ValueError):
        db.update_session("bbbbbbbbbbbb", src_ip="1.1.1.1")  # not an updatable column
    db.close()


def test_prune(tmp_path):
    db = SQLiteStorage(str(tmp_path / "x.db"))
    populate(db, now=time.time() - 40 * 86400)
    populate_new = time.time()
    db.create_session(
        "cccccccccccc", started=populate_new, src_ip="192.0.2.9", src_port=1, dst_port=2
    )
    assert db.prune(30) == 4
    assert db.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    for table in ("auth_attempts", "commands", "requests", "downloads"):
        assert db.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    db.close()


def test_readonly_connection_cannot_write(tmp_path, db):
    ro = SQLiteStorage(db.path, readonly=True)
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        ro.conn.execute("DELETE FROM sessions")
    ro.close()
