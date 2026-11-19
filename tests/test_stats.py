from __future__ import annotations

import time

import pytest

from conftest import populate
from sshhoneypot.stats import mask_ip, md, render_markdown
from sshhoneypot.storage import SQLiteStorage


@pytest.fixture
def db(tmp_path):
    s = SQLiteStorage(str(tmp_path / "hp.db"))
    populate(s)
    yield s
    s.close()


def test_render_sections_and_totals(db):
    out = render_markdown(db, days=30, now=time.time())
    assert out.startswith("### Results: last 30 days")
    for heading in (
        "#### Top usernames",
        "#### Top passwords (tried from at least 2 source IPs)",
        "#### Top username:password pairs",
        "#### Top source addresses",
        "#### Top client versions",
        "#### Top HASSH client fingerprints",
        "#### Most common first commands",
    ):
        assert heading in out
    assert "| Login attempts | 6 |" in out
    assert "| Sessions that reached the fake shell | 1 |" in out
    assert "| 1 | `root` | 3 | 2 |" in out
    assert "| 1 | `uname -a` | 2 | 2 |" in out
    assert "| 1 | `SSH-2.0-libssh_0.9.6` | 2 | 1 |" in out


def test_privacy_defaults(db):
    out = render_markdown(db)
    assert "198.51.100.x" in out and "198.51.100.7" not in out
    assert "my-real-Passw0rd" not in out  # seen from one source only
    full = render_markdown(db, full_ips=True, min_sources=1)
    assert "198.51.100.7" in full and "my-real-Passw0rd" in full


def test_countries_only_with_geoip_data(tmp_path, db):
    assert "#### Top source countries" in render_markdown(db)  # data has countries
    empty = SQLiteStorage(str(tmp_path / "empty.db"))
    empty.create_session(
        "dddddddddddd", started=time.time(), src_ip="192.0.2.1", src_port=1, dst_port=2
    )
    assert "#### Top source countries" not in render_markdown(empty)
    assert "#### Top source countries" in render_markdown(empty, geoip_enabled=True)
    empty.close()


def test_hostile_values_cannot_break_markdown(db):
    out = render_markdown(db, min_sources=1)
    for line in out.splitlines():
        if line.startswith("|"):
            # every table row keeps its column count: pipes inside values are escaped
            assert line.count("|") - line.count("\\|") in (3, 4, 5, 6, 7)
    assert "`<img src=x onerror=\"alert(1)\">\\|'rm -rf /'`" in out


def test_helpers():
    assert mask_ip("203.0.113.42") == "203.0.113.x"
    assert mask_ip("2001:db8:1:2::5") == "2001:db8:1::/48"
    assert mask_ip("not-an-ip") == "not-an-ip"
    assert md("") == "`(empty)`"
    assert md("a|b`c\nd") == "`a\\|b'c�d`"
    assert md("x" * 200, 10) == "`" + "x" * 10 + "…`"


def test_empty_database(tmp_path):
    db = SQLiteStorage(str(tmp_path / "e.db"))
    out = render_markdown(db)
    assert "| Connections | 0 |" in out and "(none)" in out
    db.close()
