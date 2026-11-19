from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from conftest import client, populate
from sshhoneypot.cli import main, serve
from sshhoneypot.storage import SQLiteStorage


@pytest.fixture
def cfg_file(tmp_path, key_dir):
    p = tmp_path / "config.yml"
    p.write_text(
        f"database: {tmp_path / 'hp.db'}\nstate_dir: {key_dir}\nhost_key_types: [ssh-ed25519]\n",
        encoding="utf-8",
    )
    return p


def test_stats_command(cfg_file, tmp_path, capsys):
    db = SQLiteStorage(str(tmp_path / "hp.db"))
    populate(db)
    db.close()
    assert main(["-c", str(cfg_file), "stats", "--days", "7"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("### Results: last 7 days")
    assert "honeypot stats --days 7" in out


def test_stats_without_database(cfg_file, capsys):
    assert main(["-c", str(cfg_file), "stats"]) == 1
    assert "does not exist" in capsys.readouterr().err


def test_prune_and_check_config(cfg_file, tmp_path, capsys):
    db = SQLiteStorage(str(tmp_path / "hp.db"))
    populate(db, now=1_000_000.0)  # 1970: everything is old
    db.close()
    assert main(["-c", str(cfg_file), "prune", "--days", "30"]) == 0
    assert "deleted 4 sessions" in capsys.readouterr().out
    assert main(["-c", str(cfg_file), "check-config"]) == 0
    assert "listen 127.0.0.1:2222" in capsys.readouterr().out


def test_configuration_error(tmp_path, capsys):
    bad = tmp_path / "bad.yml"
    bad.write_text("auth: {policy: maybe}\n", encoding="utf-8")
    assert main(["-c", str(bad), "check-config"]) == 2
    assert "configuration error" in capsys.readouterr().err


async def test_serve_end_to_end(make_config, tmp_path):
    """The real `honeypot run` wiring: storage, logs, host keys, prune task, shutdown."""
    cfg = make_config(state_dir=str(tmp_path / "state"))
    stop = asyncio.Event()
    started: asyncio.Future = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(serve(cfg, stop, started=started))
    hp = await asyncio.wait_for(started, 30)
    # Generated on first start into the state dir:
    assert (tmp_path / "state" / "ssh_host_ed25519_key").is_file()
    with pytest.raises(Exception, match="denied"):
        async with client(hp.port, username="root", password="x"):
            pass
    stop.set()
    await asyncio.wait_for(task, 10)
    db = SQLiteStorage(cfg.database, readonly=True)
    assert db.summary(0)["auth_attempts"] == 1
    db.close()
    assert "Failed password for root" in Path(cfg.auth_log).read_text(encoding="utf-8")
