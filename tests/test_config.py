from __future__ import annotations

import os
from pathlib import Path

import asyncssh
import pytest
from pydantic import ValidationError

from sshhoneypot.config import Config, load_config
from sshhoneypot.hostkeys import load_or_create_host_keys

ROOT = Path(__file__).resolve().parents[1]


def test_defaults_are_safe():
    cfg = Config()
    assert cfg.listen.host == "127.0.0.1"
    assert cfg.dashboard.host == "127.0.0.1"
    assert cfg.auth.policy == "reject"
    assert cfg.json_log is None


def test_shipped_config_loads(monkeypatch):
    for var in [v for v in os.environ if v.startswith("HONEYPOT_")]:
        monkeypatch.delenv(var)
    cfg = load_config(ROOT / "config.yml")
    assert cfg.listen.port == 2222 and cfg.listen.host == "127.0.0.1"
    assert cfg.auth.policy == "reject"
    assert Path(cfg.database).is_absolute()  # resolved against the config file


def test_env_overrides(monkeypatch, tmp_path):
    p = tmp_path / "c.yml"
    p.write_text("database: rel/hp.db\nauth_log: logs/auth.log\n", encoding="utf-8")
    monkeypatch.setenv("HONEYPOT_LISTEN_HOST", "0.0.0.0")
    monkeypatch.setenv("HONEYPOT_LISTEN_PORT", "2200")
    monkeypatch.setenv("HONEYPOT_JSON_LOG", str(tmp_path / "e.jsonl"))
    monkeypatch.delenv("HONEYPOT_DB", raising=False)
    monkeypatch.delenv("HONEYPOT_AUTH_LOG", raising=False)
    cfg = load_config(p)
    assert (cfg.listen.host, cfg.listen.port) == ("0.0.0.0", 2200)
    assert cfg.database == str((tmp_path / "rel" / "hp.db").resolve())
    assert cfg.auth_log == str((tmp_path / "logs" / "auth.log").resolve())
    assert cfg.json_log == str(tmp_path / "e.jsonl")
    monkeypatch.setenv("HONEYPOT_AUTH_LOG", "")
    assert load_config(p).auth_log is None


@pytest.mark.parametrize(
    "data",
    [
        {"banner": "SSH-2.0-OpenSSH_9.6"},
        {"banner": "OpenSSH\r\nInjected"},
        {"hostname": "bad host;"},
        {"auth": {"policy": "credentials"}},  # no credentials listed
        {"auth": {"policy": "open-sesame"}},
        {"limits": {"max_input_bytes": 1}},
        {"unknown_key": 1},
    ],
)
def test_invalid_config_is_rejected(data):
    with pytest.raises(ValidationError):
        Config.model_validate(data)


def test_missing_explicit_config_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope.yml")


def test_host_keys_are_persistent(tmp_path):
    first = load_or_create_host_keys(str(tmp_path), ["ssh-ed25519", "ecdsa-sha2-nistp256"])
    second = load_or_create_host_keys(str(tmp_path), ["ssh-ed25519", "ecdsa-sha2-nistp256"])
    assert [k.get_fingerprint() for k in first] == [k.get_fingerprint() for k in second]
    assert (tmp_path / "ssh_host_ed25519_key").is_file()
    assert (tmp_path / "ssh_host_ed25519_key.pub").is_file()
    key = asyncssh.read_private_key(str(tmp_path / "ssh_host_ecdsa_key"))
    assert key.get_algorithm() == "ecdsa-sha2-nistp256"
    if os.name == "posix":
        assert (tmp_path / "ssh_host_ed25519_key").stat().st_mode & 0o077 == 0
