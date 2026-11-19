"""Configuration: a YAML file for behaviour, environment variables for secrets.

Relative paths in the YAML file are resolved against the file's directory.
Environment overrides (handy in Docker and systemd):

    HONEYPOT_CONFIG          path of the YAML file (default: ./config.yml)
    HONEYPOT_DB              database path
    HONEYPOT_STATE_DIR       directory for the generated host keys
    HONEYPOT_LISTEN_HOST     SSH listen address
    HONEYPOT_LISTEN_PORT     SSH listen port
    HONEYPOT_AUTH_LOG        sshd-style text log ("" disables it)
    HONEYPOT_JSON_LOG        JSON-lines event log ("" disables it)
    HONEYPOT_DASHBOARD_HOST  dashboard bind address
    HONEYPOT_DASHBOARD_PORT  dashboard port

Secrets are only ever read from the environment / .env:

    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
    HONEYPOT_DASHBOARD_USER, HONEYPOT_DASHBOARD_PASSWORD
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ListenConfig(_Strict):
    # Loopback by default so that running the project from a checkout never
    # exposes anything by accident. Deployments set 0.0.0.0 explicitly.
    host: str = "127.0.0.1"
    port: int = Field(default=2222, ge=0, le=65535)


class Credential(_Strict):
    """A username/password pair the "credentials" policy accepts. "*" matches anything."""

    username: str
    password: str


class AuthConfig(_Strict):
    # reject:          every attempt fails (credential harvesting only, the default)
    # after_attempts:  the Nth password attempt from one source IP succeeds
    # credentials:     the listed weak username/password pairs succeed
    policy: Literal["reject", "after_attempts", "credentials"] = "reject"
    accept_after: int = Field(default=3, ge=1, le=100)
    credentials: list[Credential] = Field(default_factory=list)
    # Usernames that "exist" on the fake host. Others get sshd's "Invalid user"
    # treatment in the auth.log (it changes nothing else).
    valid_users: list[str] = Field(default_factory=lambda: ["root", "ubuntu"])
    max_attempts_per_connection: int = Field(default=6, ge=1, le=100)
    # Seconds to wait before answering a failed attempt (sshd waits too).
    failure_delay: float = Field(default=1.0, ge=0, le=10)

    @model_validator(mode="after")
    def _check(self) -> AuthConfig:
        if self.policy == "credentials" and not self.credentials:
            raise ValueError(
                "auth.policy 'credentials' needs at least one entry in auth.credentials"
            )
        return self


class LimitsConfig(_Strict):
    max_connections: int = Field(default=100, ge=1, le=10_000)
    max_connections_per_ip: int = Field(default=5, ge=1, le=1_000)
    login_timeout: float = Field(default=30, gt=0)  # seconds to finish authentication
    idle_timeout: float = Field(default=120, gt=0)  # seconds without input
    max_session_duration: float = Field(default=600, gt=0)  # hard cap per connection
    max_input_bytes: int = Field(default=64 * 1024, ge=256)  # per connection, after auth
    max_commands: int = Field(default=200, ge=1)  # per connection
    max_line_length: int = Field(default=4096, ge=64, le=65536)
    max_channels: int = Field(default=4, ge=1, le=64)  # session channels per connection


class GeoIPConfig(_Strict):
    database: str | None = None


class DashboardConfig(_Strict):
    host: str = "127.0.0.1"
    port: int = 8081


class TelegramConfig(_Strict):
    batch_interval: float = Field(default=60.0, ge=5.0)
    max_sessions_per_message: int = Field(default=10, ge=1, le=30)


_PRINTABLE = re.compile(r"^[\x20-\x7e]+$")


class Config(_Strict):
    database: str = "data/honeypot.db"
    state_dir: str = "data"
    auth_log: str | None = "data/auth.log"
    # rfc3339 matches rsyslog on Ubuntu 24.04 / Debian 12; classic is "Nov 19 10:15:01".
    auth_log_timestamps: Literal["rfc3339", "classic"] = "rfc3339"
    auth_log_max_bytes: int = Field(default=20 * 1024 * 1024, ge=1024)
    auth_log_backups: int = Field(default=3, ge=1, le=50)
    json_log: str | None = None
    # Hostname written into auth.log lines. Keep it different from the real
    # host name so mini-siem (or anyone reading the log) can tell them apart.
    log_hostname: str = "honeypot"
    retention_days: int = Field(default=90, ge=1)

    # What the attacker sees.
    banner: str = "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
    hostname: str = "web-prod-01"
    host_key_types: list[Literal["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]] = Field(
        default_factory=lambda: ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]
    )

    listen: ListenConfig = Field(default_factory=ListenConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    geoip: GeoIPConfig = Field(default_factory=GeoIPConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    telegram: TelegramConfig = Field(default_factory=TelegramConfig)

    @field_validator("banner")
    @classmethod
    def _banner(cls, v: str) -> str:
        if v.startswith("SSH-"):
            raise ValueError("banner is the part after 'SSH-2.0-', e.g. 'OpenSSH_9.6p1 Ubuntu-3'")
        if not _PRINTABLE.match(v) or len(v) > 200:
            raise ValueError("banner must be printable ASCII, at most 200 characters")
        return v

    @field_validator("hostname", "log_hostname")
    @classmethod
    def _hostname(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", v):
            raise ValueError(f"invalid hostname: {v!r}")
        return v


def _resolve(base: Path, value: str | None) -> str | None:
    if not value:
        return value
    p = Path(value)
    return str(p if p.is_absolute() else (base / p).resolve())


def load_config(path: str | Path | None = None) -> Config:
    path = Path(path or os.environ.get("HONEYPOT_CONFIG", "config.yml"))
    data = {}
    if path.is_file():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    elif path.name != "config.yml" or "HONEYPOT_CONFIG" in os.environ:
        raise FileNotFoundError(f"config file not found: {path}")
    cfg = Config.model_validate(data)
    apply_overrides(cfg, path.resolve().parent)
    return cfg


def apply_overrides(cfg: Config, base: Path) -> None:
    env = os.environ
    cfg.database = env.get("HONEYPOT_DB") or _resolve(base, cfg.database) or cfg.database
    cfg.state_dir = env.get("HONEYPOT_STATE_DIR") or _resolve(base, cfg.state_dir) or cfg.state_dir
    if "HONEYPOT_AUTH_LOG" in env:
        cfg.auth_log = env["HONEYPOT_AUTH_LOG"] or None
    else:
        cfg.auth_log = _resolve(base, cfg.auth_log)
    if "HONEYPOT_JSON_LOG" in env:
        cfg.json_log = env["HONEYPOT_JSON_LOG"] or None
    else:
        cfg.json_log = _resolve(base, cfg.json_log)
    cfg.geoip.database = _resolve(base, cfg.geoip.database)
    if host := env.get("HONEYPOT_LISTEN_HOST"):
        cfg.listen.host = host
    if port := env.get("HONEYPOT_LISTEN_PORT"):
        cfg.listen.port = int(port)
    if host := env.get("HONEYPOT_DASHBOARD_HOST"):
        cfg.dashboard.host = host
    if port := env.get("HONEYPOT_DASHBOARD_PORT"):
        cfg.dashboard.port = int(port)
