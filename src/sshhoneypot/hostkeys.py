"""Persistent SSH host keys.

Generated on first start into the state directory and reused afterwards, so
returning bots see the same fingerprint (a host key that changes on every
restart is an easy honeypot tell). The keys are never shipped or committed.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import asyncssh

log = logging.getLogger(__name__)

_FILES = {
    "ssh-ed25519": ("ssh_host_ed25519_key", {}),
    "ecdsa-sha2-nistp256": ("ssh_host_ecdsa_key", {}),
    "ssh-rsa": ("ssh_host_rsa_key", {"key_size": 3072}),
}


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def load_or_create_host_keys(state_dir: str, types: list[str]) -> list[asyncssh.SSHKey]:
    directory = Path(state_dir)
    directory.mkdir(parents=True, exist_ok=True)
    keys: list[asyncssh.SSHKey] = []
    for alg in types:
        filename, params = _FILES[alg]
        path = directory / filename
        if path.exists():
            key = asyncssh.read_private_key(str(path))
        else:
            key = asyncssh.generate_private_key(alg, **params)
            _write_private(path, key.export_private_key())
            path.with_suffix(".pub").write_bytes(key.export_public_key())
            log.info("generated host key %s (%s)", path, key.get_fingerprint())
        keys.append(key)
    return keys
