"""Client fingerprinting: HASSH and the negotiated algorithms.

HASSH (https://github.com/salesforce/hassh) is the MD5 of the algorithm lists
a client offers in its SSH_MSG_KEXINIT::

    md5("kex_algorithms;encryption_c2s;mac_c2s;compression_c2s")

Different SSH libraries and bot frameworks offer different lists, so the hash
identifies the *tool* even when it lies in its version string.

asyncssh does not expose the peer's KEXINIT or the negotiated algorithms
publicly, so this reads private connection attributes (``_client_kexinit``,
``_kex_algs``, ``_enc_alg_cs``, ``_mac_alg_cs``; checked against asyncssh
2.24). If a future version renames them, the affected fields quietly become
``None`` and everything else keeps working. ``tests/test_server.py`` pins
the behaviour so an upgrade that breaks it is noticed.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any

MSG_KEXINIT = 20
_FIELDS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_c2s",
    "encryption_s2c",
    "mac_c2s",
    "mac_s2c",
    "compression_c2s",
    "compression_s2c",
    "languages_c2s",
    "languages_s2c",
)


def _parse(payload: bytes, offset: int) -> dict[str, str] | None:
    pos = offset + 16  # cookie
    out: dict[str, str] = {}
    try:
        for name in _FIELDS:
            (length,) = struct.unpack_from(">I", payload, pos)
            pos += 4
            if length > 65536 or pos + length > len(payload):
                return None
            out[name] = payload[pos : pos + length].decode("ascii", "replace")
            pos += length
    except struct.error:
        return None
    # first_kex_packet_follows (1 byte) + reserved uint32
    if len(payload) - pos != 5:
        return None
    return out


def parse_kexinit(payload: bytes) -> dict[str, str] | None:
    """Parse a KEXINIT payload, with or without the leading message-type byte."""
    if not payload:
        return None
    if payload[0] == MSG_KEXINIT and (parsed := _parse(payload, 1)):
        return parsed
    return _parse(payload, 0)


def hassh(kexinit: dict[str, str]) -> tuple[str, str]:
    """Return (hassh, hassh_algorithms) for a parsed client KEXINIT."""
    algorithms = ";".join(
        kexinit[k] for k in ("kex_algorithms", "encryption_c2s", "mac_c2s", "compression_c2s")
    )
    digest = hashlib.md5(algorithms.encode(), usedforsecurity=False).hexdigest()
    return digest, algorithms


def _alg(conn: Any, attr: str) -> str | None:
    value = getattr(conn, attr, None)
    return value.decode("ascii", "replace") if isinstance(value, bytes) else None


def connection_fingerprint(conn: Any) -> dict[str, str | None]:
    """Best-effort fingerprint of an asyncssh server connection after key exchange."""
    out: dict[str, str | None] = {
        "client_version": None,
        "hassh": None,
        "hassh_algorithms": None,
        "kex": None,
        "cipher": None,
        "mac": None,
    }
    try:
        out["client_version"] = conn.get_extra_info("client_version")
        raw = getattr(conn, "_client_kexinit", b"")
        if isinstance(raw, bytes) and (parsed := parse_kexinit(raw)):
            out["hassh"], out["hassh_algorithms"] = hassh(parsed)
            # SSH picks the first client-offered algorithm the server also supports.
            server_kex = {
                a.decode("ascii", "replace") for a in getattr(conn, "_kex_algs", []) or []
            }
            out["kex"] = next(
                (a for a in parsed["kex_algorithms"].split(",") if a in server_kex), None
            )
        out["cipher"] = _alg(conn, "_enc_alg_cs")
        out["mac"] = _alg(conn, "_mac_alg_cs")
    except Exception:  # fingerprinting must never break a connection
        pass
    return out
