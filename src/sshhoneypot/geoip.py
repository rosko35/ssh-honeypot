"""IP -> ISO country code lookups from a local ``.mmdb`` file.

Uses a MaxMind GeoLite2-Country / GeoLite2-City or DB-IP "IP to Country Lite"
database when one is configured. Nothing is downloaded or bundled; without a
database every lookup returns ``None`` and everything else works unchanged.
Lookups are local file reads, never network requests.
"""

from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path

log = logging.getLogger(__name__)


class GeoIP:
    def __init__(self, database: str | None = None) -> None:
        self._reader = None
        if database:
            path = Path(database)
            if path.is_file():
                try:
                    import maxminddb

                    self._reader = maxminddb.open_database(str(path))
                    log.info("GeoIP database loaded: %s", path)
                except Exception as exc:  # corrupt file, wrong format, ...
                    log.warning("cannot open GeoIP database %s: %s", path, exc)
            else:
                log.warning("GeoIP database %s not found; countries will be unknown", path)
        self.lookup = lru_cache(maxsize=65536)(self._lookup)

    @property
    def enabled(self) -> bool:
        return self._reader is not None

    def _lookup(self, ip: str | None) -> str | None:
        if not ip or self._reader is None:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if not addr.is_global:
            return None
        try:
            record = self._reader.get(ip)
        except Exception:
            return None
        if not isinstance(record, dict):
            return None
        for key in ("country", "registered_country"):
            iso = (record.get(key) or {}).get("iso_code")
            if iso:
                return str(iso).upper()
        return None

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
