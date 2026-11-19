"""``honeypot stats``: a README-ready Markdown summary of what the honeypot has seen.

Privacy defaults, because this output is meant to be published:

* IP addresses are masked to their network (``203.0.113.x``), like mini-siem;
* passwords and username:password pairs are only listed when they were tried
  from at least ``min_sources`` different IPs (default 2). Bots share
  wordlists, so real attack credentials pass easily; a one-off password a
  human typed by mistake (sometimes a real one!) does not.
* every attacker-controlled string is rendered as inline code with ``|`` and
  backticks neutralised, so it cannot break the table or inject Markdown.
"""

from __future__ import annotations

import ipaddress
import time
from datetime import UTC, datetime

from .storage import SQLiteStorage

_COUNTRY = {
    "CN": "China", "US": "United States", "RU": "Russia", "BR": "Brazil",
    "IN": "India", "DE": "Germany", "NL": "Netherlands", "FR": "France",
    "GB": "United Kingdom", "VN": "Vietnam", "KR": "South Korea", "ID": "Indonesia",
    "SG": "Singapore", "HK": "Hong Kong", "TW": "Taiwan", "JP": "Japan",
    "TR": "Türkiye", "UA": "Ukraine", "IR": "Iran", "BG": "Bulgaria", "RO": "Romania",
}  # fmt: skip


def mask_ip(ip: str) -> str:
    """Hide the host part: 203.0.113.42 -> 203.0.113.x, 2001:db8:1:2::5 -> 2001:db8:1::/48."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 4:
        return ".".join(ip.split(".")[:3]) + ".x"
    return str(ipaddress.ip_network(f"{addr}/48", strict=False))


def md(text: object, limit: int = 80) -> str:
    """Render an untrusted value as a Markdown inline-code table cell."""
    s = str(text)
    if len(s) > limit:
        s = s[:limit] + "…"
    s = "".join(ch if ch.isprintable() else "�" for ch in s)
    s = s.replace("`", "'").replace("|", "\\|")
    return f"`{s}`" if s.strip() else "`(empty)`"


def _country(code: str | None) -> str:
    if not code or code == "??":
        return "Unknown"
    return f"{_COUNTRY[code]} ({code})" if code in _COUNTRY else code


def _table(header: str, align: str, rows: list[str], empty: str) -> list[str]:
    return [header, align, *(rows or [empty]), ""]


def render_markdown(
    db: SQLiteStorage,
    days: int = 30,
    limit: int = 10,
    *,
    full_ips: bool = False,
    min_sources: int = 2,
    geoip_enabled: bool = False,
    now: float | None = None,
) -> str:
    now = time.time() if now is None else now
    since = now - days * 86400
    s = db.summary(since)

    first = s["first_seen"]
    period_start = max(since, first) if first else since
    actual_days = max((now - period_start) / 86400, 1.0)
    per_day = s["auth_attempts"] / actual_days

    def d(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d")

    out: list[str] = [
        f"### Results: last {days} days",
        "",
        f"_Generated with `honeypot stats --days {days}` on {d(now)}, "
        f"covering {d(period_start)} to {d(now)}._",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Connections | {s['sessions']:,} |",
        f"| Unique source IP addresses | {s['unique_ips']:,} |",
        f"| Login attempts | {s['auth_attempts']:,} |",
        f"| Average login attempts per day | {per_day:,.0f} |",
        f"| Public-key attempts | {s['key_attempts']:,} |",
        f"| Distinct usernames | {s['usernames']:,} |",
        f"| Distinct passwords | {s['passwords']:,} |",
        f"| Sessions that reached the fake shell | {s['shell_sessions']:,} |",
        f"| Commands recorded | {s['commands']:,} |",
        f"| Distinct download URLs (logged, never fetched) | {s['download_urls']:,} |",
        "",
    ]

    rows = [
        f"| {i} | {md(u['username'])} | {u['count']:,} | {u['ips']:,} |"
        for i, u in enumerate(db.top_usernames(since, limit), 1)
    ]
    out += ["#### Top usernames", ""]
    out += _table("| # | Username | Attempts | Source IPs |", "|---:|---|---:|---:|", rows,
                  "| - | (none) | 0 | 0 |")  # fmt: skip

    note = f" (tried from at least {min_sources} source IPs)" if min_sources > 1 else ""
    rows = [
        f"| {i} | {md(p['password'])} | {p['count']:,} | {p['ips']:,} |"
        for i, p in enumerate(db.top_passwords(since, limit, min_sources), 1)
    ]
    out += [f"#### Top passwords{note}", ""]
    out += _table("| # | Password | Attempts | Source IPs |", "|---:|---|---:|---:|", rows,
                  "| - | (none) | 0 | 0 |")  # fmt: skip

    rows = [
        f"| {i} | {md(p['username'], 40)} | {md(p['password'], 40)} | "
        f"{p['count']:,} | {p['ips']:,} |"
        for i, p in enumerate(db.top_pairs(since, limit, min_sources), 1)
    ]
    out += [f"#### Top username:password pairs{note}", ""]
    out += _table("| # | Username | Password | Attempts | Source IPs |", "|---:|---|---|---:|---:|",
                  rows, "| - | (none) | | 0 | 0 |")  # fmt: skip

    label = "IP" if full_ips else "Network (host part masked)"
    rows = [
        f"| {i} | {md(r['ip'] if full_ips else mask_ip(r['ip']))} | {_country(r['country'])} | "
        f"{r['sessions']:,} | {r['attempts']:,} |"
        for i, r in enumerate(db.top_ips(since, limit), 1)
    ]
    out += ["#### Top source addresses", ""]
    out += _table(f"| # | {label} | Country | Connections | Login attempts |",
                  "|---:|---|---|---:|---:|", rows, "| - | (none) | | 0 | 0 |")  # fmt: skip

    countries = db.countries(since)
    if geoip_enabled or any(c["country"] != "??" for c in countries):
        total = sum(c["attempts"] for c in countries) or 1
        rows = [
            f"| {i} | {_country(c['country'])} | {c['attempts']:,} | "
            f"{100 * c['attempts'] / total:.1f}% | {c['ips']:,} |"
            for i, c in enumerate(countries[:limit], 1)
        ]
        out += ["#### Top source countries", ""]
        out += _table("| # | Country | Login attempts | Share | IPs |", "|---:|---|---:|---:|---:|",
                      rows, "| - | (none) | 0 | | 0 |")  # fmt: skip

    rows = [
        f"| {i} | {md(v['client_version'], 60)} | {v['sessions']:,} | {v['ips']:,} |"
        for i, v in enumerate(db.client_versions(since, limit), 1)
    ]
    out += ["#### Top client versions", ""]
    out += _table("| # | Client version | Connections | Source IPs |", "|---:|---|---:|---:|",
                  rows, "| - | (none) | 0 | 0 |")  # fmt: skip

    rows = [
        f"| {i} | {md(h['hassh'])} | {md(h['client_version'] or '', 40)} | {h['sessions']:,} |"
        for i, h in enumerate(db.top_hassh(since, min(limit, 5)), 1)
    ]
    out += ["#### Top HASSH client fingerprints", ""]
    out += _table("| # | HASSH | Seen with | Connections |", "|---:|---|---|---:|", rows,
                  "| - | (none) | | 0 |")  # fmt: skip

    rows = [
        f"| {i} | {md(c['command'], 100)} | {c['sessions']:,} | {c['ips']:,} |"
        for i, c in enumerate(db.first_commands(since, limit), 1)
    ]
    out += ["#### Most common first commands", ""]
    out += _table("| # | First command | Sessions | Source IPs |", "|---:|---|---:|---:|", rows,
                  "| - | (none) | 0 | 0 |")  # fmt: skip

    if not full_ips:
        out.append("_IP addresses are truncated to protect personal data._")
    if min_sources > 1:
        out.append(
            f"_Passwords seen from fewer than {min_sources} source IPs are omitted, "
            "so a credential typed by a real person is not published by accident._"
        )
    out.append("")
    return "\n".join(out)
