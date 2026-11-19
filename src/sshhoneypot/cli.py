"""Command line interface: ``honeypot <command>``."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import logging
import signal
import sys
from pathlib import Path

from dotenv import load_dotenv

from . import __version__
from .config import Config, load_config

log = logging.getLogger("sshhoneypot")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # httpx logs full request URLs at INFO, and the Telegram URL contains the bot token.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    # asyncssh logs every connection and auth attempt at INFO: we record those ourselves.
    logging.getLogger("asyncssh").setLevel(logging.DEBUG if verbose else logging.WARNING)


def _install_stop_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError):  # Windows
            loop.add_signal_handler(sig, stop.set)


async def serve(cfg: Config, stop: asyncio.Event, *, started: asyncio.Future | None = None) -> None:
    """Run the SSH honeypot until ``stop`` is set. ``started`` receives the running Honeypot."""
    from .geoip import GeoIP
    from .hostkeys import load_or_create_host_keys
    from .logs import AuthLog, JsonLog
    from .notifiers import build_notifiers
    from .recorder import Recorder
    from .server import Honeypot
    from .storage import SQLiteStorage

    storage = SQLiteStorage(cfg.database)
    auth_log = (
        AuthLog(
            cfg.auth_log,
            hostname=cfg.log_hostname,
            timestamps=cfg.auth_log_timestamps,
            max_bytes=cfg.auth_log_max_bytes,
            backups=cfg.auth_log_backups,
        )
        if cfg.auth_log
        else None
    )
    json_log = JsonLog(cfg.json_log) if cfg.json_log else None
    notifier = build_notifiers(cfg.telegram.batch_interval, cfg.telegram.max_sessions_per_message)
    geoip = GeoIP(cfg.geoip.database)
    recorder = Recorder(storage, auth_log=auth_log, json_log=json_log, notifier=notifier)
    keys = load_or_create_host_keys(cfg.state_dir, list(cfg.host_key_types))
    honeypot = Honeypot(cfg, recorder, keys, geoip=geoip)

    async def retention() -> None:
        while True:
            try:
                n = storage.prune(cfg.retention_days)
                if n:
                    log.info(
                        "retention: deleted %d sessions older than %d days", n, cfg.retention_days
                    )
            except Exception:
                log.exception("retention prune failed")
            await asyncio.sleep(3600)

    await notifier.start()
    await honeypot.start()
    prune_task = asyncio.create_task(retention())
    if started is not None:
        started.set_result(honeypot)
    try:
        await stop.wait()
    finally:
        log.info("shutting down")
        prune_task.cancel()
        await honeypot.stop()
        await notifier.close()
        geoip.close()
        for f in (auth_log, json_log):
            if f is not None:
                f.close()
        storage.close()


def cmd_run(cfg: Config, args: argparse.Namespace) -> int:
    async def main() -> None:
        stop = asyncio.Event()
        _install_stop_handlers(stop)
        await serve(cfg, stop)

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
    return 0


def _warn_if_exposed(cfg: Config) -> None:
    from .web import AuthSettings

    host = cfg.dashboard.host
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback and not AuthSettings.from_env().enabled:
        log.warning(
            "dashboard binds to %s without authentication. Fine inside a container that "
            "publishes on 127.0.0.1 only; otherwise set HONEYPOT_DASHBOARD_USER/PASSWORD.",
            host,
        )


def cmd_dashboard(cfg: Config, args: argparse.Namespace) -> int:
    import uvicorn

    from .web import create_app

    _warn_if_exposed(cfg)
    app = create_app(cfg.database)
    log.info("dashboard on http://%s:%d", cfg.dashboard.host, cfg.dashboard.port)
    uvicorn.run(
        app,
        host=cfg.dashboard.host,
        port=cfg.dashboard.port,
        log_level="warning",
        access_log=False,
        server_header=False,
        proxy_headers=False,
    )
    return 0


def cmd_stats(cfg: Config, args: argparse.Namespace) -> int:
    from .geoip import GeoIP
    from .stats import render_markdown
    from .storage import SQLiteStorage

    if not Path(cfg.database).exists():
        print(f"database {cfg.database} does not exist", file=sys.stderr)
        return 1
    db = SQLiteStorage(cfg.database, readonly=True)
    geoip = GeoIP(cfg.geoip.database)
    try:
        print(
            render_markdown(
                db,
                days=args.days,
                limit=args.limit,
                full_ips=args.full_ips,
                min_sources=args.min_sources,
                geoip_enabled=geoip.enabled,
            )
        )
    finally:
        db.close()
        geoip.close()
    return 0


def cmd_prune(cfg: Config, args: argparse.Namespace) -> int:
    from .storage import SQLiteStorage

    days = args.days or cfg.retention_days
    db = SQLiteStorage(cfg.database)
    try:
        n = db.prune(days)
    finally:
        db.close()
    print(
        f"deleted {n} sessions (with their attempts, commands and requests) older than {days} days"
    )
    return 0


def cmd_check_config(cfg: Config, args: argparse.Namespace) -> int:
    print(f"OK: listen {cfg.listen.host}:{cfg.listen.port}, policy {cfg.auth.policy}")
    print(f"    database {cfg.database}, state dir {cfg.state_dir}")
    print(f"    auth log {cfg.auth_log or '(disabled)'}, json log {cfg.json_log or '(disabled)'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="honeypot", description="ssh-honeypot: a low-interaction SSH honeypot"
    )
    p.add_argument(
        "-c", "--config", help="YAML config file (default: $HONEYPOT_CONFIG or config.yml)"
    )
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("run", help="run the SSH honeypot").set_defaults(func=cmd_run)
    sub.add_parser("dashboard", help="serve the read-only dashboard").set_defaults(
        func=cmd_dashboard
    )
    sub.add_parser("check-config", help="validate the configuration").set_defaults(
        func=cmd_check_config
    )

    s = sub.add_parser("stats", help="print a Markdown summary for the README")
    s.add_argument("--days", type=int, default=30)
    s.add_argument("--limit", type=int, default=10)
    s.add_argument("--full-ips", action="store_true", help="do not mask IP addresses")
    s.add_argument(
        "--min-sources",
        type=int,
        default=2,
        help="only list passwords tried from at least this many source IPs (default 2)",
    )
    s.set_defaults(func=cmd_stats)

    pr = sub.add_parser("prune", help="apply the retention period now")
    pr.add_argument("--days", type=int)
    pr.set_defaults(func=cmd_prune)
    return p


def main(argv: list[str] | None = None) -> int:
    load_dotenv(override=False)
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    try:
        cfg = load_config(args.config)
    except Exception as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    return args.func(cfg, args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
