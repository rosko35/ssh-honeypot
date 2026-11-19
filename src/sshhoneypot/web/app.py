"""Read-only dashboard: a JSON API plus a single static page (Chart.js).

Security posture (same as mini-siem):

* binds to 127.0.0.1 by default; reach it through an SSH tunnel;
* optional HTTP basic auth (HONEYPOT_DASHBOARD_USER / HONEYPOT_DASHBOARD_PASSWORD),
  compared in constant time;
* opens the database read-only, never writes;
* strict security headers: a CSP that allows scripts only from this origin and
  a pinned, SRI-checked Chart.js on jsDelivr; no inline script or style;
* everything in the database is attacker-controlled text. The API returns it
  as JSON (never as HTML) and the page inserts it with ``textContent`` only.
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.responses import FileResponse, JSONResponse

from .. import __version__
from ..storage import SQLiteStorage

STATIC = Path(__file__).parent / "static"
ASSETS = {"app.js": "text/javascript", "style.css": "text/css"}

CSP = (
    "default-src 'none'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


class AuthSettings:
    def __init__(self, user: str = "", password: str = "") -> None:
        self.user = user
        self.password = password

    @classmethod
    def from_env(cls) -> AuthSettings:
        return cls(
            os.environ.get("HONEYPOT_DASHBOARD_USER", ""),
            os.environ.get("HONEYPOT_DASHBOARD_PASSWORD", ""),
        )

    @property
    def enabled(self) -> bool:
        return bool(self.user and self.password)

    def check(self, header: str) -> bool:
        if not self.enabled:
            return True
        scheme, _, value = header.partition(" ")
        if scheme.lower() != "basic":
            return False
        try:
            user, _, password = (
                base64.b64decode(value.strip(), validate=True).decode().partition(":")
            )
        except (binascii.Error, UnicodeDecodeError):
            return False
        ok_user = secrets.compare_digest(user.encode(), self.user.encode())
        ok_pass = secrets.compare_digest(password.encode(), self.password.encode())
        return ok_user and ok_pass


def get_db(request: Request) -> Iterator[SQLiteStorage]:
    """A read-only connection per request (cheap for SQLite, safe across threads)."""
    db_path = request.app.state.db_path
    if not Path(db_path).exists():
        raise HTTPException(503, "database not created yet - is the honeypot running?")
    db = SQLiteStorage(db_path, readonly=True)
    try:
        yield db
    finally:
        db.close()


DB = Annotated[SQLiteStorage, Depends(get_db)]
Days = Annotated[int, Query(ge=1, le=365)]
Limit = Annotated[int, Query(ge=1, le=100)]
Hours = Annotated[int, Query(ge=1, le=24 * 31)]
SessionId = Annotated[str, PathParam(pattern=r"^[0-9a-f]{12}$")]


def create_app(db_path: str, *, auth: AuthSettings | None = None) -> FastAPI:
    auth = auth if auth is not None else AuthSettings.from_env()
    app = FastAPI(
        title="ssh-honeypot", version=__version__, docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.db_path = db_path

    def require_auth(request: Request) -> None:
        if not auth.check(request.headers.get("authorization", "")):
            raise HTTPException(
                401, "authentication required", {"WWW-Authenticate": 'Basic realm="ssh-honeypot"'}
            )

    def since(days: int) -> float:
        return time.time() - days * 86400

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        return response

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    api = APIRouter(prefix="/api", dependencies=[Depends(require_auth)])

    @api.get("/summary")
    def summary(db: DB, days: Days = 7) -> dict:
        return {"days": days, **db.summary(since(days))}

    @api.get("/timeline")
    def timeline(db: DB, hours: Hours = 48) -> list[dict]:
        bucket = 3600 if hours <= 24 * 7 else 6 * 3600
        return db.timeline(time.time() - hours * 3600, bucket)

    @api.get("/top-usernames")
    def top_usernames(db: DB, days: Days = 7, limit: Limit = 10) -> list[dict]:
        return db.top_usernames(since(days), limit)

    @api.get("/top-passwords")
    def top_passwords(db: DB, days: Days = 7, limit: Limit = 10) -> list[dict]:
        return db.top_passwords(since(days), limit)

    @api.get("/top-pairs")
    def top_pairs(db: DB, days: Days = 7, limit: Limit = 10) -> list[dict]:
        return db.top_pairs(since(days), limit)

    @api.get("/top-ips")
    def top_ips(db: DB, days: Days = 7, limit: Limit = 10) -> list[dict]:
        return db.top_ips(since(days), limit)

    @api.get("/countries")
    def countries(db: DB, days: Days = 7) -> list[dict]:
        return db.countries(since(days))

    @api.get("/client-versions")
    def client_versions(db: DB, days: Days = 7, limit: Limit = 10) -> list[dict]:
        return db.client_versions(since(days), limit)

    @api.get("/downloads")
    def downloads(db: DB, days: Days = 7, limit: Limit = 20) -> list[dict]:
        return db.top_downloads(since(days), limit)

    @api.get("/sessions/recent")
    def recent_sessions(db: DB, limit: Limit = 50, shell_only: bool = True) -> list[dict]:
        return db.recent_sessions(limit, shell_only=shell_only)

    @api.get("/sessions/{sid}")
    def session(db: DB, sid: SessionId) -> dict:
        data = db.session(sid)
        if data is None:
            raise HTTPException(404, "no such session")
        return data

    app.include_router(api)

    @app.get("/", include_in_schema=False, dependencies=[Depends(require_auth)])
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/assets/{name}", include_in_schema=False, dependencies=[Depends(require_auth)])
    def asset(name: str) -> FileResponse:
        if name not in ASSETS:
            raise HTTPException(404)
        return FileResponse(STATIC / name, media_type=ASSETS[name])

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return JSONResponse(
            {"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers
        )

    return app
