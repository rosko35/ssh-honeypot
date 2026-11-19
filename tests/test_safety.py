"""Static guard rails for the isolation guarantees.

These tests read the source code. They catch the obvious ways a future change
could make the honeypot interact with the host on an attacker's behalf
(spawning processes, opening sockets, touching real files from the fake
shell, enabling forwarding in asyncssh). They are not a proof; the end-to-end
tests in test_server.py check the behaviour.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "sshhoneypot"
SHELL_FILES = sorted((SRC / "shell").glob("*.py"))
ATTACKER_FACING = [*SHELL_FILES, SRC / "server.py"]

FORBIDDEN_MODULES = {
    "subprocess", "pty", "pexpect", "socket", "ssl", "urllib.request", "http.client",
    "httpx", "requests", "aiohttp", "ftplib", "telnetlib", "multiprocessing", "ctypes",
    "shutil", "tempfile", "pathlib", "io", "os",
}  # fmt: skip
FORBIDDEN_BUILTINS = {"open", "exec", "eval", "compile", "__import__", "breakpoint"}
FORBIDDEN_METHODS = {
    "system", "popen", "spawn", "create_subprocess_exec", "create_subprocess_shell",
    "open_connection", "create_connection", "connect", "urlopen", "getaddrinfo",
    "gethostbyname", "getnameinfo", "read_text", "write_text", "read_bytes", "write_bytes",
}  # fmt: skip


def _imports(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def _calls(tree: ast.AST) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id in FORBIDDEN_BUILTINS:
                out.add(f.id)
            elif isinstance(f, ast.Attribute) and f.attr in FORBIDDEN_METHODS:
                out.add(f.attr)
    return out


@pytest.mark.parametrize("path", ATTACKER_FACING, ids=lambda p: p.name)
def test_no_process_network_or_file_access(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = _imports(tree)
    bad = {m for m in imported if m in FORBIDDEN_MODULES or m.split(".")[0] in FORBIDDEN_MODULES}
    assert not bad, f"{path.name} imports {bad}"
    called = _calls(tree)
    assert not called, f"{path.name} calls {called}"


def test_shell_package_only_imports_pure_modules():
    allowed = {
        "__future__", "collections.abc", "dataclasses", "datetime", "ipaddress", "posixpath",
        "re", "shlex", "time", "typing", "urllib.parse",
    }  # fmt: skip
    for path in SHELL_FILES:
        imported = _imports(ast.parse(path.read_text(encoding="utf-8")))
        assert imported <= allowed, f"{path.name}: unexpected imports {imported - allowed}"


def _create_server_kwargs() -> dict[str, object]:
    tree = ast.parse((SRC / "server.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "create_server"
        ):
            return {
                kw.arg: ast.literal_eval(kw.value)
                for kw in node.keywords
                if kw.arg and isinstance(kw.value, ast.Constant)
            }
    raise AssertionError("asyncssh.create_server call not found")


def test_asyncssh_is_configured_without_forwarding_or_lookups():
    kw = _create_server_kwargs()
    assert kw["agent_forwarding"] is False
    assert kw["x11_forwarding"] is False
    assert kw["allow_scp"] is False
    assert kw["sftp_factory"] is None
    assert kw["rdns_lookup"] is False
    assert kw["gss_host"] is None
    assert kw["host_based_auth"] is False
    assert kw["config"] is None


def test_honeypot_server_refuses_every_forwarding_hook():
    import asyncssh

    from sshhoneypot.server import HoneypotServer

    hooks = [
        "connection_requested", "server_requested", "unix_connection_requested",
        "unix_server_requested", "tun_requested", "tap_requested",
    ]  # fmt: skip
    for name in hooks:
        assert getattr(HoneypotServer, name) is not getattr(asyncssh.SSHServer, name), name

    class Dummy:
        def request(self, *a, **k):
            pass

    srv = HoneypotServer.__new__(HoneypotServer)
    srv.rec = Dummy()
    srv.sid = "0" * 12
    srv.last_activity = 0
    srv.requests = 0
    assert srv.connection_requested("10.0.0.1", 22, "1.2.3.4", 5) is False
    assert srv.server_requested("0.0.0.0", 8080) is False
    assert srv.unix_connection_requested("/run/docker.sock") is False
    assert srv.unix_server_requested("/tmp/x") is False
    assert srv.tun_requested(None) is False
    assert srv.tap_requested(0) is False
