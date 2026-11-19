"""The fake shell: parses a command line and dispatches to simulated commands.

This module (and everything in this package) is pure string processing.
It never executes anything on the host, never spawns a process, never opens
a socket and never reads or writes the real filesystem. ``tests/test_safety.py``
checks the source for the usual ways of doing any of that.

Supported syntax is the part of sh that bots actually use: ``;``, ``&&``,
``||``, ``|``, ``>``, ``>>``, ``<``, quotes, ``$VAR`` and ``sh -c "..."``.
Command substitution and globbing are not implemented.
"""

from __future__ import annotations

import posixpath
import re
import shlex
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from . import commands
from .fs import FakeFS, FSError, build_tree

MAX_OUTPUT = 64 * 1024  # per command line
MAX_DEPTH = 3  # nested sh -c
_FD_REDIRECT = re.compile(r"(?<![^\s;|&])(?:\d*>&\d+|[2&]>>?\s*[^\s;|&]+)")
_VAR = re.compile(r"\$(?:\{(\w+)\}|([A-Za-z_]\w*|[0-9#?$!]))")
_SHELLS = {"sh", "bash", "dash", "ash", "zsh"}
_OPERATORS = {";", "&&", "||", "&", "|"}
_REDIRECTS = {">", ">>", "<", ">|"}
_WRAPPERS = {"sudo", "nohup", "time", "nice", "exec", "builtin", "env"}


class ShellSyntaxError(Exception):
    pass


@dataclass
class SimpleCommand:
    argv: list[str]
    stdout: str | None = None
    append: bool = False
    stdin: str | None = None


@dataclass
class LineResult:
    output: str = ""
    exit: bool = False
    known: bool = True
    status: int = 0


@dataclass
class _Out:
    text: str = ""
    status: int = 0
    known: bool = True


@dataclass
class FakeShell:
    hostname: str
    username: str
    src_ip: str = "203.0.113.1"
    on_download: Callable[[str, str], None] = lambda tool, url: None
    clock: Callable[[], float] = time.time
    user: str = field(init=False)
    cwd: str = field(init=False)
    home: str = field(init=False)
    uid: int = field(init=False)
    env: dict[str, str] = field(init=False)
    fs: FakeFS = field(init=False)
    history: list[str] = field(init=False, default_factory=list)
    started: float = field(init=False)

    def __post_init__(self) -> None:
        # Keep the prompt printable whatever the attacker logged in as.
        safe = re.sub(r"[^A-Za-z0-9._-]", "", self.username)[:32] or "user"
        self.user = safe
        self.uid = 0 if safe == "root" else 1000 if safe == "ubuntu" else 1001
        self.home = "/root" if safe == "root" else f"/home/{safe}"
        self.fs = FakeFS(build_tree(self.hostname, safe, self.home, self.uid))
        self.cwd = self.home
        self.started = self.clock()
        self.env = {
            "HOME": self.home,
            "USER": safe,
            "LOGNAME": safe,
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOSTNAME": self.hostname,
            "LANG": "C.UTF-8",
            "TERM": "xterm-256color",
        }

    # -- presentation -----------------------------------------------------------

    @property
    def is_root(self) -> bool:
        return self.uid == 0

    def prompt(self) -> str:
        cwd = self.cwd
        if cwd == self.home:
            cwd = "~"
        elif cwd.startswith(self.home + "/"):
            cwd = "~" + cwd[len(self.home) :]
        return f"{self.user}@{self.hostname}:{cwd}{'#' if self.is_root else '$'} "

    def motd(self) -> str:
        return commands.motd(self)

    def path(self, p: str) -> str:
        return FakeFS.normalize(self.cwd, p, self.home)

    # -- parsing ----------------------------------------------------------------

    def _var(self, name: str) -> str:
        if name == "PWD":
            return self.cwd
        return self.env.get(name, "")

    def expand(self, line: str) -> str:
        """Replace $VAR / ${VAR} outside single quotes, like sh does before word splitting."""
        out: list[str] = []
        i, n = 0, len(line)
        single = double = False
        while i < n:
            ch = line[i]
            if ch == "\\" and not single and i + 1 < n:
                out.append(line[i : i + 2])
                i += 2
                continue
            if ch == "'" and not double:
                single = not single
            elif ch == '"' and not single:
                double = not double
            elif ch == "$" and not single and (m := _VAR.match(line, i)):
                out.append(self._var(m.group(1) or m.group(2)))
                i = m.end()
                continue
            out.append(ch)
            i += 1
        return "".join(out)

    def parse(self, line: str) -> list[tuple[str, list[SimpleCommand]]]:
        """Split a line into (operator-before, pipeline) pairs."""
        line = self.expand(_FD_REDIRECT.sub(" ", line))
        lex = shlex.shlex(line, posix=True, punctuation_chars=";&|<>")
        lex.whitespace_split = True
        lex.commenters = "#"
        try:
            tokens = list(lex)
        except ValueError as exc:
            raise ShellSyntaxError("unexpected EOF while looking for matching quote") from exc

        result: list[tuple[str, list[SimpleCommand]]] = []
        op = ";"
        pipeline: list[SimpleCommand] = []
        current = SimpleCommand([])
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok in _OPERATORS or tok in (";;", "&&&", "|&"):
                if not current.argv:
                    raise ShellSyntaxError(f"syntax error near unexpected token `{tok}'")
                pipeline.append(current)
                current = SimpleCommand([])
                if tok in ("|", "|&"):
                    i += 1
                    continue
                result.append((op, pipeline))
                pipeline = []
                op = ";" if tok == "&" else tok
            elif tok in _REDIRECTS:
                if i + 1 >= len(tokens) or tokens[i + 1] in _OPERATORS | _REDIRECTS:
                    raise ShellSyntaxError("syntax error near unexpected token `newline'")
                target = tokens[i + 1]
                if tok == "<":
                    current.stdin = target
                else:
                    current.stdout = target
                    current.append = tok == ">>"
                i += 1
            else:
                current.argv.append(tok)
            i += 1
        if current.argv:
            pipeline.append(current)
        elif pipeline:
            raise ShellSyntaxError("syntax error: unexpected end of file")
        if pipeline:
            result.append((op, pipeline))
        return result

    # -- execution --------------------------------------------------------------

    def run_line(self, line: str, *, depth: int = 0) -> LineResult:
        line = line.strip()
        if not line:
            return LineResult()
        if depth == 0:
            self.history.append(line)
            del self.history[:-500]
        try:
            parsed = self.parse(line)
        except ShellSyntaxError as exc:
            return LineResult(f"-bash: {exc}\n", status=2)

        out: list[str] = []
        status = 0
        known = True
        for op, pipeline in parsed:
            if (op == "&&" and status != 0) or (op == "||" and status == 0):
                continue
            res = self._run_pipeline(pipeline, depth)
            if res is None:  # exit / logout
                return LineResult("".join(out), exit=True, known=known, status=status)
            out.append(res.text)
            status = res.status
            known = known and res.known
            if sum(len(o) for o in out) > MAX_OUTPUT:
                break
        text = "".join(out)
        if len(text) > MAX_OUTPUT:
            text = text[:MAX_OUTPUT] + "\n"
        return LineResult(text, known=known, status=status)

    def _run_pipeline(self, pipeline: list[SimpleCommand], depth: int) -> _Out | None:
        # There is no separate stderr stream. Approximation: the output of a
        # command that failed is an error message, so it goes to the terminal
        # instead of into the next command or a redirected file.
        stdin = ""
        stderr = ""
        result = _Out()
        known = True
        for i, cmd in enumerate(pipeline):
            if cmd.stdin is not None:
                node = self.fs.get(self.path(cmd.stdin))
                if node is None or node.is_dir:
                    return _Out(f"-bash: {cmd.stdin}: No such file or directory\n", 1)
                stdin = node.content
            result = self._run_simple(cmd.argv, stdin, depth)
            if result is None:
                return None
            known = known and result.known
            last = i == len(pipeline) - 1
            if result.status != 0 and (cmd.stdout is not None or not last):
                stderr += result.text
                result.text = ""
            if cmd.stdout is not None:
                err = self._redirect(cmd.stdout, result.text, cmd.append)
                if err:
                    return _Out(stderr + err, 1, known)
                result.text = ""
            stdin = result.text
        result.text = stderr + result.text
        result.known = known
        return result

    def _redirect(self, target: str, text: str, append: bool) -> str:
        if target in ("/dev/null", "/dev/stdout", "/dev/stderr"):
            return ""
        path = self.path(target)
        try:
            self.fs.write(path, text, append=append, now=self.clock(), owner=self.user)
        except FSError as exc:
            return f"-bash: {target}: {exc}\n"
        return ""

    def _run_simple(self, argv: list[str], stdin: str, depth: int) -> _Out | None:
        # Strip wrappers such as "sudo" or "nohup" and leading VAR=value assignments.
        while argv and (argv[0] in _WRAPPERS or re.fullmatch(r"[A-Za-z_]\w*=.*", argv[0])):
            if "=" in argv[0] and argv[0] not in _WRAPPERS:
                key, _, value = argv[0].partition("=")
                if len(argv) == 1:
                    self.env[key] = value
            argv = argv[1:]
            if argv and argv[0] in ("-u", "-n") and len(argv) > 1:  # sudo -u x / nice -n 5
                argv = argv[2:]
        if not argv:
            return _Out()
        name = argv[0]
        if name in ("exit", "logout"):
            return None
        if "/" in name:
            base = posixpath.basename(name)
            if posixpath.dirname(self.path(name)) in commands.BIN_DIRS and (
                base in commands.TABLE or base in _SHELLS or base == "busybox"
            ):
                name = base
                argv = [base, *argv[1:]]
        if name in _SHELLS or name == "busybox":
            return self._run_nested(argv, stdin, depth)
        if "/" in name:
            node = self.fs.get(self.path(name))
            if node is None:
                return _Out(f"-bash: {name}: No such file or directory\n", 127, False)
            if node.is_dir:
                return _Out(f"-bash: {name}: Is a directory\n", 126, False)
            return _Out(f"-bash: {name}: Permission denied\n", 126, False)
        handler = commands.TABLE.get(name)
        if handler is None:
            return _Out(f"{name}: command not found\n", 127, False)
        try:
            text, status = handler(self, argv[1:], stdin)
        except FSError as exc:
            return _Out(f"{name}: {exc}\n", 1)
        return _Out(text, status)

    def _run_nested(self, argv: list[str], stdin: str, depth: int) -> _Out | None:
        if len(argv) == 1:
            # "curl ... | sh" or "cat x | bash": run what arrived on stdin, if anything.
            if not stdin or depth >= MAX_DEPTH:
                return _Out("", 0)
            out = _Out()
            for script_line in stdin.splitlines()[:100]:
                res = self.run_line(script_line, depth=depth + 1)
                out.text += res.output
                out.status = res.status
                out.known = out.known and res.known
                if res.exit:
                    break
            return out
        if argv[0] == "busybox":
            if argv[1] not in commands.TABLE:  # Mirai & co. probe with random applet names
                return _Out(f"{argv[1]}: applet not found\n", 127, False)
            return self._run_simple(argv[1:], stdin, depth)
        if argv[1] == "-c" and len(argv) > 2:
            if depth >= MAX_DEPTH:
                return _Out("", 0)
            res = self.run_line(argv[2], depth=depth + 1)
            return _Out(res.output, res.status, res.known)
        script = argv[1]
        node = self.fs.get(self.path(script))
        if node is None:
            return _Out(f"{argv[0]}: {script}: No such file or directory\n", 127, False)
        return _Out("", 0)
