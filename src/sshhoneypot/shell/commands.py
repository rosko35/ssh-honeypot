"""Simulated commands. Each takes (shell, args, stdin) and returns (output, exit status).

Everything here works on strings and on the in-memory :class:`FakeFS`.
``wget``/``curl``/``tftp`` only *report* the URL they were asked for through
``shell.on_download`` and then print a plausible resolver failure; they never
fetch anything. ``grep`` matches fixed strings only, so an attacker cannot
hand the honeypot a catastrophic regular expression.
"""

from __future__ import annotations

import ipaddress
import posixpath
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import urlsplit  # parsing only; nothing in this package does network I/O

from .fs import KERNEL_RELEASE, KERNEL_VERSION, FSError

if TYPE_CHECKING:
    from .core import FakeShell

Handler = Callable[["FakeShell", list[str], str], tuple[str, int]]
TABLE: dict[str, Handler] = {}
BIN_DIRS = {"/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}


def command(*names: str) -> Callable[[Handler], Handler]:
    def register(fn: Handler) -> Handler:
        for n in names:
            TABLE[n] = fn
        return fn

    return register


def _flags(args: list[str]) -> tuple[set[str], list[str]]:
    """Split short flags (-la -> {l, a}) from operands. "--" ends options."""
    flags: set[str] = set()
    rest: list[str] = []
    it = iter(args)
    for a in it:
        if a == "--":
            rest.extend(it)
            break
        if a.startswith("--") and len(a) > 2:
            flags.add(a)
        elif a.startswith("-") and len(a) > 1:
            flags.update(a[1:])
        else:
            rest.append(a)
    return flags, rest


def _now(sh: FakeShell) -> datetime:
    return datetime.fromtimestamp(sh.clock(), tz=UTC)


def motd(sh: FakeShell) -> str:
    now = _now(sh)
    return (
        f"Welcome to Ubuntu 24.04.1 LTS (GNU/Linux {KERNEL_RELEASE} x86_64)\n\n"
        " * Documentation:  https://help.ubuntu.com\n"
        " * Management:     https://landscape.canonical.com\n"
        " * Support:        https://ubuntu.com/pro\n\n"
        f" System information as of {now:%a %b %d %H:%M:%S UTC %Y}\n\n"
        "  System load:  0.08               Processes:             118\n"
        "  Usage of /:   37.4% of 38.58GB   Users logged in:       0\n"
        "  Memory usage: 31%                IPv4 address for eth0: 10.0.0.5\n"
        "  Swap usage:   0%\n\n"
        "Expanded Security Maintenance for Applications is not enabled.\n\n"
        "3 updates can be applied immediately.\n"
        "To see these additional updates run: apt list --upgradable\n\n"
        f"Last login: {now:%a %b %d} 08:12:44 {now:%Y} from 10.0.0.2\n"
    )


# -- identity ---------------------------------------------------------------------


@command("whoami")
def _whoami(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    return sh.user + "\n", 0


@command("id")
def _id(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    if sh.is_root:
        return "uid=0(root) gid=0(root) groups=0(root)\n", 0
    u, n = sh.user, sh.uid
    extra = ",4(adm),27(sudo)" if u == "ubuntu" else ""
    return f"uid={n}({u}) gid={n}({u}) groups={n}({u}){extra}\n", 0


@command("hostname")
def _hostname(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    if args and args[0] in ("-I", "-i"):
        return "10.0.0.5 \n", 0
    return sh.hostname + "\n", 0


@command("uname")
def _uname(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    flags, _ = _flags(args)
    if "--all" in flags:
        flags.add("a")
    parts = {
        "s": "Linux",
        "n": sh.hostname,
        "r": KERNEL_RELEASE,
        "v": KERNEL_VERSION,
        "m": "x86_64",
        "p": "x86_64",
        "i": "x86_64",
        "o": "GNU/Linux",
    }
    order = "snrvmpio" if "a" in flags else "".join(c for c in "snrvmpio" if c in flags) or "s"
    return " ".join(parts[c] for c in order) + "\n", 0


@command("passwd")
def _passwd(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    return "passwd: Authentication token manipulation error\npasswd: password unchanged\n", 10


# -- navigation and files ---------------------------------------------------------


@command("pwd")
def _pwd(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    return sh.cwd + "\n", 0


@command("cd")
def _cd(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    target = args[0] if args else sh.home
    path = sh.path(target)
    node = sh.fs.get(path)
    if node is None:
        return f"-bash: cd: {target}: No such file or directory\n", 1
    if not node.is_dir:
        return f"-bash: cd: {target}: Not a directory\n", 1
    if path == "/root" and not sh.is_root:
        return f"-bash: cd: {target}: Permission denied\n", 1
    sh.cwd = path
    return "", 0


def _ls_line(sh: FakeShell, name: str, path: str, human: bool) -> str:
    node = sh.fs.get(path)
    assert node is not None
    when = datetime.fromtimestamp(node.mtime, tz=UTC)
    stamp = f"{when:%b} {when.day:2d} {when:%H:%M}"
    size = _human(node.size) if human else str(node.size)
    links = 2 if node.is_dir else 1
    return f"{node.perms} {links} {node.owner} {node.group} {size:>6} {stamp} {name}"


def _human(n: int) -> str:
    for unit in ("", "K", "M", "G"):
        if n < 1024:
            return f"{n}{unit}" if unit == "" else f"{n:.1f}{unit}".replace(".0", "")
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f}T"


@command("ll")
def _ll(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    return _ls(sh, ["-la", *args], stdin)


@command("ls", "dir")
def _ls(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    flags, targets = _flags(args)
    long = "l" in flags
    show_all = "a" in flags or "A" in flags
    human = "h" in flags
    out: list[str] = []
    status = 0
    for target in targets or ["."]:
        path = sh.path(target)
        node = sh.fs.get(path)
        if node is None:
            out.append(f"ls: cannot access '{target}': No such file or directory")
            status = 2
            continue
        if not node.is_dir:
            out.append(_ls_line(sh, target, path, human) if long else target)
            continue
        if path == "/root" and not sh.is_root:
            out.append(f"ls: cannot open directory '{target}': Permission denied")
            status = 2
            continue
        names = [n for n in sh.fs.children(path) if show_all or not n.startswith(".")]
        if len(targets) > 1:
            out.append(f"{target}:")
        if long:
            entries = ([".", ".."] if "a" in flags else []) + names
            out.append(f"total {4 * max(len(entries), 1)}")
            for n in entries:
                if n == ".":
                    child = path
                elif n == "..":
                    child = posixpath.dirname(path) or "/"
                else:
                    child = posixpath.join(path, n)
                out.append(_ls_line(sh, n, child, human))
        elif names:
            out.append("  ".join(names))
    return ("\n".join(out) + "\n") if out else "", status


@command("cat")
def _cat(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    _, files = _flags(args)
    if not files:
        return stdin, 0
    out: list[str] = []
    status = 0
    for name in files:
        if name == "-":
            out.append(stdin)
            continue
        path = sh.path(name)
        node = sh.fs.get(path)
        if node is None:
            out.append(f"cat: {name}: No such file or directory\n")
            status = 1
        elif node.is_dir:
            out.append(f"cat: {name}: Is a directory\n")
            status = 1
        elif (path == "/etc/shadow" or path.startswith("/root/")) and not sh.is_root:
            out.append(f"cat: {name}: Permission denied\n")
            status = 1
        else:
            out.append(node.content)
    return "".join(out), status


@command("echo")
def _echo(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    newline = True
    escapes = False
    while args and args[0] in ("-n", "-e", "-ne", "-en", "-E"):
        newline = newline and "n" not in args[0]
        escapes = escapes or "e" in args[0][1:]
        args = args[1:]
    text = " ".join(args)
    if escapes:
        text = text.replace("\\n", "\n").replace("\\t", "\t")
    return text + ("\n" if newline else ""), 0


@command("printf")
def _printf(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    if not args:
        return "printf: usage: printf [-v var] format [arguments]\n", 2
    fmt, rest = args[0], list(args[1:])
    out = fmt.replace("\\n", "\n").replace("\\t", "\t")
    while "%s" in out or "%d" in out:
        token = (
            "%s" if ("%s" in out and (out.find("%s") < out.find("%d") or "%d" not in out)) else "%d"
        )
        out = out.replace(token, rest.pop(0) if rest else "", 1)
    return out, 0


@command("touch")
def _touch(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    _, files = _flags(args)
    for name in files:
        path = sh.path(name)
        if sh.fs.get(path) is None:
            sh.fs.write(path, "", append=True, now=sh.clock(), owner=sh.user)
    return "", 0


@command("mkdir")
def _mkdir(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    flags, dirs = _flags(args)
    out = []
    for name in dirs:
        try:
            sh.fs.mkdir(sh.path(name), now=sh.clock(), owner=sh.user, parents="p" in flags)
        except FSError as exc:
            out.append(f"mkdir: cannot create directory '{name}': {exc}\n")
    return "".join(out), 1 if out else 0


@command("rm")
def _rm(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    flags, files = _flags(args)
    out = []
    for name in files:
        try:
            sh.fs.remove(sh.path(name), recursive=bool({"r", "R"} & flags))
        except FSError as exc:
            if "f" not in flags or "No such" not in str(exc):
                out.append(f"rm: cannot remove '{name}': {exc}\n")
    return "".join(out), 1 if out else 0


@command("cp", "mv")
def _cp(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    _, paths = _flags(args)
    if len(paths) < 2:
        return "cp: missing destination file operand\n", 1
    src, dst = sh.path(paths[0]), sh.path(paths[-1])
    node = sh.fs.get(src)
    if node is None or node.is_dir:
        return f"cp: cannot stat '{paths[0]}': No such file or directory\n", 1
    if sh.fs.is_dir(dst):
        dst = posixpath.join(dst, posixpath.basename(src))
    sh.fs.write(dst, node.content, append=False, now=sh.clock(), owner=sh.user)
    return "", 0


@command("chmod", "chown", "chgrp", "chattr")
def _chmod(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    _, rest = _flags(args)
    for name in rest[1:]:
        if sh.fs.get(sh.path(name)) is None:
            return f"chmod: cannot access '{name}': No such file or directory\n", 1
    return "", 0


# -- text filters (fixed strings only) --------------------------------------------


@command("grep", "egrep", "fgrep")
def _grep(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    flags, rest = _flags(args)
    if not rest:
        return "Usage: grep [OPTION]... PATTERNS [FILE]...\n", 2
    pattern, files = rest[0], rest[1:]
    text = stdin
    if files:
        node = sh.fs.get(sh.path(files[0]))
        if node is None:
            return f"grep: {files[0]}: No such file or directory\n", 2
        text = node.content
    ignore = "i" in flags
    needle = pattern.lower() if ignore else pattern
    lines = [
        ln
        for ln in text.splitlines()
        if (needle in (ln.lower() if ignore else ln)) != ("v" in flags)
    ]
    if "c" in flags:
        return f"{len(lines)}\n", 0 if lines else 1
    return ("\n".join(lines) + "\n") if lines else "", 0 if lines else 1


def _count(args: list[str], default: int = 10) -> tuple[int, list[str]]:
    n = default
    rest: list[str] = []
    it = iter(args)
    for a in it:
        if a == "-n":
            a = next(it, str(default))
            n = int(a) if a.lstrip("-").isdigit() else default
        elif a.startswith("-n") and a[2:].isdigit():
            n = int(a[2:])
        elif a.startswith("-") and a[1:].isdigit():
            n = int(a[1:])
        elif not a.startswith("-"):
            rest.append(a)
    return abs(n), rest


def _input(sh: FakeShell, files: list[str], stdin: str) -> str:
    if files:
        node = sh.fs.get(sh.path(files[0]))
        return node.content if node and not node.is_dir else ""
    return stdin


@command("head")
def _head(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    n, files = _count(args)
    lines = _input(sh, files, stdin).splitlines()[:n]
    return ("\n".join(lines) + "\n") if lines else "", 0


@command("tail")
def _tail(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    n, files = _count(args)
    lines = _input(sh, files, stdin).splitlines()
    lines = lines[-n:] if n else []
    return ("\n".join(lines) + "\n") if lines else "", 0


@command("wc")
def _wc(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    flags, files = _flags(args)
    text = _input(sh, files, stdin)
    counts = {
        "l": text.count("\n"),
        "w": len(text.split()),
        "c": len(text.encode("utf-8", "replace")),
    }
    chosen = [k for k in "lwc" if k in flags] or ["l", "w", "c"]
    if len(chosen) == 1:
        return f"{counts[chosen[0]]}\n", 0
    return " ".join(f"{counts[k]:>7}" for k in chosen) + "\n", 0


@command("awk")
def _awk(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    """Just enough awk for '{print $1,$4}' with an optional -F separator."""
    sep: str | None = None
    rest: list[str] = []
    it = iter(args)
    for a in it:
        if a == "-F":
            sep = next(it, None)
        elif a.startswith("-F"):
            sep = a[2:]
        else:
            rest.append(a)
    if not rest:
        return "usage: awk [-F fs][-v var=value][prog | -f progfile][file ...]\n", 2
    prog = rest[0].strip()
    if not (prog.startswith("{") and prog.endswith("}")) or "print" not in prog:
        return "", 0
    body = prog[1:-1].strip().rstrip(";").removeprefix("print").strip()
    fields = [f.strip() for f in body.split(",")] if body else ["$0"]
    out = []
    for line in _input(sh, rest[1:], stdin).splitlines():
        cols = line.split(sep) if sep else line.split()
        vals = []
        for f in fields:
            if f == "$0":
                vals.append(line)
            elif f.startswith("$") and f[1:].isdigit():
                i = int(f[1:])
                vals.append(cols[i - 1] if 0 < i <= len(cols) else "")
            elif f == "NF":
                vals.append(str(len(cols)))
            else:
                vals.append(f.strip('"'))
        out.append(" ".join(vals))
    return ("\n".join(out) + "\n") if out else "", 0


# -- system information -----------------------------------------------------------


@command("uptime")
def _uptime(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    if "-p" in args:
        return "up 6 weeks, 3 days, 1 hour, 30 minutes\n", 0
    return f" {_now(sh):%H:%M:%S} up 45 days,  1:30,  1 user,  load average: 0.08, 0.03, 0.01\n", 0


@command("w")
def _w(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    head, _ = _uptime(sh, [], "")
    return (
        head
        + "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        + f"{sh.user[:8]:<8} pts/0    {sh.src_ip[:16]:<16} {_now(sh):%H:%M}"
        + "    0.00s  0.02s  0.00s w\n"
    ), 0


@command("who", "users")
def _who(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    return f"{sh.user:<8} pts/0        {_now(sh):%Y-%m-%d %H:%M} ({sh.src_ip})\n", 0


@command("date")
def _date(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    if args and args[0] == "+%s":
        return f"{int(sh.clock())}\n", 0
    return f"{_now(sh):%a %b %d %H:%M:%S UTC %Y}\n", 0


PS_ROWS = [
    ("root", 1, "0.0", "0.2", "22536", "13312", "?", "Ss", "Oct05", "1:12", "/sbin/init"),
    ("root", 412, "0.0", "0.4", "50196", "17024", "?", "S<s", "Oct05", "0:41",
     "/usr/lib/systemd/systemd-journald"),
    ("root", 655, "0.0", "0.1", "7192", "3072", "?", "Ss", "Oct05", "0:09", "/usr/sbin/cron -f"),
    ("root", 702, "0.0", "0.2", "12020", "8064", "?", "Ss", "Oct05", "0:00",
     "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"),
    ("mysql", 811, "0.3", "9.8", "1789540", "395112", "?", "Ssl", "Oct05", "214:03",
     "/usr/sbin/mysqld"),
    ("root", 912, "0.0", "0.0", "55220", "1564", "?", "Ss", "Oct05", "0:00",
     "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"),
    ("www-data", 913, "0.0", "0.1", "55860", "5640", "?", "S", "Oct05", "3:27",
     "nginx: worker process"),
    ("www-data", 914, "0.0", "0.1", "55860", "5512", "?", "S", "Oct05", "3:31",
     "nginx: worker process"),
]  # fmt: skip


@command("ps")
def _ps(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    joined = "".join(args)
    me = [
        (sh.user, 24133, "0.0", "0.1", "8780", "5376", "pts/0", "Ss", "10:02", "0:00", "-bash"),
        (sh.user, 24190, "0.0", "0.0", "10884", "4480", "pts/0", "R+", "10:02", "0:00",
         "ps " + " ".join(args)),
    ]  # fmt: skip
    if "a" in joined or "e" in joined or "x" in joined:
        rows = PS_ROWS + me
        out = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
        for r in rows:
            out.append(
                f"{r[0][:8]:<8} {r[1]:>7} {r[2]:>4} {r[3]:>4} {r[4]:>6} {r[5]:>5} "
                f"{r[6]:<8} {r[7]:<4} {r[8]:>5} {r[9]:>6} {r[10]}"
            )
        return "\n".join(out) + "\n", 0
    return (
        "    PID TTY          TIME CMD\n"
        "  24133 pts/0    00:00:00 bash\n"
        "  24190 pts/0    00:00:00 ps\n",
        0,
    )


@command("free")
def _free(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    if "-h" in args:
        return (
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:           3.8Gi       1.2Gi       305Mi       4.0Mi       2.3Gi       2.4Gi\n"
            "Swap:          2.0Gi          0B       2.0Gi\n"
        ), 0
    div = 1024 if "-m" in args else 1048576 if "-g" in args else 1
    vals = [4015264, 1258232, 312448, 4096, 2444584, 2563120]
    s = [v // div for v in vals]
    return (
        "               total        used        free      shared  buff/cache   available\n"
        f"Mem:     {s[0]:>11} {s[1]:>11} {s[2]:>11} {s[3]:>11} {s[4]:>11} {s[5]:>11}\n"
        f"Swap:    {2097148 // div:>11} {0:>11} {2097148 // div:>11}\n"
    ), 0


@command("df")
def _df(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    if any("h" in a for a in args if a.startswith("-")):
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "tmpfs           393M  1.1M  392M   1% /run\n"
            "/dev/vda1        39G   15G   24G  38% /\n"
            "tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
            "/dev/vda15      105M  6.1M   99M   6% /boot/efi\n"
        ), 0
    return (
        "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
        "tmpfs             401528     1080    400448   1% /run\n"
        "/dev/vda1       40453376 15129412  25307580  38% /\n"
        "/dev/vda15        106832     6250    100582   6% /boot/efi\n"
    ), 0


@command("nproc")
def _nproc(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    return "2\n", 0


@command("ip")
def _ip(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    if args and args[0] in ("a", "addr", "address"):
        return (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
            "    link/ether 52:54:00:3a:91:7c brd ff:ff:ff:ff:ff:ff\n"
            "    inet 10.0.0.5/24 metric 100 brd 10.0.0.255 scope global dynamic eth0\n"
        ), 0
    if args and args[0] in ("r", "route"):
        return "default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.5 metric 100\n", 0
    return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n", 255


# -- shell builtins -----------------------------------------------------------------


@command("history")
def _history(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    if args and args[0] == "-c":
        sh.history.clear()
        return "", 0
    return "".join(f"{i:>5}  {line}\n" for i, line in enumerate(sh.history, 1)), 0


@command("clear", "reset")
def _clear(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    return "\x1b[H\x1b[2J", 0


@command("export", "set", "unset", "alias", "unalias", "ulimit", "umask", "source", ".",
         "true", ":", "sleep", "kill", "pkill", "killall", "sync", "wait", "trap", "shopt",
         "enable", "shell", "system", "linuxshell")  # fmt: skip
def _noop(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    for a in args:
        if "=" in a and not a.startswith("-"):
            key, _, value = a.partition("=")
            if key.isidentifier():
                sh.env[key] = value
    return "", 0


@command("false")
def _false(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    return "", 1


@command("which", "type", "command")
def _which(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    out = []
    status = 0
    for a in args:
        if a.startswith("-"):
            continue
        if a in TABLE:
            out.append(f"/usr/bin/{a}")
        else:
            status = 1
    return ("\n".join(out) + "\n") if out else "", status


@command("crontab")
def _crontab(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    if "-l" in args:
        return f"no crontab for {sh.user}\n", 1
    return "", 0


@command("scp")
def _scp(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    return "", 1


@command("top", "htop")
def _top(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    return "top: failed tty get\n", 1


# -- downloads: recorded, never performed ----------------------------------------


_WGET_VALUE_OPTS = {"-O", "-o", "-P", "-U", "-t", "-T", "-a", "-e", "-i", "-B", "--header"}
_CURL_VALUE_OPTS = {
    "-o", "-A", "-H", "-d", "-X", "-u", "-e", "-m", "-x", "-b", "-c", "-F", "-T", "-K",
    "-w", "-r", "-E", "--connect-timeout", "--max-time", "--output", "--user-agent",
    "--header", "--data", "--request", "--retry", "--proxy", "--resolve",
}  # fmt: skip


def _urls(args: list[str], value_opts: set[str]) -> tuple[list[str], set[str]]:
    urls: list[str] = []
    flags: set[str] = set()
    it = iter(args)
    for a in it:
        if a in value_opts:
            next(it, None)
        elif a.startswith("--") and "=" in a:
            continue
        elif a.startswith("-") and len(a) > 1:
            flags.add(a)
        elif a:
            urls.append(a)
    return urls, flags


def _host(url: str) -> tuple[str, int, bool]:
    """(host, port, is_ip_literal) of a URL, parsed as text only."""
    target = url if "://" in url else "http://" + url
    try:
        parts = urlsplit(target)
        host = parts.hostname or url
        port = parts.port or (
            443 if parts.scheme == "https" else 21 if parts.scheme == "ftp" else 80
        )
    except ValueError:
        return url, 80, False
    try:
        ipaddress.ip_address(host)
        return host, port, True
    except ValueError:
        return host, port, False


@command("wget")
def _wget(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    urls, flags = _urls(args, _WGET_VALUE_OPTS)
    if not urls:
        return "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n", 1
    quiet = "-q" in flags or "-nv" in flags or "--quiet" in flags
    out = []
    for url in urls:
        sh.on_download("wget", url)
        if quiet:
            continue
        stamp = _now(sh).strftime("%Y-%m-%d %H:%M:%S")
        host, port, literal = _host(url)
        if literal:
            out.append(
                f"--{stamp}--  {url}\nConnecting to {host}:{port}... failed: Connection refused.\n"
            )
        else:
            out.append(
                f"--{stamp}--  {url}\n"
                f"Resolving {host} ({host})... failed: Temporary failure in name resolution.\n"
                f"wget: unable to resolve host address '{host}'\n"
            )
    return "".join(out), 4


@command("curl")
def _curl(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    urls, flags = _urls(args, _CURL_VALUE_OPTS)
    if not urls:
        return "curl: try 'curl --help' or 'curl --manual' for more information\n", 2
    silent = any(f in flags for f in ("-s", "--silent")) or any(
        f.startswith("-") and not f.startswith("--") and "s" in f and "S" not in f for f in flags
    )
    out = []
    status = 6
    for url in urls:
        sh.on_download("curl", url)
        host, port, literal = _host(url)
        if literal:
            status = 7
            msg = (
                f"curl: (7) Failed to connect to {host} port {port} after 0 ms: Connection refused"
            )
        else:
            msg = f"curl: (6) Could not resolve host: {host}"
        if not silent:
            out.append(msg + "\n")
    return "".join(out), status


@command("tftp", "ftpget")
def _tftp(sh: FakeShell, args: list[str], stdin: str) -> tuple[str, int]:
    """busybox tftp -g -r FILE HOST / ftpget HOST LOCAL REMOTE: record, then time out."""
    remote = None
    hosts = []
    it = iter(args)
    for a in it:
        if a in ("-r", "-l"):
            value = next(it, None)
            if a == "-r":
                remote = value
        elif not a.startswith("-"):
            hosts.append(a)
    if hosts:
        tool = "tftp" if remote is not None or "-g" in args else "ftp"
        path = remote if remote is not None else (hosts[2] if len(hosts) > 2 else "")
        sh.on_download(tool, f"{tool}://{hosts[0]}/{path}")
    return "tftp: timeout\n", 1
