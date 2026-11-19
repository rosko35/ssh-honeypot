"""A tiny in-memory filesystem for the fake shell.

Nothing here touches the real disk: the tree is a dict of path -> Node built
from the constants below, copied per session. Attackers can create, append
and delete files *in that dict* (``echo key >> ~/.ssh/authorized_keys`` is a
classic), bounded by a per-session byte and node budget.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field

# 2024-11-04 02:06:24 UTC, a plausible install date for the fake host.
BASE_MTIME = 1730686000.0

MAX_SESSION_BYTES = 256 * 1024
MAX_SESSION_NODES = 256


class FSError(Exception):
    pass


@dataclass
class Node:
    is_dir: bool
    content: str = ""
    mode: str = ""
    owner: str = "root"
    group: str = "root"
    mtime: float = BASE_MTIME
    size_hint: int | None = None  # pretend size for binaries (content stays empty)

    @property
    def size(self) -> int:
        if self.is_dir:
            return 4096
        if self.size_hint is not None:
            return self.size_hint
        return len(self.content.encode("utf-8", "replace"))

    @property
    def perms(self) -> str:
        if self.mode:
            return self.mode
        return "drwxr-xr-x" if self.is_dir else "-rw-r--r--"


def _passwd(users: list[tuple[str, int, str]]) -> str:
    lines = [
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
        "sync:x:4:65534:sync:/bin:/bin/sync",
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
        "systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin",
        "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
        "mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false",
    ]
    for name, uid, home in users:
        if name != "root":
            lines.append(f"{name}:x:{uid}:{uid}:{name},,,:{home}:/bin/bash")
    return "\n".join(lines) + "\n"


CPUINFO_CORE = """processor\t: {n}
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 85
model name\t: Intel(R) Xeon(R) Gold 6230 CPU @ 2.10GHz
stepping\t: 7
cpu MHz\t\t: 2095.078
cache size\t: 28160 KB
physical id\t: 0
siblings\t: 2
core id\t\t: {n}
cpu cores\t: 2
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 \
clflush mmx fxsr sse sse2 ss syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl \
xtopology cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic \
movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch avx2 avx512f
bogomips\t: 4190.15
address sizes\t: 46 bits physical, 48 bits virtual

"""

MEMINFO = """MemTotal:        4015264 kB
MemFree:          312448 kB
MemAvailable:    2563120 kB
Buffers:          145236 kB
Cached:          2071804 kB
SwapCached:            0 kB
Active:          1784320 kB
Inactive:        1438712 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB
"""

OS_RELEASE = """PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
UBUNTU_CODENAME=noble
"""

KERNEL_RELEASE = "6.8.0-49-generic"
KERNEL_VERSION = "#49-Ubuntu SMP PREEMPT_DYNAMIC Mon Nov  4 02:06:24 UTC 2024"

INDEX_HTML = """<!doctype html>
<html><head><title>Welcome</title></head>
<body><h1>It works!</h1></body></html>
"""

BINARIES = [
    "bash",
    "sh",
    "ls",
    "cat",
    "echo",
    "cp",
    "mv",
    "rm",
    "mkdir",
    "chmod",
    "chown",
    "grep",
    "ps",
    "uname",
    "id",
    "whoami",
    "hostname",
    "pwd",
    "touch",
    "head",
    "tail",
    "wc",
    "awk",
    "sleep",
    "kill",
    "sed",
    "tar",
    "gzip",
    "mount",
    "df",
    "free",
    "uptime",
    "w",
    "who",
    "wget",
    "curl",
    "sudo",
    "su",
    "passwd",
    "crontab",
    "nproc",
    "ip",
    "ifconfig",
    "which",
    "true",
    "false",
]


def build_tree(hostname: str, username: str, home: str, uid: int) -> dict[str, Node]:
    t: dict[str, Node] = {}

    def d(path: str, **kw) -> None:
        t[path] = Node(True, **kw)

    def f(path: str, content: str = "", **kw) -> None:
        t[path] = Node(False, content, **kw)

    for path in (
        "/", "/bin", "/boot", "/dev", "/etc", "/etc/ssh", "/home", "/lib", "/media", "/mnt",
        "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/usr", "/usr/bin",
        "/usr/sbin", "/usr/lib", "/usr/local", "/usr/local/bin", "/usr/share", "/var",
        "/var/backups", "/var/cache", "/var/lib", "/var/lib/mysql", "/var/log", "/var/log/nginx",
        "/var/tmp", "/var/www", "/var/www/html", "/etc/nginx", "/etc/cron.d",
    ):  # fmt: skip
        d(path)
    d("/tmp", mode="drwxrwxrwt")
    d("/var/tmp", mode="drwxrwxrwt")
    d("/root", mode="drwx------")
    d("/var/lib/mysql", mode="drwx------", owner="mysql", group="mysql")
    d("/root/.ssh", mode="drwx------")
    f("/root/.bashrc", "# ~/.bashrc: executed by bash(1) for non-login shells.\n")
    f("/root/.profile", "# ~/.profile: executed by Bourne-compatible login shells.\n")
    f("/root/.bash_history", "", mode="-rw-------")

    if home != "/root":
        d(home, mode="drwxr-x---", owner=username, group=username)
        d(f"{home}/.ssh", mode="drwx------", owner=username, group=username)
        f(f"{home}/.bashrc", "# ~/.bashrc\n", owner=username, group=username)
        f(f"{home}/.profile", "# ~/.profile\n", owner=username, group=username)

    users = [("root", 0, "/root"), ("ubuntu", 1000, "/home/ubuntu")]
    if username not in ("root", "ubuntu"):
        users.append((username, uid, home))
    if "/home/ubuntu" not in t:
        d("/home/ubuntu", mode="drwxr-x---", owner="ubuntu", group="ubuntu")

    f("/etc/passwd", _passwd(users))
    f("/etc/group", "root:x:0:\nadm:x:4:syslog,ubuntu\nsudo:x:27:ubuntu\nubuntu:x:1000:\n")
    f("/etc/shadow", "", mode="-rw-r-----", group="shadow")
    f("/etc/hostname", hostname + "\n")
    f("/etc/hosts", f"127.0.0.1 localhost\n127.0.1.1 {hostname}\n")
    f("/etc/os-release", OS_RELEASE)
    f("/etc/issue", "Ubuntu 24.04.1 LTS \\n \\l\n\n")
    f("/etc/resolv.conf", "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n")
    f("/etc/crontab", "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin\n")
    f(
        "/etc/ssh/sshd_config",
        "Include /etc/ssh/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\n",
    )
    f("/etc/nginx/nginx.conf", "user www-data;\nworker_processes auto;\n")
    f("/var/www/html/index.html", INDEX_HTML, owner="www-data", group="www-data")
    f("/var/log/syslog", "", mode="-rw-r-----", owner="syslog", group="adm", size_hint=184321)
    f("/var/log/auth.log", "", mode="-rw-r-----", owner="syslog", group="adm", size_hint=40960)
    f("/proc/cpuinfo", CPUINFO_CORE.format(n=0) + CPUINFO_CORE.format(n=1))
    f("/proc/meminfo", MEMINFO)
    f(
        "/proc/version",
        f"Linux version {KERNEL_RELEASE} (buildd@lcy02-amd64-040) {KERNEL_VERSION}\n",
    )
    f("/proc/uptime", "3893417.21 7651234.80\n")
    for name in BINARIES:
        f(f"/usr/bin/{name}", "", mode="-rwxr-xr-x", size_hint=142312)
    return t


@dataclass
class FakeFS:
    nodes: dict[str, Node]
    used_bytes: int = 0
    created: int = 0
    _limits: tuple[int, int] = field(default=(MAX_SESSION_BYTES, MAX_SESSION_NODES))

    @staticmethod
    def normalize(cwd: str, path: str, home: str) -> str:
        if path == "~" or path.startswith("~/"):
            path = home + path[1:]
        if not path.startswith("/"):
            path = posixpath.join(cwd, path)
        norm = posixpath.normpath(path)
        return "/" if norm.startswith("//") else norm

    def get(self, path: str) -> Node | None:
        return self.nodes.get(path)

    def is_dir(self, path: str) -> bool:
        node = self.nodes.get(path)
        return bool(node and node.is_dir)

    def children(self, path: str) -> list[str]:
        prefix = path.rstrip("/") + "/"
        out = []
        for p in self.nodes:
            if p != path and p.startswith(prefix) and "/" not in p[len(prefix) :]:
                out.append(p[len(prefix) :])
        return sorted(out)

    def _budget(self, extra_bytes: int, new_node: bool) -> None:
        max_bytes, max_nodes = self._limits
        if self.used_bytes + extra_bytes > max_bytes or (new_node and self.created + 1 > max_nodes):
            raise FSError("No space left on device")

    def write(self, path: str, data: str, *, append: bool, now: float, owner: str) -> None:
        parent = posixpath.dirname(path) or "/"
        if not self.is_dir(parent):
            raise FSError("No such file or directory")
        node = self.nodes.get(path)
        if node is not None and node.is_dir:
            raise FSError("Is a directory")
        size = len(data.encode("utf-8", "replace"))
        self._budget(size, node is None)
        if node is None:
            self.nodes[path] = Node(False, data, owner=owner, group=owner, mtime=now)
            self.created += 1
        else:
            node.content = node.content + data if append else data
            node.size_hint = None
            node.mtime = now
        self.used_bytes += size

    def mkdir(self, path: str, *, now: float, owner: str, parents: bool = False) -> None:
        if path in self.nodes:
            if parents and self.nodes[path].is_dir:
                return
            raise FSError("File exists")
        parent = posixpath.dirname(path) or "/"
        if not self.is_dir(parent):
            if not parents:
                raise FSError("No such file or directory")
            self.mkdir(parent, now=now, owner=owner, parents=True)
        self._budget(0, True)
        self.nodes[path] = Node(True, owner=owner, group=owner, mtime=now)
        self.created += 1

    def remove(self, path: str, *, recursive: bool = False) -> None:
        node = self.nodes.get(path)
        if node is None:
            raise FSError("No such file or directory")
        if path == "/":
            raise FSError("Operation not permitted")
        if node.is_dir:
            if not recursive:
                raise FSError("Is a directory")
            prefix = path.rstrip("/") + "/"
            for p in [p for p in self.nodes if p.startswith(prefix)]:
                del self.nodes[p]
        del self.nodes[path]
