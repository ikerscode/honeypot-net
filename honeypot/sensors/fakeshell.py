"""Emulated shell with a fake filesystem and canned outputs.

This is NOT a shell. Each command line is split into words and looked up in a table of canned
responses. Nothing is executed, no file on the real disk is read or written, and download
commands (wget, curl, tftp, ftpget) only have their URLs recorded; they are never fetched.
"""

from __future__ import annotations

import re
import shlex
import time

URL_RE = re.compile(r"((?:https?|ftp|tftp)://[^\s'\";|&<>`)]+)", re.I)
BARE_HOST_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/[^\s'\";|&<>`)]*)")
CHAIN_RE = re.compile(r"\s*(?:;|&&|\|\||\n)\s*")
PIPE_RE = re.compile(r"\s*\|\s*")
DOWNLOADERS = {"wget", "curl", "tftp", "ftpget", "scp", "fetch", "lwp-download"}

CPUINFO = "".join(
    f"processor\t: {i}\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\n"
    f"model name\t: Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz\nstepping\t: 4\ncpu MHz\t\t: 2294.608\n"
    f"cache size\t: 25344 KB\ncpu cores\t: 2\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr\n"
    f"bogomips\t: 4589.21\n\n" for i in range(2))

UBUNTU_FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                   "bin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                   "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
                   "admin:x:1000:1000:admin,,,:/home/admin:/bin/bash\nmysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false\n",
    "/etc/hostname": "{hostname}\n",
    "/etc/issue": "Ubuntu 20.04.6 LTS \\n \\l\n\n",
    "/etc/os-release": 'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nID=ubuntu\nID_LIKE=debian\n'
                       'PRETTY_NAME="Ubuntu 20.04.6 LTS"\nVERSION_ID="20.04"\n',
    "/etc/shadow": None,  # exists but permission denied for non-root; root gets a fake line
    "/proc/cpuinfo": CPUINFO,
    "/proc/meminfo": "MemTotal:        4030464 kB\nMemFree:          912344 kB\nMemAvailable:    2871032 kB\n"
                     "Buffers:          142812 kB\nCached:          1688736 kB\nSwapTotal:       2097148 kB\nSwapFree:        2097148 kB\n",
    "/proc/version": "Linux version 5.4.0-169-generic (buildd@lcy02-amd64-102) (gcc version 9.4.0) #187-Ubuntu SMP\n",
    "/proc/mounts": "/dev/sda1 / ext4 rw,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
                    "tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size=403048k,mode=755 0 0\n",
    "/root/.bash_history": "apt update\nsystemctl restart nginx\nmysql -u root -p\n",
    "/var/www/html/index.html": "<html><body><h1>It works!</h1></body></html>\n",
    "/home/admin/.bashrc": "# ~/.bashrc\nexport PATH=$PATH:/usr/local/bin\n",
}
UBUNTU_DIRS = {"/", "/root", "/home", "/home/admin", "/etc", "/proc", "/tmp", "/var", "/var/www", "/var/www/html",
               "/var/tmp", "/dev", "/dev/shm", "/usr", "/usr/bin", "/bin", "/sbin", "/opt", "/run", "/mnt", "/boot", "/srv"}

BUSYBOX_FILES = {
    "/proc/cpuinfo": "system type\t\t: MT7621\nmachine\t\t\t: Generic\nprocessor\t\t: 0\n"
                     "cpu model\t\t: MIPS 1004Kc V2.15\nBogoMIPS\t\t: 586.13\n\n",
    "/proc/mounts": "rootfs / rootfs rw 0 0\n/dev/root / squashfs ro,relatime 0 0\nproc /proc proc rw,relatime 0 0\n"
                    "tmpfs /tmp tmpfs rw,nosuid,nodev,relatime 0 0\ntmpfs /var tmpfs rw,relatime 0 0\n",
    "/proc/version": "Linux version 3.10.14 (builder@buildhost) (gcc version 4.6.3) #1 SMP\n",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/tmp:/bin/sh\n",
    "/etc/hostname": "{hostname}\n",
}
BUSYBOX_DIRS = {"/", "/bin", "/sbin", "/etc", "/proc", "/tmp", "/var", "/var/run", "/dev", "/dev/shm", "/mnt", "/usr", "/root"}

BUSYBOX_APPLETS = {"ls", "cat", "echo", "wget", "tftp", "ftpget", "ps", "rm", "cp", "mv", "chmod", "mkdir", "sh",
                   "uname", "id", "free", "df", "kill", "dd", "head", "tail", "grep", "ifconfig", "mount", "nc", "sleep"}


TFTP_RE = re.compile(r"\btftp\b[^;|&]*?-r\s+(\S+)[^;|&]*?\s(\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9.-]+\.[a-z]{2,})\b", re.I)


def extract_urls(line: str) -> list[str]:
    """URLs the attacker wants fetched, including busybox tftp's "-r FILE HOST" form."""
    urls = URL_RE.findall(line)
    for bare in BARE_HOST_RE.findall(line):
        if not any(bare in u for u in urls):
            urls.append(bare)
    for remote, host in TFTP_RE.findall(line):
        urls.append(f"tftp://{host}/{remote}")
    return urls


def split_words(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:  # unbalanced quotes are common in bot payloads
        return segment.split()


def echo_text(args: list[str]) -> str:
    """echo with -e/-n. Only backslash escapes are interpreted; no expansion of any kind."""
    interpret, newline = False, True
    while args and args[0] in ("-e", "-n", "-ne", "-en"):
        flag = args.pop(0)
        interpret = interpret or "e" in flag
        newline = newline and "n" not in flag
    text = " ".join(args)
    if interpret:
        text = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
        text = text.replace("\\n", "\n").replace("\\t", "\t")
    return text + ("\n" if newline else "")


class FakeShell:
    """One emulated session. `flavour` is "ubuntu" (SSH) or "busybox" (telnet IoT device)."""

    def __init__(self, hostname: str = "srv-web01", username: str = "root", flavour: str = "ubuntu"):
        self.hostname = hostname
        self.username = username
        self.flavour = flavour
        self.started = time.time()
        if flavour == "busybox":
            self.files, self.dirs = dict(BUSYBOX_FILES), set(BUSYBOX_DIRS)
            self.cwd = "/"
        else:
            self.files, self.dirs = dict(UBUNTU_FILES), set(UBUNTU_DIRS)
            self.cwd = "/root" if username == "root" else f"/home/{username}"
            self.dirs.add(self.cwd)
        self.history: list[str] = []

    # ---- helpers -------------------------------------------------------
    @property
    def prompt(self) -> str:
        if self.flavour == "busybox":
            return "# " if self.username == "root" else "$ "
        sign = "#" if self.username == "root" else "$"
        home = "/root" if self.username == "root" else f"/home/{self.username}"
        cwd = "~" + self.cwd[len(home):] if self.cwd.startswith(home) else self.cwd
        return f"{self.username}@{self.hostname}:{cwd}{sign} "

    def _path(self, p: str) -> str:
        if not p.startswith("/"):
            p = self.cwd.rstrip("/") + "/" + p
        parts = []
        for part in p.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(part)
        return "/" + "/".join(parts)

    def _not_found(self, cmd: str) -> str:
        if self.flavour == "busybox":
            return f"sh: {cmd}: not found\n"
        return f"bash: {cmd}: command not found\n"

    # ---- public --------------------------------------------------------
    def run(self, line: str) -> tuple[str, bool, dict]:
        """Emulate one command line. Returns (output, close_session, details)."""
        line = line.strip()
        details = {"urls": extract_urls(line)}
        if not line:
            return "", False, details
        self.history.append(line)
        out, close = [], False
        for segment in CHAIN_RE.split(line):
            if not segment:
                continue
            stages = PIPE_RE.split(segment)
            text, close = self._run_one(split_words(stages[0]))
            for stage in stages[1:]:
                text = self._filter(split_words(stage), text)
            out.append(text)
            if close:
                break
        return "".join(out), close, details

    @staticmethod
    def _filter(words: list[str], text: str) -> str:
        """Apply a pipe stage to captured text. Only harmless text filters are emulated."""
        if not words:
            return text
        lines = text.splitlines(True)
        name, args = words[0].rsplit("/", 1)[-1], words[1:]
        count = next((int(a.lstrip("-n")) for a in args if a.lstrip("-n").isdigit()), 10)
        if name == "head":
            return "".join(lines[:count])
        if name == "tail":
            return "".join(lines[-count:])
        if name == "wc":
            return f"{len(lines)}\n" if "-l" in args else f"{len(lines)} {len(text.split())} {len(text)}\n"
        if name == "grep":
            pattern = next((a for a in args if not a.startswith("-")), "")
            return "".join(l for l in lines if pattern in l)
        return text  # "| sh", "| bash" etc: the piped text is shown, never run

    def _run_one(self, words: list[str]) -> tuple[str, bool]:
        if not words:
            return "", False
        cmd, args = words[0], words[1:]
        # Strip env assignments such as "HISTFILE=/dev/null cmd"
        while "=" in cmd and not cmd.startswith(("/", ".")) and args:
            cmd, args = args[0], args[1:]
        base = cmd.rsplit("/", 1)[-1]
        if base == "busybox":
            return self._busybox(args)
        if base in ("exit", "logout", "quit"):
            return "", True
        handler = getattr(self, f"_cmd_{base.replace('-', '_')}", None)
        if handler:
            return handler(args), False
        if base in DOWNLOADERS:
            return self._download(base, args), False
        if base in ("enable", "system", "shell", "linuxshell", "sh", "bash", "su", "sudo") and not args:
            return "", False  # Mirai-style privilege probes: a silent prompt is what bots expect
        if base in ("sh", "bash") and args:
            if args[0] == "-c" and len(args) > 1:
                return self.run(args[1])[0], False
            return f"{base}: {args[0]}: No such file or directory\n", False
        if base in ("sudo",):
            return self._run_one(args)
        if base in ("chmod", "chattr", "rm", "mkdir", "touch", "cp", "mv", "kill", "pkill", "killall", "export",
                    "unset", "cd", "su", "sleep", "nohup", "history", "crontab", "ulimit", "service", "systemctl"):
            return self._quiet(base, args), False
        if cmd.startswith("./") or cmd.startswith("/tmp/") or cmd.startswith("/dev/shm/"):
            return f"{'sh' if self.flavour == 'busybox' else 'bash'}: {cmd}: Permission denied\n", False
        return self._not_found(cmd), False

    # ---- command table -------------------------------------------------
    def _quiet(self, base: str, args: list[str]) -> str:
        if base == "cd":
            target = self._path(args[0]) if args else ("/root" if self.username == "root" else "/")
            if target in self.dirs:
                self.cwd = target
                return ""
            return f"{'sh' if self.flavour == 'busybox' else 'bash'}: cd: {args[0]}: No such file or directory\n"
        if base == "history":
            if "-c" in args:
                self.history.clear()
                return ""
            return "".join(f"  {i + 1}  {h}\n" for i, h in enumerate(self.history[-20:]))
        if base == "crontab":
            return "no crontab for root\n" if "-l" in args else ""
        if base in ("touch", "mkdir"):
            for a in args:
                if not a.startswith("-"):
                    path = self._path(a)
                    (self.dirs.add(path) if base == "mkdir" else self.files.setdefault(path, ""))
        return ""

    def _busybox(self, args: list[str]) -> tuple[str, bool]:
        if not args:
            return "BusyBox v1.24.1 (2017-06-26 12:43:21 CST) multi-call binary.\n", False
        applet = args[0]
        if applet in BUSYBOX_APPLETS:
            return self._run_one(args)
        # Mirai sends "/bin/busybox RANDOM" and waits for exactly this reply to confirm a real shell.
        return f"{applet}: applet not found\n", False

    def _download(self, tool: str, args: list[str]) -> str:
        urls = extract_urls(" ".join(args))
        target = urls[0] if urls else (args[-1] if args else "")
        host = re.sub(r"^\w+://", "", target).split("/")[0] or "host"
        if tool == "curl":
            return f"curl: (28) Failed to connect to {host} port 80 after 21004 ms: Connection timed out\n"
        if self.flavour == "busybox" or tool in ("tftp", "ftpget"):
            return f"Connecting to {host} ({host})\n{tool}: can't connect to remote host ({host}): Connection timed out\n"
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        return f"--{stamp}--  {target}\nConnecting to {host}... failed: Connection timed out.\nRetrying.\n"

    def _cmd_uname(self, args):
        flags = "".join(a.lstrip("-") for a in args)
        if self.flavour == "busybox":
            full = f"Linux {self.hostname} 3.10.14 #1 SMP Mon Jun 26 12:43:21 CST 2017 mips GNU/Linux"
            kernel, machine = "3.10.14", "mips"
        else:
            full = f"Linux {self.hostname} 5.4.0-169-generic #187-Ubuntu SMP Thu Nov 23 14:52:28 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
            kernel, machine = "5.4.0-169-generic", "x86_64"
        if "a" in flags:
            return full + "\n"
        if "r" in flags:
            return kernel + "\n"
        if "m" in flags or "p" in flags:
            return machine + "\n"
        if "n" in flags:
            return self.hostname + "\n"
        return "Linux\n"

    def _cmd_id(self, args):
        if self.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)\n"

    def _cmd_whoami(self, args):
        return self.username + "\n"

    def _cmd_hostname(self, args):
        return self.hostname + "\n"

    def _cmd_pwd(self, args):
        return self.cwd + "\n"

    def _cmd_echo(self, args):
        return echo_text(list(args))

    def _cmd_nproc(self, args):
        return "1\n" if self.flavour == "busybox" else "2\n"

    def _cmd_uptime(self, args):
        return " 14:02:11 up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\n"

    def _cmd_w(self, args):
        return (self._cmd_uptime(args) + "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                f"{self.username:<8} pts/0    -                14:01    0.00s  0.01s  0.00s w\n")

    def _cmd_who(self, args):
        return f"{self.username}     pts/0        2026-01-01 14:01\n"

    def _cmd_free(self, args):
        return ("              total        used        free      shared  buff/cache   available\n"
                "Mem:        4030464      995384      912344        1220     2122736     2871032\n"
                "Swap:       2097148           0     2097148\n")

    def _cmd_df(self, args):
        return ("Filesystem     1K-blocks    Used Available Use% Mounted on\n"
                "/dev/sda1       40581564 9123456  29371724  24% /\ntmpfs            2015232       0   2015232   0% /dev/shm\n")

    def _cmd_ps(self, args):
        return ("  PID TTY          TIME CMD\n    1 ?        00:00:12 init\n  612 ?        00:00:03 sshd\n"
                "  845 ?        00:01:44 nginx\n  901 ?        00:02:10 mysqld\n 2231 pts/0    00:00:00 bash\n 2290 pts/0    00:00:00 ps\n")

    def _cmd_ifconfig(self, args):
        return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 10.0.0.12  netmask 255.255.255.0  broadcast 10.0.0.255\n"
                "        ether 52:54:00:3a:91:7c  txqueuelen 1000  (Ethernet)\n")

    def _cmd_ip(self, args):
        return ("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 10.0.0.12/24 brd 10.0.0.255 scope global eth0\n")

    def _cmd_lscpu(self, args):
        return ("Architecture:        x86_64\nCPU(s):              2\nModel name:          Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz\n"
                "Hypervisor vendor:   KVM\n")

    def _cmd_env(self, args):
        return f"SHELL=/bin/bash\nUSER={self.username}\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOME=/root\n"

    def _cmd_which(self, args):
        return "".join(f"/usr/bin/{a}\n" for a in args if a in {"wget", "curl", "python3", "perl", "gcc"})

    def _cmd_last(self, args):
        return f"{self.username}     pts/0        10.0.0.2       Mon Jan  1 14:01   still logged in\n\nwtmp begins Mon Jan  1 00:00:01 2026\n"

    def _cmd_netstat(self, args):
        return ("Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address  Foreign Address  State\n"
                "tcp        0      0 0.0.0.0:22     0.0.0.0:*        LISTEN\ntcp        0      0 0.0.0.0:80     0.0.0.0:*        LISTEN\n"
                "tcp        0      0 127.0.0.1:3306 0.0.0.0:*        LISTEN\n")

    _cmd_ss = _cmd_netstat

    def _cmd_ls(self, args):
        targets = [a for a in args if not a.startswith("-")] or [self.cwd]
        out = []
        for t in targets:
            path = self._path(t)
            if path in self.files:
                out.append(t)
                continue
            if path not in self.dirs:
                return f"ls: cannot access '{t}': No such file or directory\n"
            prefix = path.rstrip("/") + "/"
            names = sorted({p[len(prefix):].split("/")[0] for p in list(self.files) + list(self.dirs)
                            if p.startswith(prefix) and p != path})
            out.extend(names)
        if any(a.startswith("-") and "l" in a for a in args):
            return "".join(f"-rw-r--r-- 1 root root 4096 Jan  1 12:00 {n}\n" for n in out)
        return "  ".join(out) + ("\n" if out else "")

    def _cmd_cat(self, args):
        out = []
        for a in args:
            if a.startswith("-"):
                continue
            path = self._path(a)
            if path in self.files:
                content = self.files[path]
                if content is None:
                    content = ("root:$6$Qx1h$Zk2v0r9fJ5c1b8n7m6l5k4j3h2g1f0e9d8c7b6a5:19700:0:99999:7:::\n"
                               if self.username == "root" else None)
                    if content is None:
                        out.append(f"cat: {a}: Permission denied\n")
                        continue
                out.append(content.replace("{hostname}", self.hostname))
            elif path in self.dirs:
                out.append(f"cat: {a}: Is a directory\n")
            else:
                out.append(f"cat: {a}: No such file or directory\n")
        return "".join(out)

    def _cmd_head(self, args):
        text = self._cmd_cat([a for a in args if not a.startswith("-") and not a.isdigit()])
        return "".join(text.splitlines(True)[:10])

    _cmd_tail = _cmd_head

    def _cmd_grep(self, args):
        return ""

    def _cmd_dd(self, args):
        # Mirai reads the ELF header of a local binary with dd to learn the CPU architecture.
        return "0+1 records in\n0+1 records out\n"

    def _cmd_passwd(self, args):
        return "passwd: password updated successfully\n"
