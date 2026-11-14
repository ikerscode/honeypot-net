"""Low-interaction Telnet sensor posing as a BusyBox-based IoT device (router / DVR).

Mirai and its descendants log in with factory default credentials, then send "enable",
"system", "shell", "sh" and "/bin/busybox <RANDOM>" and wait for "<RANDOM>: applet not found"
before dropping a loader. All of that is answered from canned text in fakeshell.py.
"""

from __future__ import annotations

import socket
import time
import uuid

from .base import AuthPolicy, Sensor
from .fakeshell import FakeShell

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ECHO, SGA = 1, 3
MAX_LOGIN_TRIES = 3


def strip_iac(data: bytes) -> bytes:
    """Remove telnet negotiation sequences, keeping only the user's bytes."""
    out, i = bytearray(), 0
    while i < len(data):
        b = data[i]
        if b != IAC:
            out.append(b)
            i += 1
            continue
        if i + 1 >= len(data):
            break
        cmd = data[i + 1]
        if cmd == IAC:  # escaped 0xff
            out.append(IAC)
            i += 2
        elif cmd in (WILL, WONT, DO, DONT):
            i += 3
        elif cmd == SB:
            end = data.find(bytes([IAC, SE]), i)
            i = len(data) if end < 0 else end + 2
        else:
            i += 2
    return bytes(out)


class LineReader:
    """Reads lines ending in CR, LF, CRLF or CR NUL from a socket, with a size cap."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""
        self._after_cr = False  # a lone CR ended the last line: swallow a following LF/NUL

    def readline(self, limit: int = 4096) -> str | None:
        while True:
            if self._after_cr and self.buf[:1] in (b"\n", b"\x00"):
                self.buf = self.buf[1:]
            if self.buf:
                self._after_cr = False
            cut = min((i for i in (self.buf.find(b"\r"), self.buf.find(b"\n")) if i >= 0), default=-1)
            if cut >= 0:
                line, sep, self.buf = self.buf[:cut], self.buf[cut:cut + 1], self.buf[cut + 1:]
                if sep == b"\r":
                    self._after_cr = True
                return line[:limit].decode("utf-8", "replace")
            if len(self.buf) > limit:
                line, self.buf = self.buf[:limit], b""
                return line.decode("utf-8", "replace")
            chunk = self.sock.recv(1024)
            if not chunk:
                return None
            self.buf += strip_iac(chunk)


class TelnetSensor(Sensor):
    name = "telnet"

    def __init__(self, cfg, shipper, port=None):
        super().__init__(cfg, shipper, port if port is not None else cfg.telnet_port)
        self.policy = AuthPolicy(cfg.telnet_policy)
        self.hostname = "router"

    def handle(self, sock: socket.socket, src_ip: str, src_port: int) -> None:
        session_id = uuid.uuid4().hex[:16]
        started = time.time()
        self.emit("connect", src_ip, src_port, session_id)
        reader = LineReader(sock)
        user = password = None
        success, commands, attempts = False, 0, 0
        try:
            # Offer to echo and suppress go-ahead, as most embedded telnetd builds do.
            sock.sendall(bytes([IAC, WILL, ECHO, IAC, WILL, SGA]))
            for _ in range(MAX_LOGIN_TRIES):
                sock.sendall(b"\r\n" + self.hostname.encode() + b" login: ")
                user = reader.readline(256)
                if user is None:
                    return
                sock.sendall(b"Password: ")
                password = reader.readline(256)
                if password is None:
                    return
                attempts += 1
                success = self.policy.attempt(src_ip)
                self.emit("auth", src_ip, src_port, session_id, username=user, password=password,
                          auth_method="password", success=success, attempt=attempts)
                if success:
                    break
                time.sleep(0.3)
                sock.sendall(b"\r\nLogin incorrect\r\n")
            if not success:
                return
            commands = self._shell(sock, reader, user, src_ip, src_port, session_id, started)
        finally:
            self.emit("session_end", src_ip, src_port, session_id, duration=round(time.time() - started, 3),
                      username=user if success else None, password=password if success else None, success=success,
                      data={"commands": commands, "auth_attempts": attempts})

    def _shell(self, sock, reader, user, src_ip, src_port, session_id, started) -> int:
        shell = FakeShell(self.hostname, "root", flavour="busybox")
        sock.sendall(b"\r\n\r\nBusyBox v1.24.1 (2017-06-26 12:43:21 CST) built-in shell (ash)\r\n"
                     b"Enter 'help' for a list of built-in commands.\r\n\r\n" + shell.prompt.encode())
        commands = 0
        while time.time() - started < self.cfg.session_max:
            try:
                line = reader.readline()
            except (socket.timeout, TimeoutError):
                break
            if line is None:
                break
            if line.strip():
                commands += 1
                output, close, details = shell.run(line)
                self.emit("command", src_ip, src_port, session_id, command=line[:2048],
                          data={"mode": "shell", **details})
                for url in details["urls"]:
                    self.emit("download_attempt", src_ip, src_port, session_id, data={"url": url[:1024], "fetched": False})
                if output:
                    sock.sendall(output.replace("\n", "\r\n").encode())
                if close:
                    break
            sock.sendall(shell.prompt.encode())
        return commands
