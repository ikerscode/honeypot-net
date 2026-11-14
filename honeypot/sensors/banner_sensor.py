"""Generic TCP banner sensor: sends a service-like greeting and logs the first bytes the client sends.

Profiles mimic just enough of Redis or MySQL for scanners to classify the port. The client's
first bytes are stored as hex plus a printable preview, then the connection is closed. Redis
bots usually send "INFO", "CONFIG SET dir" or "SLAVEOF" next; all of that is only logged.
"""

from __future__ import annotations

import socket
import uuid

from .base import Sensor

FIRST_BYTES = 2048

# MySQL 5.7 initial handshake packet (protocol 10). Salt bytes are fixed: nothing is authenticated.
_MYSQL_GREETING_BODY = (b"\x0a" + b"5.7.42-0ubuntu0.18.04.1\x00" + b"\x2a\x00\x00\x00" + b"abcdefgh\x00"
                        + b"\xff\xf7" + b"\x08" + b"\x02\x00" + b"\xff\x81" + b"\x15" + b"\x00" * 10
                        + b"ijklmnopqrst\x00" + b"mysql_native_password\x00")
MYSQL_GREETING = len(_MYSQL_GREETING_BODY).to_bytes(3, "little") + b"\x00" + _MYSQL_GREETING_BODY

PROFILES = {
    # Redis sends nothing first; it answers commands. "-NOAUTH" tempts bots to try AUTH passwords.
    "redis": {"greeting": b"", "reply": b"-NOAUTH Authentication required.\r\n"},
    "mysql": {"greeting": MYSQL_GREETING, "reply": b""},
    "raw": {"greeting": b"", "reply": b""},
}


def printable(data: bytes, limit: int = 400) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])


class BannerSensor(Sensor):
    name = "banner"

    def __init__(self, cfg, shipper, port: int, profile: str = "raw"):
        super().__init__(cfg, shipper, port)
        self.profile = profile if profile in PROFILES else "raw"

    def handle(self, sock: socket.socket, src_ip: str, src_port: int) -> None:
        sock.settimeout(8)
        prof = PROFILES[self.profile]
        if prof["greeting"]:
            sock.sendall(prof["greeting"])
        data = b""
        try:
            while len(data) < FIRST_BYTES:
                chunk = sock.recv(FIRST_BYTES - len(data))
                if not chunk:
                    break
                data += chunk
                if prof["reply"]:
                    sock.sendall(prof["reply"])
                if len(data) >= 16 and data.endswith(b"\n"):
                    break
        except OSError:  # timeouts and clients that hang up mid-reply still get logged
            pass
        preview = printable(data)
        auth_pw = None
        if self.profile == "redis":
            words = preview.replace(".", " ").split()
            if len(words) >= 2 and "AUTH" in (w.upper() for w in words):
                idx = [w.upper() for w in words].index("AUTH")
                auth_pw = words[idx + 1] if idx + 1 < len(words) else None
        self.emit("banner", src_ip, src_port, uuid.uuid4().hex[:16],
                  data={"profile": self.profile, "first_bytes_hex": data[:512].hex(), "preview": preview, "length": len(data)},
                  username=None, password=auth_pw)
