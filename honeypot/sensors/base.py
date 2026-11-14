"""Shared plumbing for all sensors: a threaded TCP listener, PROXY protocol parsing and event helpers.

Safety model for every sensor: input from the network is only ever stored as data and matched
against strings. Nothing is executed, evaluated, written to a path chosen by the client, or fetched.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
import uuid

from ..config import SensorConfig
from ..shipper import Shipper

log = logging.getLogger("honeypot.sensor")


def read_proxy_header(sock: socket.socket, timeout: float = 3.0) -> tuple[str, int] | None:
    """Consume a PROXY protocol v1 line ("PROXY TCP4 src dst sport dport\\r\\n").

    Only used behind the compose edge relay, which always sends it. Reads byte by byte so not a
    single byte of the real client stream is swallowed.
    """
    sock.settimeout(timeout)
    line = b""
    while not line.endswith(b"\r\n") and len(line) < 108:  # 107 is the v1 maximum
        ch = sock.recv(1)
        if not ch:
            return None
        line += ch
    parts = line.decode("ascii", "replace").split()
    if len(parts) == 6 and parts[0] == "PROXY":
        return parts[2], int(parts[4])
    return None


class Sensor:
    """Base class. Subclasses set `name` and implement handle(sock, src_ip, src_port)."""

    name = "base"

    def __init__(self, cfg: SensorConfig, shipper: Shipper, port: int):
        self.cfg = cfg
        self.shipper = shipper
        self.port = port
        self._slots = threading.BoundedSemaphore(cfg.max_conns)
        self._server: socket.socket | None = None
        self._stop = threading.Event()

    # ---- events --------------------------------------------------------
    def emit(self, event_type: str, src_ip: str, src_port: int, session_id: str | None = None, **fields) -> dict:
        event = {
            "event_id": uuid.uuid4().hex,
            "ts": time.time(),
            "sensor": self.name,
            "event_type": event_type,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": self.port,
            "session_id": session_id,
            "simulated": self.cfg.is_lab_source(src_ip),
            **fields,
        }
        self.shipper.emit(event)
        return event

    # ---- listener ------------------------------------------------------
    def bind(self) -> socket.socket:
        family = socket.AF_INET6 if ":" in self.cfg.bind else socket.AF_INET
        srv = socket.socket(family, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.cfg.bind, self.port))
        srv.listen(128)
        self.port = srv.getsockname()[1]  # resolves port 0 in tests
        self._server = srv
        return srv

    def serve_forever(self) -> None:
        srv = self._server or self.bind()
        srv.settimeout(1.0)
        log.info("%s sensor listening on %s:%s", self.name, self.cfg.bind, self.port)
        while not self._stop.is_set():
            try:
                sock, addr = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            # Connection cap: when full, drop new connections instead of growing threads.
            if not self._slots.acquire(blocking=False):
                sock.close()
                continue
            threading.Thread(target=self._wrap, args=(sock, addr), daemon=True).start()

    def start(self) -> threading.Thread:
        self.bind()
        t = threading.Thread(target=self.serve_forever, name=f"{self.name}-{self.port}", daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
        if self._server:
            self._server.close()

    def _wrap(self, sock: socket.socket, addr) -> None:
        src_ip, src_port = addr[0], addr[1]
        try:
            if self.cfg.proxy_protocol:
                real = read_proxy_header(sock)
                if real is None:
                    return
                src_ip, src_port = real
            sock.settimeout(self.cfg.session_timeout)
            self.handle(sock, src_ip, src_port)
        except (OSError, EOFError, ValueError) as exc:
            log.debug("%s connection from %s ended: %s", self.name, src_ip, exc)
        except Exception:
            log.exception("%s handler error", self.name)
        finally:
            try:
                sock.close()
            except OSError:
                pass
            self._slots.release()

    def handle(self, sock: socket.socket, src_ip: str, src_port: int) -> None:  # pragma: no cover
        raise NotImplementedError


class AuthPolicy:
    """Decides when a login "succeeds" so the attacker reaches the emulated shell.

    "never" | "always" | "after:N": the attempt after N failures from the same source IP is
    accepted, then the counter resets (so a brute-force run sees several "valid" logins).
    """

    def __init__(self, spec: str):
        self.mode, _, n = spec.partition(":")
        self.n = int(n or 0)
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

    def attempt(self, src_ip: str) -> bool:
        if self.mode == "always":
            return True
        if self.mode != "after":
            return False
        with self._lock:
            count = self._counts.get(src_ip, 0)
            if count >= self.n:
                self._counts[src_ip] = 0
                return True
            self._counts[src_ip] = count + 1
            if len(self._counts) > 100_000:
                self._counts.clear()
            return False
