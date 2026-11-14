"""Low-interaction SSH sensor built on paramiko's server mode.

Records: client version string, HASSH (MD5 of the client's KEXINIT algorithm lists), every
password and public-key attempt, and, when the auth policy lets the client in, every command
typed into the emulated shell or sent as an exec request. No PTY, subprocess or real shell is
ever created; see fakeshell.py.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import threading
import time
import uuid

import paramiko

from ..config import data_dir
from .base import AuthPolicy, Sensor
from .fakeshell import FakeShell

logging.getLogger("paramiko").setLevel(logging.CRITICAL)  # malformed clients are normal here
log = logging.getLogger("honeypot.ssh")

SERVER_VERSION = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11"


def hassh_of(kex: dict) -> tuple[str, str]:
    """HASSH = md5("kex;ciphers;macs;compression") over the client-to-server lists."""
    algos = ";".join(",".join(kex.get(k) or []) for k in (
        "kex_algo_list", "client_encrypt_algo_list", "client_mac_algo_list", "client_compress_algo_list"))
    return hashlib.md5(algos.encode()).hexdigest(), algos


class RecordingTransport(paramiko.Transport):
    """Transport that keeps a copy of the client's KEXINIT lists for fingerprinting."""

    hp_client_kex: dict | None = None
    _hp_capturing = False

    def _parse_kex_init(self, m):
        self._hp_capturing = True
        try:
            return super()._parse_kex_init(m)
        finally:
            self._hp_capturing = False

    def _really_parse_kex_init(self, m, ignore_first_byte=False):
        parsed = super()._really_parse_kex_init(m, ignore_first_byte)
        if self._hp_capturing and self.hp_client_kex is None:
            self.hp_client_kex = parsed
        return parsed


def load_host_key(path) -> paramiko.PKey:
    """A persistent RSA host key per node (a changing key on every restart is a honeypot tell)."""
    try:
        return paramiko.RSAKey(filename=str(path))
    except (OSError, paramiko.SSHException):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(path))
        return key


class HoneyServer(paramiko.ServerInterface):
    def __init__(self, sensor: "SSHSensor", src_ip: str, src_port: int, session_id: str):
        self.sensor = sensor
        self.src_ip, self.src_port, self.session_id = src_ip, src_port, session_id
        self.username: str | None = None
        self.password: str | None = None
        self.exec_command: bytes | None = None
        self.shell_requested = threading.Event()
        self.attempts = 0

    def _emit(self, event_type: str, **fields):
        return self.sensor.emit(event_type, self.src_ip, self.src_port, self.session_id, **fields)

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        self.attempts += 1
        ok = self.sensor.policy.attempt(self.src_ip)
        self._emit("auth", username=username, password=password, auth_method="password", success=ok,
                   attempt=self.attempts)
        if ok:
            self.username, self.password = username, password
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        # Public keys are logged (they identify operators across IPs) but never accepted.
        fp_sha256 = key.fingerprint if hasattr(key, "fingerprint") else ""
        self._emit("auth", username=username, password=None, auth_method="publickey", success=False,
                   key_type=key.get_name(), key_fingerprint=fp_sha256,
                   key_md5=key.get_fingerprint().hex())
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_window_change_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_requested.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = bytes(command)[:4096]
        self.shell_requested.set()
        return True

    def check_channel_env_request(self, channel, name, value):
        return True

    def check_port_forward_request(self, address, port):
        self._emit("forward_request", data={"address": str(address), "port": port, "kind": "remote"})
        return False

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        # Bots use honeypots as proxies: record the intended destination, refuse the tunnel.
        self._emit("forward_request", data={"destination": f"{destination[0]}:{destination[1]}", "kind": "direct-tcpip"})
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SSHSensor(Sensor):
    name = "ssh"

    def __init__(self, cfg, shipper, port=None, host_key_path=None):
        super().__init__(cfg, shipper, port if port is not None else cfg.ssh_port)
        self.policy = AuthPolicy(cfg.ssh_policy)
        key_path = host_key_path or (data_dir() / f"ssh_host_rsa_{cfg.node_id}.key")
        self.host_key = load_host_key(key_path)
        self.hostname = "srv-web01"

    def handle(self, sock: socket.socket, src_ip: str, src_port: int) -> None:
        session_id = uuid.uuid4().hex[:16]
        started = time.time()
        self.emit("connect", src_ip, src_port, session_id)
        transport = RecordingTransport(sock)
        transport.local_version = SERVER_VERSION
        transport.add_server_key(self.host_key)
        server = HoneyServer(self, src_ip, src_port, session_id)
        commands = 0
        try:
            try:
                transport.start_server(server=server)
            except (paramiko.SSHException, EOFError, OSError):
                return
            finally:
                self._emit_client_info(transport, src_ip, src_port, session_id)
            chan = self._wait_for_channel(transport)
            if chan is None:
                return
            server.shell_requested.wait(10)
            if server.exec_command is not None:
                commands = self._run_exec(chan, server, src_ip, src_port, session_id)
            else:
                commands = self._run_shell(chan, server, src_ip, src_port, session_id, started)
        finally:
            self.emit("session_end", src_ip, src_port, session_id, duration=round(time.time() - started, 3),
                      username=server.username, password=server.password, success=server.username is not None,
                      data={"commands": commands, "auth_attempts": server.attempts})
            transport.close()

    def _wait_for_channel(self, transport):
        """Wait for a session channel, but stop as soon as the client goes away (bots that only
        test passwords disconnect without opening a channel)."""
        deadline = time.time() + self.cfg.session_timeout
        while transport.is_active() and time.time() < deadline:
            chan = transport.accept(timeout=1)
            if chan is not None:
                return chan
        return None

    def _emit_client_info(self, transport, src_ip, src_port, session_id):
        data = {"client_version": (transport.remote_version or "")[:256]}
        if transport.hp_client_kex:
            hassh, algos = hassh_of(transport.hp_client_kex)
            data.update(hassh=hassh, hassh_algorithms=algos[:2048])
        self.emit("client_version", src_ip, src_port, session_id, fingerprint=data.get("hassh"), data=data)

    def _command(self, shell, line, src_ip, src_port, session_id, mode) -> tuple[str, bool]:
        output, close, details = shell.run(line)
        self.emit("command", src_ip, src_port, session_id, command=line[:2048], data={"mode": mode, **details})
        for url in details["urls"]:
            self.emit("download_attempt", src_ip, src_port, session_id, data={"url": url[:1024], "fetched": False})
        return output, close

    def _run_exec(self, chan, server, src_ip, src_port, session_id) -> int:
        shell = FakeShell(self.hostname, server.username or "root")
        line = server.exec_command.decode("utf-8", "replace")
        output, _ = self._command(shell, line, src_ip, src_port, session_id, "exec")
        chan.sendall(output.replace("\n", "\r\n").encode() if output else b"")
        chan.send_exit_status(0)
        chan.close()
        return 1

    def _run_shell(self, chan, server, src_ip, src_port, session_id, started) -> int:
        """Line-oriented interaction with local echo, an idle timeout and a hard session cap."""
        shell = FakeShell(self.hostname, server.username or "root")
        chan.settimeout(self.cfg.session_timeout)
        chan.sendall(b"Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-169-generic x86_64)\r\n\r\n"
                     b"Last login: Mon Jan  1 14:01:12 2026 from 10.0.0.2\r\n")
        chan.sendall(shell.prompt.encode())
        buf, commands = b"", 0
        while time.time() - started < self.cfg.session_max:
            try:
                data = chan.recv(1024)
            except (socket.timeout, TimeoutError):
                chan.sendall(b"\r\ntimed out waiting for input: auto-logout\r\n")
                break
            if not data:
                break
            for byte in data:
                if byte in (13, 10):  # Enter
                    chan.sendall(b"\r\n")
                    line = buf.decode("utf-8", "replace")
                    buf = b""
                    if line.strip():
                        commands += 1
                        output, close = self._command(shell, line, src_ip, src_port, session_id, "shell")
                        if output:
                            chan.sendall(output.replace("\n", "\r\n").encode())
                        if close:
                            chan.close()
                            return commands
                    chan.sendall(shell.prompt.encode())
                elif byte in (8, 127):  # backspace
                    if buf:
                        buf = buf[:-1]
                        chan.sendall(b"\b \b")
                elif byte == 3:  # Ctrl-C
                    buf = b""
                    chan.sendall(b"^C\r\n" + shell.prompt.encode())
                elif byte == 4:  # Ctrl-D
                    chan.close()
                    return commands
                elif byte >= 32 and len(buf) < 4096:
                    buf += bytes([byte])
                    chan.sendall(bytes([byte]))
        chan.close()
        return commands
