"""Settings, read from environment variables so the same code runs as a process or in a container.

Everything binds to 127.0.0.1 unless HP_BIND says otherwise (the compose file sets 0.0.0.0
inside containers, where the host only publishes ports on 127.0.0.1).
"""

from __future__ import annotations

import ipaddress
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Nodes the collector knows about by default. node-local is the no-docker node; the other
# ids are the compose nodes plus extra synthetic regions used by the injection simulator.
DEFAULT_NODES = {
    "node-local": "local",
    "node-lon": "eu-west (London)",
    "node-fra": "eu-central (Frankfurt)",
    "node-nyc": "us-east (New York)",
    "node-sgp": "ap-southeast (Singapore)",
}


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def data_dir() -> Path:
    path = Path(_env("HP_DATA_DIR", str(PROJECT_ROOT / "data")))
    path.mkdir(parents=True, exist_ok=True)
    return path


def parse_secrets(text: str) -> dict[str, str]:
    """Parse "node-a=secret1,node-b=secret2" into a dict."""
    out = {}
    for part in text.replace("\n", ",").split(","):
        part = part.strip()
        if "=" in part:
            node, secret = part.split("=", 1)
            out[node.strip()] = secret.strip()
    return out


def secrets_file() -> Path:
    return data_dir() / "node-secrets.env"


def load_node_secrets() -> dict[str, str]:
    """Per-node shared secrets for the collector.

    Order: HP_NODE_SECRETS env var, else data/node-secrets.env (created with random
    secrets on first use so a fresh checkout works without setup).
    """
    env = os.environ.get("HP_NODE_SECRETS")
    if env:
        return parse_secrets(env)
    path = secrets_file()
    if not path.exists():
        lines = [f"{node}={secrets.token_hex(32)}" for node in DEFAULT_NODES]
        path.write_text("\n".join(lines) + "\n")
        path.chmod(0o600)
    return parse_secrets(path.read_text())


def parse_networks(text: str) -> list:
    nets = []
    for part in text.split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return nets


@dataclass
class SensorConfig:
    """Configuration for one sensor node (all sensors in a node share it)."""

    node_id: str = field(default_factory=lambda: _env("HP_NODE_ID", "node-local"))
    region: str = field(default_factory=lambda: _env("HP_REGION", "local"))
    collector_url: str = field(default_factory=lambda: _env("HP_COLLECTOR_URL", "http://127.0.0.1:8103"))
    secret: str = field(default_factory=lambda: _env("HP_NODE_SECRET", ""))
    bind: str = field(default_factory=lambda: _env("HP_BIND", "127.0.0.1"))
    ssh_port: int = field(default_factory=lambda: int(_env("HP_SSH_PORT", "2222")))
    telnet_port: int = field(default_factory=lambda: int(_env("HP_TELNET_PORT", "2323")))
    http_port: int = field(default_factory=lambda: int(_env("HP_HTTP_PORT", "8180")))
    # Generic banner sensors: "port:profile" pairs.
    banner_ports: str = field(default_factory=lambda: _env("HP_BANNER_PORTS", "6380:redis,3307:mysql"))
    # SSH auth policy: "never", "always", or "after:N" (accept the attempt after N failures per source IP).
    ssh_policy: str = field(default_factory=lambda: _env("HP_SSH_POLICY", "after:3"))
    telnet_policy: str = field(default_factory=lambda: _env("HP_TELNET_POLICY", "after:1"))
    session_timeout: int = field(default_factory=lambda: int(_env("HP_SESSION_TIMEOUT", "120")))
    session_max: int = field(default_factory=lambda: int(_env("HP_SESSION_MAX", "600")))
    heartbeat_interval: int = field(default_factory=lambda: int(_env("HP_HEARTBEAT", "15")))
    # Read a PROXY protocol v1 header first (set when sensors sit behind the compose edge relay).
    proxy_protocol: bool = field(default_factory=lambda: _env("HP_PROXY_PROTOCOL", "0") == "1")
    # Source ranges treated as lab traffic: events from them are flagged simulated=true.
    sim_sources: str = field(default_factory=lambda: _env("HP_SIM_SOURCES", "127.0.0.0/8,::1/128"))
    max_conns: int = field(default_factory=lambda: int(_env("HP_MAX_CONNS", "64")))

    def __post_init__(self):
        if not self.secret:
            # No-docker mode: read this node's secret from the collector's secrets file.
            self.secret = load_node_secrets().get(self.node_id, "")
        self._sim_nets = parse_networks(self.sim_sources)

    @property
    def spool_dir(self) -> Path:
        path = Path(_env("HP_SPOOL_DIR", str(data_dir() / "spool" / self.node_id)))
        path.mkdir(parents=True, exist_ok=True)
        return path

    def is_lab_source(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._sim_nets if net.version == addr.version)


@dataclass
class CollectorConfig:
    bind: str = field(default_factory=lambda: _env("HP_BIND", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("HP_COLLECTOR_PORT", "8103")))
    db_path: Path = field(default_factory=lambda: Path(_env("HP_DB", str(data_dir() / "honeypot.db"))))
    replay_window: int = field(default_factory=lambda: int(_env("HP_REPLAY_WINDOW", "300")))
    threat_intel_url: str = field(default_factory=lambda: _env("HP_TI_URL", "http://127.0.0.1:8102/api/enrich"))
    # Where the simulator sends live traffic (host + ports of a sensor node).
    sim_target: str = field(default_factory=lambda: _env("HP_SIM_TARGET", "127.0.0.1"))
