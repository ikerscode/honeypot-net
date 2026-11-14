"""Sensor node runner: starts the requested sensors in one process sharing one shipper."""

from __future__ import annotations

import logging
import signal
import threading

from ..config import SensorConfig
from ..shipper import Shipper

SENSOR_TYPES = ("ssh", "telnet", "http", "banner")
log = logging.getLogger("honeypot.node")


def build_sensors(cfg: SensorConfig, shipper: Shipper, types: list[str]) -> list:
    from .banner_sensor import BannerSensor
    from .http_sensor import HTTPSensor
    from .ssh_sensor import SSHSensor
    from .telnet_sensor import TelnetSensor

    sensors = []
    for kind in types:
        if kind == "ssh":
            sensors.append(SSHSensor(cfg, shipper))
        elif kind == "telnet":
            sensors.append(TelnetSensor(cfg, shipper))
        elif kind == "http":
            sensors.append(HTTPSensor(cfg, shipper))
        elif kind == "banner":
            for spec in cfg.banner_ports.split(","):
                if ":" in spec:
                    port, profile = spec.split(":", 1)
                    sensors.append(BannerSensor(cfg, shipper, int(port), profile.strip()))
        else:
            raise ValueError(f"unknown sensor type {kind!r}; choose from {SENSOR_TYPES} or 'all'")
    return sensors


def run_node(types: list[str], cfg: SensorConfig | None = None) -> None:
    """Run sensors until SIGINT/SIGTERM. `types` may contain "all"."""
    cfg = cfg or SensorConfig()
    if not cfg.secret:
        raise SystemExit(f"no shared secret for {cfg.node_id}: set HP_NODE_SECRET or start the collector once")
    if "all" in types:
        types = list(SENSOR_TYPES)
    proc = "+".join(types)
    shipper = Shipper(cfg.node_id, cfg.region, cfg.secret, cfg.collector_url, cfg.spool_dir / proc,
                      cfg.heartbeat_interval, proc=proc)
    sensors = build_sensors(cfg, shipper, types)
    shipper.sensors = [f"{s.name}:{s.port}" for s in sensors]
    for s in sensors:
        s.start()
    shipper.start()
    log.info("node %s (%s) running %s -> %s", cfg.node_id, cfg.region, shipper.sensors, cfg.collector_url)
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    signal.signal(signal.SIGINT, lambda *_: done.set())
    done.wait()
    for s in sensors:
        s.stop()
    shipper.stop()
