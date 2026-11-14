"""Event shipping from a sensor node to the collector, with an on-disk spool.

Flow: sensors call Shipper.emit(event) -> events queue in memory -> a background thread
writes them to the spool directory in small batch files -> the same thread POSTs the oldest
batch files to the collector and deletes each one only after a 200 response.

If the collector is down the files simply stay on disk and are retried with exponential
backoff. Each retry is re-signed with a fresh timestamp and nonce, and the collector ignores
duplicate event_ids, so a batch that was delivered but whose response got lost is harmless.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
import uuid
from pathlib import Path

import httpx

from . import __version__
from .signing import build_envelope

log = logging.getLogger("honeypot.shipper")

MAX_SPOOL_FILES = 5000  # cap the backlog so a long outage cannot fill the disk
BATCH_SIZE = 200


class Shipper:
    def __init__(self, node_id: str, region: str, secret: str, collector_url: str, spool_dir: Path,
                 heartbeat_interval: int = 15, flush_interval: float = 1.0, proc: str = "main"):
        self.node_id = node_id
        self.region = region
        self.secret = secret
        self.ingest_url = collector_url.rstrip("/") + "/api/ingest"
        self.spool_dir = Path(spool_dir)
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self.heartbeat_interval = heartbeat_interval
        self.flush_interval = flush_interval
        self.proc = proc  # which process of the node this is (a node may run one process per sensor)
        self.sensors: list[str] = []
        self.started = time.time()
        self.sent_events = 0
        self.dropped_files = 0
        self._queue: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._backoff = 0.0
        self._next_try = 0.0
        self._last_heartbeat = 0.0
        self._client = httpx.Client(timeout=5.0)

    # ---- producer side -------------------------------------------------
    def emit(self, event: dict) -> None:
        """Queue one event. Adds the node identity and an id; never blocks the sensor."""
        event.setdefault("event_id", uuid.uuid4().hex)
        event.setdefault("ts", time.time())
        event["node_id"] = self.node_id
        event["region"] = self.region
        self._queue.put(event)

    # ---- spool ---------------------------------------------------------
    def spool_files(self) -> list[Path]:
        return sorted(self.spool_dir.glob("batch-*.json"))

    def write_spool(self) -> int:
        """Move queued events into one spool file. Returns how many were written."""
        batch = []
        while len(batch) < BATCH_SIZE:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if not batch:
            return 0
        name = f"batch-{time.time_ns()}-{uuid.uuid4().hex[:6]}.json"
        tmp = self.spool_dir / (name + ".tmp")
        tmp.write_text(json.dumps(batch))
        os.replace(tmp, self.spool_dir / name)  # atomic: a crash never leaves a half batch
        self._enforce_cap()
        return len(batch)

    def _enforce_cap(self) -> None:
        files = self.spool_files()
        for old in files[: max(0, len(files) - MAX_SPOOL_FILES)]:
            old.unlink(missing_ok=True)
            self.dropped_files += 1

    def _post(self, kind: str, payload: dict) -> bool:
        body, headers = build_envelope(self.node_id, self.secret, kind, payload)
        try:
            resp = self._client.post(self.ingest_url, content=body, headers=headers)
        except httpx.HTTPError as exc:
            log.debug("collector unreachable: %s", exc)
            return False
        if resp.status_code != 200:
            log.warning("collector rejected %s: %s %s", kind, resp.status_code, resp.text[:200])
        return resp.status_code == 200

    def flush_spool(self, max_files: int = 20) -> int:
        """Send spooled batches oldest-first. Stops at the first failure. Returns files sent."""
        sent = 0
        for path in self.spool_files()[:max_files]:
            try:
                events = json.loads(path.read_text())
            except (OSError, ValueError):
                path.unlink(missing_ok=True)  # corrupt file: drop it rather than block the queue
                continue
            if not self._post("events", {"events": events}):
                self._backoff = min(60.0, max(1.0, self._backoff * 2))
                self._next_try = time.time() + self._backoff
                return sent
            path.unlink(missing_ok=True)
            self.sent_events += len(events)
            sent += 1
        self._backoff = 0.0
        return sent

    def heartbeat(self) -> bool:
        return self._post("heartbeat", {"node": {
            "region": self.region,
            "proc": self.proc,
            "sensors": self.sensors,
            "version": __version__,
            "uptime": round(time.time() - self.started),
            "spool_backlog": len(self.spool_files()),
            "sent_events": self.sent_events,
            "dropped_files": self.dropped_files,
        }})

    # ---- background loop ----------------------------------------------
    def tick(self) -> None:
        while self.write_spool():
            pass
        now = time.time()
        if now >= self._next_try:
            self.flush_spool()
        if now - self._last_heartbeat >= self.heartbeat_interval:
            self._last_heartbeat = now
            self.heartbeat()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:  # keep shipping alive whatever happens
                log.exception("shipper tick failed")
            self._stop.wait(self.flush_interval)
        while self.write_spool():  # persist anything still queued on shutdown
            pass

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="shipper", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
