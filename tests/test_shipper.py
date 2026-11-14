"""Spool and retry: events survive a collector outage and arrive exactly once afterwards."""

import httpx
from fastapi.testclient import TestClient

from honeypot.collector.app import create_app
from honeypot.config import CollectorConfig
from honeypot.shipper import Shipper


def test_spool_retries_until_collector_is_back(tmp_path):
    shipper = Shipper("node-a", "test", "secret-a", "http://testserver", tmp_path / "spool", heartbeat_interval=999)
    # Phase 1: collector down. Every request fails at the transport level.
    def down(request):
        raise httpx.ConnectError("collector down")
    shipper._client = httpx.Client(transport=httpx.MockTransport(down))
    for i in range(5):
        shipper.emit({"event_type": "auth", "sensor": "ssh", "src_ip": "203.0.113.9", "username": "root", "password": str(i)})
    shipper.tick()
    assert len(shipper.spool_files()) == 1, "events must be on disk while the collector is down"
    shipper.emit({"event_type": "auth", "sensor": "ssh", "src_ip": "203.0.113.9", "username": "root", "password": "x"})
    shipper._next_try = 0
    shipper.tick()
    assert len(shipper.spool_files()) == 2

    # Phase 2: collector up. Batches are re-signed with fresh nonces and delivered.
    cfg = CollectorConfig()
    cfg.db_path = tmp_path / "c.db"
    app = create_app(cfg, {"node-a": "secret-a"})
    shipper._client = TestClient(app)
    shipper._next_try = 0
    shipper.tick()
    assert shipper.spool_files() == []
    rows = app.state.db.query("SELECT COUNT(*) n FROM events WHERE node_id='node-a'")
    assert rows[0]["n"] == 6

    # Re-sending an already delivered batch (lost response) does not duplicate events.
    import json
    events = app.state.db.query("SELECT event_id FROM events LIMIT 2")
    resend = [{"event_id": e["event_id"], "event_type": "auth", "src_ip": "203.0.113.9"} for e in events]
    (tmp_path / "spool" / "batch-0-dup.json").write_text(json.dumps(resend))
    shipper.tick()
    assert app.state.db.query("SELECT COUNT(*) n FROM events")[0]["n"] == 6


def test_spool_cap_drops_oldest(tmp_path, monkeypatch):
    import honeypot.shipper as mod
    monkeypatch.setattr(mod, "MAX_SPOOL_FILES", 3)
    shipper = Shipper("node-a", "t", "s", "http://x", tmp_path / "spool")
    for i in range(5):
        shipper.emit({"event_type": "connect", "n": i})
        shipper.write_spool()
    assert len(shipper.spool_files()) == 3 and shipper.dropped_files == 2
