"""Collector API end to end with FastAPI's test client: signed ingest, rejections, analysis, export."""

import pytest
from fastapi.testclient import TestClient

from honeypot.collector.app import create_app
from honeypot.config import CollectorConfig
from honeypot.signing import build_envelope
from honeypot.simulate import inject


@pytest.fixture
def client(tmp_path):
    cfg = CollectorConfig()
    cfg.db_path = tmp_path / "api.db"
    app = create_app(cfg, {"node-lon": "s1", "node-fra": "s2", "node-nyc": "s3", "node-sgp": "s4"})
    return TestClient(app)


def post(client, node, secret, payload, kind="events"):
    body, headers = build_envelope(node, secret, kind, payload)
    return client.post("/api/ingest", content=body, headers=headers), body, headers


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok", "name": "honeypot-net", "version": "0.1.0"}


def test_ingest_accepts_signed_and_rejects_bad(client):
    ev = {"event_id": "abc", "ts": 1.0e9, "sensor": "http", "event_type": "http_request", "src_ip": "203.0.113.5",
          "method": "GET", "path": "/.env", "data": {"headers": {"User-Agent": "zgrab"}}}
    resp, body, headers = post(client, "node-lon", "s1", {"events": [ev]})
    assert resp.status_code == 200 and resp.json()["inserted"] == 1
    assert client.post("/api/ingest", content=body, headers=headers).status_code == 401  # replay
    resp, _, _ = post(client, "node-lon", "wrong", {"events": [ev]})
    assert resp.status_code == 401
    row = client.get("/api/events").json()[0]
    assert row["category"] == "info_disclosure" and row["node_id"] == "node-lon"


def test_injected_campaigns_show_up_in_analysis(client):
    events = inject.generate(days=7, scale=0.3, seed=3)
    by_node = {}
    for e in events:
        by_node.setdefault(e.pop("node_id"), []).append(e)
    secrets = {"node-lon": "s1", "node-fra": "s2", "node-nyc": "s3", "node-sgp": "s4"}
    for node, evs in by_node.items():
        for i in range(0, len(evs), 500):
            assert post(client, node, secrets[node], {"events": evs[i:i + 500]})[0].status_code == 200
    ov = client.get("/api/overview").json()
    assert ov["events"] == len(events) == ov["simulated_events"]
    labels = {c["label"] for c in client.get("/api/campaigns").json()["campaigns"]}
    assert "IoT botnet (Mirai-style)" in labels and "targeted brute force" in labels
    assert client.get("/api/exploits").json()["by_cve"]
    geo = client.get("/api/geo").json()
    assert geo["lookup_sources"].get("simulated")
    assert client.get("/api/temporal").json()["heatmap"]
    # Exports exclude simulated data by default; STIX bundle is well formed when included.
    assert client.get("/api/export/csv").text.strip() == "ip,first_seen,last_seen,events,auth_attempts,commands,exploit_attempts,protocols,nodes,country,asn,as_name,score"
    bundle = client.get("/api/export/stix?sim=1").json()
    assert bundle["type"] == "bundle" and any(o["type"] == "indicator" for o in bundle["objects"])
    assert client.post("/api/simulate/purge").json()["events"] == len(events)


def test_enrich_fails_soft(client, monkeypatch):
    resp = client.post("/api/enrich").json()
    assert "available" in resp
