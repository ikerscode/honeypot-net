"""Collector API: authenticated ingest from sensor nodes, analysis endpoints, simulator controls, exports.

Run with `python -m honeypot collector` (binds 127.0.0.1:8103 by default).
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from ..localguard import LocalGuard
from .. import NAME, __version__
from ..analysis import bruteforce, campaigns, credentials, exploits, infrastructure, trends
from ..config import PROJECT_ROOT, CollectorConfig, load_node_secrets
from ..export import attacker_rows, enrich, to_csv, to_stix
from ..geo import GeoResolver
from ..signing import NODE_HEADER, SIG_HEADER, Verifier, VerifyError
from ..simulate import inject, live
from .db import Database

MAX_BODY = 4 * 1024 * 1024
MAX_EVENTS_PER_BATCH = 1000
STATIC = PROJECT_ROOT / "static"


class SimRunner:
    """Runs one simulator job at a time in a background thread so HUD requests return at once."""

    def __init__(self):
        self.lock = threading.Lock()
        self.current: dict | None = None
        self.history: list[dict] = []

    def start(self, name: str, fn) -> dict:
        with self.lock:
            if self.current and self.current["state"] == "running":
                raise HTTPException(409, f"{self.current['name']} is still running")
            job = {"name": name, "state": "running", "started": time.time(), "result": None}
            self.current = job

        def work():
            try:
                job["result"] = fn()
                job["state"] = "done"
            except Exception as exc:  # report the failure in the HUD instead of a silent thread death
                job["result"] = {"error": f"{type(exc).__name__}: {exc}"}
                job["state"] = "failed"
            job["finished"] = time.time()
            self.history = ([dict(job)] + self.history)[:20]

        threading.Thread(target=work, daemon=True).start()
        return job


def create_app(cfg: CollectorConfig | None = None, node_secrets: dict | None = None) -> FastAPI:
    cfg = cfg or CollectorConfig()
    secrets = node_secrets if node_secrets is not None else load_node_secrets()
    db = Database(cfg.db_path)
    verifier = Verifier(secrets, cfg.replay_window)
    geo = GeoResolver()
    runner = SimRunner()
    app = FastAPI(title=NAME, version=__version__)
    app.add_middleware(LocalGuard)  # localhost-only: host allowlist, CSRF block, CSP
    app.state.db, app.state.verifier, app.state.geo = db, verifier, geo

    def sim(v: int) -> bool:
        return bool(v)

    # ---- health + ingest ----------------------------------------------
    @app.get("/api/health")
    def health():
        return {"status": "ok", "name": NAME, "version": __version__}

    @app.post("/api/ingest")
    async def ingest(request: Request):
        body = await request.body()
        if len(body) > MAX_BODY:
            raise HTTPException(413, "body too large")
        try:
            env = verifier.verify(body, request.headers.get(SIG_HEADER), request.headers.get(NODE_HEADER))
        except VerifyError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        node_id = env["node_id"]
        if env.get("kind") == "heartbeat":
            info = env.get("node") if isinstance(env.get("node"), dict) else {}
            db.heartbeat(node_id, info, simulated=bool(info.get("simulated")))
            return {"ok": True, "kind": "heartbeat"}
        events = env.get("events")
        if not isinstance(events, list) or len(events) > MAX_EVENTS_PER_BATCH:
            raise HTTPException(400, "events must be a list of at most 1000 items")
        inserted = db.insert_events(events, node_id)
        return {"ok": True, "received": len(events), "inserted": inserted}

    # ---- live view -----------------------------------------------------
    @app.get("/api/overview")
    def overview(sim_: int = Query(1, alias="sim")):
        f = "" if sim(sim_) else " AND simulated=0"
        q = lambda sql: db.query(sql)[0]  # noqa: E731
        return {
            "events": q("SELECT COUNT(*) n FROM events WHERE 1=1" + f)["n"],
            "simulated_events": q("SELECT COUNT(*) n FROM events WHERE simulated=1")["n"],
            "unique_ips": q("SELECT COUNT(DISTINCT src_ip) n FROM events WHERE 1=1" + f)["n"],
            "auth_attempts": q("SELECT COUNT(*) n FROM events WHERE event_type='auth'" + f)["n"],
            "commands": q("SELECT COUNT(*) n FROM events WHERE event_type='command'" + f)["n"],
            "exploit_attempts": q("SELECT COUNT(*) n FROM events WHERE event_type='http_request' AND category NOT IN "
                                  "('benign_or_unknown','scan')" + f)["n"],
            "sessions": q("SELECT COUNT(*) n FROM sessions WHERE 1=1" + f)["n"],
            "nodes": q("SELECT COUNT(*) n FROM nodes")["n"],
        }

    @app.get("/api/events")
    def events(limit: int = 100, sim_: int = Query(1, alias="sim"), ip: str | None = None, event_type: str | None = None):
        sql, params = "SELECT * FROM events WHERE 1=1", []
        if not sim(sim_):
            sql += " AND simulated=0"
        if ip:
            sql += " AND src_ip=?"
            params.append(ip)
        if event_type:
            sql += " AND event_type=?"
            params.append(event_type)
        rows = db.query(sql + " ORDER BY received DESC, ts DESC LIMIT ?", (*params, min(limit, 1000)))
        for r in rows:
            r["data"] = json.loads(r["data"] or "{}")
        return rows

    @app.get("/api/rate")
    def rate(minutes: int = 60, sim_: int = Query(1, alias="sim")):
        """Events received per minute, per sensor, over the last `minutes` (by arrival time)."""
        since = time.time() - minutes * 60
        rows = db.query("SELECT CAST(received/60 AS INTEGER)*60 m, sensor, COUNT(*) n FROM events WHERE received>=?"
                        + ("" if sim(sim_) else " AND simulated=0") + " GROUP BY m, sensor ORDER BY m", (since,))
        return rows

    # ---- analysis ------------------------------------------------------
    @app.get("/api/bruteforce")
    def api_bruteforce(sim_: int = Query(1, alias="sim"), window: int = 60, threshold: int = 10):
        out = bruteforce.detect(db, sim(sim_), window, threshold)
        out["spraying_passwords"] = bruteforce.spraying_targets(db, sim(sim_))
        return out

    @app.get("/api/credentials")
    def api_credentials(sim_: int = Query(1, alias="sim")):
        return credentials.analyse(db, sim(sim_))

    @app.get("/api/campaigns")
    def api_campaigns(sim_: int = Query(1, alias="sim"), cred: float = 0.5, cmd: float = 0.6):
        return campaigns.analyse(db, sim(sim_), cred, cmd)

    @app.get("/api/exploits")
    def api_exploits(sim_: int = Query(1, alias="sim")):
        return exploits.analyse(db, sim(sim_))

    @app.get("/api/infrastructure")
    def api_infra(sim_: int = Query(1, alias="sim")):
        return infrastructure.analyse(db, geo, sim(sim_))

    @app.get("/api/ip/{ip}")
    def api_ip(ip: str, sim_: int = Query(1, alias="sim")):
        return infrastructure.ip_profile(db, geo, ip, sim(sim_))

    @app.get("/api/geo")
    def api_geo(sim_: int = Query(1, alias="sim")):
        return trends.geography(db, geo, sim(sim_))

    @app.post("/api/geo/reload")
    def api_geo_reload():
        geo.reload()
        return geo.status()

    @app.get("/api/temporal")
    def api_temporal(sim_: int = Query(1, alias="sim"), bucket: int | None = None):
        return trends.temporal(db, sim(sim_), bucket)

    @app.get("/api/nodes")
    def api_nodes():
        """Node health: newest heartbeat, sensors and spool backlog summed over the node's processes."""
        now = time.time()
        rows = db.query("SELECT n.node_id, n.region, n.version, n.first_seen, n.last_heartbeat, n.last_event, n.simulated, "
                        "(SELECT COUNT(*) FROM events e WHERE e.node_id=n.node_id) events FROM nodes n ORDER BY node_id")
        procs = db.query("SELECT * FROM node_processes")
        for r in rows:
            mine = [p for p in procs if p["node_id"] == r["node_id"]]
            r["sensors"] = sorted({s for p in mine for s in json.loads(p["sensors"] or "[]")})
            r["processes"] = len(mine)
            r["spool_backlog"] = sum(p["spool_backlog"] or 0 for p in mine)
            r["dropped_files"] = sum(p["dropped_files"] or 0 for p in mine)
            age = now - r["last_heartbeat"] if r["last_heartbeat"] else None
            r["heartbeat_age"] = round(age, 1) if age is not None else None
            r["status"] = ("simulated" if r["simulated"] else "no heartbeat" if age is None
                           else "ok" if age < 60 else "stale")
        return rows

    # ---- simulator -----------------------------------------------------
    def verify_live(result: dict, since: float) -> dict:
        """After a live run, check the events really reached the database and were classified."""
        time.sleep(3)  # shipper flushes every second; give it a moment
        rows = db.query("SELECT event_type, path, category FROM events WHERE received>=? AND simulated=1 ORDER BY ts",
                        (since,))
        counts: dict[str, int] = {}
        for r in rows:
            counts[r["event_type"]] = counts.get(r["event_type"], 0) + 1
        checks, used = [], set()
        for exp in result.get("expected", []):
            if "category" in exp:
                # Several probes share a path ("/"), so match each to the next unused row in order.
                idx = next((i for i, r in enumerate(rows) if i not in used and r["path"] == exp["path"]), None)
                used.add(idx)
                got = rows[idx]["category"] if idx is not None else None
                checks.append({"check": f"{exp['path'][:60]} -> {exp['category']}", "got": got, "pass": got == exp["category"]})
            else:
                got = counts.get(exp["event_type"], 0)
                checks.append({"check": f">= {exp['min']} {exp['event_type']} events", "got": got, "pass": got >= exp["min"]})
        result["verification"] = {"events_landed": counts, "checks": checks,
                                  "passed": sum(c["pass"] for c in checks), "total": len(checks)}
        return result

    @app.post("/api/simulate/live/{scenario}")
    def simulate_live(scenario: str, host: str | None = None):
        if scenario not in live.SCENARIOS and scenario != "all_live":
            raise HTTPException(404, "unknown scenario")
        target = host or cfg.sim_target

        def job():
            since = time.time()
            if scenario == "all_live":
                return {"results": [verify_live(live.run(s, target), since) for s in live.SCENARIOS]}
            return verify_live(live.run(scenario, target), since)

        return runner.start(scenario, job)

    @app.post("/api/simulate/inject")
    def simulate_inject(days: int = 14, scale: float = 1.0):
        days, scale = max(1, min(days, 60)), max(0.1, min(scale, 5.0))
        url = f"http://127.0.0.1:{cfg.port}"
        return runner.start("inject", lambda: inject.run(url, secrets, days, scale))

    @app.get("/api/simulate/status")
    def simulate_status():
        return {"current": runner.current, "history": runner.history[:5]}

    @app.post("/api/simulate/purge")
    def simulate_purge():
        return db.purge_simulated()

    # ---- exports + threat intel ---------------------------------------
    # Exports leave out simulated data unless asked: synthetic IPs must not end up in real intel feeds.
    @app.get("/api/export/csv")
    def export_csv(sim_: int = Query(0, alias="sim")):
        return PlainTextResponse(to_csv(attacker_rows(db, geo, sim(sim_))), media_type="text/csv",
                                 headers={"Content-Disposition": "attachment; filename=attackers.csv"})

    @app.get("/api/export/stix")
    def export_stix(sim_: int = Query(0, alias="sim")):
        bundle = to_stix(attacker_rows(db, geo, sim(sim_)))
        if sim(sim_):
            for obj in bundle["objects"]:
                if obj["type"] == "indicator":
                    obj["labels"].append("simulated-test-data")
        return JSONResponse(bundle, headers={"Content-Disposition": "attachment; filename=attackers.stix.json"})

    @app.post("/api/enrich")
    def api_enrich(sim_: int = Query(0, alias="sim"), limit: int = 50):
        ips = [r["ip"] for r in attacker_rows(db, geo, sim(sim_))][:limit]
        return enrich(cfg.threat_intel_url, ips)

    # ---- HUD -----------------------------------------------------------
    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=str(Path(STATIC))), name="static")
    return app
