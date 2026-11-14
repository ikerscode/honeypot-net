"""SQLite storage for the collector: events, sessions and nodes.

Event fields arrive from sensors and contain attacker-controlled text. They are stored as plain
values through parameterised queries only, truncated to sane lengths, and escaped by the HUD.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from ..classify import classify_request

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    event_id TEXT UNIQUE,
    ts REAL NOT NULL,
    received REAL,
    node_id TEXT, region TEXT, sensor TEXT, event_type TEXT,
    src_ip TEXT, src_port INTEGER, dst_port INTEGER, session_id TEXT,
    username TEXT, password TEXT, success INTEGER, auth_method TEXT,
    command TEXT, method TEXT, path TEXT,
    category TEXT, severity TEXT, cves TEXT, scanner TEXT, scanner_kind TEXT,
    fingerprint TEXT,
    data TEXT,
    simulated INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS ix_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS ix_events_session ON events(session_id);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    node_id TEXT, sensor TEXT, src_ip TEXT,
    start_ts REAL, end_ts REAL, duration REAL,
    auth_attempts INTEGER DEFAULT 0, login_success INTEGER DEFAULT 0,
    username TEXT, password TEXT,
    commands INTEGER DEFAULT 0,
    client_version TEXT, hassh TEXT,
    simulated INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_sessions_ip ON sessions(src_ip);
CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT PRIMARY KEY,
    region TEXT, version TEXT,
    first_seen REAL, last_heartbeat REAL, last_event REAL,
    simulated INTEGER DEFAULT 0
);
-- One row per sensor process of a node (run.sh runs each sensor type as its own process).
CREATE TABLE IF NOT EXISTS node_processes (
    node_id TEXT, proc TEXT, sensors TEXT, version TEXT, last_heartbeat REAL,
    uptime INTEGER, spool_backlog INTEGER, sent_events INTEGER, dropped_files INTEGER,
    PRIMARY KEY (node_id, proc)
);
"""

STR_LIMITS = {"username": 256, "password": 256, "command": 2048, "path": 4096, "method": 16, "src_ip": 64,
              "sensor": 16, "event_type": 32, "session_id": 64, "auth_method": 32, "fingerprint": 128, "region": 64}
EVENT_COLUMNS = ["event_id", "ts", "received", "node_id", "region", "sensor", "event_type", "src_ip", "src_port",
                 "dst_port", "session_id", "username", "password", "success", "auth_method", "command", "method",
                 "path", "category", "severity", "cves", "scanner", "scanner_kind", "fingerprint", "data", "simulated"]


def _s(value, limit):
    if value is None:
        return None
    return str(value)[:limit]


def _i(value):
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def normalise_event(ev: dict, node_id: str, region: str | None, now: float) -> dict:
    """Coerce one incoming event into column values, classifying HTTP requests on the way."""
    row = {k: _s(ev.get(k), lim) for k, lim in STR_LIMITS.items()}
    try:
        ts = float(ev.get("ts", now))
    except (TypeError, ValueError):
        ts = now
    data = ev.get("data") if isinstance(ev.get("data"), dict) else {}
    row.update(
        event_id=_s(ev.get("event_id"), 64) or f"{node_id}-{now}-{id(ev)}",
        ts=min(ts, now + 300),  # clamp clock skew into the future
        received=now,
        node_id=node_id,  # always the authenticated node, never what the event claims
        region=row["region"] or region,
        src_port=_i(ev.get("src_port")),
        dst_port=_i(ev.get("dst_port")),
        success=1 if ev.get("success") else 0,
        simulated=1 if ev.get("simulated") else 0,
        category=None, severity=None, cves=None, scanner=None, scanner_kind=None,
    )
    for extra in ("auth_method", "duration", "attempt", "key_type", "key_fingerprint", "key_md5"):
        if extra in ev and extra not in STR_LIMITS:
            data[extra] = ev[extra]
    if ev.get("key_fingerprint"):
        row["fingerprint"] = _s(ev["key_fingerprint"], 128)
    if row["event_type"] == "http_request":
        headers = data.get("headers") if isinstance(data.get("headers"), dict) else {}
        verdict = classify_request(row["method"] or "", row["path"] or "", headers, str(data.get("body") or ""))
        row.update(category=verdict["category"], severity=verdict["severity"], cves=",".join(verdict["cves"]) or None,
                   scanner=verdict["scanner"], scanner_kind=verdict["scanner_kind"])
        data["classification"] = verdict
        ua = next((v for k, v in headers.items() if k.lower() == "user-agent"), None)
        row["fingerprint"] = _s(ua, 128)
    row["data"] = json.dumps(data)[:32768]
    return row


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def query(self, sql: str, params=()) -> list[dict]:
        conn = self.connect()
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    # ---- writes --------------------------------------------------------
    def insert_events(self, events: list[dict], node_id: str, region: str | None = None) -> int:
        now = time.time()
        rows = [normalise_event(ev, node_id, region, now) for ev in events if isinstance(ev, dict)]
        placeholders = ",".join("?" for _ in EVENT_COLUMNS)
        inserted = 0
        with self._lock:
            conn = self.connect()
            try:
                with conn:
                    for row in rows:
                        cur = conn.execute(f"INSERT OR IGNORE INTO events ({','.join(EVENT_COLUMNS)}) VALUES ({placeholders})",
                                           [row[c] for c in EVENT_COLUMNS])
                        if cur.rowcount:  # duplicates from spool retries are skipped entirely
                            inserted += 1
                            self._update_session(conn, row)
                    if rows:
                        sim = 1 if all(r["simulated"] for r in rows) else 0
                        conn.execute(
                            "INSERT INTO nodes (node_id, region, first_seen, last_event, simulated) VALUES (?,?,?,?,?) "
                            "ON CONFLICT(node_id) DO UPDATE SET last_event=excluded.last_event, "
                            "region=COALESCE(nodes.region, excluded.region)",
                            (node_id, rows[0]["region"], now, now, sim))
            finally:
                conn.close()
        return inserted

    @staticmethod
    def _update_session(conn: sqlite3.Connection, row: dict) -> None:
        sid = row["session_id"]
        if not sid:
            return
        conn.execute("INSERT OR IGNORE INTO sessions (session_id, node_id, sensor, src_ip, start_ts, end_ts, simulated) "
                     "VALUES (?,?,?,?,?,?,?)", (sid, row["node_id"], row["sensor"], row["src_ip"], row["ts"], row["ts"],
                                                row["simulated"]))
        conn.execute("UPDATE sessions SET start_ts=MIN(start_ts, ?), end_ts=MAX(end_ts, ?) WHERE session_id=?",
                     (row["ts"], row["ts"], sid))
        et = row["event_type"]
        if et == "auth":
            conn.execute("UPDATE sessions SET auth_attempts=auth_attempts+1 WHERE session_id=?", (sid,))
            if row["success"]:
                conn.execute("UPDATE sessions SET login_success=1, username=?, password=? WHERE session_id=?",
                             (row["username"], row["password"], sid))
        elif et == "command":
            conn.execute("UPDATE sessions SET commands=commands+1 WHERE session_id=?", (sid,))
        elif et == "client_version":
            data = json.loads(row["data"] or "{}")
            conn.execute("UPDATE sessions SET client_version=?, hassh=? WHERE session_id=?",
                         (str(data.get("client_version", ""))[:256], data.get("hassh"), sid))
        elif et == "session_end":
            conn.execute("UPDATE sessions SET duration=end_ts-start_ts WHERE session_id=?", (sid,))

    def heartbeat(self, node_id: str, info: dict, simulated: bool = False) -> None:
        now = time.time()
        proc = _s(info.get("proc"), 32) or "main"
        with self._lock:
            conn = self.connect()
            try:
                with conn:
                    conn.execute(
                        "INSERT INTO nodes (node_id, region, version, first_seen, last_heartbeat, simulated) "
                        "VALUES (?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET region=excluded.region, "
                        "version=excluded.version, last_heartbeat=excluded.last_heartbeat, simulated=excluded.simulated",
                        (node_id, _s(info.get("region"), 64), _s(info.get("version"), 32), now, now, 1 if simulated else 0))
                    conn.execute(
                        "INSERT OR REPLACE INTO node_processes (node_id, proc, sensors, version, last_heartbeat, uptime, "
                        "spool_backlog, sent_events, dropped_files) VALUES (?,?,?,?,?,?,?,?,?)",
                        (node_id, proc, json.dumps(info.get("sensors", []))[:1024], _s(info.get("version"), 32), now,
                         _i(info.get("uptime")), _i(info.get("spool_backlog")), _i(info.get("sent_events")),
                         _i(info.get("dropped_files"))))
            finally:
                conn.close()

    def purge_simulated(self) -> dict:
        with self._lock:
            conn = self.connect()
            try:
                with conn:
                    ev = conn.execute("DELETE FROM events WHERE simulated=1").rowcount
                    se = conn.execute("DELETE FROM sessions WHERE simulated=1").rowcount
                    conn.execute("DELETE FROM node_processes WHERE node_id IN (SELECT node_id FROM nodes WHERE simulated=1)")
                    no = conn.execute("DELETE FROM nodes WHERE simulated=1").rowcount
            finally:
                conn.close()
        return {"events": ev, "sessions": se, "nodes": no}
