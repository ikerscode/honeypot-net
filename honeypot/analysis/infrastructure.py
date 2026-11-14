"""Attacker infrastructure: per-IP profiles, /24 and ASN grouping, client fingerprints and
automated-vs-human session classification from command timing."""

from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict

from . import ip_prefix24, sim_filter


def classify_timing(times: list[float]) -> tuple[str, float | None]:
    """Label an interactive session from the gaps between its commands.

    Bots paste whole scripts: gaps well under a second and very regular. People read output and
    type: gaps of seconds with large variation. Returns (label, median_gap).
    """
    if len(times) < 2:
        return ("single command" if times else "no commands"), None
    gaps = [b - a for a, b in zip(times, times[1:])]
    med = statistics.median(gaps)
    spread = statistics.pstdev(gaps) / (statistics.mean(gaps) or 1)
    if med < 1.0:
        return "automated", round(med, 3)
    if med >= 1.5 and spread > 0.35:
        return "human-like", round(med, 3)
    return "scripted (paced)", round(med, 3)


def session_kinds(db, include_sim: bool = True, limit: int = 200) -> list[dict]:
    rows = db.query("SELECT session_id, ts, src_ip, node_id, sensor FROM events WHERE event_type='command'"
                    + sim_filter(include_sim) + " ORDER BY ts")
    by_session: dict[str, dict] = {}
    for r in rows:
        s = by_session.setdefault(r["session_id"], {"session_id": r["session_id"], "src_ip": r["src_ip"],
                                                     "node_id": r["node_id"], "sensor": r["sensor"], "times": []})
        s["times"].append(r["ts"])
    out = []
    for s in by_session.values():
        label, med = classify_timing(s["times"])
        out.append({**{k: v for k, v in s.items() if k != "times"}, "commands": len(s["times"]),
                    "start": s["times"][0], "median_gap_s": med, "kind": label})
    out.sort(key=lambda x: x["start"], reverse=True)
    return out[:limit]


def analyse(db, geo, include_sim: bool = True, top: int = 50) -> dict:
    rows = db.query("SELECT src_ip, ts, node_id, sensor, event_type, category, simulated, data FROM events "
                    "WHERE src_ip IS NOT NULL" + sim_filter(include_sim))
    ips: dict[str, dict] = {}
    for r in rows:
        p = ips.setdefault(r["src_ip"], {"ip": r["src_ip"], "events": 0, "first_seen": r["ts"], "last_seen": r["ts"],
                                         "nodes": set(), "sensors": set(), "auth": 0, "commands": 0, "exploits": 0,
                                         "hint": None})
        p["events"] += 1
        p["first_seen"] = min(p["first_seen"], r["ts"])
        p["last_seen"] = max(p["last_seen"], r["ts"])
        p["nodes"].add(r["node_id"])
        p["sensors"].add(r["sensor"])
        p["auth"] += r["event_type"] == "auth"
        p["commands"] += r["event_type"] == "command"
        p["exploits"] += bool(r["category"] and r["category"] not in ("benign_or_unknown", "scan"))
        if r["simulated"] and p["hint"] is None and r["data"] and "sim_geo" in r["data"]:
            p["hint"] = json.loads(r["data"]).get("sim_geo")
    prefixes, asns = defaultdict(set), defaultdict(lambda: {"ips": set(), "events": 0, "name": None, "country": None})
    for p in ips.values():
        g = geo.resolve(p["ip"], p.pop("hint"))
        p.update(country=g["country"], asn=g["asn"], as_name=g["as_name"], geo_source=g["source"])
        p["nodes"], p["sensors"] = sorted(p["nodes"]), sorted(p["sensors"])
        prefixes[ip_prefix24(p["ip"])].add(p["ip"])
        key = g["asn"] or "unknown"
        asns[key]["ips"].add(p["ip"])
        asns[key]["events"] += p["events"]
        asns[key]["name"] = g["as_name"]
        asns[key]["country"] = g["country"]
    top_ips = sorted(ips.values(), key=lambda p: p["events"], reverse=True)[:top]
    fingerprints = db.query(
        "SELECT event_type, fingerprint, COUNT(*) n, COUNT(DISTINCT src_ip) ips FROM events WHERE fingerprint IS NOT NULL"
        " AND fingerprint != ''" + sim_filter(include_sim) + " GROUP BY event_type, fingerprint ORDER BY ips DESC, n DESC LIMIT 40")
    versions = db.query("SELECT client_version, hassh, COUNT(*) sessions, COUNT(DISTINCT src_ip) ips FROM sessions "
                        "WHERE client_version IS NOT NULL AND client_version != ''" + sim_filter(include_sim) +
                        " GROUP BY client_version, hassh ORDER BY ips DESC LIMIT 30")
    kinds = session_kinds(db, include_sim)
    return {
        "unique_ips": len(ips),
        "top_ips": top_ips,
        "prefixes": sorted(({"prefix": k, "ips": len(v)} for k, v in prefixes.items() if len(v) > 1),
                           key=lambda x: x["ips"], reverse=True)[:30],
        "asns": sorted(({"asn": k, "as_name": v["name"], "country": v["country"], "ips": len(v["ips"]), "events": v["events"]}
                        for k, v in asns.items()), key=lambda x: x["ips"], reverse=True)[:30],
        "fingerprints": [{"kind": {"client_version": "HASSH", "auth": "SSH public key",
                                   "http_request": "HTTP User-Agent"}.get(f["event_type"], f["event_type"]),
                          "value": f["fingerprint"], "events": f["n"], "ips": f["ips"]} for f in fingerprints],
        "client_versions": versions,
        "session_kinds": kinds,
        "session_kind_counts": dict(Counter(k["kind"] for k in kinds)),
    }


def ip_profile(db, geo, ip: str, include_sim: bool = True) -> dict:
    events = db.query("SELECT * FROM events WHERE src_ip=?" + sim_filter(include_sim) + " ORDER BY ts", (ip,))
    if not events:
        return {"ip": ip, "found": False}
    hint = next((json.loads(e["data"]).get("sim_geo") for e in events if e["simulated"] and "sim_geo" in (e["data"] or "")), None)
    sessions = db.query("SELECT * FROM sessions WHERE src_ip=?" + sim_filter(include_sim) + " ORDER BY start_ts", (ip,))
    creds = Counter((e["username"], e["password"]) for e in events if e["event_type"] == "auth")
    cmds = [{"ts": e["ts"], "session_id": e["session_id"], "command": e["command"]} for e in events if e["event_type"] == "command"]
    times_by_session = defaultdict(list)
    for c in cmds:
        times_by_session[c["session_id"]].append(c["ts"])
    return {
        "ip": ip, "found": True, "prefix": ip_prefix24(ip), "geo": geo.resolve(ip, hint),
        "first_seen": events[0]["ts"], "last_seen": events[-1]["ts"], "events": len(events),
        "simulated": all(e["simulated"] for e in events),
        "nodes": sorted({e["node_id"] for e in events}), "protocols": sorted({e["sensor"] for e in events}),
        "event_types": dict(Counter(e["event_type"] for e in events)),
        "credentials": [{"username": u, "password": p, "count": n} for (u, p), n in creds.most_common(50)],
        "commands": cmds[:200],
        "exploits": [{"ts": e["ts"], "method": e["method"], "path": e["path"], "category": e["category"], "cves": e["cves"]}
                     for e in events if e["event_type"] == "http_request"][:100],
        "fingerprints": sorted({e["fingerprint"] for e in events if e["fingerprint"]}),
        "client_versions": sorted({s["client_version"] for s in sessions if s["client_version"]}),
        "sessions": [{**s, "timing": classify_timing(times_by_session.get(s["session_id"], []))[0]} for s in sessions[-50:]],
    }
