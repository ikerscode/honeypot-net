"""Threat-intel output: attacker IP list as CSV and STIX 2.1, plus optional enrichment through the
local threat-intel platform (http://127.0.0.1:8102/api/enrich). Enrichment fails soft."""

from __future__ import annotations

import csv
import io
import json
import time
import uuid

import httpx

from . import __version__
from .analysis import infrastructure

NAMESPACE = uuid.UUID("6f1c7a0e-4b8e-4e43-9b55-0a7c1f2d9e11")  # stable ids: same IP -> same indicator id


def attacker_rows(db, geo, include_sim: bool = True, limit: int = 1000) -> list[dict]:
    data = infrastructure.analyse(db, geo, include_sim, top=limit)
    out = []
    for p in data["top_ips"]:
        if p["country"] == "private":
            continue  # lab traffic is not intel
        score = min(100, p["auth"] + 10 * p["exploits"] + 5 * p["commands"] + 5 * len(p["nodes"]))
        out.append({"ip": p["ip"], "first_seen": iso(p["first_seen"]), "last_seen": iso(p["last_seen"]),
                    "events": p["events"], "auth_attempts": p["auth"], "commands": p["commands"],
                    "exploit_attempts": p["exploits"], "protocols": " ".join(p["sensors"]), "nodes": " ".join(p["nodes"]),
                    "country": p["country"], "asn": p["asn"] or "", "as_name": p["as_name"] or "", "score": score})
    return out


def iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ts))


CSV_FIELDS = ["ip", "first_seen", "last_seen", "events", "auth_attempts", "commands", "exploit_attempts",
              "protocols", "nodes", "country", "asn", "as_name", "score"]


def to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS)
    w.writeheader()
    if rows:
        for r in rows:
            # Neutralise spreadsheet formula injection: attacker-chosen text must not start with = + - @.
            w.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v) for k, v in r.items()})
    return buf.getvalue()


def to_stix(rows: list[dict]) -> dict:
    now = iso(time.time())
    identity_id = f"identity--{uuid.uuid5(NAMESPACE, 'honeypot-net')}"
    objects = [{"type": "identity", "spec_version": "2.1", "id": identity_id, "created": now, "modified": now,
                "name": "honeypot-net sensor network", "identity_class": "system"}]
    for r in rows:
        kind = "ipv6-addr" if ":" in r["ip"] else "ipv4-addr"
        objects.append({
            "type": kind, "spec_version": "2.1", "id": f"{kind}--{uuid.uuid5(NAMESPACE, r['ip'])}", "value": r["ip"],
        })
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid5(NAMESPACE, 'ind:' + r['ip'])}",
            "created": now, "modified": now, "created_by_ref": identity_id,
            "name": f"Honeypot attacker {r['ip']}",
            "description": (f"{r['events']} events on honeypot sensors ({r['protocols']}); {r['auth_attempts']} login attempts, "
                            f"{r['exploit_attempts']} exploit attempts, {r['commands']} shell commands. "
                            f"AS{r['asn']} {r['as_name']} {r['country']}."),
            "indicator_types": ["malicious-activity"], "pattern_type": "stix",
            "pattern": f"[{kind}:value = '{r['ip']}']", "valid_from": r["first_seen"],
            "confidence": r["score"], "labels": ["honeypot", *r["protocols"].split()],
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def enrich(url: str, ips: list[str], timeout: float = 4.0) -> dict:
    """POST {"indicators": [{"type": "ipv4-addr", "value": ip}, ...]} to the threat-intel platform."""
    payload = {"source": "honeypot-net", "version": __version__,
               "indicators": [{"type": "ipv6-addr" if ":" in ip else "ipv4-addr", "value": ip} for ip in ips[:200]]}
    try:
        resp = httpx.post(url, json=payload, timeout=timeout)
        resp.raise_for_status()
        try:
            body = resp.json()
        except json.JSONDecodeError:
            body = resp.text[:2000]
        return {"available": True, "url": url, "sent": len(payload["indicators"]), "result": body}
    except httpx.HTTPError as exc:
        return {"available": False, "url": url, "sent": 0, "error": f"{type(exc).__name__}: {exc}"[:300]}
