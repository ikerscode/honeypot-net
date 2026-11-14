"""Geographic and temporal trends: countries/ASNs, timeline, weekday x hour heatmap (UTC),
per-node comparison and burst detection."""

from __future__ import annotations

import json
import statistics
import time
from collections import Counter, defaultdict

from . import sim_filter

WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def geography(db, geo, include_sim: bool = True, top: int = 25) -> dict:
    rows = db.query("SELECT src_ip, COUNT(*) n, MAX(simulated) sim, "
                    "MAX(CASE WHEN data LIKE '%sim_geo%' THEN data END) d FROM events "
                    "WHERE src_ip IS NOT NULL" + sim_filter(include_sim) + " GROUP BY src_ip")
    countries, country_ips, asns, sources = Counter(), Counter(), Counter(), Counter()
    for r in rows:
        hint = json.loads(r["d"]).get("sim_geo") if r["sim"] and r["d"] else None
        g = geo.resolve(r["src_ip"], hint)
        countries[g["country"]] += r["n"]
        country_ips[g["country"]] += 1
        asns[(g["asn"], g["as_name"])] += r["n"]
        sources[g["source"]] += 1
    return {
        "countries": [{"country": c, "events": n, "ips": country_ips[c]} for c, n in countries.most_common(top)],
        "asns": [{"asn": a or "unknown", "as_name": name, "events": n} for (a, name), n in asns.most_common(top)],
        "lookup_sources": dict(sources),
        "geo_db": geo.status(),
    }


def detect_bursts(series: list[tuple[int, int]], k: float = 5.0, min_count: int = 5) -> list[dict]:
    """Flag buckets far above normal. `series` holds (bucket_start, distinct source IPs).

    Distinct IPs are used rather than raw events because a single brute-force session already
    produces dozens of events; a burst means many sources at once (botnet wave, mass scan).
    The limit is the larger of median + k*MAD (robust) and mean + 3 standard deviations, so
    sparse data with a median of zero does not flag every busy hour.
    """
    counts = [c for _, c in series]
    if len(counts) < 6:
        return []
    med = statistics.median(counts)
    mad = max(statistics.median(abs(c - med) for c in counts), 1.0)
    limit = max(med + k * mad, statistics.mean(counts) + 3 * statistics.pstdev(counts))
    return [{"ts": t, "ips": c, "baseline": med, "limit": round(limit, 1), "score": round((c - med) / mad, 1)}
            for t, c in series if c > limit and c >= min_count]


def temporal(db, include_sim: bool = True, bucket: int | None = None) -> dict:
    rows = db.query("SELECT ts, node_id, sensor, src_ip FROM events WHERE event_type NOT IN ('session_end')"
                    + sim_filter(include_sim))
    if not rows:
        return {"bucket_seconds": bucket or 3600, "timeline": [], "heatmap": [[0] * 24 for _ in range(7)],
                "weekdays": WEEKDAYS, "per_node": [], "bursts": []}
    span = max(r["ts"] for r in rows) - min(r["ts"] for r in rows)
    bucket = bucket or (3600 if span > 2 * 86400 else 600 if span > 6 * 3600 else 60)
    timeline, per_node, bucket_ips = Counter(), defaultdict(Counter), defaultdict(set)
    heat = [[0] * 24 for _ in range(7)]
    node_totals, node_sensors = Counter(), defaultdict(Counter)
    for r in rows:
        b = int(r["ts"] // bucket) * bucket
        timeline[b] += 1
        bucket_ips[b].add(r["src_ip"])
        per_node[r["node_id"]][b] += 1
        t = time.gmtime(r["ts"])
        heat[t.tm_wday][t.tm_hour] += 1
        node_totals[r["node_id"]] += 1
        node_sensors[r["node_id"]][r["sensor"]] += 1
    # Fill empty buckets so the baseline for burst detection counts quiet periods too.
    start, end = min(timeline), max(timeline)
    series = [(t, timeline.get(t, 0)) for t in range(start, end + bucket, bucket)][-2000:]
    peak_hour = max(range(24), key=lambda h: sum(heat[d][h] for d in range(7)))
    peak_day = max(range(7), key=lambda d: sum(heat[d]))
    return {
        "bucket_seconds": bucket,
        "timeline": [[t, c] for t, c in series],
        "heatmap": heat, "weekdays": WEEKDAYS,
        "peak_hour_utc": peak_hour, "peak_weekday": WEEKDAYS[peak_day],
        "per_node": [{"node_id": n, "events": node_totals[n], "by_sensor": dict(node_sensors[n]),
                      "peak_bucket": max(per_node[n].values())} for n in sorted(node_totals, key=node_totals.get, reverse=True)],
        "bursts": [{**x, "events": timeline.get(x["ts"], 0)}
                   for x in detect_bursts([(t, len(bucket_ips.get(t, ()))) for t, _ in series])],
    }
