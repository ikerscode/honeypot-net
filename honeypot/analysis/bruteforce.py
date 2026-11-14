"""Brute-force detection: authentication attempt rate per source IP in fixed time windows.

An IP is flagged when, in any window of `window` seconds, it makes at least `threshold`
attempts. The pattern is then labelled from the shape of what it tried:
  - spraying:   many usernames, very few passwords, roughly one try per user
  - targeted:   one or two usernames, ten or more passwords
  - default-credential probe: a handful of factory defaults (IoT bots)
  - dictionary: many user/password pairs (typical botnet credential list)
"""

from __future__ import annotations

from collections import Counter

from . import sim_filter


def attack_shape(users: Counter, passwords: Counter, attempts: int) -> str:
    nu, np_ = len(users), len(passwords)
    if attempts < 3:
        return "probe"
    if nu >= 5 and np_ <= 2:
        return "password spraying"
    if nu <= 2 and np_ >= 10:
        return "targeted brute force"
    if attempts < 10:
        return "default-credential probe"
    return "dictionary / credential stuffing"


def detect(db, include_sim: bool = True, window: int = 60, threshold: int = 10, limit: int = 100) -> dict:
    rows = db.query("SELECT ts, src_ip, sensor, node_id, username, password, success FROM events "
                    "WHERE event_type='auth'" + sim_filter(include_sim) + " ORDER BY ts")
    per_ip: dict[str, dict] = {}
    for r in rows:
        p = per_ip.setdefault(r["src_ip"], {"buckets": Counter(), "users": Counter(), "passwords": Counter(),
                                            "sensors": set(), "nodes": set(), "success": 0, "first": r["ts"], "n": 0})
        p["n"] += 1
        p["buckets"][int(r["ts"] // window)] += 1
        p["users"][r["username"] or ""] += 1
        p["passwords"][r["password"] or ""] += 1
        p["sensors"].add(r["sensor"])
        p["nodes"].add(r["node_id"])
        p["success"] += r["success"] or 0
        p["last"] = r["ts"]
    results = []
    for ip, p in per_ip.items():
        peak = max(p["buckets"].values())
        hot = sum(1 for c in p["buckets"].values() if c >= threshold)
        span = max(p["last"] - p["first"], 1.0)
        results.append({
            "ip": ip, "attempts": p["n"], "peak_per_window": peak, "windows_over_threshold": hot,
            "avg_per_min": round(p["n"] / (span / 60), 2) if p["n"] > 1 else 0,
            "distinct_users": len(p["users"]), "distinct_passwords": len(p["passwords"]),
            "successes": p["success"], "sensors": sorted(p["sensors"]), "nodes": sorted(p["nodes"]),
            "first_seen": p["first"], "last_seen": p["last"],
            "brute_force": peak >= threshold, "shape": attack_shape(p["users"], p["passwords"], p["n"]),
            # Many attempts but never fast enough to cross the per-window threshold: deliberate pacing
            # to stay under rate-based defences such as fail2ban.
            "low_and_slow": peak < threshold and p["n"] >= threshold,
        })
    results.sort(key=lambda x: (x["brute_force"] or x["low_and_slow"], x["attempts"]), reverse=True)
    # Global attempt-rate timeline (attempts per window across all IPs), last 200 buckets.
    timeline = Counter(int(r["ts"] // window) * window for r in rows)
    keys = sorted(timeline)[-200:]
    return {
        "window_seconds": window, "threshold": threshold,
        "flagged": sum(1 for r in results if r["brute_force"]),
        "total_attempts": len(rows), "source_ips": len(results),
        "low_and_slow": sum(1 for r in results if r["low_and_slow"]),
        "shapes": dict(Counter(r["shape"] for r in results if r["attempts"] >= 5)),
        "ips": results[:limit],
        "rate": [[k, timeline[k]] for k in keys],
    }


def spraying_targets(db, include_sim: bool = True) -> list[dict]:
    """Passwords tried against many usernames (from any number of IPs)."""
    rows = db.query("SELECT password, COUNT(DISTINCT username) users, COUNT(DISTINCT src_ip) ips, COUNT(*) n "
                    "FROM events WHERE event_type='auth' AND password IS NOT NULL" + sim_filter(include_sim) +
                    " GROUP BY password HAVING users >= 5 ORDER BY users DESC LIMIT 20")
    return rows

