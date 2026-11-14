"""Campaign clustering: group source IPs that behave alike.

Each IP gets two feature sets: the user:password pairs it tried, and the commands it ran
(normalised so random file names do not hide reuse). IPs are linked when the Jaccard similarity
of either set reaches the threshold, and linked IPs are merged with union-find. A campaign is a
connected group of 2+ IPs; its label comes from the combined credential shape.
"""

from __future__ import annotations

import re
from collections import Counter

from . import ip_prefix24, sim_filter
from .bruteforce import attack_shape


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def normalise_command(cmd: str) -> str:
    """Replace values that change per run (URLs, IPs, random names, numbers) with placeholders."""
    cmd = re.sub(r"(?:https?|ftp|tftp)://\S+", "<url>", cmd)
    cmd = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", cmd)
    cmd = re.sub(r"busybox [A-Z0-9]{4,}", "busybox <rand>", cmd)
    cmd = re.sub(r"\b[a-zA-Z0-9]{12,}\b", "<id>", cmd)
    cmd = re.sub(r"\d+", "<n>", cmd)
    return " ".join(cmd.split())[:200]


class UnionFind:
    def __init__(self, items):
        self.parent = {i: i for i in items}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def build_profiles(db, include_sim: bool) -> dict[str, dict]:
    profiles: dict[str, dict] = {}
    for r in db.query("SELECT src_ip, username, password, node_id FROM events WHERE event_type='auth'"
                      + sim_filter(include_sim)):
        p = profiles.setdefault(r["src_ip"], {"creds": set(), "cmds": set(), "users": Counter(),
                                              "passwords": Counter(), "attempts": 0, "nodes": set()})
        p["creds"].add(f"{r['username']}:{r['password']}")
        p["users"][r["username"]] += 1
        p["passwords"][r["password"]] += 1
        p["attempts"] += 1
        p["nodes"].add(r["node_id"])
    for r in db.query("SELECT src_ip, command, node_id FROM events WHERE event_type='command'" + sim_filter(include_sim)):
        p = profiles.setdefault(r["src_ip"], {"creds": set(), "cmds": set(), "users": Counter(),
                                              "passwords": Counter(), "attempts": 0, "nodes": set()})
        p["cmds"].add(normalise_command(r["command"] or ""))
        p["nodes"].add(r["node_id"])
    return profiles


def cluster(profiles: dict[str, dict], cred_threshold: float = 0.5, cmd_threshold: float = 0.6,
            min_creds: int = 3, max_ips: int = 600) -> list[dict]:
    # Only IPs with enough behaviour to compare; cap the count to keep this O(n^2) step cheap.
    ips = [ip for ip, p in profiles.items() if len(p["creds"]) >= min_creds or len(p["cmds"]) >= 2]
    ips = sorted(ips, key=lambda i: profiles[i]["attempts"] + len(profiles[i]["cmds"]), reverse=True)[:max_ips]
    uf = UnionFind(ips)
    link_reason: dict[tuple, str] = {}
    for i, a in enumerate(ips):
        pa = profiles[a]
        for b in ips[i + 1:]:
            pb = profiles[b]
            jc = jaccard(pa["creds"], pb["creds"]) if len(pa["creds"]) >= min_creds and len(pb["creds"]) >= min_creds else 0
            jm = jaccard(pa["cmds"], pb["cmds"]) if len(pa["cmds"]) >= 2 and len(pb["cmds"]) >= 2 else 0
            if jc >= cred_threshold or jm >= cmd_threshold:
                uf.union(a, b)
                link_reason[(a, b)] = "credentials" if jc >= cred_threshold else "commands"
    groups: dict[str, list[str]] = {}
    for ip in ips:
        groups.setdefault(uf.find(ip), []).append(ip)
    campaigns = []
    for members in groups.values():
        if len(members) < 2:
            continue
        users, passwords, creds, cmds, nodes, attempts = Counter(), Counter(), Counter(), Counter(), set(), 0
        for ip in members:
            p = profiles[ip]
            users.update(p["users"])
            passwords.update(p["passwords"])
            creds.update(p["creds"])
            cmds.update(p["cmds"])
            nodes |= p["nodes"]
            attempts += p["attempts"]
        reasons = Counter(r for (a, b), r in link_reason.items() if a in members)
        shape = attack_shape(users, passwords, attempts) if attempts else "command reuse"
        busybox = sum(n for c, n in cmds.items() if "busybox" in c)
        if busybox and busybox * 2 >= sum(cmds.values()) * 0.3:
            shape = "IoT botnet (Mirai-style)"
        elif attempts and len(members) >= 5 and shape == "dictionary / credential stuffing":
            shape = "botnet credential stuffing"
        campaigns.append({
            "size": len(members), "ips": sorted(members)[:50], "prefixes": len({ip_prefix24(i) for i in members}),
            "attempts": attempts, "nodes": sorted(nodes), "label": shape,
            "linked_by": dict(reasons),
            "shared_creds": [c for c, n in creds.most_common(8) if n > 1],
            "shared_commands": [c for c, n in cmds.most_common(6) if n > 1],
        })
    campaigns.sort(key=lambda c: c["size"], reverse=True)
    for i, c in enumerate(campaigns, 1):
        c["id"] = f"C{i:02d}"
    return campaigns


def analyse(db, include_sim: bool = True, cred_threshold: float = 0.5, cmd_threshold: float = 0.6) -> dict:
    profiles = build_profiles(db, include_sim)
    campaigns = cluster(profiles, cred_threshold, cmd_threshold)
    return {"campaigns": campaigns, "ips_compared": len(profiles),
            "thresholds": {"credentials_jaccard": cred_threshold, "commands_jaccard": cmd_threshold}}
