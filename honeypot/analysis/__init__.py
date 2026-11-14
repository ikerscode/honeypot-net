"""Analysis engine over the collector's SQLite database.

Every function takes the Database plus `include_sim` (whether simulated events count) and
returns plain JSON-serialisable dicts that the API serves directly.
"""

from __future__ import annotations


def sim_filter(include_sim: bool, alias: str = "") -> str:
    """SQL fragment that drops simulated rows when they should be excluded."""
    prefix = f"{alias}." if alias else ""
    return "" if include_sim else f" AND {prefix}simulated=0"


def ip_prefix24(ip: str) -> str:
    if ":" in ip:  # IPv6: group by /48
        parts = ip.split(":")
        return ":".join(parts[:3]) + "::/48"
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ip
