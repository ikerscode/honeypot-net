"""Offline IP -> ASN / country lookup.

Sources, in order:
 1. data/geo/ip2asn-combined.tsv.gz from iptoasn.com (public domain, ASN + country per range),
    fetched only when the owner runs `python -m honeypot geo-download`.
 2. A user-supplied MaxMind GeoLite2 Country/City .mmdb in data/geo/ (read with maxminddb).
 3. For simulated events only: the synthetic attribution the injector attached, labelled "simulated".
Otherwise the answer is "unknown". No lookup ever leaves the machine.
"""

from __future__ import annotations

import bisect
import gzip
import ipaddress
import logging
import threading
from functools import lru_cache
from pathlib import Path

from .config import data_dir

log = logging.getLogger("honeypot.geo")
IPTOASN_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
UNKNOWN = {"country": "unknown", "asn": None, "as_name": None, "source": "none"}


def geo_dir() -> Path:
    path = data_dir() / "geo"
    path.mkdir(parents=True, exist_ok=True)
    return path


class AsnTable:
    """Sorted range table loaded from the iptoasn TSV; lookups are a binary search."""

    def __init__(self, path: Path):
        self.starts: dict[int, list[int]] = {4: [], 6: []}
        self.rows: dict[int, list[tuple[int, int, str, str]]] = {4: [], 6: []}
        opener = gzip.open if str(path).endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5 or parts[2] == "0":  # ASN 0 = not routed
                    continue
                try:
                    a, b = ipaddress.ip_address(parts[0]), ipaddress.ip_address(parts[1])
                except ValueError:
                    continue
                self.starts[a.version].append(int(a))
                self.rows[a.version].append((int(b), int(parts[2]), parts[3], parts[4]))
        for v in (4, 6):  # the file is sorted already; sort defensively for hand-made fixtures
            order = sorted(range(len(self.starts[v])), key=self.starts[v].__getitem__)
            self.starts[v] = [self.starts[v][i] for i in order]
            self.rows[v] = [self.rows[v][i] for i in order]

    def lookup(self, ip: str) -> dict | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        v, n = addr.version, int(addr)
        i = bisect.bisect_right(self.starts[v], n) - 1
        if i >= 0 and n <= self.rows[v][i][0]:
            end, asn, country, name = self.rows[v][i]
            return {"country": country or "unknown", "asn": asn, "as_name": name, "source": "iptoasn"}
        return None


class GeoResolver:
    def __init__(self, directory: Path | None = None):
        self.directory = directory or geo_dir()
        self._asn: AsnTable | None = None
        self._mmdb = None
        self._loaded = False
        self._lock = threading.Lock()

    def _load(self) -> None:
        with self._lock:
            if self._loaded:
                return
            self._loaded = True
            tsv = self.directory / "ip2asn-combined.tsv.gz"
            if not tsv.exists():
                tsv = self.directory / "ip2asn-combined.tsv"
            if tsv.exists():
                try:
                    self._asn = AsnTable(tsv)
                except OSError as exc:
                    log.warning("could not load %s: %s", tsv, exc)
            mmdbs = sorted(self.directory.glob("*.mmdb"))
            if mmdbs:
                try:
                    import maxminddb
                    self._mmdb = maxminddb.open_database(str(mmdbs[0]))
                except Exception as exc:  # optional dependency or bad file
                    log.warning("could not open %s: %s", mmdbs[0], exc)

    def reload(self) -> None:
        self._loaded = False
        self.lookup.cache_clear()
        self._load()

    def status(self) -> dict:
        self._load()
        return {"iptoasn": self._asn is not None, "mmdb": self._mmdb is not None,
                "directory": str(self.directory), "download_url": IPTOASN_URL}

    @lru_cache(maxsize=65536)
    def lookup(self, ip: str) -> dict:
        self._load()
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return dict(UNKNOWN)
        if not addr.is_global:
            return {"country": "private", "asn": None, "as_name": "private/lab network", "source": "rfc1918"}
        result = dict(UNKNOWN)
        if self._asn:
            hit = self._asn.lookup(ip)
            if hit:
                result = hit
        if self._mmdb:
            try:
                rec = self._mmdb.get(ip) or {}
                cc = (rec.get("country") or {}).get("iso_code")
                if cc:
                    result["country"] = cc
                    result["source"] = result["source"] + "+mmdb" if result["source"] != "none" else "mmdb"
                city = ((rec.get("city") or {}).get("names") or {}).get("en")
                if city:
                    result["city"] = city
            except Exception:
                pass
        return result

    def resolve(self, ip: str, sim_hint: dict | None = None) -> dict:
        """Lookup, falling back to the injector's synthetic attribution for simulated events."""
        result = self.lookup(ip)
        if result["source"] == "none" and sim_hint:
            return {"country": sim_hint.get("country", "unknown"), "asn": sim_hint.get("asn"),
                    "as_name": sim_hint.get("as_name"), "source": "simulated"}
        return result


def download_iptoasn(dest: Path | None = None) -> Path:
    """Fetch the iptoasn combined table (about 7 MB). Only called on explicit request."""
    import httpx

    dest = dest or geo_dir() / "ip2asn-combined.tsv.gz"
    tmp = dest.with_suffix(".part")
    with httpx.stream("GET", IPTOASN_URL, timeout=120, follow_redirects=True) as resp:
        resp.raise_for_status()
        with open(tmp, "wb") as fh:
            for chunk in resp.iter_bytes():
                fh.write(chunk)
    with gzip.open(tmp, "rt") as fh:  # sanity check before replacing the old copy
        if len(fh.readline().split("\t")) < 5:
            raise ValueError("downloaded file does not look like ip2asn TSV")
    tmp.replace(dest)
    return dest
