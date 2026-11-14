"""Command line entry point.

  python -m honeypot collector                    start the collector + HUD (127.0.0.1:8103)
  python -m honeypot sensor <ssh|telnet|http|banner|all> [...]
  python -m honeypot edge                         compose-only TCP relay (see edge.py)
  python -m honeypot simulate <scenario>          live: ssh_bruteforce ssh_interactive telnet_mirai
                                                  http_exploits banner_probe all_live | inject
  python -m honeypot analyze [--no-sim]           print an analysis summary
  python -m honeypot export --format csv|stix     write attacker IPs
  python -m honeypot geo-download                 fetch the iptoasn.com ASN/country table
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time

from .config import CollectorConfig, load_node_secrets


def cmd_collector(args):
    import uvicorn

    from .collector.app import create_app

    cfg = CollectorConfig()
    if args.port:
        cfg.port = args.port
    uvicorn.run(create_app(cfg), host=cfg.bind, port=cfg.port, log_level="warning")


def cmd_sensor(args):
    from .sensors import run_node

    run_node(args.types)


def cmd_edge(args):
    from .edge import run

    run()


def cmd_simulate(args):
    if args.scenario == "inject":
        from .simulate import inject

        result = inject.run(args.collector, load_node_secrets(), args.days, args.scale, args.seed)
    else:
        from .simulate import live

        ports = {"ssh": args.ssh_port, "telnet": args.telnet_port, "http": args.http_port,
                 "redis": args.redis_port, "mysql": args.mysql_port}
        result = live.run(args.scenario, args.host, ports)
    print(json.dumps(result, indent=2, default=str))


def _db():
    from .collector.db import Database

    return Database(CollectorConfig().db_path)


def cmd_analyze(args):
    from .analysis import bruteforce, campaigns, credentials, exploits, infrastructure, trends
    from .geo import GeoResolver

    db, geo, sim = _db(), GeoResolver(), not args.no_sim
    bf = bruteforce.detect(db, sim)
    cr = credentials.analyse(db, sim, top=5)
    ca = campaigns.analyse(db, sim)
    ex = exploits.analyse(db, sim)
    inf = infrastructure.analyse(db, geo, sim, top=5)
    te = trends.temporal(db, sim)
    ge = trends.geography(db, geo, sim, top=5)
    print(f"auth attempts: {bf['total_attempts']} from {bf['source_ips']} IPs; brute-force flagged: {bf['flagged']}, low-and-slow: {bf['low_and_slow']}; shapes {bf['shapes']}")
    print("top passwords:", ", ".join(f"{d['label']}({d['value']})" for d in cr["top_passwords"]))
    print("credential families:", ", ".join(f"{f['family']}={f['attempts']}" for f in cr["families"][:5]))
    print(f"campaigns: {len(ca['campaigns'])}")
    for c in ca["campaigns"][:8]:
        print(f"  {c['id']} {c['label']:<32} {c['size']:>3} IPs  {c['attempts']:>5} attempts  linked by {c['linked_by']}")
    print(f"exploit attempts: {ex['exploit_attempts']} of {ex['http_requests']} HTTP requests")
    print("  by CVE:", ", ".join(f"{c['cve']}({c['count']})" for c in ex["by_cve"][:10]))
    print(f"unique IPs: {inf['unique_ips']}; sessions by timing: {inf['session_kind_counts']}")
    print("countries:", ", ".join(f"{c['country']}({c['events']})" for c in ge["countries"]), "| lookup:", ge["lookup_sources"])
    print(f"peak hour (UTC): {te.get('peak_hour_utc')}  peak weekday: {te.get('peak_weekday')}  bursts: {len(te['bursts'])}")
    if args.json:
        print(json.dumps({"bruteforce": bf, "campaigns": ca, "exploits": ex}, default=str)[:20000])


def cmd_export(args):
    from .export import attacker_rows, to_csv, to_stix
    from .geo import GeoResolver

    rows = attacker_rows(_db(), GeoResolver(), args.include_sim)
    text = to_csv(rows) if args.format == "csv" else json.dumps(to_stix(rows), indent=2)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(text)
        print(f"wrote {len(rows)} attacker IPs to {args.output}")
    else:
        sys.stdout.write(text)


def cmd_geo_download(args):
    from .geo import IPTOASN_URL, download_iptoasn

    print(f"downloading {IPTOASN_URL} ...")
    start = time.time()
    path = download_iptoasn()
    print(f"saved {path} ({path.stat().st_size // 1024} KiB) in {time.time() - start:.1f}s")
    print("optional: drop a GeoLite2-Country.mmdb or GeoLite2-City.mmdb into the same folder for country/city data")


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m honeypot", description="honeypot-net sensors, collector and analysis")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("collector", help="run the collector API + HUD")
    s.add_argument("--port", type=int)
    s.set_defaults(fn=cmd_collector)

    s = sub.add_parser("sensor", help="run sensors (configure with HP_* env vars)")
    s.add_argument("types", nargs="+", help="ssh telnet http banner or all")
    s.set_defaults(fn=cmd_sensor)

    s = sub.add_parser("edge", help="compose edge relay (HP_EDGE_MAP)")
    s.set_defaults(fn=cmd_edge)

    s = sub.add_parser("simulate", help="run a simulator scenario")
    s.add_argument("scenario", choices=["ssh_bruteforce", "ssh_interactive", "telnet_mirai", "http_exploits",
                                        "banner_probe", "all_live", "inject"])
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--ssh-port", type=int, default=2222)
    s.add_argument("--telnet-port", type=int, default=2323)
    s.add_argument("--http-port", type=int, default=8180)
    s.add_argument("--redis-port", type=int, default=6380)
    s.add_argument("--mysql-port", type=int, default=3307)
    s.add_argument("--collector", default="http://127.0.0.1:8103", help="inject: collector URL")
    s.add_argument("--days", type=int, default=14)
    s.add_argument("--scale", type=float, default=1.0)
    s.add_argument("--seed", type=int)
    s.set_defaults(fn=cmd_simulate)

    s = sub.add_parser("analyze", help="print an analysis summary from the database")
    s.add_argument("--no-sim", action="store_true", help="exclude simulated events")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_analyze)

    s = sub.add_parser("export", help="export attacker IPs")
    s.add_argument("--format", choices=["csv", "stix"], default="csv")
    s.add_argument("--output", "-o")
    s.add_argument("--include-sim", action="store_true", help="include simulated events (off by default)")
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser("geo-download", help="download the iptoasn.com IP-to-ASN/country table")
    s.set_defaults(fn=cmd_geo_download)

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    args.fn(args)


if __name__ == "__main__":
    main()
