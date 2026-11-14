# honeypot-net

A small distributed honeypot network for a home lab. Low-interaction sensors (SSH, Telnet,
HTTP and a generic TCP banner sensor) pretend to be vulnerable, record what attackers try and
ship signed JSON events to a central collector. The collector stores everything in SQLite and
analyses it: brute-force patterns, credential lists, campaigns, exploit attempts by CVE,
attacker infrastructure, and geographic and time trends. A simulator produces traffic to test
it all, since a honeypot on 127.0.0.1 never sees a real attacker.

## Architecture

```
            attacker / simulator
                    |
   127.0.0.1 only   v
 +-------------------------------------------------------------+
 | sensor node (node_id + region)                              |
 |   ssh :2222   telnet :2323   http :8180   banner :6380/:3307 |
 |   paramiko     fake busybox   bait pages   redis/mysql look  |
 |        \            |             |          /               |
 |         +------ fake shell / static replies (nothing runs) --+
 |                          |                                   |
 |                   Shipper: queue -> spool dir on disk        |
 |                   HMAC-SHA256 sign (ts + nonce) + heartbeat  |
 +--------------------------|----------------------------------+
                            | POST /api/ingest
                            v
 +-------------------------------------------------------------+
 | collector :8103                                             |
 |   verify signature, timestamp window, nonce (replay)        |
 |   classify HTTP requests (rules -> category, CVE, scanner)  |
 |   SQLite: events, sessions, nodes, node_processes           |
 |   analysis: bruteforce, credentials, campaigns, exploits,   |
 |             infrastructure, geo + temporal trends           |
 |   simulator (live + injection), CSV / STIX 2.1 export,      |
 |   optional enrichment via threat-intel :8102                |
 |   HUD at /                                                   |
 +-------------------------------------------------------------+
```

In docker-compose the sensors and the collector sit on an `internal: true` network with no
route out. A tiny relay container (`edge`) is the only thing on a normal bridge: it publishes
the ports on 127.0.0.1 and forwards bytes inward, adding a PROXY protocol v1 line so sensors
still log the real client address.

```
 host 127.0.0.1:{8103,2222-2224,2323-2325,8180-8182,6380,3307}
                 |
             [ edge ]  ---- bridge "edge" (the only network with a gateway)
                 |
   ====== "sensornet" (internal: no gateway, no DNS outside) ======
     |              |             |             |
 [collector]   [node-lon]    [node-fra]    [node-nyc]
```

## Quick start

No docker (collector plus one local node, one process per sensor type):

```
./run.sh
# HUD: http://127.0.0.1:8103
```

`run.sh` creates `.venv` (with system site packages), installs `requirements.txt`, starts
the collector, waits for it, then starts the four sensor processes as node `node-local`.
Per-node secrets are generated into `data/node-secrets.env` on first start. Ctrl-C stops all.

Docker (collector, three sensor nodes, edge relay):

```
./compose.sh          # writes .env with per-node secrets, builds under the shared flock, up -d
./compose.sh down
```

This needs the docker compose v2 plugin (`docker compose`). The image build is wrapped in
`flock $XDG_RUNTIME_DIR/seclab-docker.lock` (override with `SECLAB_DOCKER_LOCK`) so lab builds never run in parallel.

CLI:

```
python -m honeypot collector
python -m honeypot sensor ssh|telnet|http|banner|all      # configured with HP_* env vars
python -m honeypot simulate ssh_bruteforce|ssh_interactive|telnet_mirai|http_exploits|banner_probe|all_live
python -m honeypot simulate inject --days 14 --scale 1
python -m honeypot analyze [--no-sim]
python -m honeypot export --format csv|stix [-o file] [--include-sim]
python -m honeypot geo-download
```

Tests: `.venv/bin/python -m pytest -q` (about one second).

## HUD tour

Three tabs, mostly plain tables, one heatmap.

- **Live**: totals (events, IPs, auth attempts, commands, exploit attempts, events received in
  the last 1 and 10 minutes), sensor node health (last heartbeat, events, spool backlog,
  sensors) and the event feed, refreshed every 5 seconds.
- **Analysis**: one "Run analysis" button. Brute force per IP, top credential pairs and
  default-credential families, campaigns, exploits by category and CVE, scanners, escaped sample
  requests, top IPs (click one for its full profile), ASNs, shared /24s, fingerprints,
  countries, the weekday x hour heatmap, per-node comparison, bursts and session timing.
- **Simulate & export**: one button per live scenario, the injection simulator, purge of
  simulated data, a status panel that shows each run's log and a pass/fail check that the
  events really landed with the right classification, CSV and STIX downloads, and the
  threat-intel enrichment button.

The "include simulated" tick box in the header applies to every view. Exports leave simulated
data out unless it is ticked, and then STIX indicators carry the label `simulated-test-data`.

## Terminal HUD

`python -m honeypot tui` shows a curses dashboard of the collector API (default
`http://127.0.0.1:8103`, change with `--url`). Views: Live, Brute force, Infrastructure (Enter
opens an IP profile) and Nodes. Keys: Tab or 1-4 switch view, arrows move, Enter opens a detail,
Esc goes back, `s` runs the live scenarios, `i` injects synthetic events, `p` purges simulated
events (asks first), `r` refreshes, `q` quits. Add `--once` to print every view as plain text
for SSH sessions, scripts or a quick check.

Attacker-controlled strings (usernames, paths, commands) are stripped of control characters
before they are displayed.

## How each requirement is met

**SSH sensor** (`honeypot/sensors/ssh_sensor.py`). paramiko server mode with a persistent RSA
host key per node and an OpenSSH-looking banner. Logs the client version, HASSH (MD5 of the
client KEXINIT kex/cipher/mac/compression lists, captured by a Transport subclass), every
password attempt and every public-key attempt (SHA256 and MD5 fingerprints; keys are never
accepted). The auth policy `HP_SSH_POLICY` is `never`, `always` or `after:N` (the attempt
after N failures from the same IP is accepted). Accepted sessions get the emulated shell:
PTY with local echo, exec requests, idle timeout (`HP_SESSION_TIMEOUT`) and a hard cap
(`HP_SESSION_MAX`). Port-forward and direct-tcpip requests are logged and refused.

**Fake shell** (`honeypot/sensors/fakeshell.py`). A table of canned outputs over a fake
filesystem: uname, id, whoami, w, ps, free, df, ifconfig, ip, cat of /proc/cpuinfo,
/etc/passwd and friends, ls, cd, history, echo -e, simple pipes (head, tail, grep, wc). wget,
curl, tftp and ftpget print a believable timeout and the URL is recorded as a
`download_attempt` event with `fetched: false`. Nothing is ever executed or fetched.

**Telnet sensor** (`telnet_sensor.py`). IAC negotiation, `login:`/`Password:` prompts,
credential logging, BusyBox prompt. Answers the Mirai sequence (`enable`, `system`, `shell`,
`sh`, `/bin/busybox RANDOM` -> `RANDOM: applet not found`).

**HTTP sensor** (`http_sensor.py`). Hand-written request parsing (so malformed exploit requests
still get logged), capped headers (16 KB) and stored body (8 KB). Bait: WordPress login,
phpMyAdmin, a generic router login, `/.env` and `/.git/config` with fake honeytoken secrets
(the AWS pair is the public documentation example), `/cgi-bin/*`, Apache-style 404s.
Credentials from login forms and Basic auth become `auth` events.

**Exploit classifier** (`honeypot/classify.py`). Regex rules over the URL-decoded (twice) and
Log4j de-obfuscated request: path traversal (CVE-2021-41773/42013, Citrix, Fortinet, Pulse,
Ivanti), Log4Shell (CVE-2021-44228), Shellshock (CVE-2014-6271), Struts and Confluence OGNL,
Spring4Shell and Spring Cloud, ThinkPHP, PHPUnit, PHP-CGI, Laravel Ignition, vBulletin,
Drupalgeddon2, F5, ProxyShell, IoT/router CVEs used by Mirai variants (GPON, Huawei HG532,
Realtek SDK, D-Link HNAP and login.cgi, TP-Link AX21, Hikvision, Zyxel, Netgear, JAWS DVR),
plus generic SQLi, command injection, PHP code, XSS, webshell, secrets-file and admin panel
probes. Scanner identification from the User-Agent: masscan, zgrab, Nuclei, Censys, Shodan,
Expanse, InternetMeasurement, LeakIX, Nmap, sqlmap, Nikto, WPScan, common libraries.
Classification runs at the collector, so improving a rule improves analysis of new data
without touching sensors.

**Banner sensor** (`banner_sensor.py`). Redis-looking (`-NOAUTH`) and MySQL-looking (a real 5.7
handshake packet) ports. Logs the first 2 KB as hex and a printable preview; Redis AUTH
passwords are pulled out as credentials.

**Distribution and signing** (`signing.py`, `shipper.py`). Each node has a node_id, a region
label and its own shared secret. Messages are JSON envelopes with node_id, timestamp, random
nonce and kind (`events` or `heartbeat`); the header carries HMAC-SHA256 over the raw body.
The collector checks the signature with `hmac.compare_digest`, that the body's node_id matches
the claimed node, that the timestamp is within 300 s, and that the nonce is new. Events are
stored under the authenticated node_id, never the one written inside an event. The shipper
writes events to batch files in a spool directory (atomic rename) and deletes a file only
after a 200. If the collector is down the backlog stays on disk, retried with exponential
backoff up to 60 s and capped at 5000 files; each retry is re-signed with a fresh nonce, and
duplicate event ids are ignored, so a lost response never duplicates data. Heartbeats report
uptime, sensors and spool backlog.

**Analysis** (`honeypot/analysis/`).
- `bruteforce.py`: attempts per IP in 60 s windows, flag at 10 per window, a "low and slow"
  flag for IPs that stay under the threshold on purpose, and a pattern label (dictionary,
  spraying, targeted, default-credential probe). Passwords tried against many users.
- `credentials.py`: top users, passwords and pairs, and families (Mirai IoT list, camera/DVR,
  Raspberry Pi, network gear, service accounts, cloud image users, common weak passwords).
- `campaigns.py`: per-IP sets of user:password pairs and normalised commands (URLs, IPs,
  random names and numbers replaced by placeholders), Jaccard similarity, union-find
  clustering, campaign labels (botnet credential stuffing, Mirai-style IoT botnet, password
  spraying, targeted brute force).
- `exploits.py`: counts by category, CVE (with distinct IPs), scanner, path, payload URLs, and
  sample requests.
- `infrastructure.py`: per-IP profile (first/last seen, nodes, protocols, credentials,
  commands, fingerprints, sessions), /24 and ASN grouping, HASSH / key / User-Agent reuse,
  and session timing: median gap under 1 s is automated, slower and irregular is human-like.
- `trends.py`: country and ASN counts, timeline, weekday x hour heatmap (UTC), per-node
  comparison, and burst detection on distinct source IPs per bucket (above both median + 5 MAD
  and mean + 3 sd).

**Geography** (`geo.py`). Offline only. `python -m honeypot geo-download` fetches the
public-domain iptoasn.com `ip2asn-combined.tsv.gz` (ASN + country per range) into
`data/geo/`; a GeoLite2 Country or City `.mmdb` dropped in the same folder is also used
(through `maxminddb`). Without either, real IPs show as "unknown". Synthetic events from the
injector carry their own made-up attribution, labelled source "simulated" in every view.

**Threat-intel tie-in** (`export.py`). Attacker IPs as CSV (with spreadsheet formula
neutralising) and as a STIX 2.1 bundle (identity, `ipv4-addr`/`ipv6-addr` objects and
indicators with stable uuid5 ids). The enrich button POSTs
`{"indicators": [{"type": "ipv4-addr", "value": ...}]}` to
`http://127.0.0.1:8102/api/enrich` (override with `HP_TI_URL`) and reports
`available: false` if nothing answers.

**Simulator** (`honeypot/simulate/`). Live mode drives the real sensors: SSH brute force with a
16-pair wordlist (new connection per username, as real servers drop username changes), a
human-paced interactive SSH session running recon commands, a Mirai-style telnet login with
the applet check and loader download, 18 HTTP exploit probes sent byte-for-byte, and banner
probes. After a HUD-triggered run the collector checks that the expected events arrived and
were classified as expected. Injection mode generates about 5000 signed events over 14 days
and four nodes: botnet credential stuffing (45 IPs, some sharing /24s), a targeted operator
(two IPs in one /24, slow guessing, shared SSH key, office hours, human-paced session), Mirai
telnet scanners with a two-hour burst, web exploit sweeps, password spraying and research
scanners. Every simulated event has `simulated=true`; the HUD can hide or purge them.
Sensors also flag anything from `HP_SIM_SOURCES` (loopback by default) as simulated.

## Safety and isolation

- **Low interaction by design.** No sensor starts a process, opens a PTY, evaluates input,
  includes a file, writes to an attacker-chosen path or makes an outbound connection on an
  attacker's behalf. Download URLs are strings in the database. The fake shell is a lookup
  table.
- **Bound to 127.0.0.1 by default**, both in no-docker mode and for every published compose
  port. Exposing a sensor to the internet is a deliberate step described in
  [docs/DEPLOY.md](docs/DEPLOY.md).
- **Containers**: non-root uid 10001, read-only root filesystem, `cap_drop: ALL`,
  `no-new-privileges`, memory, CPU and pid limits, writable state only in a per-node volume
  and a 16 MB `/tmp` tmpfs. All sensor ports are above 1024, so no capability is needed.
- **No egress from sensors.** They are only on an `internal: true` network. Verified: from
  inside `node-lon`, connecting to 1.1.1.1:443, 1.1.1.1:53 and 8.8.8.8:80 fails with
  "Network is unreachable" and DNS resolution fails, while the collector is reachable.
- The edge relay is the one container with a route out. It only forwards bytes to fixed
  internal targets and runs with the same hardening.
- **Resource caps** in the sensors: a connection limit per sensor (`HP_MAX_CONNS`, 64), session
  timeouts, header/body/first-bytes caps, a bounded spool.
- **Untrusted data in the collector**: parameterised SQL only, string length caps, a 4 MB
  ingest body limit and 1000 events per batch, HUD output escaped with `hud.esc`, CSV export
  neutralises formula injection.
- **Simulated attacks only target this project.** Live simulator targets default to
  127.0.0.1 (or the compose `edge`), and payload URLs use the RFC 5737 documentation ranges.
  Injected IPs are random public addresses with synthetic ASNs from the private-use range
  (64512-65534); exports exclude simulated data unless asked.

## Limitations (honest list)

- **Low interaction means easy to fingerprint.** The SSH server is paramiko (its KEXINIT
  algorithm order and some protocol behaviour differ from OpenSSH whatever the banner says),
  the fake shell knows a few dozen commands, there is no real filesystem state, pipes and
  `&&` are only roughly emulated, and outputs are identical across nodes. Tools that check for
  honeypots (or simply run `cat /proc/self/status` or compile something) will notice.
- The SSH auth policy accepts any password once the counter is reached, which is itself a tell.
- Telnet and HTTP handle one session or one request per connection; no keep-alive, no TLS.
- The replay nonce cache is in memory: after a collector restart only the 300 s timestamp
  window protects against replay.
- Geography is only as good as the offline databases you install; without them real IPs are
  "unknown". ASN and country are not attribution: most traffic comes from compromised hosts,
  cloud VMs and VPNs.
- Campaign clustering is O(n^2) over IPs (capped at 600 IPs) and threshold-based; the
  thresholds (0.5 credentials, 0.6 commands) are judgment calls, not tuned on real data.
- Session timing classification uses median gaps and is easy to fool with a sleep.
- Synthetic injected data is shaped to look plausible, not statistically modelled on a real
  dataset.
- The edge relay can reach the internet (it has to sit on a normal bridge to publish ports).
- Tested with docker 28 using the plain docker CLI with the same settings as
  `docker-compose.yml`; this machine has no compose v2 plugin, so `compose.sh` itself has not
  been run end to end here.

## Ideas for extension

- Medium interaction for one sensor (a proper SSH proxy to a throwaway VM), kept on its own
  isolated network.
- Capture uploaded files over SFTP/SCP into a quarantine store with hashes only.
- JA3/JA4 TLS fingerprints on an HTTPS sensor.
- Persist the nonce cache in SQLite and rotate node secrets with an overlap period.
- Per-node randomised banners, hostnames and fake files to make cross-node fingerprinting harder.
- Feed campaign clusters into the threat-intel platform as STIX `campaign` and
  `intrusion-set` objects with relationships.
