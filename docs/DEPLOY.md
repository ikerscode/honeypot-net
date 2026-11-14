# Deploying a sensor node on the internet

The lab default is 127.0.0.1 only. A real honeypot needs real traffic, so this is the short,
practical way to put one sensor node on a disposable VPS without putting anything else at
risk. Only the sensor goes on the internet. The collector stays at home (or on another
private box) and is never exposed.

## 1. Account and provider

- Use a **separate cloud account** (separate email, separate billing, its own API keys). If the
  box is abused or the account is closed, nothing else of yours goes with it.
- **Read the provider's acceptable use policy first.** Some providers forbid honeypots, or
  require you to tell them. Several will suspend a VM that receives a lot of attack traffic
  or that looks like it is scanning. Check, and keep the reply if you ask support.
- Smallest instance is enough (1 vCPU, 1 GB RAM). Pick a region per node if you want the
  geographic comparison to mean something.
- **Never run a sensor on your home network or a network that belongs to someone else**
  (university, employer). A honeypot attracts hostile traffic to whatever IP it sits on.

## 2. Base host

```
apt update && apt full-upgrade -y
apt install -y docker.io unattended-upgrades wireguard ufw
dpkg-reconfigure -plow unattended-upgrades     # automatic security updates
```

Move your own SSH off port 22 so the honeypot can take it, allow key login only, and restrict
it to your WireGuard address once the tunnel works:

```
# /etc/ssh/sshd_config.d/admin.conf
Port 22222
PasswordAuthentication no
PermitRootLogin no
```

## 3. Firewall: only sensor ports are public

```
ufw default deny incoming
ufw default allow outgoing
ufw allow 51820/udp                 # WireGuard
ufw allow in on wg0 to any port 22222 proto tcp   # admin SSH, tunnel only
ufw allow 2222/tcp                  # honeypot ssh    (public port 22 is redirected here)
ufw allow 2323/tcp                  # honeypot telnet (public port 23)
ufw allow 8180/tcp                  # honeypot http   (public port 80)
ufw enable
```

Redirect the well-known ports to the unprivileged sensor ports, so nothing needs root. The
redirect happens before filtering, which is why ufw allows the sensor ports rather than 22/23/80:

```
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222
iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-ports 2323
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8180
```

(Make these persistent with `iptables-persistent` or the ufw `before.rules` file.) Note that
Docker edits iptables itself and can bypass ufw for published ports; publishing only the
sensor ports, as below, keeps that harmless.

## 4. Collector reachable over the tunnel only

The sensor ships events to the collector over **WireGuard** (or an SSH reverse tunnel). The
collector listens on its tunnel address, never on a public interface.

- WireGuard: put the collector at 10.66.0.1 and the VPS at 10.66.0.2. On the collector host
  run it with `HP_BIND=10.66.0.1`. On the sensor set `HP_COLLECTOR_URL=http://10.66.0.1:8103`.
- SSH alternative, from the collector side:
  `ssh -N -R 18103:127.0.0.1:8103 -p 22222 admin@vps` and on the sensor
  `HP_COLLECTOR_URL=http://127.0.0.1:18103`.

The traffic is already HMAC-signed with replay protection, but the tunnel keeps the
collector's address and API off the internet entirely.

## 5. Run the sensor

Build or copy the image (`docker save honeypot-net:0.1.0 | ssh ... docker load`), then run one
node with the same hardening as the compose file:

```
docker run -d --name hp-node --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 10001:10001 \
  --tmpfs /tmp:size=16m --pids-limit 128 --memory 192m --cpus 0.5 \
  --network host \
  -e HP_NODE_ID=node-ams -e HP_REGION="eu-west (Amsterdam)" \
  -e HP_NODE_SECRET=<secret shared with the collector> \
  -e HP_COLLECTOR_URL=http://10.66.0.1:8103 \
  -e HP_BIND=0.0.0.0 -e HP_SIM_SOURCES=127.0.0.0/8 \
  -e HP_BANNER_PORTS= \
  -v hp-node-data:/data honeypot-net:0.1.0 sensor ssh telnet http
```

- Add the node and its secret to the collector's `HP_NODE_SECRETS` (or `data/node-secrets.env`).
- Set `HP_SIM_SOURCES` to loopback only, so no real attacker is ever marked as simulated.
- `--network host` is used here so the firewall rules above apply directly. If you prefer a
  bridge, publish only the three sensor ports.
- Leave `HP_PROXY_PROTOCOL` unset: there is no relay in front of the sensor.
- Outbound egress: the sensor only needs UDP 51820 to the collector's WireGuard endpoint. If
  you want the same no-egress guarantee as the lab, restrict outgoing traffic with
  `ufw default deny outgoing` plus allow rules for WireGuard, DNS and apt mirrors.

## 6. Running it

- Watch node health in the HUD (Live tab: last heartbeat and spool backlog). A growing backlog
  means the tunnel is down; events wait on disk and are sent when it returns.
- Rebuild the VPS from scratch rather than repairing it if anything looks odd. Destroy it when
  the experiment ends.
- Keep the host patched (unattended-upgrades) and update the image when Python packages get
  security fixes.

## 7. Log retention and GDPR (UK)

IP addresses are personal data under UK GDPR when they can be linked to a person, and some
attacking IPs belong to ordinary people whose devices are infected.

- Lawful basis: legitimate interests (security research and protecting systems). Write a short
  legitimate interests assessment and keep it with the project.
- Keep only what you need: the sensors already store no more than the attack itself. Set a
  retention period (for example 90 days for raw events) and delete older rows:
  `DELETE FROM events WHERE ts < strftime('%s','now','-90 days');` plus the matching
  `sessions` rows. Aggregates (counts, CVE stats) can be kept longer.
- Do not publish raw IP lists. If you share exports (CSV/STIX), share them with security
  contacts or a threat-intel platform for defence, not publicly.
- If the project is part of university work, check whether it needs ethics approval before the
  node goes live.
