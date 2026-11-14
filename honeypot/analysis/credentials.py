"""Credential analysis: top usernames, passwords and pairs, and default-credential families."""

from __future__ import annotations

from collections import Counter

from . import sim_filter

# Known default / commonly abused credential sets. The Mirai list is from the source code
# released in 2016; the rest are vendor defaults and cloud image usernames seen in honeypot data.
FAMILIES: dict[str, set[tuple[str, str]] | set[str]] = {
    "Mirai IoT defaults": {
        ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"), ("admin", "admin"), ("root", "888888"),
        ("root", "xmhdipc"), ("root", "default"), ("root", "juantech"), ("root", "123456"), ("root", "54321"),
        ("support", "support"), ("root", ""), ("admin", "password"), ("root", "root"), ("root", "12345"),
        ("user", "user"), ("admin", ""), ("root", "pass"), ("admin", "admin1234"), ("root", "1111"),
        ("admin", "smcadmin"), ("admin", "1111"), ("root", "666666"), ("root", "password"), ("root", "1234"),
        ("root", "klv123"), ("Administrator", "admin"), ("service", "service"), ("supervisor", "supervisor"),
        ("guest", "guest"), ("guest", "12345"), ("admin1", "password"), ("administrator", "1234"),
        ("666666", "666666"), ("888888", "888888"), ("ubnt", "ubnt"), ("root", "klv1234"), ("root", "Zte521"),
        ("root", "hi3518"), ("root", "jvbzd"), ("root", "anko"), ("root", "zlxx."), ("root", "7ujMko0vizxv"),
        ("root", "7ujMko0admin"), ("root", "system"), ("root", "ikwb"), ("root", "dreambox"), ("root", "user"),
        ("root", "realtek"), ("root", "00000000"), ("admin", "1111111"), ("admin", "1234"), ("admin", "12345"),
        ("admin", "54321"), ("admin", "123456"), ("admin", "7ujMko0admin"), ("admin", "pass"), ("admin", "meinsm"),
        ("tech", "tech"),
    },
    "Camera / DVR vendor defaults": {("admin", "12345"), ("admin", "888888"), ("admin", "9999"), ("root", "pass"),
                                     ("admin", "4321"), ("root", "vizxv"), ("admin", "Admin123"), ("default", "default")},
    "Raspberry Pi / SBC": {("pi", "raspberry"), ("pi", "raspberrypi"), ("orangepi", "orangepi"), ("ubuntu", "ubuntu")},
    "Network gear defaults": {("ubnt", "ubnt"), ("cisco", "cisco"), ("admin", "motorola"), ("mikrotik", ""),
                              ("admin", "zhone"), ("telecomadmin", "admintelecom"), ("e8ehome", "e8ehome")},
    "Database / app service accounts": {"oracle", "postgres", "mysql", "redis", "elastic", "hadoop", "tomcat",
                                        "minecraft", "git", "jenkins", "zabbix", "nagios", "sonar", "es"},
    "Cloud image default users": {"ubuntu", "ec2-user", "centos", "debian", "azureuser", "admin", "opc", "fedora"},
}
WEAK_PASSWORDS = {"123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567",
                  "dragon", "123123", "abc123", "admin", "root", "toor", "letmein", "passw0rd", "P@ssw0rd", "1q2w3e4r"}


def family_of(user: str | None, password: str | None) -> str:
    user, password = user or "", password or ""
    for name, entries in FAMILIES.items():
        sample = next(iter(entries))
        if isinstance(sample, tuple):
            if (user, password) in entries:
                return name
        elif user.lower() in entries:
            return name
    if password in WEAK_PASSWORDS:
        return "Common weak password"
    return "other"


def analyse(db, include_sim: bool = True, top: int = 20) -> dict:
    rows = db.query("SELECT username, password, sensor, src_ip FROM events WHERE event_type='auth'"
                    + sim_filter(include_sim))
    users = Counter(r["username"] for r in rows if r["username"] is not None)
    passwords = Counter(r["password"] for r in rows if r["password"] is not None)
    pairs = Counter((r["username"], r["password"]) for r in rows if r["password"] is not None)
    fam_attempts, fam_ips = Counter(), {}
    for r in rows:
        fam = family_of(r["username"], r["password"])
        fam_attempts[fam] += 1
        fam_ips.setdefault(fam, set()).add(r["src_ip"])
    by_sensor = Counter(r["sensor"] for r in rows)
    return {
        "total": len(rows),
        "unique_users": len(users), "unique_passwords": len(passwords), "unique_pairs": len(pairs),
        "top_users": [{"label": u, "value": c} for u, c in users.most_common(top)],
        "top_passwords": [{"label": p, "value": c} for p, c in passwords.most_common(top)],
        "top_pairs": [{"username": u, "password": p, "count": c, "family": family_of(u, p)}
                      for (u, p), c in pairs.most_common(top)],
        "families": [{"family": f, "attempts": c, "ips": len(fam_ips[f])} for f, c in fam_attempts.most_common()],
        "by_sensor": dict(by_sensor),
    }
