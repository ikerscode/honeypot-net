"""Terminal HUD spec for the collector API (rendered by honeypot.termhud).

Mirrors the web HUD: live feed, brute force, infrastructure and node health.
Endpoints are the collector routes in honeypot/collector/app.py.
"""

SPEC = {
    "title": "HONEYPOT-NET",
    "views": [
        {"name": "Live", "endpoint": "/api/events?limit=80", "rows": "",
         "columns": [["event_type", 12], ["src_ip", 16], ["node_id", 10], ["sensor", 8],
                     ["username", 14], ["category", 18], ["simulated", 5]]},
        {"name": "Brute force", "endpoint": "/api/bruteforce", "rows": "ips",
         "columns": [["ip", 16], ["attempts", 9], ["peak_per_window", 8], ["distinct_users", 6],
                     ["distinct_passwords", 9], ["successes", 8], ["shape", 14], ["brute_force", 6]],
         "detail": "/api/ip/{ip}"},
        {"name": "Infrastructure", "endpoint": "/api/infrastructure", "rows": "top_ips",
         "columns": [["ip", 16], ["events", 8], ["country", 4], ["asn", 8], ["nodes", 24]],
         "detail": "/api/ip/{ip}"},
        {"name": "Nodes", "endpoint": "/api/nodes", "rows": "",
         "columns": [["node_id", 14], ["region", 22], ["status", 12], ["heartbeat_age", 14],
                     ["events", 8], ["spool_backlog", 14], ["sensors", 30]]},
    ],
    "actions": [
        {"key": "s", "label": "run live scenarios", "method": "POST",
         "endpoint": "/api/simulate/live/all_live"},
        {"key": "i", "label": "inject synthetic events", "method": "POST",
         "endpoint": "/api/simulate/inject?days=14&scale=1.0"},
        {"key": "p", "label": "purge simulated events", "method": "POST",
         "endpoint": "/api/simulate/purge", "confirm": True},
    ],
    "refresh": 3,
}
