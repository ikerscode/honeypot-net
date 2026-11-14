#!/usr/bin/env bash
# No-docker mode: collector + one local sensor node (one process per sensor type), all on 127.0.0.1.
#   ./run.sh            start everything, Ctrl-C stops everything
#   ./run.sh collector  collector + HUD only
umask 077  # data (captured credentials, samples, intel) is private to this user
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
    python3 -m venv --system-site-packages .venv
fi
.venv/bin/pip install -q -r requirements.txt
PY=.venv/bin/python
mkdir -p data/logs

pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

$PY -m honeypot collector &
pids+=($!)
echo "collector + HUD: http://127.0.0.1:8103"

if [ "${1:-}" != "collector" ]; then
    # Wait for the collector so it has written data/node-secrets.env before sensors read it.
    for _ in $(seq 1 30); do
        curl -fs http://127.0.0.1:8103/api/health >/dev/null 2>&1 && break
        sleep 0.5
    done
    export HP_NODE_ID=node-local HP_REGION=local
    for kind in ssh telnet http banner; do
        $PY -m honeypot sensor "$kind" >"data/logs/sensor-$kind.log" 2>&1 &
        pids+=($!)
    done
    echo "sensors on 127.0.0.1: ssh 2222, telnet 2323, http 8180, banner 6380 (redis) 3307 (mysql)"
    echo "logs in data/logs/"
fi
wait
