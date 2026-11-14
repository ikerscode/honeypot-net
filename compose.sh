#!/usr/bin/env bash
# Docker mode: create per-node secrets (once), build the image, start the stack.
#   ./compose.sh          build + up -d
#   ./compose.sh down     stop and remove containers (volumes are kept)
set -euo pipefail
cd "$(dirname "$0")"

if [ "${1:-}" = "down" ]; then
    exec docker compose down
fi

if [ ! -f .env ]; then
    umask 077
    {
        for node in LON FRA NYC SGP; do
            echo "HP_SECRET_${node}=$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
        done
    } > .env
    echo "wrote per-node secrets to .env"
fi

# Builds from all seclab projects share one lock so they never run in parallel.
flock /home/iker/seclab-notes/.docker.lock docker build -t honeypot-net:0.1.0 -f docker/Dockerfile .
docker compose up -d
echo "HUD: http://127.0.0.1:8103  (ssh 2222-2224, telnet 2323-2325, http 8180-8182, redis 6380, mysql 3307)"
