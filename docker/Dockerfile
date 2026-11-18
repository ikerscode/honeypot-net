# One image for the collector, the sensors and the edge relay; the command picks the role.
FROM python:3.15-slim

RUN pip install --no-cache-dir "fastapi==0.115.6" "uvicorn==0.34.0" "paramiko==3.5.0" "httpx==0.28.1" "maxminddb==2.6.2"

# Unprivileged user; /data is the only writable path (a volume) besides a small /tmp tmpfs.
RUN useradd --uid 10001 --system --no-create-home --shell /usr/sbin/nologin hp \
    && mkdir /data && chown hp:hp /data

WORKDIR /app
COPY honeypot /app/honeypot
COPY static /app/static

ENV HP_DATA_DIR=/data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER hp
ENTRYPOINT ["python", "-m", "honeypot"]
