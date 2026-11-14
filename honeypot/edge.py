"""Edge relay used by docker-compose.

Docker does not publish ports for containers that sit only on an `internal: true` network, and
the whole point of that network is that sensors cannot reach the internet. So one small relay
container joins both the internal network and a normal bridge, publishes the ports on the host's
127.0.0.1, and forwards bytes to the sensors. For sensor ports it prepends a PROXY protocol v1
line so the sensor still logs the real client address.

Mapping format (HP_EDGE_MAP): "listen_port=host:port[:proxy]" separated by commas.
"""

from __future__ import annotations

import asyncio
import logging
import os

log = logging.getLogger("honeypot.edge")
MAX_CONNS = 256


def parse_map(text: str) -> list[tuple[int, str, int, bool]]:
    out = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        listen, target = item.split("=", 1)
        parts = target.split(":")
        out.append((int(listen), parts[0], int(parts[1]), len(parts) > 2 and parts[2] == "proxy"))
    return out


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()


def make_handler(host: str, port: int, proxy: bool, slots: asyncio.Semaphore):
    async def handle(c_reader, c_writer):
        if slots.locked():
            c_writer.close()
            return
        async with slots:
            peer = c_writer.get_extra_info("peername") or ("0.0.0.0", 0)
            local = c_writer.get_extra_info("sockname") or ("0.0.0.0", 0)
            try:
                u_reader, u_writer = await asyncio.wait_for(asyncio.open_connection(host, port), 5)
            except (OSError, asyncio.TimeoutError):
                c_writer.close()
                return
            if proxy:
                fam = "TCP6" if ":" in peer[0] else "TCP4"
                u_writer.write(f"PROXY {fam} {peer[0]} {local[0]} {peer[1]} {local[1]}\r\n".encode())
            await asyncio.gather(_pipe(c_reader, u_writer), _pipe(u_reader, c_writer))
    return handle


async def serve(mapping: list[tuple[int, str, int, bool]], bind: str = "0.0.0.0") -> None:
    slots = asyncio.Semaphore(MAX_CONNS)
    servers = []
    for listen, host, port, proxy in mapping:
        servers.append(await asyncio.start_server(make_handler(host, port, proxy, slots), bind, listen))
        log.info("edge %s:%s -> %s:%s%s", bind, listen, host, port, " (PROXY v1)" if proxy else "")
    await asyncio.gather(*(s.serve_forever() for s in servers))


def run() -> None:
    mapping = parse_map(os.environ.get("HP_EDGE_MAP", ""))
    if not mapping:
        raise SystemExit("HP_EDGE_MAP is empty")
    asyncio.run(serve(mapping, os.environ.get("HP_BIND", "127.0.0.1")))
