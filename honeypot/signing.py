"""HMAC-SHA256 signing of sensor -> collector messages, with replay protection.

Wire format: the request body is a JSON envelope
    {"node_id": ..., "ts": <unix seconds>, "nonce": <random hex>, "kind": "events"|"heartbeat", ...}
and the header X-HP-Signature carries hex(HMAC-SHA256(node_secret, raw_body)).

The signature covers the exact bytes sent, so the collector verifies before parsing anything
else. ts + nonce inside the signed body stop an attacker who captured one message from
replaying it: old timestamps fall outside the window and recent ones are caught by the nonce cache.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time

SIG_HEADER = "X-HP-Signature"
NODE_HEADER = "X-HP-Node"


def sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def build_envelope(node_id: str, secret: str, kind: str, payload: dict, now: float | None = None) -> tuple[bytes, dict]:
    """Return (body, headers) ready to POST. A fresh ts and nonce are used on every call,
    so spooled batches get re-signed when they are retried."""
    envelope = {
        "node_id": node_id,
        "ts": now if now is not None else time.time(),
        "nonce": secrets.token_hex(16),
        "kind": kind,
        **payload,
    }
    body = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()
    headers = {SIG_HEADER: sign(secret, body), NODE_HEADER: node_id, "Content-Type": "application/json"}
    return body, headers


class VerifyError(Exception):
    """Raised when a message must be rejected. The message is safe to return to the client."""


class NonceCache:
    """Remembers nonces for the replay window. In memory: a collector restart clears it, but the
    timestamp window still bounds what could be replayed after a restart."""

    def __init__(self, window: int):
        self.window = window
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, nonce: str, now: float) -> bool:
        with self._lock:
            if len(self._seen) > 50_000:
                cutoff = now - self.window * 2
                self._seen = {n: t for n, t in self._seen.items() if t > cutoff}
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True


class Verifier:
    def __init__(self, node_secrets: dict[str, str], window: int = 300):
        self.node_secrets = node_secrets
        self.window = window
        self.nonces = NonceCache(window)

    def verify(self, body: bytes, signature: str | None, node_header: str | None, now: float | None = None) -> dict:
        """Check signature, node identity, timestamp and nonce. Returns the parsed envelope."""
        now = now if now is not None else time.time()
        if not signature or not node_header:
            raise VerifyError("missing signature headers")
        secret = self.node_secrets.get(node_header)
        if not secret:
            raise VerifyError("unknown node")
        # Constant-time comparison so the signature cannot be guessed byte by byte from timing.
        if not hmac.compare_digest(sign(secret, body), signature.lower()):
            raise VerifyError("bad signature")
        try:
            envelope = json.loads(body)
        except ValueError as exc:
            raise VerifyError("body is not JSON") from exc
        if envelope.get("node_id") != node_header:
            raise VerifyError("node id mismatch")
        ts = envelope.get("ts")
        if not isinstance(ts, (int, float)) or abs(now - ts) > self.window:
            raise VerifyError("timestamp outside window")
        nonce = envelope.get("nonce")
        if not isinstance(nonce, str) or len(nonce) < 16:
            raise VerifyError("bad nonce")
        if not self.nonces.check_and_add(nonce, now):
            raise VerifyError("replayed nonce")
        return envelope
