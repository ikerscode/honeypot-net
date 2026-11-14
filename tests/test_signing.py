import json

import pytest

from honeypot.signing import Verifier, VerifyError, build_envelope, sign

SECRETS = {"node-a": "secret-a", "node-b": "secret-b"}


def sig_headers(body, node="node-a", secret="secret-a"):
    return sign(secret, body), node


def test_valid_message_verifies():
    body, headers = build_envelope("node-a", "secret-a", "events", {"events": []})
    env = Verifier(SECRETS).verify(body, headers["X-HP-Signature"], headers["X-HP-Node"])
    assert env["node_id"] == "node-a" and env["kind"] == "events"


def test_tampered_body_rejected():
    body, headers = build_envelope("node-a", "secret-a", "events", {"events": [{"src_ip": "1.2.3.4"}]})
    tampered = body.replace(b"1.2.3.4", b"9.9.9.9")
    with pytest.raises(VerifyError, match="bad signature"):
        Verifier(SECRETS).verify(tampered, headers["X-HP-Signature"], "node-a")


def test_wrong_secret_and_unknown_node_rejected():
    body, headers = build_envelope("node-a", "not-the-secret", "events", {"events": []})
    with pytest.raises(VerifyError, match="bad signature"):
        Verifier(SECRETS).verify(body, headers["X-HP-Signature"], "node-a")
    body, headers = build_envelope("node-z", "x", "events", {"events": []})
    with pytest.raises(VerifyError, match="unknown node"):
        Verifier(SECRETS).verify(body, headers["X-HP-Signature"], "node-z")


def test_node_cannot_speak_for_another_node():
    # node-b signs a body that claims to be node-a, with its own (valid) key.
    body, _ = build_envelope("node-a", "secret-b", "events", {"events": []})
    with pytest.raises(VerifyError, match="node id mismatch"):
        Verifier(SECRETS).verify(body, sign("secret-b", body), "node-b")


def test_replay_rejected():
    v = Verifier(SECRETS)
    body, headers = build_envelope("node-a", "secret-a", "events", {"events": []})
    v.verify(body, headers["X-HP-Signature"], "node-a")
    with pytest.raises(VerifyError, match="replayed nonce"):
        v.verify(body, headers["X-HP-Signature"], "node-a")


def test_stale_timestamp_rejected():
    body, headers = build_envelope("node-a", "secret-a", "events", {"events": []}, now=1_000_000)
    with pytest.raises(VerifyError, match="timestamp"):
        Verifier(SECRETS, window=300).verify(body, headers["X-HP-Signature"], "node-a", now=1_000_000 + 301)


def test_missing_headers_rejected():
    body = json.dumps({"node_id": "node-a"}).encode()
    with pytest.raises(VerifyError):
        Verifier(SECRETS).verify(body, None, None)
