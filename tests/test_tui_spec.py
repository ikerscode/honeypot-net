"""Terminal HUD spec: every view answers, every action maps to a real route, and control characters are stripped."""

import pytest
from fastapi.testclient import TestClient

from honeypot import termhud
from honeypot.collector.app import create_app
from honeypot.config import CollectorConfig
from honeypot.tui_spec import SPEC


@pytest.fixture
def app(tmp_path):
    cfg = CollectorConfig()
    cfg.db_path = tmp_path / "tui.db"
    return create_app(cfg, {"node-lon": "s1"})


@pytest.fixture
def client(app):
    return TestClient(app)


HDRS = {"host": "127.0.0.1"}


def test_every_view_endpoint_answers(client):
    for view in SPEC["views"]:
        resp = client.get(view["endpoint"], headers=HDRS)
        assert resp.status_code == 200, view["name"]
        if "rows" in view:
            assert isinstance(termhud.dig(resp.json(), view["rows"]), list), view["name"]


def test_every_action_endpoint_is_a_real_route(app):
    for action in SPEC["actions"]:
        path = action["endpoint"].split("?", 1)[0]
        method = action.get("method", "POST")
        matched = [r for r in app.routes
                   if getattr(r, "path_regex", None) and r.path_regex.match(path) and method in getattr(r, "methods", ())]
        assert matched, f"{action['label']}: {method} {path} is not a route"


def test_action_keys_are_single_letters_and_unique():
    keys = [a["key"] for a in SPEC["actions"]]
    assert len(keys) == len(set(keys))
    for key in keys:
        assert len(key) == 1 and key.isalpha() and key not in "qrjk", key
    assert SPEC["refresh"] == 3


def test_clean_strips_escape_sequences():
    assert "\x1b" not in termhud.clean("admin\x1b[2J")
    assert termhud.clean("admin\x1b[2J") == "admin?[2J"
    assert "\n" not in termhud.clean("a\nb")
