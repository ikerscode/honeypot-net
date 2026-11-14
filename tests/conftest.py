import os

os.environ.setdefault("SECLAB_ALLOWED_HOSTS", "testserver")  # FastAPI TestClient host

"""Shared fixtures: every test gets its own data directory, so nothing touches data/."""

import pytest

from honeypot.collector.db import Database


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    monkeypatch.setenv("HP_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("HP_NODE_SECRETS", "node-a=secret-a,node-b=secret-b")
    return tmp_path


@pytest.fixture
def db(tmp_path):
    return Database(tmp_path / "test.db")


class FakeShipper:
    """Collects events in memory instead of sending them."""

    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)

    def of(self, event_type):
        return [e for e in self.events if e["event_type"] == event_type]


@pytest.fixture
def shipper():
    return FakeShipper()
