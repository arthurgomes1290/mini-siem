"""Smoke tests: Etapa 1 — the package imports, schema validates, DB initializes."""

from __future__ import annotations

from datetime import datetime, timezone

from mini_siem import __version__
from mini_siem.schema import Event
from mini_siem.storage.db import SCHEMA_VERSION, connect, init_db


def test_version_is_set():
    assert __version__


def test_event_validates_and_serializes_to_ecs():
    event = Event(
        timestamp=datetime(2026, 10, 11, 14, 30, tzinfo=timezone.utc),
        host_name="web-01",
        source_type="auth",
        event_action="login_failed",
        event_outcome="failure",
        user_name="root",
        source_ip="203.0.113.42",
        message_raw="Failed password for root from 203.0.113.42",
        severity="medium",
    )
    ecs = event.to_ecs()
    assert ecs["host.name"] == "web-01"
    assert ecs["source.ip"] == "203.0.113.42"
    assert ecs["event.action"] == "login_failed"
    assert ecs["severity"] == "medium"


def test_init_db_creates_schema(tmp_path):
    db = tmp_path / "siem.db"
    init_db(db)

    conn = connect(db)
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {"events", "alerts", "schema_version"}.issubset(tables)

        version = conn.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()[0]
        assert version == SCHEMA_VERSION
    finally:
        conn.close()
