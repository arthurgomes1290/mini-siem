"""Testes de persistência e consulta sobre a tabela events."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from mini_siem.schema import Event
from mini_siem.storage.db import connect, init_db
from mini_siem.storage.queries import (
    count_events,
    insert_event,
    parse_since,
    recent_events,
)


def _make_event(**overrides):
    base = dict(
        timestamp=datetime(2026, 10, 11, 14, 0, 0, tzinfo=timezone.utc),
        host_name="web-01",
        source_type="auth",
        event_action="login_failed",
        event_outcome="failure",
        user_name="root",
        source_ip="203.0.113.42",
        message_raw="raw",
        severity="medium",
    )
    base.update(overrides)
    return Event(**base)


@pytest.fixture
def conn(tmp_path):
    db = tmp_path / "siem.db"
    init_db(db)
    c = connect(db)
    yield c
    c.close()


def test_insert_and_count(conn):
    assert count_events(conn) == 0
    insert_event(conn, _make_event())
    insert_event(conn, _make_event(source_ip="198.51.100.5"))
    assert count_events(conn) == 2


def test_recent_events_filters_by_ip(conn):
    insert_event(conn, _make_event(source_ip="1.1.1.1"))
    insert_event(conn, _make_event(source_ip="2.2.2.2"))
    rows = recent_events(conn, source_ip="2.2.2.2")
    assert len(rows) == 1
    assert rows[0]["source_ip"] == "2.2.2.2"


def test_recent_events_filters_by_user(conn):
    insert_event(conn, _make_event(user_name="root"))
    insert_event(conn, _make_event(user_name="deploy"))
    rows = recent_events(conn, user_name="root")
    assert len(rows) == 1
    assert rows[0]["user_name"] == "root"


def test_recent_events_filters_by_source_type(conn):
    insert_event(conn, _make_event(source_type="auth"))
    insert_event(
        conn,
        _make_event(
            source_type="nginx",
            event_action="http_request",
            http_status=404,
            http_path="/.env",
        ),
    )
    rows = recent_events(conn, source_type="nginx")
    assert len(rows) == 1
    assert rows[0]["http_status"] == 404


def test_recent_events_respects_since(conn):
    now = datetime.now(timezone.utc)
    insert_event(conn, _make_event(timestamp=now - timedelta(hours=2)))
    insert_event(conn, _make_event(timestamp=now - timedelta(minutes=5)))
    rows = recent_events(conn, since=now - timedelta(minutes=30))
    assert len(rows) == 1


def test_recent_events_orders_newest_first(conn):
    now = datetime.now(timezone.utc)
    insert_event(conn, _make_event(timestamp=now - timedelta(minutes=10), user_name="old"))
    insert_event(conn, _make_event(timestamp=now, user_name="new"))
    rows = recent_events(conn)
    assert rows[0]["user_name"] == "new"
    assert rows[1]["user_name"] == "old"


def test_parse_since_formats():
    now = datetime.now(timezone.utc)
    assert (now - parse_since("5m")).total_seconds() == pytest.approx(300, abs=2)
    assert (now - parse_since("2h")).total_seconds() == pytest.approx(7200, abs=2)
    assert (now - parse_since("1d")).total_seconds() == pytest.approx(86400, abs=2)


def test_parse_since_invalid():
    with pytest.raises(ValueError):
        parse_since("abc")
    with pytest.raises(ValueError):
        parse_since("10x")
    with pytest.raises(ValueError):
        parse_since("")
