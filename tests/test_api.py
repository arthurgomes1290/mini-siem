"""Testes da API FastAPI com TestClient."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from mini_siem.schema import Event
from mini_siem.storage.db import connect, init_db
from mini_siem.storage.queries import insert_alert, insert_event


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = tmp_path / "siem.db"
    monkeypatch.setenv("SIEM_DB_PATH", str(db))
    init_db(db)
    conn = connect(db)
    _seed(conn)
    conn.close()

    # importa depois do monkeypatch pra lifespan pegar o path certo
    from mini_siem.api.app import app

    with TestClient(app) as c:
        yield c


def _seed(conn):
    now = datetime.now(timezone.utc)
    insert_event(conn, Event(
        timestamp=now - timedelta(minutes=5),
        host_name="web-01", source_type="auth",
        event_action="login_failed", event_outcome="failure",
        user_name="root", source_ip="203.0.113.42",
        message_raw="Failed password for root from 203.0.113.42", severity="medium",
    ))
    insert_event(conn, Event(
        timestamp=now - timedelta(minutes=4),
        host_name="web-01", source_type="auth",
        event_action="login_failed", event_outcome="failure",
        user_name="root", source_ip="203.0.113.42",
        message_raw="Failed password for root from 203.0.113.42 (2)", severity="medium",
    ))
    insert_event(conn, Event(
        timestamp=now - timedelta(minutes=3),
        host_name="web-01", source_type="nginx",
        event_action="http_request", event_outcome="failure",
        source_ip="198.51.100.4", http_status=404, http_path="/.env",
        message_raw="GET /.env 404", severity="medium",
    ))
    insert_alert(
        conn,
        rule_id="ssh_bruteforce",
        rule_name="SSH Brute Force",
        severity="high",
        entity="203.0.113.42",
        event_count=5,
        first_seen=now - timedelta(minutes=5),
        last_seen=now - timedelta(minutes=4),
        dedupe_key="ssh_bruteforce:203.0.113.42:bucket",
        attack_tactic="TA0006",
        attack_technique="T1110",
    )
    insert_alert(
        conn,
        rule_id="unusual_sudo",
        rule_name="Sudo by Unusual User",
        severity="critical",
        entity="eve",
        event_count=1,
        first_seen=now - timedelta(minutes=1),
        last_seen=now - timedelta(minutes=1),
        dedupe_key="unusual_sudo:eve:today",
        attack_tactic="TA0004",
        attack_technique="T1548.003",
    )


# ---------- JSON API ----------


def test_api_events_returns_data(client):
    r = client.get("/api/events?since=1h")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 3
    assert len(body["events"]) == 3


def test_api_events_filter_by_ip(client):
    r = client.get("/api/events?ip=203.0.113.42&since=1h")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    assert all(e["source_ip"] == "203.0.113.42" for e in body["events"])


def test_api_events_filter_by_source(client):
    r = client.get("/api/events?source=nginx&since=1h")
    body = r.json()
    assert body["count"] == 1
    assert body["events"][0]["http_status"] == 404


def test_api_events_invalid_since_returns_400(client):
    r = client.get("/api/events?since=lixo")
    assert r.status_code == 400


def test_api_alerts_returns_data(client):
    r = client.get("/api/alerts?since=1d")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2


def test_api_alerts_filter_by_severity(client):
    r = client.get("/api/alerts?severity=critical&since=1d")
    body = r.json()
    assert body["count"] == 1
    assert body["alerts"][0]["entity"] == "eve"


def test_api_alerts_filter_by_rule(client):
    r = client.get("/api/alerts?rule=ssh_bruteforce&since=1d")
    body = r.json()
    assert body["count"] == 1
    assert body["alerts"][0]["rule_id"] == "ssh_bruteforce"


def test_api_search_finds_text(client):
    r = client.get("/api/search?q=.env")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    assert any(".env" in e["message_raw"] for e in body["events"])


def test_api_search_requires_q(client):
    r = client.get("/api/search")
    assert r.status_code == 422  # FastAPI validation


def test_api_stats_shape(client):
    r = client.get("/api/stats")
    assert r.status_code == 200
    body = r.json()
    for key in (
        "event_count_24h", "alert_count_24h", "critical_count_24h",
        "top_ips", "severity_counts", "timeline",
    ):
        assert key in body
    assert body["event_count_24h"] == 3
    assert body["alert_count_24h"] == 2
    assert body["critical_count_24h"] == 1
    # top IPs
    ips = {row["ip"] for row in body["top_ips"]}
    assert "203.0.113.42" in ips


# ---------- HTML ----------


def test_home_renders_dashboard(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    html = r.text
    assert "mini-siem" in html
    assert "203.0.113.42" in html or "Top IPs" in html


def test_partial_alerts_renders(client):
    r = client.get("/partials/alerts")
    assert r.status_code == 200
    assert "severity" in r.text or "ssh_bruteforce" in r.text


def test_partial_events_renders(client):
    r = client.get("/partials/events")
    assert r.status_code == 200
    assert "203.0.113.42" in r.text or "web-01" in r.text
