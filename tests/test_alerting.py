"""Testes do módulo alerting + migração schema v2."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from mini_siem.alerting import dispatch_pending_alerts
from mini_siem.alerting.formatter import build_payload, detect_provider, format_text
from mini_siem.storage.db import SCHEMA_VERSION, connect, init_db
from mini_siem.storage.queries import insert_alert


class _Response:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _MockClient:
    """Dublê do httpx.Client — grava posts, devolve status configurado."""

    def __init__(self, status_code: int = 204, raise_exc: Exception | None = None):
        self.status_code = status_code
        self.raise_exc = raise_exc
        self.calls: list[dict] = []

    def post(self, url: str, json=None, timeout=None):
        self.calls.append({"url": url, "json": json, "timeout": timeout})
        if self.raise_exc:
            raise self.raise_exc
        return _Response(self.status_code)


@pytest.fixture
def conn(tmp_path):
    db = tmp_path / "siem.db"
    init_db(db)
    c = connect(db)
    yield c
    c.close()


def _ins(conn, n: int = 1) -> int | None:
    return insert_alert(
        conn,
        rule_id="ssh_bruteforce",
        rule_name="SSH Brute Force",
        severity="high",
        entity=f"203.0.113.{n}",
        event_count=6,
        first_seen=datetime(2026, 10, 11, 14, 29, 58, tzinfo=timezone.utc),
        last_seen=datetime(2026, 10, 11, 14, 30, 4, tzinfo=timezone.utc),
        dedupe_key=f"ssh_bruteforce:203.0.113.{n}:bucket",
        attack_tactic="TA0006",
        attack_technique="T1110",
    )


# ---------- formatter ----------


def test_detect_provider():
    assert detect_provider("https://discord.com/api/webhooks/x/y") == "discord"
    assert detect_provider("https://discordapp.com/api/webhooks/x/y") == "discord"
    assert detect_provider("https://hooks.slack.com/services/A/B/C") == "slack"
    assert detect_provider("https://example.com/hook") == "generic"
    assert detect_provider("") == "generic"


def test_format_text_has_essentials():
    alert = {
        "severity": "high",
        "rule_name": "SSH BF",
        "entity": "1.2.3.4",
        "event_count": 5,
        "attack_tactic": "TA0006",
        "attack_technique": "T1110",
        "first_seen": "2026-10-11T14:29:58+00:00",
        "last_seen": "2026-10-11T14:30:04+00:00",
    }
    text = format_text(alert)
    assert "HIGH" in text
    assert "1.2.3.4" in text
    assert "T1110" in text
    assert "🚨" in text  # emoji de high


def test_build_payload_discord_vs_slack():
    alert = {
        "severity": "high",
        "rule_name": "X",
        "entity": "Y",
        "event_count": 1,
        "attack_tactic": "",
        "attack_technique": "",
        "first_seen": "a",
        "last_seen": "b",
    }
    d = build_payload("discord", alert)
    s = build_payload("slack", alert)
    g = build_payload("generic", alert)
    assert d["username"] == "mini-siem"
    assert "content" in d
    assert "text" in s and "text" not in d
    assert "alert" in g and g["alert"]["entity"] == "Y"


# ---------- dispatcher ----------


def test_dispatch_sends_pending_and_marks_notified(conn):
    _ins(conn, 1)
    _ins(conn, 2)
    client = _MockClient(status_code=204)

    sent = dispatch_pending_alerts(
        conn,
        "https://discord.com/api/webhooks/x/y",
        http_client=client,
    )
    assert sent == 2
    assert len(client.calls) == 2
    notified = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE notified_at IS NOT NULL"
    ).fetchone()[0]
    assert notified == 2


def test_dispatch_skips_already_notified(conn):
    _ins(conn, 1)
    conn.execute("UPDATE alerts SET notified_at = '2026-10-11' WHERE id = 1")
    client = _MockClient()

    sent = dispatch_pending_alerts(
        conn, "https://discord.com/x", http_client=client
    )
    assert sent == 0
    assert client.calls == []


def test_dispatch_keeps_pending_on_http_error(conn):
    _ins(conn, 1)
    client = _MockClient(status_code=500)

    sent = dispatch_pending_alerts(
        conn, "https://discord.com/x", http_client=client
    )
    assert sent == 0
    notified = conn.execute(
        "SELECT notified_at FROM alerts WHERE id = 1"
    ).fetchone()[0]
    assert notified is None


def test_dispatch_keeps_pending_on_exception(conn):
    _ins(conn, 1)
    client = _MockClient(raise_exc=RuntimeError("boom"))

    sent = dispatch_pending_alerts(
        conn, "https://discord.com/x", http_client=client
    )
    assert sent == 0


def test_dispatch_requires_url(conn):
    with pytest.raises(ValueError):
        dispatch_pending_alerts(conn, "")


def test_dispatch_fifo_order(conn):
    _ins(conn, 1)
    _ins(conn, 2)
    _ins(conn, 3)
    client = _MockClient()

    dispatch_pending_alerts(
        conn, "https://discord.com/x", http_client=client
    )
    assert "203.0.113.1" in client.calls[0]["json"]["content"]
    assert "203.0.113.2" in client.calls[1]["json"]["content"]
    assert "203.0.113.3" in client.calls[2]["json"]["content"]


def test_dispatch_respects_limit(conn):
    for i in range(1, 6):
        _ins(conn, i)
    client = _MockClient()
    sent = dispatch_pending_alerts(
        conn, "https://discord.com/x", http_client=client, limit=2
    )
    assert sent == 2
    assert len(client.calls) == 2


def test_retry_after_failure_eventually_succeeds(conn):
    _ins(conn, 1)
    fail_client = _MockClient(status_code=500)
    dispatch_pending_alerts(conn, "https://discord.com/x", http_client=fail_client)
    ok_client = _MockClient(status_code=204)
    sent = dispatch_pending_alerts(conn, "https://discord.com/x", http_client=ok_client)
    assert sent == 1


# ---------- migração ----------


def test_schema_v2_has_notified_at(tmp_path):
    db = tmp_path / "siem.db"
    init_db(db)
    c = connect(db)
    try:
        cols = [r[1] for r in c.execute("PRAGMA table_info(alerts)")]
        assert "notified_at" in cols
        version = c.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()[0]
        assert version == SCHEMA_VERSION
    finally:
        c.close()


def test_migration_adds_column_on_legacy_db(tmp_path):
    """Simula um DB antigo (v1 sem notified_at) e garante que init_db migra."""
    db = tmp_path / "legacy.db"
    raw = sqlite3.connect(str(db))
    raw.executescript(
        """
        CREATE TABLE schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        INSERT INTO schema_version(version) VALUES (1);
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            entity TEXT NOT NULL,
            attack_tactic TEXT,
            attack_technique TEXT,
            event_count INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            dedupe_key TEXT NOT NULL UNIQUE,
            details_json TEXT
        );
        INSERT INTO alerts
          (rule_id, rule_name, severity, entity, event_count,
           first_seen, last_seen, dedupe_key)
        VALUES
          ('r', 'R', 'high', 'e', 1, '2026-01-01', '2026-01-01', 'k');
        """
    )
    raw.close()

    init_db(db)

    c = connect(db)
    try:
        cols = [r[1] for r in c.execute("PRAGMA table_info(alerts)")]
        assert "notified_at" in cols
        rows = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        assert rows == 1
        version = c.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()[0]
        assert version == SCHEMA_VERSION
    finally:
        c.close()
