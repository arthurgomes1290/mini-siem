"""Testes do motor de detecção: um por tipo de regra + dedupe + load_rules."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mini_siem.detection.engine import load_rules, run_rules
from mini_siem.schema import Event
from mini_siem.storage.db import connect, init_db
from mini_siem.storage.queries import count_alerts, insert_event, recent_alerts


PROJECT_RULES_DIR = Path(__file__).resolve().parent.parent / "config" / "rules"


@pytest.fixture
def conn(tmp_path):
    db = tmp_path / "siem.db"
    init_db(db)
    c = connect(db)
    yield c
    c.close()


def _ev(**kw):
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
    base.update(kw)
    return Event(**base)


THRESHOLD_RULE = {
    "id": "ssh_bruteforce",
    "name": "SSH Brute Force",
    "type": "threshold",
    "severity": "high",
    "filter": {"source_type": "auth", "event_action": "login_failed"},
    "group_by": "source_ip",
    "window_minutes": 5,
    "threshold": 5,
    "attack": {"tactic": "TA0006", "technique": "T1110"},
}


def test_threshold_fires_when_count_reaches_limit(conn):
    base = datetime(2026, 10, 11, 14, 0, 0, tzinfo=timezone.utc)
    for i in range(6):
        insert_event(conn, _ev(timestamp=base + timedelta(seconds=i)))
    results = run_rules(conn, [THRESHOLD_RULE], since=base - timedelta(minutes=10))
    assert len(results["ssh_bruteforce"]) == 1
    alert = recent_alerts(conn)[0]
    assert alert["entity"] == "203.0.113.42"
    assert alert["event_count"] == 6
    assert alert["attack_technique"] == "T1110"


def test_threshold_does_not_fire_below(conn):
    base = datetime(2026, 10, 11, 14, 0, 0, tzinfo=timezone.utc)
    for i in range(3):
        insert_event(conn, _ev(timestamp=base + timedelta(seconds=i)))
    results = run_rules(conn, [THRESHOLD_RULE], since=base - timedelta(minutes=10))
    assert results["ssh_bruteforce"] == []
    assert count_alerts(conn) == 0


def test_threshold_dedupe_is_idempotent(conn):
    base = datetime(2026, 10, 11, 14, 0, 0, tzinfo=timezone.utc)
    for i in range(6):
        insert_event(conn, _ev(timestamp=base + timedelta(seconds=i)))
    first = run_rules(conn, [THRESHOLD_RULE], since=base - timedelta(minutes=10))
    second = run_rules(conn, [THRESHOLD_RULE], since=base - timedelta(minutes=10))
    assert len(first["ssh_bruteforce"]) == 1
    assert second["ssh_bruteforce"] == []
    assert count_alerts(conn) == 1


SEQUENCE_RULE = {
    "id": "login_after_failures",
    "name": "Login After Failures",
    "type": "sequence",
    "severity": "critical",
    "precondition": {
        "filter": {"source_type": "auth", "event_action": "login_failed"},
        "group_by": "source_ip",
        "window_minutes": 10,
        "min_count": 3,
    },
    "trigger": {
        "filter": {"source_type": "auth", "event_action": "login_success"},
        "group_by": "source_ip",
    },
    "attack": {"tactic": "TA0001", "technique": "T1110.001"},
}


def test_sequence_fires_on_success_after_many_failures(conn):
    base = datetime(2026, 10, 11, 14, 0, 0, tzinfo=timezone.utc)
    for i in range(4):
        insert_event(conn, _ev(timestamp=base + timedelta(minutes=i), source_ip="1.2.3.4"))
    insert_event(
        conn,
        _ev(
            timestamp=base + timedelta(minutes=5),
            source_ip="1.2.3.4",
            event_action="login_success",
            event_outcome="success",
            user_name="root",
            severity="low",
        ),
    )
    results = run_rules(conn, [SEQUENCE_RULE], since=base - timedelta(hours=1))
    assert len(results["login_after_failures"]) == 1
    alert = recent_alerts(conn)[0]
    assert alert["entity"] == "1.2.3.4"


def test_sequence_does_not_fire_without_enough_failures(conn):
    base = datetime(2026, 10, 11, 14, 0, 0, tzinfo=timezone.utc)
    insert_event(conn, _ev(timestamp=base, source_ip="1.2.3.4"))
    insert_event(
        conn,
        _ev(
            timestamp=base + timedelta(minutes=1),
            source_ip="1.2.3.4",
            event_action="login_success",
            event_outcome="success",
        ),
    )
    results = run_rules(conn, [SEQUENCE_RULE], since=base - timedelta(hours=1))
    assert results["login_after_failures"] == []


WEB_SCAN_RULE = {
    "id": "web_dir_scan",
    "name": "Web Dir Scan",
    "type": "threshold",
    "severity": "medium",
    "filter": {"source_type": "nginx", "http_status": 404},
    "group_by": "source_ip",
    "window_minutes": 2,
    "threshold": 3,
    "attack": {"tactic": "TA0043", "technique": "T1595.003"},
}


def test_web_dir_scan_threshold(conn):
    base = datetime(2026, 10, 11, 14, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        insert_event(
            conn,
            _ev(
                timestamp=base + timedelta(seconds=i * 10),
                source_type="nginx",
                event_action="http_request",
                event_outcome="failure",
                user_name=None,
                source_ip="9.9.9.9",
                http_status=404,
                http_path=f"/scan{i}",
            ),
        )
    results = run_rules(conn, [WEB_SCAN_RULE], since=base - timedelta(minutes=10))
    assert len(results["web_dir_scan"]) == 1
    alert = recent_alerts(conn)[0]
    assert alert["entity"] == "9.9.9.9"
    assert alert["attack_technique"] == "T1595.003"


OFF_HOURS_RULE = {
    "id": "off_hours_login",
    "name": "Off Hours Login",
    "type": "time_of_day",
    "severity": "medium",
    "filter": {"source_type": "auth", "event_action": "login_success"},
    "group_by": "user_name",
    "allowed_hours": [8, 18],
    "timezone": "UTC",
    "attack": {"tactic": "TA0001", "technique": "T1078"},
}


def test_time_of_day_fires_outside_window(conn):
    # 03:00 UTC está fora da janela [8, 18)
    ts = datetime(2026, 10, 11, 3, 0, 0, tzinfo=timezone.utc)
    insert_event(
        conn,
        _ev(
            timestamp=ts,
            event_action="login_success",
            event_outcome="success",
            user_name="ubuntu",
            severity="low",
        ),
    )
    results = run_rules(conn, [OFF_HOURS_RULE], since=ts - timedelta(days=1))
    assert len(results["off_hours_login"]) == 1


def test_time_of_day_silent_inside_window(conn):
    ts = datetime(2026, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    insert_event(
        conn,
        _ev(
            timestamp=ts,
            event_action="login_success",
            event_outcome="success",
            user_name="ubuntu",
            severity="low",
        ),
    )
    results = run_rules(conn, [OFF_HOURS_RULE], since=ts - timedelta(days=1))
    assert results["off_hours_login"] == []


RARITY_RULE = {
    "id": "unusual_sudo",
    "name": "Unusual Sudo",
    "type": "rarity",
    "severity": "high",
    "filter": {"source_type": "auth", "event_action": "sudo"},
    "group_by": "user_name",
    "baseline_days": 7,
    "max_historical_count": 0,
    "attack": {"tactic": "TA0004", "technique": "T1548.003"},
}


def test_rarity_fires_for_first_time_sudo(conn):
    ts = datetime(2026, 10, 11, 14, 0, 0, tzinfo=timezone.utc)
    insert_event(
        conn,
        _ev(
            timestamp=ts,
            event_action="sudo",
            event_outcome="success",
            user_name="eve",
            source_ip=None,
        ),
    )
    results = run_rules(conn, [RARITY_RULE], since=ts - timedelta(hours=1))
    assert len(results["unusual_sudo"]) == 1
    alert = recent_alerts(conn)[0]
    assert alert["entity"] == "eve"


def test_rarity_silent_for_known_user(conn):
    base = datetime(2026, 10, 11, 14, 0, 0, tzinfo=timezone.utc)
    # histórico: usuário "ops" já usou sudo há 2 dias
    insert_event(
        conn,
        _ev(
            timestamp=base - timedelta(days=2),
            event_action="sudo",
            user_name="ops",
            source_ip=None,
        ),
    )
    # novo uso agora
    insert_event(
        conn,
        _ev(
            timestamp=base,
            event_action="sudo",
            user_name="ops",
            source_ip=None,
        ),
    )
    results = run_rules(conn, [RARITY_RULE], since=base - timedelta(hours=1))
    assert results["unusual_sudo"] == []


def test_load_rules_from_project_config():
    rules = load_rules(PROJECT_RULES_DIR)
    ids = {r["id"] for r in rules}
    assert ids == {
        "ssh_bruteforce",
        "login_after_failures",
        "web_dir_scan",
        "off_hours_login",
        "unusual_sudo",
    }
    for rule in rules:
        assert "attack" in rule
        assert rule["attack"].get("technique")


def test_load_rules_rejects_unknown_type(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "id: foo\nname: Foo\ntype: nonsense\nseverity: high\n"
    )
    with pytest.raises(ValueError):
        load_rules(tmp_path)


def test_filter_rejects_arbitrary_sql_fields(conn):
    base = datetime(2026, 10, 11, 14, 0, 0, tzinfo=timezone.utc)
    insert_event(conn, _ev(timestamp=base))
    bad_rule = {
        **THRESHOLD_RULE,
        "filter": {"source_type; DROP TABLE events; --": "x"},
    }
    results = run_rules(conn, [bad_rule], since=base - timedelta(minutes=10))
    assert results["ssh_bruteforce"] == []
    # eventos continuam intactos
    rows = list(conn.execute("SELECT COUNT(*) FROM events"))
    assert rows[0][0] == 1
