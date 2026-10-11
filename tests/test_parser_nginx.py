"""Testes do parser do Nginx (combined log)."""

from __future__ import annotations

from pathlib import Path

from mini_siem.parser import parse_file
from mini_siem.parser.nginx import parse_line


FIXTURES = Path(__file__).parent / "fixtures"


def test_success_200_is_low():
    line = (
        '192.0.2.1 - - [11/Oct/2026:14:30:00 +0000] '
        '"GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"'
    )
    event = parse_line(line)
    assert event is not None
    assert event.source_ip == "192.0.2.1"
    assert event.http_status == 200
    assert event.http_path == "/"
    assert event.event_outcome == "success"
    assert event.severity == "low"
    assert event.source_type == "nginx"


def test_404_is_medium_failure():
    line = (
        '198.51.100.4 - - [11/Oct/2026:14:30:01 +0000] '
        '"GET /.env HTTP/1.1" 404 162 "-" "curl/7.68"'
    )
    event = parse_line(line)
    assert event is not None
    assert event.http_status == 404
    assert event.event_outcome == "failure"
    assert event.severity == "medium"
    assert event.http_path == "/.env"


def test_500_is_high_failure():
    line = (
        '10.0.0.10 - - [11/Oct/2026:14:30:07 +0000] '
        '"GET /crash HTTP/1.1" 500 300 "-" "python-requests/2.31"'
    )
    event = parse_line(line)
    assert event is not None
    assert event.http_status == 500
    assert event.severity == "high"
    assert event.event_outcome == "failure"


def test_timestamp_is_timezone_aware():
    line = (
        '192.0.2.1 - - [11/Oct/2026:14:30:00 +0000] '
        '"GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"'
    )
    event = parse_line(line)
    assert event is not None
    assert event.timestamp.tzinfo is not None


def test_custom_host_name():
    line = (
        '192.0.2.1 - - [11/Oct/2026:14:30:00 +0000] '
        '"GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"'
    )
    event = parse_line(line, host_name="edge-01")
    assert event is not None
    assert event.host_name == "edge-01"


def test_malformed_returns_none():
    assert parse_line("isto não é um log nginx") is None
    assert parse_line("") is None


def test_parse_file_fixture_shapes():
    events = list(parse_file("nginx", FIXTURES / "nginx_sample.log"))
    assert len(events) == 7
    statuses = {e.http_status for e in events}
    assert statuses == {200, 401, 404, 500}
    severities = {e.severity for e in events}
    assert {"low", "medium", "high"}.issubset(severities)
