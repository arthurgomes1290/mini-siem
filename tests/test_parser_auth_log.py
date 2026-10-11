"""Testes do parser de auth.log."""

from __future__ import annotations

from pathlib import Path

from mini_siem.parser import parse_file
from mini_siem.parser.auth_log import parse_line


FIXTURES = Path(__file__).parent / "fixtures"


def test_failed_password_regular_user():
    line = (
        "Oct 11 14:29:58 web-01 sshd[1234]: Failed password for root "
        "from 203.0.113.42 port 55110 ssh2"
    )
    event = parse_line(line)
    assert event is not None
    assert event.event_action == "login_failed"
    assert event.event_outcome == "failure"
    assert event.user_name == "root"
    assert event.source_ip == "203.0.113.42"
    assert event.host_name == "web-01"
    assert event.severity == "medium"
    assert event.source_type == "auth"


def test_failed_password_invalid_user_strips_prefix():
    line = (
        "Oct 11 14:30:00 web-01 sshd[1234]: Failed password for invalid user "
        "admin from 198.51.100.5 port 44220 ssh2"
    )
    event = parse_line(line)
    assert event is not None
    assert event.user_name == "admin"
    assert event.event_action == "login_failed"


def test_accepted_password():
    line = (
        "Oct 11 14:30:02 web-01 sshd[1235]: Accepted password for ubuntu "
        "from 10.0.0.5 port 54321 ssh2"
    )
    event = parse_line(line)
    assert event is not None
    assert event.event_action == "login_success"
    assert event.event_outcome == "success"
    assert event.user_name == "ubuntu"
    assert event.severity == "low"


def test_accepted_publickey():
    line = (
        "Oct 11 14:30:04 web-01 sshd[1240]: Accepted publickey for deploy "
        "from 10.0.0.9 port 54400 ssh2"
    )
    event = parse_line(line)
    assert event is not None
    assert event.event_action == "login_success"
    assert event.user_name == "deploy"


def test_sudo_invocation():
    line = (
        "Oct 11 14:30:05 web-01 sudo:  ubuntu : TTY=pts/0 ; PWD=/home/ubuntu "
        "; USER=root ; COMMAND=/bin/ls /root"
    )
    event = parse_line(line)
    assert event is not None
    assert event.event_action == "sudo"
    assert event.user_name == "ubuntu"
    assert event.severity == "medium"


def test_sudo_pam_session_is_ignored():
    line = (
        "Oct 11 14:30:12 web-01 sudo: pam_unix(sudo:session): session opened "
        "for user root(uid=0) by ubuntu(uid=1000)"
    )
    assert parse_line(line) is None


def test_cron_session_is_ignored():
    line = (
        "Oct 11 14:30:11 web-01 CRON[1240]: pam_unix(cron:session): "
        "session opened for user root(uid=0) by (uid=0)"
    )
    assert parse_line(line) is None


def test_preauth_connection_closed_is_ignored():
    line = (
        "Oct 11 14:30:10 web-01 sshd[1236]: Connection closed by "
        "192.0.2.33 port 22 [preauth]"
    )
    assert parse_line(line) is None


def test_malformed_line_returns_none():
    assert parse_line("isto não é uma linha de syslog") is None
    assert parse_line("") is None


def test_reference_year_is_applied():
    line = (
        "Oct 11 14:29:58 web-01 sshd[1234]: Failed password for root "
        "from 203.0.113.42 port 55110 ssh2"
    )
    event = parse_line(line, reference_year=2022)
    assert event is not None
    assert event.timestamp.year == 2022


def test_parse_file_fixture_covers_all_actions():
    events = list(parse_file("auth", FIXTURES / "auth_sample.log"))
    actions = [e.event_action for e in events]
    assert "login_failed" in actions
    assert "login_success" in actions
    assert "sudo" in actions
    assert len(events) == 6
