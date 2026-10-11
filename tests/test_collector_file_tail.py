"""Testes do coletor de arquivo (tail -F com rotação)."""

from __future__ import annotations

import os
import threading
import time

import pytest

from mini_siem.collector.file_tail import tail


AUTH_LINE_FAIL = (
    "Oct 11 14:29:58 web-01 sshd[1234]: Failed password for root "
    "from 203.0.113.42 port 55110 ssh2\n"
)
AUTH_LINE_OK = (
    "Oct 11 14:30:02 web-01 sshd[1235]: Accepted password for ubuntu "
    "from 10.0.0.5 port 54321 ssh2\n"
)


def _run_tail_in_thread(path, source, sink, stop, **kwargs):
    t = threading.Thread(
        target=tail,
        args=(path, source, sink.append, stop),
        kwargs=kwargs,
        daemon=True,
    )
    t.start()
    return t


def _wait_until(predicate, timeout=2.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def test_tail_reads_existing_lines(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(AUTH_LINE_FAIL + AUTH_LINE_OK)
    sink: list = []
    stop = threading.Event()
    t = _run_tail_in_thread(log, "auth", sink, stop)
    try:
        assert _wait_until(lambda: len(sink) >= 2), f"só vi {len(sink)} eventos"
        assert sink[0].event_action == "login_failed"
        assert sink[1].event_action == "login_success"
    finally:
        stop.set()
        t.join(timeout=1)


def test_tail_follows_new_lines(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    sink: list = []
    stop = threading.Event()
    t = _run_tail_in_thread(log, "auth", sink, stop)
    try:
        time.sleep(0.1)
        with open(log, "a") as fh:
            fh.write(AUTH_LINE_FAIL)
        assert _wait_until(lambda: len(sink) >= 1)
        assert sink[0].source_ip == "203.0.113.42"
    finally:
        stop.set()
        t.join(timeout=1)


def test_tail_handles_rotation(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(AUTH_LINE_FAIL)
    sink: list = []
    stop = threading.Event()
    t = _run_tail_in_thread(log, "auth", sink, stop)
    try:
        assert _wait_until(lambda: len(sink) >= 1)
        # logrotate: renomeia e cria arquivo novo com mesmo nome.
        rotated = tmp_path / "auth.log.1"
        os.rename(log, rotated)
        log.write_text(AUTH_LINE_OK)
        assert _wait_until(lambda: len(sink) >= 2, timeout=3.0)
        assert sink[-1].event_action == "login_success"
    finally:
        stop.set()
        t.join(timeout=1)


def test_tail_from_end_skips_backfill(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(AUTH_LINE_FAIL)  # pré-existente
    sink: list = []
    stop = threading.Event()
    t = _run_tail_in_thread(log, "auth", sink, stop, start_from_end=True)
    try:
        time.sleep(0.3)
        assert sink == []
        with open(log, "a") as fh:
            fh.write(AUTH_LINE_OK)
        assert _wait_until(lambda: len(sink) >= 1)
        assert sink[0].event_action == "login_success"
    finally:
        stop.set()
        t.join(timeout=1)


def test_tail_waits_for_file_to_appear(tmp_path):
    log = tmp_path / "will_appear.log"
    sink: list = []
    stop = threading.Event()
    t = _run_tail_in_thread(log, "auth", sink, stop)
    try:
        time.sleep(0.2)
        log.write_text(AUTH_LINE_FAIL)
        assert _wait_until(lambda: len(sink) >= 1, timeout=2.0)
    finally:
        stop.set()
        t.join(timeout=1)
