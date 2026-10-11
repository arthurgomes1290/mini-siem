"""Testes do servidor syslog UDP."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from mini_siem.collector.syslog_server import _strip_pri, serve_udp


AUTH_LINE_FAIL = (
    "Oct 11 14:29:58 web-01 sshd[1234]: Failed password for root "
    "from 203.0.113.42 port 55110 ssh2"
)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_until(predicate, timeout=2.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def test_strip_pri_removes_prefix():
    assert _strip_pri("<34>message") == "message"
    assert _strip_pri("<191>deep") == "deep"


def test_strip_pri_leaves_malformed_alone():
    assert _strip_pri("message") == "message"
    assert _strip_pri("<notanumber>x") == "<notanumber>x"
    assert _strip_pri("<") == "<"


def test_serve_udp_receives_and_parses():
    port = _free_port()
    sink: list = []
    stop = threading.Event()
    server = threading.Thread(
        target=serve_udp,
        args=("127.0.0.1", port, "auth", sink.append, stop),
        daemon=True,
    )
    server.start()
    time.sleep(0.1)  # dá tempo para o bind

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = f"<34>{AUTH_LINE_FAIL}".encode()
        client.sendto(payload, ("127.0.0.1", port))
        client.close()

        assert _wait_until(lambda: len(sink) >= 1)
        assert sink[0].event_action == "login_failed"
        assert sink[0].source_ip == "203.0.113.42"
    finally:
        stop.set()
        server.join(timeout=2)


def test_serve_udp_ignores_noise():
    port = _free_port()
    sink: list = []
    stop = threading.Event()
    server = threading.Thread(
        target=serve_udp,
        args=("127.0.0.1", port, "auth", sink.append, stop),
        daemon=True,
    )
    server.start()
    time.sleep(0.1)

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.sendto(b"nao e syslog", ("127.0.0.1", port))
        time.sleep(0.3)
        assert sink == []
    finally:
        stop.set()
        server.join(timeout=2)
