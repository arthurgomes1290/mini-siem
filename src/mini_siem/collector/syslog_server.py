"""Servidor syslog UDP mínimo (RFC3164).

RFC3164 formata mensagens como ``<PRI>MSG`` onde PRI é um inteiro entre
``<0>`` e ``<191>``. Fazemos *strip* do PRI e passamos o resto para o
parser escolhido — tipicamente o parser ``auth`` quando um rsyslog está
reencaminhando ``/var/log/auth.log`` por rede.

Decisões:

* **UDP only** no MVP. TCP syslog existe (RFC5425/6587) mas adiciona
  framing e complexidade. Fácil de evoluir depois.
* **Timeout curto no socket** para que o loop verifique ``stop_event``
  com frequência e termine limpo.
"""

from __future__ import annotations

import socket
import sys
import threading
from typing import Callable

from ..parser import parse_line
from ..schema import Event


OnEvent = Callable[[Event], None]


def _strip_pri(text: str) -> str:
    if text.startswith("<"):
        end = text.find(">")
        if end != -1 and text[1:end].isdigit():
            return text[end + 1 :]
    return text


def serve_udp(
    host: str,
    port: int,
    source_type: str,
    on_event: OnEvent,
    stop_event: threading.Event,
    *,
    bufsize: int = 65535,
    socket_timeout: float = 0.3,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(socket_timeout)

    try:
        while not stop_event.is_set():
            try:
                data, _addr = sock.recvfrom(bufsize)
            except socket.timeout:
                continue
            except OSError:
                break

            text = data.decode("utf-8", errors="replace")
            text = _strip_pri(text)

            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                event = parse_line(source_type, line)
                if event is None:
                    continue
                try:
                    on_event(event)
                except Exception as exc:  # pragma: no cover
                    print(f"[warn] on_event falhou: {exc}", file=sys.stderr)
    finally:
        sock.close()
