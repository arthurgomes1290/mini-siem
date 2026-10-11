"""Tail de arquivo com tratamento de rotação (``logrotate``).

Comportamento:

* Lê o arquivo linha a linha. Linhas parciais são buferizadas até o ``\\n``.
* Se o inode do caminho mudar (logrotate renomeou o atual e criou um
  novo), reabre do início do novo arquivo.
* Se o arquivo for removido ou ainda não existir, espera educadamente.
* ``start_from_end=True`` posiciona no fim ao abrir (modo "tail -F"
  realista). ``False`` processa tudo + novo (ótimo para demo e backfill).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from ..parser import parse_line
from ..schema import Event


OnEvent = Callable[[Event], None]


def tail(
    path: str | Path,
    source_type: str,
    on_event: OnEvent,
    stop_event: threading.Event,
    *,
    start_from_end: bool = False,
    poll_interval: float = 0.3,
) -> None:
    path = Path(path)
    fh = None
    inode: Optional[int] = None
    buf = ""

    def _open() -> None:
        nonlocal fh, inode
        if fh is not None:
            fh.close()
        fh = open(path, "r", errors="replace")
        inode = os.fstat(fh.fileno()).st_ino
        if start_from_end:
            fh.seek(0, os.SEEK_END)

    try:
        while not stop_event.is_set():
            if fh is None:
                if not path.exists():
                    if stop_event.wait(poll_interval):
                        break
                    continue
                _open()

            assert fh is not None
            chunk = fh.read()
            if chunk:
                buf += chunk
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    event = parse_line(source_type, line)
                    if event is not None:
                        try:
                            on_event(event)
                        except Exception as exc:  # pragma: no cover
                            print(f"[warn] on_event falhou: {exc}", file=sys.stderr)
                continue

            # Sem dados novos: verifica rotação.
            try:
                current_ino = os.stat(path).st_ino
                if current_ino != inode:
                    _open()
                    continue
            except FileNotFoundError:
                fh.close()
                fh = None
                continue

            if stop_event.wait(poll_interval):
                break
    finally:
        if fh is not None:
            fh.close()
