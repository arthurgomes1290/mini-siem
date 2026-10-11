"""Orquestrador producer-consumer dos coletores.

Vários coletores (tail de arquivos, servidor syslog) rodam em threads
separadas e empurram ``Event`` em uma única ``queue.Queue``. Uma thread
*writer* dedicada consome a fila e grava no SQLite.

Por quê não escrever direto do coletor?

* SQLite não gosta de múltiplos writers simultâneos. Uma thread escritora
  única elimina a disputa pelo write-lock.
* O backpressure é natural: se o SQLite ficar lento, a fila enche; se
  encher demais, `put()` bloqueia o coletor. Melhor do que perder eventos
  silenciosamente.
* Testes e substituição ficam fáceis: dá para trocar o writer por qualquer
  callable (ex.: um sink em memória nos testes).
"""

from __future__ import annotations

import queue
import sqlite3
import sys
import threading
import time
from typing import Callable, Optional

from ..schema import Event
from ..storage.queries import insert_event


OnEvent = Callable[[Event], None]
CollectorTarget = Callable[[OnEvent, threading.Event], None]


class CollectorRunner:
    def __init__(self, conn: sqlite3.Connection, maxsize: int = 10_000) -> None:
        self.conn = conn
        self.queue: "queue.Queue[Event]" = queue.Queue(maxsize=maxsize)
        self.stop_event = threading.Event()
        self._collectors: list[tuple[CollectorTarget, str]] = []
        self._collector_threads: list[threading.Thread] = []
        self._writer_thread: Optional[threading.Thread] = None
        self.events_written = 0

    def _on_event(self, event: Event) -> None:
        self.queue.put(event)

    def _writer_loop(self) -> None:
        while not self.stop_event.is_set() or not self.queue.empty():
            try:
                event = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                insert_event(self.conn, event)
                self.events_written += 1
            except Exception as exc:  # pragma: no cover — defensivo
                print(f"[warn] write falhou: {exc}", file=sys.stderr)
            finally:
                self.queue.task_done()

    def add_collector(self, target: CollectorTarget, name: str) -> None:
        self._collectors.append((target, name))

    def start(self) -> None:
        self._writer_thread = threading.Thread(
            target=self._writer_loop, name="writer", daemon=True
        )
        self._writer_thread.start()
        for target, name in self._collectors:
            t = threading.Thread(
                target=target,
                args=(self._on_event, self.stop_event),
                name=name,
                daemon=True,
            )
            self._collector_threads.append(t)
            t.start()

    def stop(self, timeout: float = 2.0) -> None:
        self.stop_event.set()
        for t in self._collector_threads:
            t.join(timeout=timeout)
        if self._writer_thread is not None:
            self._writer_thread.join(timeout=timeout)

    def wait(self, poll: float = 0.5) -> None:
        """Bloqueia a thread principal até stop() ser chamado."""
        while not self.stop_event.is_set():
            time.sleep(poll)
