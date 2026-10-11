"""Registry e iterador de arquivos para os parsers.

Cada parser expõe ``parse_line(line) -> Event | None``. Novas fontes se
adicionam registrando aqui — o resto do sistema (collector, CLI) usa só
``parse_line(source_type, line)`` e ``parse_file(source_type, path)``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterator, Optional

from ..schema import Event
from . import auth_log, nginx


_Parser = Callable[[str], Optional[Event]]

PARSERS: dict[str, _Parser] = {
    "auth": auth_log.parse_line,
    "nginx": nginx.parse_line,
}


def parse_line(source_type: str, line: str) -> Optional[Event]:
    try:
        parser = PARSERS[source_type]
    except KeyError as exc:
        raise ValueError(
            f"source desconhecida: {source_type!r}. Use um de {sorted(PARSERS)}"
        ) from exc
    return parser(line)


def parse_file(source_type: str, path: str | Path) -> Iterator[Event]:
    with open(path, "r", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            event = parse_line(source_type, line)
            if event is not None:
                yield event
