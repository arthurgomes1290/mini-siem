"""Parser para /var/log/auth.log (Debian/Ubuntu).

Reconhece três ações relevantes para o SIEM:

- ``login_failed``   — "Failed password for ..." (SSH)
- ``login_success``  — "Accepted (password|publickey|...) for ..." (SSH)
- ``sudo``           — invocações de ``sudo`` com TTY/COMMAND

Linhas irrelevantes (CRON, pam_unix de sessão, keep-alives) ou malformadas
retornam ``None``. Parsers nunca lançam exceção para dado inválido —
apenas sinalizam "não é meu assunto". Isso simplifica o collector.

Limitação conhecida: o formato syslog tradicional não traz o ano. Usamos
o ano corrente (ou ``reference_year`` explícito). Para logs cruzando a
virada do ano isso é aproximação; sistemas modernos usam journald/RFC5424
com timestamp completo (migração futura).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from ..schema import Event


_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<rest>.*)$"
)

_SSH_FAILED = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\S+) port \d+ ssh2$"
)

_SSH_ACCEPTED = re.compile(
    r"^Accepted (?:password|publickey|keyboard-interactive\S*) for "
    r"(?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2$"
)

_SUDO_INVOCATION = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=\S+\s*;\s*"
    r"COMMAND=(?P<command>.+)$"
)


def _parse_timestamp(month: str, day: str, time_str: str, year: int) -> datetime:
    naive = datetime.strptime(
        f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S"
    )
    return naive.replace(tzinfo=timezone.utc)


def parse_line(line: str, reference_year: Optional[int] = None) -> Optional[Event]:
    m = _SYSLOG_PREFIX.match(line)
    if not m:
        return None

    year = reference_year or datetime.now(timezone.utc).year
    try:
        ts = _parse_timestamp(m["month"], m["day"], m["time"], year)
    except ValueError:
        return None

    host = m["host"]
    program = m["program"]
    rest = m["rest"]

    if program.startswith("sshd"):
        fail = _SSH_FAILED.match(rest)
        if fail:
            return Event(
                timestamp=ts,
                host_name=host,
                source_type="auth",
                event_action="login_failed",
                event_outcome="failure",
                user_name=fail["user"],
                source_ip=fail["ip"],
                message_raw=line,
                severity="medium",
            )

        ok = _SSH_ACCEPTED.match(rest)
        if ok:
            return Event(
                timestamp=ts,
                host_name=host,
                source_type="auth",
                event_action="login_success",
                event_outcome="success",
                user_name=ok["user"],
                source_ip=ok["ip"],
                message_raw=line,
                severity="low",
            )

    if program == "sudo":
        sudo = _SUDO_INVOCATION.match(rest)
        if sudo:
            return Event(
                timestamp=ts,
                host_name=host,
                source_type="auth",
                event_action="sudo",
                event_outcome="success",
                user_name=sudo["user"],
                message_raw=line,
                severity="medium",
            )

    return None
