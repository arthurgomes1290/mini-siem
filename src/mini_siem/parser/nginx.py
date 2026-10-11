"""Parser para logs de acesso do Nginx no formato ``combined`` (default).

Formato::

    $remote_addr - $remote_user [$time_local] "$request" $status
    $body_bytes_sent "$http_referer" "$http_user_agent"

Toda linha vira um evento ``http_request`` com severidade derivada do
status HTTP:

- 2xx/3xx → severity=low,    outcome=success
- 4xx     → severity=medium, outcome=failure
- 5xx     → severity=high,   outcome=failure
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional, Tuple

from ..schema import Event, Severity


_LINE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+\S+'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def _severity_outcome(status: int) -> Tuple[Severity, str]:
    if status >= 500:
        return "high", "failure"
    if status >= 400:
        return "medium", "failure"
    return "low", "success"


def parse_line(line: str, host_name: str = "nginx") -> Optional[Event]:
    m = _LINE.match(line)
    if not m:
        return None

    try:
        status = int(m["status"])
        ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

    severity, outcome = _severity_outcome(status)
    return Event(
        timestamp=ts,
        host_name=host_name,
        source_type="nginx",
        event_action="http_request",
        event_outcome=outcome,
        source_ip=m["ip"],
        http_status=status,
        http_path=m["path"],
        message_raw=line,
        severity=severity,
    )
