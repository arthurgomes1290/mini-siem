"""Event schema (ECS-like).

Single source of truth for events across the pipeline. Every parser outputs
an ``Event``; everything downstream (storage, detection, API) reads this shape.

ECS uses dotted field names (``host.name``, ``source.ip``). We store flat
snake_case fields in Python (ergonomic) and emit the dotted form only when
serializing with :meth:`Event.to_ecs`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict


SourceType = Literal["auth", "nginx", "syslog"]
Outcome = Literal["success", "failure"]
Severity = Literal["low", "medium", "high", "critical"]


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    host_name: str
    source_type: SourceType
    event_action: str
    event_outcome: Optional[Outcome] = None
    user_name: Optional[str] = None
    source_ip: Optional[str] = None
    http_status: Optional[int] = None
    http_path: Optional[str] = None
    message_raw: str
    severity: Severity = "low"

    def to_ecs(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "host.name": self.host_name,
            "source.type": self.source_type,
            "event.action": self.event_action,
            "event.outcome": self.event_outcome,
            "user.name": self.user_name,
            "source.ip": self.source_ip,
            "http.status": self.http_status,
            "http.path": self.http_path,
            "message.raw": self.message_raw,
            "severity": self.severity,
        }
