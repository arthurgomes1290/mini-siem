"""Operações de persistência e consulta sobre a tabela ``events``.

As duas únicas operações do caminho quente são ``insert_event`` (escrita) e
``recent_events`` (leitura). Mantemos SQL cru e parâmetros bindados — ORM
seria exagero e esconderia os índices que importam.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from ..schema import Event


def insert_event(conn: sqlite3.Connection, event: Event) -> int:
    cur = conn.execute(
        """
        INSERT INTO events (
            timestamp, host_name, source_type, event_action, event_outcome,
            user_name, source_ip, http_status, http_path, message_raw, severity
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.timestamp.isoformat(),
            event.host_name,
            event.source_type,
            event.event_action,
            event.event_outcome,
            event.user_name,
            event.source_ip,
            event.http_status,
            event.http_path,
            event.message_raw,
            event.severity,
        ),
    )
    return cur.lastrowid


def recent_events(
    conn: sqlite3.Connection,
    *,
    since: Optional[datetime] = None,
    source_ip: Optional[str] = None,
    user_name: Optional[str] = None,
    source_type: Optional[str] = None,
    limit: int = 100,
) -> list[dict]:
    where: list[str] = []
    params: list = []

    if since is not None:
        where.append("timestamp >= ?")
        params.append(since.isoformat())
    if source_ip:
        where.append("source_ip = ?")
        params.append(source_ip)
    if user_name:
        where.append("user_name = ?")
        params.append(user_name)
    if source_type:
        where.append("source_type = ?")
        params.append(source_type)

    sql = "SELECT * FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY timestamp DESC, id DESC LIMIT ?"
    params.append(int(limit))

    return [dict(row) for row in conn.execute(sql, params)]


def count_events(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def _iso(value: Any) -> str:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def insert_alert(
    conn: sqlite3.Connection,
    *,
    rule_id: str,
    rule_name: str,
    severity: str,
    entity: str,
    event_count: int,
    first_seen: Any,
    last_seen: Any,
    dedupe_key: str,
    attack_tactic: Optional[str] = None,
    attack_technique: Optional[str] = None,
    details: Optional[dict] = None,
) -> Optional[int]:
    """Insere um alerta. Retorna o id ou None se já existe (UNIQUE dedupe_key)."""
    try:
        cur = conn.execute(
            """
            INSERT INTO alerts (
                rule_id, rule_name, severity, entity,
                attack_tactic, attack_technique, event_count,
                first_seen, last_seen, dedupe_key, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule_id,
                rule_name,
                severity,
                str(entity),
                attack_tactic,
                attack_technique,
                int(event_count),
                _iso(first_seen),
                _iso(last_seen),
                dedupe_key,
                json.dumps(details) if details else None,
            ),
        )
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None


def recent_alerts(
    conn: sqlite3.Connection,
    *,
    since: Optional[datetime] = None,
    rule_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
) -> list[dict]:
    where: list[str] = []
    params: list = []
    if since is not None:
        where.append("last_seen >= ?")
        params.append(since.isoformat())
    if rule_id:
        where.append("rule_id = ?")
        params.append(rule_id)
    if severity:
        where.append("severity = ?")
        params.append(severity)

    sql = "SELECT * FROM alerts"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY last_seen DESC, id DESC LIMIT ?"
    params.append(int(limit))
    return [dict(row) for row in conn.execute(sql, params)]


def count_alerts(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


def parse_since(expr: str) -> datetime:
    """Converte '15m' / '1h' / '2d' em datetime UTC absoluto no passado."""
    if not expr or len(expr) < 2:
        raise ValueError(f"--since inválido: {expr!r}. Use ex: 15m, 1h, 2d")

    unit = expr[-1].lower()
    try:
        n = int(expr[:-1])
    except ValueError as exc:
        raise ValueError(f"--since inválido: {expr!r}. Use ex: 15m, 1h, 2d") from exc

    if unit == "m":
        delta = timedelta(minutes=n)
    elif unit == "h":
        delta = timedelta(hours=n)
    elif unit == "d":
        delta = timedelta(days=n)
    else:
        raise ValueError(f"--since: unidade desconhecida {unit!r}. Use m/h/d.")

    return datetime.now(timezone.utc) - delta
