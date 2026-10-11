"""Handlers de detecção.

Cada handler recebe ``(conn, rule, since)`` e retorna a lista de ``id``
de alertas realmente criados nesta execução (os suprimidos por dedupe
não contam).

Convenções:

- ``filter`` em YAML é um dict ``{coluna: valor}``. Só colunas em
  :data:`ALLOWED_FILTER_FIELDS` são permitidas, evitando SQL injection
  mesmo em arquivos de regra adulterados.
- ``group_by`` é o nome da coluna que define a *entidade* da regra
  (``source_ip``, ``user_name``, ...). Idem whitelist.
- Chaves de ``dedupe_key`` embutem o *bucket* do tempo. Rodar ``detect``
  duas vezes seguidas sobre o mesmo dado é idempotente — a segunda
  tentativa viola UNIQUE e é silenciosamente ignorada.
"""

from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..storage.queries import insert_alert


ALLOWED_FILTER_FIELDS = {
    "source_type",
    "event_action",
    "event_outcome",
    "user_name",
    "source_ip",
    "host_name",
    "http_status",
    "severity",
}

ALLOWED_GROUP_BY = {"source_ip", "user_name", "host_name"}


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _build_filter(filter_: Optional[dict]) -> tuple[str, list]:
    clauses: list[str] = []
    params: list = []
    for key, value in (filter_ or {}).items():
        if key not in ALLOWED_FILTER_FIELDS:
            raise ValueError(f"filtro inválido: campo {key!r} não permitido")
        clauses.append(f"{key} = ?")
        params.append(value)
    where = " AND ".join(clauses) if clauses else "1=1"
    return where, params


def _check_group_by(group_by: str) -> str:
    if group_by not in ALLOWED_GROUP_BY:
        raise ValueError(
            f"group_by inválido: {group_by!r}. Use um de {sorted(ALLOWED_GROUP_BY)}"
        )
    return group_by


def _floor_to_window(ts: datetime, minutes: int) -> datetime:
    secs = minutes * 60
    floored = (int(ts.timestamp()) // secs) * secs
    return datetime.fromtimestamp(floored, tz=timezone.utc)


def _attack(rule: dict) -> tuple[Optional[str], Optional[str]]:
    attack = rule.get("attack") or {}
    return attack.get("tactic"), attack.get("technique")


def apply_threshold(
    conn: sqlite3.Connection, rule: dict, since: Optional[datetime]
) -> list[int]:
    where, params = _build_filter(rule.get("filter"))
    group_by = _check_group_by(rule["group_by"])
    window = int(rule["window_minutes"])
    threshold = int(rule["threshold"])

    if since is None:
        since = datetime.now(timezone.utc) - timedelta(minutes=window)

    sql = f"""
        SELECT {group_by} AS entity,
               COUNT(*)    AS cnt,
               MIN(timestamp) AS first_seen,
               MAX(timestamp) AS last_seen
        FROM events
        WHERE {where}
          AND timestamp >= ?
          AND {group_by} IS NOT NULL
        GROUP BY {group_by}
        HAVING COUNT(*) >= ?
    """
    rows = list(conn.execute(sql, params + [since.isoformat(), threshold]))

    tactic, technique = _attack(rule)
    created: list[int] = []
    for row in rows:
        bucket = _floor_to_window(_parse_iso(row["first_seen"]), window)
        key = f"{rule['id']}:{row['entity']}:{bucket.isoformat()}"
        aid = insert_alert(
            conn,
            rule_id=rule["id"],
            rule_name=rule["name"],
            severity=rule["severity"],
            entity=row["entity"],
            event_count=row["cnt"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            dedupe_key=key,
            attack_tactic=tactic,
            attack_technique=technique,
            details={
                "window_minutes": window,
                "threshold": threshold,
            },
        )
        if aid is not None:
            created.append(aid)
    return created


def apply_sequence(
    conn: sqlite3.Connection, rule: dict, since: Optional[datetime]
) -> list[int]:
    pre = rule["precondition"]
    trig = rule["trigger"]
    group_by = _check_group_by(pre["group_by"])
    trig_group = _check_group_by(trig.get("group_by", group_by))
    if trig_group != group_by:
        raise ValueError(
            f"regra {rule['id']}: precondition.group_by != trigger.group_by"
        )

    window = int(pre["window_minutes"])
    min_count = int(pre["min_count"])
    pre_where, pre_params = _build_filter(pre["filter"])
    trig_where, trig_params = _build_filter(trig["filter"])

    if since is None:
        since = datetime.now(timezone.utc) - timedelta(hours=24)

    trig_sql = f"""
        SELECT id, timestamp, {group_by} AS entity
        FROM events
        WHERE {trig_where}
          AND timestamp >= ?
          AND {group_by} IS NOT NULL
        ORDER BY timestamp
    """
    triggers = list(
        conn.execute(trig_sql, trig_params + [since.isoformat()])
    )

    tactic, technique = _attack(rule)
    created: list[int] = []
    for t in triggers:
        trig_ts = _parse_iso(t["timestamp"])
        win_start = trig_ts - timedelta(minutes=window)
        count_sql = f"""
            SELECT COUNT(*)    AS cnt,
                   MIN(timestamp) AS first_seen
            FROM events
            WHERE {pre_where}
              AND {group_by} = ?
              AND timestamp >= ?
              AND timestamp < ?
        """
        row = conn.execute(
            count_sql,
            pre_params + [t["entity"], win_start.isoformat(), t["timestamp"]],
        ).fetchone()
        if row["cnt"] < min_count:
            continue
        key = f"{rule['id']}:{t['entity']}:{t['timestamp']}"
        aid = insert_alert(
            conn,
            rule_id=rule["id"],
            rule_name=rule["name"],
            severity=rule["severity"],
            entity=t["entity"],
            event_count=int(row["cnt"]) + 1,
            first_seen=row["first_seen"] or t["timestamp"],
            last_seen=t["timestamp"],
            dedupe_key=key,
            attack_tactic=tactic,
            attack_technique=technique,
            details={
                "precondition_count": int(row["cnt"]),
                "window_minutes": window,
            },
        )
        if aid is not None:
            created.append(aid)
    return created


def apply_time_of_day(
    conn: sqlite3.Connection, rule: dict, since: Optional[datetime]
) -> list[int]:
    try:
        from zoneinfo import ZoneInfo
    except ImportError:  # pragma: no cover
        ZoneInfo = None  # type: ignore[assignment]

    where, params = _build_filter(rule.get("filter"))
    group_by = _check_group_by(rule.get("group_by", "user_name"))
    allowed = rule["allowed_hours"]
    if (
        not isinstance(allowed, list)
        or len(allowed) != 2
        or not all(isinstance(h, int) for h in allowed)
    ):
        raise ValueError(f"regra {rule['id']}: allowed_hours deve ser [start, end]")
    start_h, end_h = allowed

    tz_name = rule.get("timezone", "UTC")
    try:
        tz = ZoneInfo(tz_name) if ZoneInfo else timezone.utc
    except Exception:
        tz = timezone.utc

    if since is None:
        since = datetime.now(timezone.utc) - timedelta(days=1)

    sql = f"""
        SELECT id, timestamp, {group_by} AS entity
        FROM events
        WHERE {where}
          AND timestamp >= ?
          AND {group_by} IS NOT NULL
    """
    rows = list(conn.execute(sql, params + [since.isoformat()]))

    tactic, technique = _attack(rule)
    created: list[int] = []
    for row in rows:
        ts = _parse_iso(row["timestamp"]).astimezone(tz)
        if start_h <= ts.hour < end_h:
            continue
        key = f"{rule['id']}:{row['entity']}:{ts.date().isoformat()}"
        aid = insert_alert(
            conn,
            rule_id=rule["id"],
            rule_name=rule["name"],
            severity=rule["severity"],
            entity=row["entity"],
            event_count=1,
            first_seen=row["timestamp"],
            last_seen=row["timestamp"],
            dedupe_key=key,
            attack_tactic=tactic,
            attack_technique=technique,
            details={
                "hour_local": ts.hour,
                "tz": tz_name,
                "allowed_hours": allowed,
            },
        )
        if aid is not None:
            created.append(aid)
    return created


def apply_rarity(
    conn: sqlite3.Connection, rule: dict, since: Optional[datetime]
) -> list[int]:
    where, params = _build_filter(rule.get("filter"))
    group_by = _check_group_by(rule["group_by"])
    baseline_days = int(rule.get("baseline_days", 7))
    max_hist = int(rule.get("max_historical_count", 0))

    if since is None:
        since = datetime.now(timezone.utc) - timedelta(days=1)

    sql = f"""
        SELECT id, timestamp, {group_by} AS entity
        FROM events
        WHERE {where}
          AND timestamp >= ?
          AND {group_by} IS NOT NULL
        ORDER BY timestamp
    """
    rows = list(conn.execute(sql, params + [since.isoformat()]))

    tactic, technique = _attack(rule)
    created: list[int] = []
    seen: set[str] = set()
    for row in rows:
        entity = row["entity"]
        if entity in seen:
            continue
        baseline_start = _parse_iso(row["timestamp"]) - timedelta(days=baseline_days)
        hist_sql = f"""
            SELECT COUNT(*) AS cnt
            FROM events
            WHERE {where}
              AND {group_by} = ?
              AND timestamp >= ?
              AND timestamp < ?
        """
        hist_count = conn.execute(
            hist_sql,
            params + [entity, baseline_start.isoformat(), row["timestamp"]],
        ).fetchone()["cnt"]
        if hist_count > max_hist:
            seen.add(entity)
            continue
        key = f"{rule['id']}:{entity}:{row['timestamp'][:10]}"
        aid = insert_alert(
            conn,
            rule_id=rule["id"],
            rule_name=rule["name"],
            severity=rule["severity"],
            entity=entity,
            event_count=1,
            first_seen=row["timestamp"],
            last_seen=row["timestamp"],
            dedupe_key=key,
            attack_tactic=tactic,
            attack_technique=technique,
            details={
                "baseline_days": baseline_days,
                "historical_count": int(hist_count),
            },
        )
        if aid is not None:
            created.append(aid)
        seen.add(entity)
    return created


HANDLERS = {
    "threshold": apply_threshold,
    "sequence": apply_sequence,
    "time_of_day": apply_time_of_day,
    "rarity": apply_rarity,
}
