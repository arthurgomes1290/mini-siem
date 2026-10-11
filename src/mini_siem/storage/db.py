"""SQLite schema, connection and migration.

Design notes:

- WAL mode so a reader (API/dashboard) does not block a writer (collector).
- Timestamps stored as ISO-8601 text — lexicographically sortable and
  timezone-aware, which is enough for the queries we care about.
- Indexes on the three fields we filter by most: timestamp, source_ip,
  user_name.
- A tiny ``schema_version`` table records applied migrations. The migration
  path is idempotent — safe to re-run ``init_db`` on an existing DB.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 2

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    host_name     TEXT    NOT NULL,
    source_type   TEXT    NOT NULL,
    event_action  TEXT    NOT NULL,
    event_outcome TEXT,
    user_name     TEXT,
    source_ip     TEXT,
    http_status   INTEGER,
    http_path     TEXT,
    message_raw   TEXT    NOT NULL,
    severity      TEXT    NOT NULL DEFAULT 'low'
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_user_name ON events(user_name);

CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
    rule_id          TEXT    NOT NULL,
    rule_name        TEXT    NOT NULL,
    severity         TEXT    NOT NULL,
    entity           TEXT    NOT NULL,
    attack_tactic    TEXT,
    attack_technique TEXT,
    event_count      INTEGER NOT NULL DEFAULT 1,
    first_seen       TEXT    NOT NULL,
    last_seen        TEXT    NOT NULL,
    dedupe_key       TEXT    NOT NULL UNIQUE,
    details_json     TEXT,
    notified_at      TEXT             -- v2: timestamp do envio bem-sucedido
);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at  ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id     ON alerts(rule_id);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(path),
        isolation_level=None,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    cols = [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]
    return column in cols


def _migrate(conn: sqlite3.Connection) -> None:
    """Aplicações idempotentes para DBs criados em versões antigas."""
    # v2: coluna notified_at em alerts
    if not _column_exists(conn, "alerts", "notified_at"):
        conn.execute("ALTER TABLE alerts ADD COLUMN notified_at TEXT")
    # Índice: criado após o ALTER para não quebrar DBs legados no primeiro
    # ``init_db`` depois do upgrade. IF NOT EXISTS deixa idempotente.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_notified_at ON alerts(notified_at)"
    )


def init_db(db_path: str | Path) -> None:
    conn = connect(db_path)
    try:
        conn.executescript(_SCHEMA_SQL)
        _migrate(conn)
        current = conn.execute(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version"
        ).fetchone()[0]
        if current < SCHEMA_VERSION:
            conn.execute(
                "INSERT INTO schema_version(version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
    finally:
        conn.close()
