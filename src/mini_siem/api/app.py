"""FastAPI app: dashboard + API JSON.

Decisões:

- **Dependency ``get_conn``** abre uma conexão SQLite por request e fecha no
  final. SQLite+WAL permite múltiplos leitores concorrentes com um writer
  (que é o collector).
- **Lifespan em vez de @on_event**: forma moderna e única de setup/teardown.
  Chama ``init_db`` no startup — safe mesmo se já existe (migração
  idempotente).
- **Templates Jinja + HTMX**: HTML server-rendered no load inicial, HTMX
  faz polling de fragmentos a cada 5s. Zero build step, zero SPA.
- **Rotas JSON separadas** (``/api/*``) permitem consumo por outros clientes
  ou testes diretos, enquanto ``/`` cuida da UI.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..storage.db import connect, init_db
from ..storage.queries import (
    parse_since,
    recent_alerts,
    recent_events,
)


_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


def _db_path() -> str:
    return os.environ.get("SIEM_DB_PATH", "/data/siem.db")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(_db_path())
    yield


app = FastAPI(title="mini-siem", lifespan=lifespan)


def get_conn():
    conn = connect(_db_path())
    try:
        yield conn
    finally:
        conn.close()


def _since_from_query(since: Optional[str]) -> Optional[datetime]:
    if not since:
        return None
    try:
        return parse_since(since)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ------------------------------------------------------------------ API JSON


@app.get("/api/events")
def api_events(
    since: Optional[str] = Query(default="1h"),
    ip: Optional[str] = None,
    user: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 100,
    conn: sqlite3.Connection = Depends(get_conn),
):
    rows = recent_events(
        conn,
        since=_since_from_query(since),
        source_ip=ip,
        user_name=user,
        source_type=source,
        limit=limit,
    )
    return {"count": len(rows), "events": rows}


@app.get("/api/alerts")
def api_alerts(
    since: Optional[str] = Query(default="1d"),
    rule: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    conn: sqlite3.Connection = Depends(get_conn),
):
    rows = recent_alerts(
        conn,
        since=_since_from_query(since),
        rule_id=rule,
        severity=severity,
        limit=limit,
    )
    return {"count": len(rows), "alerts": rows}


@app.get("/api/search")
def api_search(
    q: str = Query(..., min_length=1, max_length=200),
    limit: int = 50,
    conn: sqlite3.Connection = Depends(get_conn),
):
    """Busca free-text em ``message_raw`` via LIKE. Simples o bastante
    para MVP; FTS5 do SQLite seria upgrade óbvio."""
    rows = conn.execute(
        """
        SELECT * FROM events
        WHERE message_raw LIKE ?
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (f"%{q}%", int(limit)),
    ).fetchall()
    return {"count": len(rows), "query": q, "events": [dict(r) for r in rows]}


@app.get("/api/stats")
def api_stats(conn: sqlite3.Connection = Depends(get_conn)):
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    hour_ago = now - timedelta(hours=1)

    event_count_24h = conn.execute(
        "SELECT COUNT(*) FROM events WHERE timestamp >= ?",
        (day_ago.isoformat(),),
    ).fetchone()[0]
    alert_count_24h = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE last_seen >= ?",
        (day_ago.isoformat(),),
    ).fetchone()[0]
    critical_24h = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'critical' AND last_seen >= ?",
        (day_ago.isoformat(),),
    ).fetchone()[0]

    top_ips = conn.execute(
        """
        SELECT source_ip, COUNT(*) AS cnt
        FROM events
        WHERE source_ip IS NOT NULL AND timestamp >= ?
        GROUP BY source_ip
        ORDER BY cnt DESC
        LIMIT 10
        """,
        (day_ago.isoformat(),),
    ).fetchall()

    severity_counts = conn.execute(
        """
        SELECT severity, COUNT(*)
        FROM alerts
        WHERE last_seen >= ?
        GROUP BY severity
        """,
        (day_ago.isoformat(),),
    ).fetchall()

    # Timeline: 1-min buckets na última hora.
    timeline = conn.execute(
        """
        SELECT substr(timestamp, 1, 16) AS bucket, COUNT(*) AS cnt
        FROM events
        WHERE timestamp >= ?
        GROUP BY bucket
        ORDER BY bucket
        """,
        (hour_ago.isoformat(),),
    ).fetchall()

    return {
        "event_count_24h": event_count_24h,
        "alert_count_24h": alert_count_24h,
        "critical_count_24h": critical_24h,
        "top_ips": [{"ip": r[0], "count": r[1]} for r in top_ips],
        "severity_counts": {r[0]: r[1] for r in severity_counts},
        "timeline": [{"bucket": r[0], "count": r[1]} for r in timeline],
    }


# --------------------------------------------------------------- HTML / HTMX


@app.get("/", response_class=HTMLResponse)
def home(request: Request, conn: sqlite3.Connection = Depends(get_conn)):
    stats = api_stats(conn)
    return templates.TemplateResponse(
        request, "dashboard.html", {"stats": stats},
    )


@app.get("/partials/alerts", response_class=HTMLResponse)
def partial_alerts(
    request: Request,
    limit: int = 20,
    conn: sqlite3.Connection = Depends(get_conn),
):
    alerts = recent_alerts(conn, limit=limit)
    return templates.TemplateResponse(
        request, "partials/alerts.html", {"alerts": alerts},
    )


@app.get("/partials/events", response_class=HTMLResponse)
def partial_events(
    request: Request,
    limit: int = 20,
    conn: sqlite3.Connection = Depends(get_conn),
):
    events = recent_events(conn, limit=limit)
    return templates.TemplateResponse(
        request, "partials/events.html", {"events": events},
    )
