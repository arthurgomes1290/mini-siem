"""Camada de alerting.

Duas formas de dedupe convivem no projeto, cada uma resolvendo um problema:

1. **Dedupe de persistência** (``storage.insert_alert`` + ``UNIQUE(dedupe_key)``):
   impede o mesmo alerta ser gravado 2× no DB. Isolado da notificação —
   mesmo que o webhook falhe depois, o alerta existe e pode ser reenviado.

2. **Dedupe de envio** (``alerts.notified_at``): impede notificar o mesmo
   alerta várias vezes. Se o POST falha, ``notified_at`` fica NULL e a
   próxima execução de ``notify`` tenta de novo. Idempotente por natureza.

Separar as duas simplifica *retry*: um `cron` chamando ``notify`` a cada
30s reenvia o que ficou pra trás sem risco de duplicar o que já saiu.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

from .formatter import build_payload, detect_provider
from .webhook import send


def dispatch_pending_alerts(
    conn: sqlite3.Connection,
    webhook_url: str,
    *,
    provider: str = "auto",
    limit: int = 100,
    http_client: Optional[Any] = None,
    timeout: float = 5.0,
) -> int:
    """Envia alertas com ``notified_at IS NULL`` e marca os bem-sucedidos.

    Retorna a quantidade enviada com sucesso. Falhas (status != 2xx,
    exceção, timeout) deixam ``notified_at`` NULL, de modo que a próxima
    chamada tenta de novo.
    """
    if not webhook_url:
        raise ValueError("webhook_url vazio")

    if provider == "auto":
        provider = detect_provider(webhook_url)

    rows = conn.execute(
        """
        SELECT * FROM alerts
        WHERE notified_at IS NULL
        ORDER BY id ASC
        LIMIT ?
        """,
        (int(limit),),
    ).fetchall()

    sent = 0
    for row in rows:
        alert = dict(row)
        payload = build_payload(provider, alert)
        ok = send(webhook_url, payload, timeout=timeout, http_client=http_client)
        if ok:
            conn.execute(
                "UPDATE alerts SET notified_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), alert["id"]),
            )
            sent += 1
    return sent
