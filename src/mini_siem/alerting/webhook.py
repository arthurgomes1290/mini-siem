"""HTTP POST para webhooks de chat.

Contrato: ``send()`` **nunca lança**. Retorna ``True`` em 2xx, ``False``
caso contrário. O caller (dispatcher) decide se marca ``notified_at``.
"""

from __future__ import annotations

import sys
from typing import Any, Optional

import httpx


def send(
    url: str,
    payload: dict,
    *,
    timeout: float = 5.0,
    http_client: Optional[Any] = None,
) -> bool:
    try:
        if http_client is not None:
            response = http_client.post(url, json=payload, timeout=timeout)
        else:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(url, json=payload)
        status = getattr(response, "status_code", 0)
        return 200 <= status < 300
    except Exception as exc:  # noqa: BLE001 — ponto certo para engolir
        print(f"[warn] webhook falhou: {exc}", file=sys.stderr)
        return False
