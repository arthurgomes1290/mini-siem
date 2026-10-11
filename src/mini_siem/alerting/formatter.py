"""Formatação de alertas para webhooks de chat (Discord/Slack/genérico).

A detecção de provider é por URL — Discord e Slack têm hosts
estáveis. Para endpoints próprios cai em ``generic`` (JSON cru + texto).
"""

from __future__ import annotations

from typing import Any


SEVERITY_EMOJI = {
    "low": "ℹ️",
    "medium": "⚠️",
    "high": "🚨",
    "critical": "💀",
}

# Cores em decimal, usadas por Discord embeds (não aplicadas na forma simples).
SEVERITY_COLOR = {
    "low": 0x3498DB,
    "medium": 0xF1C40F,
    "high": 0xE67E22,
    "critical": 0xE74C3C,
}


def detect_provider(url: str) -> str:
    url_lower = (url or "").lower()
    if "discord.com" in url_lower or "discordapp.com" in url_lower:
        return "discord"
    if "slack.com" in url_lower:
        return "slack"
    return "generic"


def format_text(alert: dict[str, Any]) -> str:
    severity = (alert.get("severity") or "medium").lower()
    emoji = SEVERITY_EMOJI.get(severity, "⚠️")
    tactic = alert.get("attack_tactic") or "-"
    technique = alert.get("attack_technique") or "-"
    return (
        f"{emoji} **[{severity.upper()}] {alert.get('rule_name', '?')}**\n"
        f"Entity: `{alert.get('entity', '?')}`\n"
        f"Events: {alert.get('event_count', 1)}\n"
        f"MITRE: {technique} ({tactic})\n"
        f"First: {alert.get('first_seen', '?')}\n"
        f"Last:  {alert.get('last_seen', '?')}"
    )


def build_payload(provider: str, alert: dict[str, Any]) -> dict[str, Any]:
    text = format_text(alert)
    if provider == "discord":
        return {"username": "mini-siem", "content": text}
    if provider == "slack":
        return {"text": text}
    # genérico: texto + alerta cru. Compatível com qualquer sink que
    # aceite JSON (webhook próprio, ntfy, etc.)
    return {"text": text, "alert": alert}
