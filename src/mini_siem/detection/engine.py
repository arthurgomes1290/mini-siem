"""Carregamento de regras YAML e orquestração dos handlers."""

from __future__ import annotations

import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from .rules import HANDLERS


_REQUIRED = ("id", "name", "type", "severity")


def _validate(rule: dict) -> None:
    for key in _REQUIRED:
        if key not in rule:
            raise ValueError(
                f"regra em {rule.get('_source_path', '?')} sem campo obrigatório {key!r}"
            )
    if rule["type"] not in HANDLERS:
        raise ValueError(
            f"regra {rule['id']}: tipo desconhecido {rule['type']!r}. "
            f"Tipos válidos: {sorted(HANDLERS)}"
        )


def load_rules(rules_dir: str | Path) -> list[dict]:
    rules_dir = Path(rules_dir)
    if not rules_dir.is_dir():
        raise FileNotFoundError(f"diretório de regras não existe: {rules_dir}")

    files = sorted(list(rules_dir.glob("*.yml")) + list(rules_dir.glob("*.yaml")))
    rules: list[dict] = []
    for path in files:
        with open(path, "r") as fh:
            rule = yaml.safe_load(fh)
        if not isinstance(rule, dict):
            raise ValueError(f"regra em {path}: YAML raiz deve ser um mapping")
        rule["_source_path"] = str(path)
        _validate(rule)
        rules.append(rule)
    return rules


def run_rules(
    conn: sqlite3.Connection,
    rules: list[dict],
    since: Optional[datetime] = None,
) -> dict[str, list[int]]:
    """Executa todas as regras e devolve, por rule_id, os ids dos alertas criados."""
    results: dict[str, list[int]] = {}
    for rule in rules:
        handler = HANDLERS[rule["type"]]
        try:
            ids = handler(conn, rule, since)
        except Exception as exc:
            print(f"[warn] regra {rule['id']} falhou: {exc}", file=sys.stderr)
            ids = []
        results[rule["id"]] = ids
    return results
