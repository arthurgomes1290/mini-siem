"""CLI entrypoint.

Subcommands:

* ``version``  — prints the package version.
* ``init-db``  — creates the SQLite schema.
* ``parse``    — reads a log file and prints one JSON ECS event per line.
* ``run``      — starts collectors (tail + syslog UDP) writing into SQLite.
* ``query``    — queries recent events from SQLite.
* ``detect``   — runs YAML rules against the event store and raises alerts.
* ``alerts``   — queries recent alerts from SQLite.
* ``notify``   — sends pending alerts via webhook (Discord/Slack/generic).
* ``serve``    — serves the FastAPI dashboard + JSON API.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys

from . import __version__
from .alerting import dispatch_pending_alerts
from .collector import CollectorRunner
from .collector.file_tail import tail
from .collector.syslog_server import serve_udp
from .detection.engine import load_rules, run_rules
from .parser import PARSERS, parse_file
from .storage.db import connect, init_db
from .storage.queries import parse_since, recent_alerts, recent_events


WEBHOOK_PROVIDERS = ("auto", "discord", "slack", "generic")


def _default_db_path() -> str:
    return os.environ.get("SIEM_DB_PATH", "/data/siem.db")


def _cmd_version(_: argparse.Namespace) -> int:
    print(__version__)
    return 0


def _cmd_init_db(args: argparse.Namespace) -> int:
    db = args.db or _default_db_path()
    init_db(db)
    print(f"[ok] schema inicializado em {db}")
    return 0


def _cmd_parse(args: argparse.Namespace) -> int:
    count = 0
    for event in parse_file(args.source, args.path):
        print(json.dumps(event.to_ecs(), ensure_ascii=False))
        count += 1
    print(f"[info] {count} eventos extraídos de {args.path}", file=sys.stderr)
    return 0


def _parse_tail_spec(spec: str) -> tuple[str, str]:
    source, sep, path = spec.partition(":")
    if not sep or not source or not path:
        raise ValueError(f"--tail inválido: {spec!r}. Formato: SRC:PATH")
    if source not in PARSERS:
        raise ValueError(
            f"--tail SRC desconhecido: {source!r}. Use um de {sorted(PARSERS)}"
        )
    return source, path


def _parse_syslog_spec(spec: str) -> tuple[int, str]:
    port_str, _, source = spec.partition(":")
    source = source or "auth"
    try:
        port = int(port_str)
    except ValueError as exc:
        raise ValueError(f"--syslog inválido: {spec!r}. Formato: PORT[:SRC]") from exc
    if source not in PARSERS:
        raise ValueError(
            f"--syslog SRC desconhecido: {source!r}. Use um de {sorted(PARSERS)}"
        )
    return port, source


def _cmd_run(args: argparse.Namespace) -> int:
    db = args.db or _default_db_path()
    init_db(db)
    conn = connect(db)
    runner = CollectorRunner(conn)

    for spec in args.tail or []:
        source, path = _parse_tail_spec(spec)

        def _tail_target(on_event, stop_event, _path=path, _source=source):
            tail(_path, _source, on_event, stop_event, start_from_end=args.from_end)

        runner.add_collector(_tail_target, name=f"tail:{source}:{path}")
        print(f"[info] tail {source} ← {path}", file=sys.stderr)

    for spec in args.syslog or []:
        port, source = _parse_syslog_spec(spec)

        def _syslog_target(on_event, stop_event, _port=port, _source=source):
            serve_udp(args.syslog_bind, _port, _source, on_event, stop_event)

        runner.add_collector(_syslog_target, name=f"syslog:{port}:{source}")
        print(f"[info] syslog UDP {args.syslog_bind}:{port} ({source})", file=sys.stderr)

    if not runner._collectors:
        print("[err] nenhuma fonte configurada. Use --tail e/ou --syslog.", file=sys.stderr)
        return 2

    def _handle_signal(_signo, _frame):
        print("\n[info] parando collectors…", file=sys.stderr)
        runner.stop()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    print(f"[info] db={db}  ^C para parar.", file=sys.stderr)
    runner.start()
    runner.wait()
    print(f"[info] eventos escritos: {runner.events_written}", file=sys.stderr)
    return 0


def _default_rules_dir() -> str:
    local = os.path.join(os.getcwd(), "config", "rules")
    if os.path.isdir(local):
        return local
    return "/app/config/rules"


def _cmd_detect(args: argparse.Namespace) -> int:
    db = args.db or _default_db_path()
    conn = connect(db)
    rules = load_rules(args.rules or _default_rules_dir())
    since = parse_since(args.since) if args.since else None
    results = run_rules(conn, rules, since=since)
    total = sum(len(ids) for ids in results.values())
    for rule in rules:
        n = len(results.get(rule["id"], []))
        if n:
            tactic = (rule.get("attack") or {}).get("technique", "")
            print(f"[alert] {rule['id']:<24} {rule['severity']:<8} {tactic:<12} → {n} novo(s)")
    print(
        f"[info] {total} alertas gerados ({len(rules)} regras avaliadas)",
        file=sys.stderr,
    )

    if args.notify:
        url = args.webhook_url or os.environ.get("SIEM_WEBHOOK_URL")
        if not url:
            print("[warn] --notify sem SIEM_WEBHOOK_URL — nada enviado", file=sys.stderr)
        else:
            sent = dispatch_pending_alerts(conn, url, provider=args.provider)
            print(f"[info] {sent} webhooks enviados", file=sys.stderr)
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    if args.db:
        os.environ["SIEM_DB_PATH"] = args.db
    uvicorn.run(
        "mini_siem.api.app:app",
        host=args.host,
        port=args.port,
        log_level="info",
        reload=args.reload,
    )
    return 0


def _cmd_notify(args: argparse.Namespace) -> int:
    db = args.db or _default_db_path()
    conn = connect(db)
    url = args.webhook_url or os.environ.get("SIEM_WEBHOOK_URL")
    if not url:
        print(
            "[err] configure SIEM_WEBHOOK_URL ou use --webhook-url",
            file=sys.stderr,
        )
        return 2
    sent = dispatch_pending_alerts(
        conn, url, provider=args.provider, limit=args.limit
    )
    print(f"[info] {sent} webhooks enviados", file=sys.stderr)
    return 0


def _cmd_alerts(args: argparse.Namespace) -> int:
    db = args.db or _default_db_path()
    conn = connect(db)
    since = parse_since(args.since) if args.since else None
    rows = recent_alerts(
        conn,
        since=since,
        rule_id=args.rule,
        severity=args.severity,
        limit=args.limit,
    )
    for row in rows:
        print(json.dumps(row, ensure_ascii=False))
    print(f"[info] {len(rows)} alertas", file=sys.stderr)
    return 0


def _cmd_query(args: argparse.Namespace) -> int:
    db = args.db or _default_db_path()
    conn = connect(db)
    since = parse_since(args.since) if args.since else None
    rows = recent_events(
        conn,
        since=since,
        source_ip=args.ip,
        user_name=args.user,
        source_type=args.source,
        limit=args.limit,
    )
    for row in rows:
        print(json.dumps(row, ensure_ascii=False))
    print(f"[info] {len(rows)} eventos", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mini-siem")
    sub = parser.add_subparsers(dest="command", required=True)

    p_version = sub.add_parser("version", help="mostra a versão")
    p_version.set_defaults(func=_cmd_version)

    p_init = sub.add_parser("init-db", help="cria o schema no SQLite")
    p_init.add_argument(
        "--db",
        help="caminho do banco (default: $SIEM_DB_PATH ou /data/siem.db)",
    )
    p_init.set_defaults(func=_cmd_init_db)

    p_parse = sub.add_parser(
        "parse",
        help="normaliza um arquivo de log e imprime JSONL ECS no stdout",
    )
    p_parse.add_argument(
        "--source", required=True, choices=sorted(PARSERS),
        help="tipo da fonte (auth | nginx)",
    )
    p_parse.add_argument("path", help="caminho do arquivo de log")
    p_parse.set_defaults(func=_cmd_parse)

    p_run = sub.add_parser(
        "run",
        help="roda collectors (tail + syslog) escrevendo em SQLite",
    )
    p_run.add_argument(
        "--tail", action="append", metavar="SRC:PATH",
        help="tail de arquivo (repetível). Ex: --tail auth:/var/log/auth.log",
    )
    p_run.add_argument(
        "--syslog", action="append", metavar="PORT[:SRC]",
        help="servidor syslog UDP (repetível). Ex: --syslog 5514:auth",
    )
    p_run.add_argument(
        "--syslog-bind", default="0.0.0.0",
        help="interface para bind do syslog (default: 0.0.0.0)",
    )
    p_run.add_argument(
        "--from-end", action="store_true",
        help="tail parte do fim do arquivo (ignora conteúdo pré-existente)",
    )
    p_run.add_argument("--db", help="caminho do SQLite")
    p_run.set_defaults(func=_cmd_run)

    p_query = sub.add_parser(
        "query",
        help="consulta eventos no SQLite (JSONL)",
    )
    p_query.add_argument("--since", help="janela recente: 15m, 1h, 2d, ...")
    p_query.add_argument("--ip", help="filtra por source_ip exato")
    p_query.add_argument("--user", help="filtra por user_name exato")
    p_query.add_argument(
        "--source", choices=sorted(PARSERS), help="filtra por source_type",
    )
    p_query.add_argument("--limit", type=int, default=100, help="limite de linhas")
    p_query.add_argument("--db", help="caminho do SQLite")
    p_query.set_defaults(func=_cmd_query)

    p_detect = sub.add_parser(
        "detect",
        help="aplica regras YAML aos eventos e grava alertas",
    )
    p_detect.add_argument(
        "--rules",
        help="diretório com arquivos .yml de regras (default: ./config/rules)",
    )
    p_detect.add_argument("--since", help="só considerar eventos a partir de (ex: 1h)")
    p_detect.add_argument(
        "--notify",
        action="store_true",
        help="após detect, dispara webhooks dos alertas pendentes",
    )
    p_detect.add_argument(
        "--webhook-url",
        help="URL do webhook (default: $SIEM_WEBHOOK_URL)",
    )
    p_detect.add_argument(
        "--provider",
        default="auto",
        choices=WEBHOOK_PROVIDERS,
        help="formato do payload (default: auto, detecta pela URL)",
    )
    p_detect.add_argument("--db", help="caminho do SQLite")
    p_detect.set_defaults(func=_cmd_detect)

    p_serve = sub.add_parser(
        "serve",
        help="roda a API FastAPI + dashboard web",
    )
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true", help="autoreload (dev)")
    p_serve.add_argument("--db", help="caminho do SQLite")
    p_serve.set_defaults(func=_cmd_serve)

    p_notify = sub.add_parser(
        "notify",
        help="envia webhooks para alertas com notified_at IS NULL",
    )
    p_notify.add_argument("--webhook-url", help="URL do webhook (default: $SIEM_WEBHOOK_URL)")
    p_notify.add_argument(
        "--provider", default="auto", choices=WEBHOOK_PROVIDERS,
    )
    p_notify.add_argument("--limit", type=int, default=100)
    p_notify.add_argument("--db", help="caminho do SQLite")
    p_notify.set_defaults(func=_cmd_notify)

    p_alerts = sub.add_parser("alerts", help="consulta alertas gerados (JSONL)")
    p_alerts.add_argument("--since", help="só alertas com last_seen >= janela (15m/1h/1d)")
    p_alerts.add_argument("--rule", help="filtra por rule_id")
    p_alerts.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        help="filtra por severidade",
    )
    p_alerts.add_argument("--limit", type=int, default=100)
    p_alerts.add_argument("--db", help="caminho do SQLite")
    p_alerts.set_defaults(func=_cmd_alerts)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
