#!/usr/bin/env python3
"""Gerador de logs sintéticos para o mini-SIEM.

Um cenário por regra, cada um com timestamps relativos a *agora* (UTC) para
que o motor de detecção dispare imediatamente após a ingestão.

Cenários:
  ssh_bruteforce        6 falhas SSH do mesmo IP em ~1 min        (threshold)
  login_after_failures  4 falhas + 1 sucesso do mesmo IP          (sequence)
  web_dir_scan          5 nginx 404 do mesmo IP em ~1 min         (threshold)
  off_hours_login       1 login SSH às 03:00 UTC (= 00:00 BRT)    (time_of_day)
  unusual_sudo          1 sudo por usuário sem histórico          (rarity)

Uso típico:
  python tools/log_generator.py                        # gera todos
  python tools/log_generator.py --scenario ssh_bruteforce
  python tools/log_generator.py --out-dir ./data/synthetic --append
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable


MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
HOST = "web-01"


def _syslog_ts(ts: datetime) -> str:
    """Formato 'Mon DD HH:MM:SS' em UTC — o parser auth_log trata como UTC."""
    return f"{MONTHS[ts.month - 1]} {ts.day:>2} {ts:%H:%M:%S}"


def _nginx_ts(ts: datetime) -> str:
    """Formato combined: '[dd/Mon/YYYY:HH:MM:SS +0000]'."""
    return f"{ts.day:02d}/{MONTHS[ts.month - 1]}/{ts.year}:{ts:%H:%M:%S} +0000"


def _ssh_failed(ts: datetime, user: str, ip: str, pid: int = 1234) -> str:
    return (
        f"{_syslog_ts(ts)} {HOST} sshd[{pid}]: "
        f"Failed password for {user} from {ip} port 55110 ssh2"
    )


def _ssh_accepted(
    ts: datetime, user: str, ip: str, method: str = "password", pid: int = 1234
) -> str:
    return (
        f"{_syslog_ts(ts)} {HOST} sshd[{pid}]: "
        f"Accepted {method} for {user} from {ip} port 55110 ssh2"
    )


def _sudo_cmd(ts: datetime, user: str, cmd: str = "/bin/ls /root") -> str:
    return (
        f"{_syslog_ts(ts)} {HOST} sudo:  {user} : "
        f"TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
    )


def _nginx_hit(
    ts: datetime, ip: str, path: str, status: int, method: str = "GET"
) -> str:
    return (
        f'{ip} - - [{_nginx_ts(ts)}] "{method} {path} HTTP/1.1" '
        f'{status} 162 "-" "curl/7.68"'
    )


Scenario = Callable[[datetime], tuple[list[str], list[str]]]  # (nginx, auth)


def scenario_ssh_bruteforce(now: datetime) -> tuple[list[str], list[str]]:
    auth = [
        _ssh_failed(now - timedelta(seconds=90 - i * 15), "root",
                    "203.0.113.42", pid=1234 + i)
        for i in range(6)
    ]
    return [], auth


def scenario_login_after_failures(now: datetime) -> tuple[list[str], list[str]]:
    ip = "198.51.100.77"
    auth = [
        _ssh_failed(now - timedelta(seconds=180 - i * 30), "deploy",
                    ip, pid=1800 + i)
        for i in range(4)
    ]
    auth.append(_ssh_accepted(now - timedelta(seconds=20), "deploy", ip,
                              method="password", pid=1810))
    return [], auth


def scenario_web_dir_scan(now: datetime) -> tuple[list[str], list[str]]:
    ip = "192.0.2.66"
    paths = ["/.env", "/wp-admin", "/phpmyadmin", "/.git/config", "/admin.php"]
    nginx = [
        _nginx_hit(now - timedelta(seconds=60 - i * 10), ip, path, 404)
        for i, path in enumerate(paths)
    ]
    return nginx, []


def scenario_off_hours_login(now: datetime) -> tuple[list[str], list[str]]:
    # 03:00 UTC = 00:00 America/Sao_Paulo (fora de [08, 18)).
    # Se "hoje 03:00 UTC" ainda não aconteceu, volta um dia para caber na
    # janela default de "since" de 24h.
    ts = now.replace(hour=3, minute=0, second=0, microsecond=0)
    if ts > now:
        ts -= timedelta(days=1)
    auth = [_ssh_accepted(ts, "deploy", "10.0.0.9", method="publickey")]
    return [], auth


def scenario_unusual_sudo(now: datetime) -> tuple[list[str], list[str]]:
    auth = [_sudo_cmd(now - timedelta(seconds=10), "attacker1",
                      cmd="/usr/bin/cat /etc/shadow")]
    return [], auth


SCENARIOS: dict[str, Scenario] = {
    "ssh_bruteforce": scenario_ssh_bruteforce,
    "login_after_failures": scenario_login_after_failures,
    "web_dir_scan": scenario_web_dir_scan,
    "off_hours_login": scenario_off_hours_login,
    "unusual_sudo": scenario_unusual_sudo,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Gera logs sintéticos para disparar as 5 regras do mini-SIEM.",
    )
    parser.add_argument(
        "--scenario",
        default="all",
        choices=["all", *SCENARIOS],
        help="qual cenário gerar (default: all)",
    )
    parser.add_argument(
        "--out-dir",
        default="./data/synthetic",
        help="diretório de saída (default: ./data/synthetic)",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="anexa aos arquivos existentes em vez de truncar",
    )
    args = parser.parse_args(argv)

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    auth_path = out / "auth.log"
    nginx_path = out / "nginx.log"

    now = datetime.now(timezone.utc)
    selected = (
        SCENARIOS if args.scenario == "all" else {args.scenario: SCENARIOS[args.scenario]}
    )

    nginx_lines: list[str] = []
    auth_lines: list[str] = []
    per_scenario: list[tuple[str, int]] = []
    for name, fn in selected.items():
        ng, au = fn(now)
        nginx_lines.extend(ng)
        auth_lines.extend(au)
        per_scenario.append((name, len(ng) + len(au)))

    mode = "a" if args.append else "w"
    with open(auth_path, mode) as fh:
        for ln in auth_lines:
            fh.write(ln + "\n")
    with open(nginx_path, mode) as fh:
        for ln in nginx_lines:
            fh.write(ln + "\n")

    for name, n in per_scenario:
        print(f"[gen] {name:<22} {n} linha(s)")
    print(f"[ok] auth  → {auth_path} ({len(auth_lines)} linhas)")
    print(f"[ok] nginx → {nginx_path} ({len(nginx_lines)} linhas)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
