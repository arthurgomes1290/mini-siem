# mini-siem

> SIEM enxuto, funcional e demonstrável — coleta logs reais, normaliza para um
> esquema ECS-like, aplica regras de detecção com mapeamento MITRE ATT&CK e
> dispara alertas via webhook.

Stack: **Python 3.12 · FastAPI · SQLite · Docker · Linux**.

[![CI](https://github.com/arthurgomesadr/mini-siem/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

---

## Por que existe

Portfólio: um SIEM em miniatura que cabe num repositório e pode ser explicado
linha por linha numa entrevista, sem esconder complexidade atrás de
dependências pesadas. Cobre o pipeline completo: **coleta → normalização →
armazenamento → detecção → alerta → visualização**.

## Arquitetura

```
                 ┌───────────────────────────────────────┐
                 │             MINI-SIEM                 │
                 │                                       │
  /var/log/      │  ┌─────────┐   fila   ┌─────────┐     │
  auth.log  ───►─┼─►│collector├─────────►│ parser  │     │
  nginx     ───►─┼─►│ (tail)  │          │ (ECS)   │     │
                 │  └─────────┘          └────┬────┘     │
  syslog UDP ───►┼─►┌─────────┐               ▼          │
  (5514)         │  │ syslog  │          ┌─────────┐     │
                 │  │ server  │─────────►│storage  │     │
                 │  └─────────┘          │ SQLite  │     │
                 │                       └────┬────┘     │
                 │                            ▼          │
                 │                       ┌─────────┐     │
                 │                       │detection│◄── YAML (regras + ATT&CK)
                 │                       └────┬────┘     │
                 │                            ▼          │
                 │                       ┌─────────┐     │
                 │                       │alerting │──► webhook (Discord/Slack)
                 │                       │(dedupe) │     │
                 │                       └────┬────┘     │
                 │                            ▼          │
                 │                       ┌─────────┐     │
                 │                       │  API    │──► Dashboard (FastAPI + Jinja + HTMX)
                 │                       └─────────┘     │
                 └───────────────────────────────────────┘
```

**Em uma frase:** fonte → coletor → fila em memória → parser → evento ECS-like
→ SQLite → motor de regras → alerta → (webhook + API/dashboard).

## Rápido: `make demo`

Em menos de 10 segundos: gera logs sintéticos, ingere, roda detecção e lista
alertas — um por regra.

```bash
./tools/demo.sh          # ou: make demo
```

Saída esperada (resumida):

```
[demo] 4/4 rodando detecção
[alert] login_after_failures     critical T1110.001    → 1 novo(s)
[alert] off_hours_login          medium   T1078        → 1 novo(s)
[alert] ssh_bruteforce           high     T1110        → 1 novo(s)
[alert] unusual_sudo             high     T1548.003    → 1 novo(s)
[alert] web_dir_scan             medium   T1595.003    → 1 novo(s)
```

## Dashboard

```bash
python -m mini_siem serve --db ./data/demo.db
# ou: make up && docker compose exec siem python -m mini_siem serve
```

Depois: <http://localhost:8000>.

![Dashboard](docs/screenshots/dashboard.png)

Rotas úteis:

| Rota | O quê |
|---|---|
| `GET /`            | Dashboard (contadores, timeline, severidade, top IPs) |
| `GET /api/events`  | Eventos recentes (filtros: `since`, `ip`, `user`, `source`) |
| `GET /api/alerts`  | Alertas (filtros: `since`, `rule`, `severity`) |
| `GET /api/search?q=` | Busca free-text em `message.raw` |
| `GET /api/stats`   | Contadores, timeline 1 min, severidade, top IPs |

## Regras de detecção (MITRE ATT&CK)

Regras são YAML em `config/rules/`. Cada arquivo mapeia explicitamente para
uma técnica ATT&CK — vocabulário de SOC do dia a dia.

| # | Regra | Tipo | ATT&CK | Severidade |
|---|---|---|---|---|
| 1 | SSH Brute Force | `threshold` | [T1110](https://attack.mitre.org/techniques/T1110/) · Credential Access | high |
| 2 | Successful Login After Multiple Failures | `sequence` | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) · Initial Access | critical |
| 3 | Web Directory Scanning | `threshold` | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) · Reconnaissance | medium |
| 4 | Login Outside Business Hours | `time_of_day` | [T1078](https://attack.mitre.org/techniques/T1078/) · Valid Accounts | medium |
| 5 | Sudo by Unusual User | `rarity` | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) · Privilege Escalation | high |

Novas regras não exigem código — só um YAML novo com um dos 4 tipos:
`threshold`, `sequence`, `time_of_day`, `rarity`.

## Esquema de evento (ECS-like)

Todos os parsers devolvem este contrato — o "idioma" interno do SIEM.

| Campo | Tipo | Exemplo |
|---|---|---|
| `timestamp`     | ISO-8601 UTC | `2026-10-11T14:33:02Z` |
| `host.name`     | string       | `web-01` |
| `source.type`   | `auth` \| `nginx` \| `syslog` | `auth` |
| `event.action`  | `login_failed` \| `login_success` \| `sudo` \| `http_request` | `login_failed` |
| `event.outcome` | `success` \| `failure` | `failure` |
| `user.name`     | string \| null | `root` |
| `source.ip`     | string \| null | `203.0.113.42` |
| `http.status`   | int \| null    | `404` |
| `http.path`     | string \| null | `/.env` |
| `message.raw`   | string         | linha original |
| `severity`      | `low` \| `medium` \| `high` \| `critical` | `medium` |

## Rodando localmente

**Pré-requisitos:** Python 3.12 e `make` (opcional). Para o modo Docker: Docker Engine.

### Opção 1 — venv local

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export PYTHONPATH=src
python -m mini_siem init-db --db ./data/siem.db
python -m mini_siem run --tail auth:/var/log/auth.log --db ./data/siem.db
# em outro terminal:
python -m mini_siem detect --db ./data/siem.db
python -m mini_siem serve --db ./data/siem.db
```

### Opção 2 — Docker

```bash
cp .env.example .env     # ajuste SIEM_WEBHOOK_URL se quiser Discord/Slack
make up                  # build + up
make init-db
make shell               # entra no container para rodar os comandos acima
```

## CLI

```
mini-siem version
mini-siem init-db [--db PATH]
mini-siem parse --source {auth|nginx} FILE          # imprime JSONL ECS
mini-siem run --tail SRC:PATH [--tail ...] [--syslog PORT[:SRC]]
mini-siem query [--since 1h] [--ip ...] [--user ...] [--source ...]
mini-siem detect [--since 1h] [--notify] [--webhook-url URL]
mini-siem alerts [--since 1d] [--rule ID] [--severity ...]
mini-siem notify [--webhook-url URL] [--provider auto|discord|slack|generic]
mini-siem serve [--host 0.0.0.0] [--port 8000]
```

## Testes

```bash
make test                  # python -m pytest
```

77 testes cobrindo parsers, detecção, dedupe, collector (tail + syslog UDP),
storage, API e webhook. CI roda em cada push/PR via GitHub Actions.

## Decisões e trade-offs

| Decisão | Por quê | Trade-off |
|---|---|---|
| **SQLite** como storage | Zero infra, suficiente para 100k+ eventos; demonstrável sem cluster | Um writer apenas; sem FTS sério. Produção usaria OpenSearch/Elastic. |
| **Fila `queue.Queue` em memória** entre coletor e writer | Simples; backpressure natural; uma thread escritora elimina disputa de lock | Perde eventos se o processo cair. Produção: Kafka/Redis Streams. |
| **ECS-like próprio** (não ECS 100%) | Didático; mostra conhecimento sem a complexidade do esquema completo | Não interopera direto com Elastic. |
| **Regras YAML + motor próprio** (não [Sigma](https://sigmahq.io/)) | Transparência total; dá para explicar linha por linha | Reinventa roda — Sigma é o padrão de facto. Melhoria futura. |
| **Mapeamento ATT&CK por regra** | Vocabulário de SOC; diferencial no portfólio | Exige consultar o framework ao escrever cada regra. |
| **FastAPI + Jinja + HTMX** (sem SPA) | Dashboard em 1 arquivo HTML; API moderna sem build step | Visual mais sóbrio — assumido. |
| **Bind mount de `/var/log/auth.log`** no container | Coleta de logs reais, autêntica | Depende de Linux (escopo). |
| **Dedupe por `(regra, entidade, janela)`** | Evita spam de webhook; padrão SOC | Pode suprimir alertas legítimos — mitigável com severity escalation. |

## Limitações conhecidas

- **Sem HA / sem fila durável.** Processo morre → eventos em voo perdidos.
- **Timestamp syslog clássico sem ano** (Debian/Ubuntu auth.log). Usamos o ano
  corrente; log cruzando a virada do ano fica aproximado. Journald/RFC5424
  seriam o próximo passo.
- **SQLite com um writer único** limita throughput de ingestão a algumas
  milhares de linhas/s — suficiente para 1 host, insuficiente para fleet.
- **Dashboard sem autenticação.** OK para localhost; em rede precisa de
  reverse proxy com auth.
- **Fuso para `time_of_day`** vem do YAML; se o host trocar de TZ, revise.

## Melhorias futuras

1. **Correlação cross-source** — encadear `ssh_bruteforce → login_after_failures
   → unusual_sudo` do mesmo IP/sessão em um único *incident chain*, em vez de
   três alertas soltos.
2. **Suporte a regras Sigma** — parser Sigma → formato interno; interoperável
   com o padrão de facto da indústria.
3. **Enriquecimento** — GeoIP (MaxMind GeoLite2), reputação de IP (AbuseIPDB /
   AlienVault OTX), contexto de usuário (último login, horário habitual).
   Eleva a razão sinal/ruído.
4. **Storage pluggable** — abstrair a camada de storage para suportar
   OpenSearch/ClickHouse quando o volume justificar.

## Estrutura do repositório

```
mini-siem/
├── config/rules/              # YAML + ATT&CK mapping
├── docs/                      # diagrama, screenshots
├── src/mini_siem/
│   ├── collector/             # file_tail + syslog_server (UDP)
│   ├── parser/                # auth_log, nginx
│   ├── storage/               # SQLite + queries
│   ├── detection/             # engine + handlers (threshold, sequence, ...)
│   ├── alerting/              # dedupe + webhook (Discord/Slack/generic)
│   └── api/                   # FastAPI + Jinja + HTMX
├── tools/
│   ├── log_generator.py       # 5 cenários sintéticos
│   └── demo.sh                # make demo end-to-end
└── tests/                     # 77 testes
```

## Licença

MIT.
