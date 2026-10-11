# Mini-SIEM — Plano de Projeto

> Projeto de portfólio: SIEM enxuto, funcional e demonstrável, cobrindo coleta,
> normalização, detecção e resposta.
>
> **Perfil:** iniciante em Python, iniciante em segurança.
> **Stack decidida:** Python 3.12 · FastAPI · SQLite · Docker Compose · Linux nativo.

---

## 1. Visão de arquitetura

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
                 │                       │  API    │──► Dashboard (FastAPI + Jinja)
                 │                       └─────────┘     │
                 └───────────────────────────────────────┘
```

**Fluxo em uma frase:** fonte → coletor → fila em memória → parser → evento
ECS-like → SQLite → motor de regras → alerta → (webhook + API/dashboard).

---

## 2. Estrutura de pastas

```
mini-siem/
├── README.md
├── docker-compose.yml
├── Dockerfile
├── requirements.txt           # pin simples, sem Poetry (menos atrito p/ iniciante)
├── .env.example
├── Makefile                   # make up / test / seed / demo
├── docs/
│   ├── architecture.png
│   └── screenshots/
├── config/
│   ├── settings.yml           # webhook, limiares default, horários "normais"
│   └── rules/
│       ├── ssh_bruteforce.yml
│       ├── login_after_failures.yml
│       ├── web_dir_scan.yml
│       ├── off_hours_login.yml
│       └── unusual_sudo.yml
├── src/mini_siem/
│   ├── __init__.py
│   ├── main.py                # CLI: run, parse, detect, seed
│   ├── schema.py              # dataclass Event (ECS-like) + validação
│   ├── collector/
│   │   ├── file_tail.py       # tail -F com tratamento de rotação
│   │   └── syslog_server.py   # UDP + TCP na mesma porta
│   ├── parser/
│   │   ├── auth_log.py
│   │   ├── nginx.py
│   │   └── syslog_rfc.py
│   ├── storage/
│   │   ├── db.py              # schema + migração "manual" simples
│   │   └── queries.py         # buscas por tempo/IP/usuário
│   ├── detection/
│   │   ├── engine.py          # loop + janelas deslizantes
│   │   └── rules.py           # tipos: threshold, sequence, time_of_day, rarity
│   ├── alerting/
│   │   ├── dedupe.py          # chave = (regra, entidade, janela)
│   │   └── webhook.py
│   └── api/
│       ├── app.py             # FastAPI
│       ├── routes.py          # /events /alerts /search /stats
│       └── templates/
│           ├── base.html
│           └── dashboard.html # Jinja + HTMX (sem build step)
├── tools/
│   ├── log_generator.py       # 5 cenários sintéticos, 1 por regra
│   └── demo.sh                # executa cenário + mostra alerta disparado
└── tests/
    ├── conftest.py
    ├── fixtures/{auth,nginx,syslog}_sample.log
    ├── test_parser_auth_log.py
    ├── test_parser_nginx.py
    ├── test_detection_bruteforce.py
    ├── test_detection_dir_scan.py
    └── test_dedupe.py
```

---

## 3. Decisões e trade-offs (para defender em entrevista)

| Decisão | Por quê | Trade-off / limitação |
|---|---|---|
| **SQLite** como storage | Zero infra, demonstrável, suficiente p/ 100k+ eventos | Concorrência limitada (um writer), sem full-text sério. SIEM real usaria OpenSearch/Elastic. |
| **Fila `queue.Queue` em memória** entre estágios | Simples, didático, uma thread por estágio | Perde eventos se o processo cair. Produção: Kafka/Redis Streams. |
| **Esquema ECS-like próprio** (não ECS 100%) | Didático, mostra conhecimento sem complexidade de campos | Não interopera direto com Elastic. Dá para evoluir depois. |
| **Regras em YAML + motor próprio** (não Sigma) | Transparência total; iniciante consegue explicar linha por linha | Reinventa roda — Sigma seria "melhoria futura" (vale citar). |
| **Mapeamento ATT&CK por regra** (tactic + technique) | Diferencial enorme no portfólio; mostra vocabulário de SOC | Precisa consultar o framework ao escrever cada regra. |
| **FastAPI + Jinja + HTMX** (sem React) | Dashboard funcional em ~1 arquivo HTML; API moderna sem overengineering | Visual mais simples. É aceitável e até elogiado — mostra foco. |
| **Bind mount `/var/log/auth.log` RO** no container | Coleta real, autêntica | Depende de Linux (atende ao escopo). |
| **Dedupe por `(regra, entidade, janela)`** | Evita spam de webhook; padrão SOC | Pode suprimir alertas legítimos — mitigar com severity escalation. |
| **Testes focados em parser e regras** | Onde regressão é mais provável e barato de cobrir | Não cobre fluxo end-to-end (justificável no MVP). |

---

## 4. Esquema de evento (ECS-like) — contrato central

Todos os parsers devolvem este dicionário. É o "idioma" interno do SIEM.

| Campo | Tipo | Exemplo |
|---|---|---|
| `timestamp` | ISO-8601 UTC | `2026-10-11T14:33:02Z` |
| `host.name` | string | `web-01` |
| `source.type` | `"auth"` \| `"nginx"` \| `"syslog"` | `"auth"` |
| `event.action` | `"login_failed"` \| `"login_success"` \| `"sudo"` \| `"http_request"` \| ... | `"login_failed"` |
| `event.outcome` | `"success"` \| `"failure"` | `"failure"` |
| `user.name` | string \| null | `"root"` |
| `source.ip` | string \| null | `"203.0.113.42"` |
| `http.status` | int \| null | `404` |
| `http.path` | string \| null | `"/.env"` |
| `message.raw` | string (linha original, para auditoria) | `"Failed password for root from ..."` |
| `severity` | `"low"` \| `"medium"` \| `"high"` \| `"critical"` | `"medium"` |

---

## 5. Regras de detecção (MVP, com MITRE ATT&CK)

| # | Regra | Tipo | ATT&CK |
|---|---|---|---|
| 1 | Força bruta SSH (N falhas em X min) | threshold | T1110 — Brute Force |
| 2 | Login bem-sucedido após várias falhas | sequence | T1110.001 + TA0001 |
| 3 | Varredura de diretórios web (muitos 404 do mesmo IP) | threshold | T1595.003 — Wordlist Scanning |
| 4 | Login fora do horário habitual | time_of_day | T1078 — Valid Accounts |
| 5 | Uso de sudo por usuário incomum | rarity | T1548.003 — Sudo and Sudo Caching |

---

## 6. Plano de entrega (uma etapa por vez, cada uma rodável)

1. **Fundação:** estrutura de pastas, `schema.py`, SQLite com migração, `docker-compose.yml`, Makefile. ✅ `make up` sobe container vazio, `make test` roda (sem testes ainda).
2. **Parsers + testes pytest:** `auth.log` e `nginx` com fixtures reais. ✅ `python -m mini_siem parse tests/fixtures/auth_sample.log` imprime JSON.
3. **Collector + storage:** tail de arquivo (com rotação) e servidor syslog UDP, grava em SQLite. ✅ aponta pro `auth.log` real e consulta via CLI.
4. **Motor de detecção + 5 regras YAML** com ATT&CK. ✅ `siem detect` dispara alertas sobre eventos existentes.
5. **Alerting:** dedupe + webhook Discord (configurável). ✅ cai mensagem no canal.
6. **API + dashboard:** `/events`, `/alerts`, `/search`, página HTML com gráficos simples (Chart.js via CDN). ✅ `http://localhost:8000`.
7. **Gerador de logs sintéticos:** um cenário por regra; `make demo` dispara tudo e você grava screenshots. ✅ demo reproduzível.
8. **Polimento:** README com diagrama, screenshots, limitações; GitHub Actions rodando pytest. ✅ repo "entrevistável".

---

## 7. Melhorias futuras (para citar no fim do README)

1. **Correlação cross-source:** encadear SSH-bruteforce → login-success → sudo-incomum na mesma sessão/IP = *incident chain* em vez de 3 alertas soltos.
2. **Suporte a regras Sigma:** parser Sigma → formato interno; mostra que você conhece o padrão de facto da indústria.
3. **Enriquecimento:** GeoIP (MaxMind GeoLite2 free), reputação de IP (AbuseIPDB/AlienVault OTX), e contexto de usuário (último login conhecido, horário habitual) — eleva o sinal/ruído.

---

## 8. Status

- [x] Arquitetura aprovada
- [x] Etapa 1 — Fundação
- [x] Etapa 2 — Parsers + testes
- [x] Etapa 3 — Collector + storage
- [x] Etapa 4 — Motor de detecção + 5 regras
- [x] Etapa 5 — Alerting (dedupe + webhook)
- [x] Etapa 6 — API + dashboard
- [x] Etapa 7 — Gerador de logs sintéticos
- [x] Etapa 8 — Polimento + README + CI
