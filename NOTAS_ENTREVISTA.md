# Mini-SIEM — Notas para Entrevista

> Documento vivo. Serve como roteiro para explicar o projeto em entrevista
> técnica, bem como para defender cada decisão de design.
>
> **Estado atual:** Etapas 1–6 de 8 concluídas. Faltam gerador de logs
> sintéticos e polimento (README + CI).

---

## 1. Elevator pitch (30s)

> "Construí um SIEM em miniatura em Python, do zero, para aprender e demonstrar
> o pipeline completo de SOC: coleta de logs reais (auth.log, Nginx, syslog UDP),
> normalização para um esquema ECS-like, armazenamento em SQLite, motor de
> detecção com 5 regras em YAML mapeadas para MITRE ATT&CK, dedupe de alertas
> e CLI operacional. O código é modular — collector, parser, storage, detection,
> alerting, API — para que cada camada seja substituível (SQLite → OpenSearch,
> regra própria → Sigma, etc.). Testes com pytest em cada módulo."

---

## 2. Stack e por que cada escolha

| Camada | Escolha | Por quê |
|---|---|---|
| Linguagem | Python 3.12 | Ecossistema de parsers/log maduro, legibilidade, familiaridade. |
| Framework HTTP | FastAPI (Etapa 6) | Async-ready, OpenAPI grátis, Pydantic nativo. |
| Validação | Pydantic 2 | Mensagens de erro excelentes, type-safe, zero boilerplate. |
| Storage | SQLite (WAL) | Zero infra para rodar/demonstrar, suficiente p/ 100k+ eventos. |
| Config | YAML | Legível por humanos; regras SIEM reais usam YAML (Sigma, Falco). |
| CLI | argparse | Stdlib, suficiente, sem dependência externa. |
| Testes | pytest | Padrão de facto. |
| Container | Docker Compose | Portabilidade, demo em 1 comando. |

**Trade-off consciente:** não usei Poetry/Pipenv (`requirements.txt` puro) para
reduzir atrito de setup. Em projeto maior, trocaria.

---

## 3. Arquitetura

```
                 ┌───────────────────────────────────────┐
                 │             MINI-SIEM                 │
                 │                                       │
  /var/log/      │  ┌─────────┐  queue  ┌─────────┐      │
  auth.log  ───►─┼─►│collector├────────►│ parser  │      │
  nginx     ───►─┼─►│ (tail)  │         │ (ECS)   │      │
                 │  └─────────┘         └────┬────┘      │
  syslog UDP ───►┼─►┌─────────┐              ▼           │
  (5514)         │  │ syslog  │         ┌─────────┐      │
                 │  │ server  │────────►│storage  │      │
                 │  └─────────┘         │ SQLite  │      │
                 │                      └────┬────┘      │
                 │                           ▼           │
                 │                      ┌─────────┐      │
                 │                      │detection│◄── regras YAML + ATT&CK
                 │                      └────┬────┘      │
                 │                           ▼           │
                 │                      ┌─────────┐      │
                 │                      │alerting │──► webhook (Etapa 5)
                 │                      └────┬────┘      │
                 │                           ▼           │
                 │                      ┌─────────┐      │
                 │                      │  API    │──► Dashboard (Etapa 6)
                 │                      └─────────┘      │
                 └───────────────────────────────────────┘
```

**Fluxo em uma frase:** fonte → coletor → fila em memória → parser →
Event ECS-like → SQLite → motor de regras → alerta (webhook + API).

---

## 4. Esquema de evento (ECS-like)

Contrato central: todo parser produz um `Event` com estes campos:

| Campo | Tipo | Exemplo |
|---|---|---|
| `timestamp` | ISO-8601 UTC | `2026-10-11T14:33:02Z` |
| `host_name` | str | `web-01` |
| `source_type` | `auth` \| `nginx` \| `syslog` | `auth` |
| `event_action` | str | `login_failed`, `http_request`, `sudo` |
| `event_outcome` | `success` \| `failure` | `failure` |
| `user_name` | str \| null | `root` |
| `source_ip` | str \| null | `203.0.113.42` |
| `http_status` | int \| null | `404` |
| `http_path` | str \| null | `/.env` |
| `message_raw` | str | linha original (auditoria) |
| `severity` | `low` \| `medium` \| `high` \| `critical` | `medium` |

### Por que não ECS puro?

**Decisão:** campos planos em snake_case Python (`event_action`), serializados
em dotted ECS (`event.action`) via `Event.to_ecs()`.

**Defesa:** código Python fica ergonômico (`event.source_ip` é natural;
`event["source.ip"]` seria barulho). A compatibilidade ECS é mantida *no limite*
(serialização, CLI `parse`). Dois mundos sem conflito.

**Alternativa rejeitada:** aliases Pydantic (`Field(alias="source.ip")`) —
funciona mas obscurece o código e trava a sintaxe de acesso.

---

## 5. Storage: SQLite — por que basta

### Decisões

1. **WAL mode + `synchronous=NORMAL`** — reader e writer concorrentes (API lê
   enquanto collector escreve) sem bloqueio.
2. **Timestamps como ISO-8601 text** — lexicograficamente ordenáveis, timezone-
   aware. SQLite não tem tipo nativo; outras alternativas (unix epoch) são
   menos legíveis e piores para debug.
3. **Índices em `(timestamp)`, `(source_ip)`, `(user_name)`** — as 3 colunas
   mais filtradas. Sem índice extra em `event_action` para evitar overhead de
   escrita; na escala MVP, scan + filtro em memória é suficiente.
4. **Tabela `schema_version`** — mesmo com 1 migração, demonstra consciência
   de evolução de schema.
5. **`UNIQUE(dedupe_key)` em `alerts`** — dedupe no banco em vez de na
   aplicação. Zero race condition entre múltiplos processos de detecção.

### Trade-off

- SQLite tem **um writer global**. Resolvido com um único writer thread
  (ver §6).
- Não escala horizontalmente. Troca para Postgres/OpenSearch seria a próxima
  evolução; o módulo `storage/queries.py` isola isso.

---

## 6. Collector: producer-consumer explícito

### Decisão

N threads de coletor (`file_tail`, `syslog_server`) são **producers** que
colocam `Event` em uma `queue.Queue(maxsize=10_000)`. **Uma** thread
`writer` é consumer, dona exclusiva da conexão SQLite.

### Por que não escrita direta por thread?

- SQLite tem **lock de escrita global** → múltiplos writers = contenção.
- Backpressure natural: fila cheia bloqueia o producer (não perde evento
  silenciosamente, não trava o SQLite).
- Testável: substituir o writer por um `sink.append` nos testes é trivial.
- Shutdown limpo: o writer drena a fila após `stop_event` antes de sair.

### File tail

**Decisão:** detecção de rotação por **inode**, não por tamanho.

- Logrotate renomeia o arquivo e cria um novo com o mesmo nome. O inode do
  caminho muda; o tamanho é truncate (também sinal, mas falso positivo
  possível). Inode é como o próprio logrotate "fala".
- Buffer de linha parcial: `read()` pode retornar meio evento; só emito ao
  encontrar `\n`.
- `start_from_end=True` existe para modo produção realista; `False` facilita
  demo (processa tudo + segue).

### Syslog UDP

**Decisão:** UDP com `settimeout(0.3s)` no socket.

- Sem timeout, `recvfrom()` bloqueia pra sempre → `stop_event` nunca é
  verificado → shutdown trava.
- UDP only no MVP: TCP syslog (RFC5425/6587) adiciona framing e handshake.
  Fácil de adicionar depois.
- Strip de `<PRI>` (RFC3164): `<34>Oct...` → `Oct...` antes de passar ao
  parser, que não precisa saber que veio de syslog.

---

## 7. Parser: contrato "nunca lança exceção"

### Decisão

`parse_line(source_type, line)` retorna `Event | None`. Linha irrelevante
(CRON, pam_unix session) → `None`. Linha malformada → `None`. **Nunca `raise`**.

### Por que

- Logs reais têm UTF-8 inválido, formato variante, lixo entre linhas. Se o
  parser lança, o collector precisa envolver em try/except — regra de ouro
  invertida: dever "não quebrar" fica com quem conhece o formato.
- Chamador trata um único retorno: `if event: on_event(event)`.
- Invariante testável explicitamente (`test_malformed_line_returns_none`).

### `invalid user` achatado para user normal

```
Failed password for invalid user admin from 198.51.100.5 ...
```

Vira `user_name="admin"`, não `"invalid user admin"`. Perder essa info seria
estragar a regra "login após falhas" — tentativas em usuário inexistente são
sinal de bruteforce enumeration.

### Registry em `parser/__init__.py`

Adicionar nova fonte amanhã = 1 linha no dict `PARSERS`. Collector e CLI já
usam `parse_line(source_type, line)` genérico.

---

## 8. Detection: 4 primitivas → 5 regras

### Decisões

1. **Batch mode, não streaming**. `mini-siem detect` roda sob demanda contra
   o SQLite. Produz alertas, grava, retorna.
2. **4 tipos de regra** cobrem as 5:
   - `threshold`: N eventos de X em janela de M min, agrupados por entidade
     → bruteforce SSH **e** varredura de diretório (reuso!)
   - `sequence`: evento B após ≥N eventos A da mesma entidade em janela
     → login após falhas
   - `time_of_day`: evento fora do horário permitido em TZ configurável
     → login fora do expediente
   - `rarity`: entidade com ≤N ocorrências em baseline de D dias
     → sudo por usuário incomum
3. **YAML plano, validado por `_validate` no load**: campos obrigatórios +
   `type` entre os conhecidos. Sem Pydantic nas regras — simplicidade.
4. **Dedupe por UNIQUE(dedupe_key)** no banco:
   - `threshold`: `{rule}:{entity}:{bucket_window_floor}`
   - `sequence`: `{rule}:{entity}:{trigger_timestamp}`
   - `time_of_day`: `{rule}:{entity}:{data_local}`
   - `rarity`: `{rule}:{entity}:{data}`
   - Resultado: rodar `detect` 10× no mesmo dado = 1 alerta no DB.

### As 5 regras + MITRE ATT&CK

| ID | Tipo | Severidade | Tactic | Technique |
|---|---|---|---|---|
| `ssh_bruteforce` | threshold | high | TA0006 — Credential Access | T1110 — Brute Force |
| `login_after_failures` | sequence | critical | TA0001 — Initial Access | T1110.001 — Password Guessing |
| `web_dir_scan` | threshold | medium | TA0043 — Reconnaissance | T1595.003 — Wordlist Scanning |
| `off_hours_login` | time_of_day | medium | TA0001 — Initial Access | T1078 — Valid Accounts |
| `unusual_sudo` | rarity | high | TA0004 — Privilege Escalation | T1548.003 — Sudo and Sudo Caching |

### Segurança: whitelist em `filter`/`group_by`

**Problema:** `filter` em YAML vira cláusula SQL. Se o atacante edita
`ssh_bruteforce.yml` para `filter: {"source_type; DROP TABLE events; --": "x"}`,
sem whitelist viraria SQL injection.

**Mitigação:** `ALLOWED_FILTER_FIELDS` e `ALLOWED_GROUP_BY` são sets fixos no
código. Qualquer campo fora disso levanta `ValueError`. Teste cobre
(`test_filter_rejects_arbitrary_sql_fields`).

### Sliding window — honesto sobre o que fiz

Uso **janela fixa a partir de `--since`** em `threshold`, não sliding real.
Sliding de verdade = para cada evento, contar vizinhos nos últimos X min →
SQL caro ou ring buffer em memória. Trade-off consciente: aceito falsos
negativos nas bordas da janela em troca de simplicidade. Vale citar
proativamente.

---

## 8b. Alerting: webhook com retry gratuito

### Decisões

1. **Dois dedupes separados**:
   - **Persistência**: `UNIQUE(dedupe_key)` em `alerts` (Etapa 4).
   - **Envio**: coluna `notified_at` (Etapa 5). `NULL` = ainda não notificado.
   - **Por que separar**: se o webhook falhar (rede caiu, Discord 503), o
     alerta já existe no banco e a próxima execução de `notify` tenta de
     novo. Zero perda de informação, retry gratuito.
2. **Schema v2 com migração idempotente**:
   - `init_db` detecta coluna faltando via `PRAGMA table_info` e aplica
     `ALTER TABLE`. Rodar em DB antigo = migra; em DB novo = no-op.
   - Teste `test_migration_adds_column_on_legacy_db` cria um DB v1 cru e
     verifica que `init_db` migra sem perder dados.
3. **`send()` nunca lança**:
   - Retorna `bool`. Timeout, 5xx, DNS fail = `False`. Dispatcher mantém
     `notified_at` NULL em falha → próximo retry pega.
4. **Auto-detect de provider por URL**:
   - Discord: `discord.com`/`discordapp.com` → embed-friendly payload com
     `username` + `content`.
   - Slack: `hooks.slack.com` → `text`.
   - Genérico: qualquer outra → `{text, alert}`, útil pra ntfy, webhook próprio.
5. **FIFO por `id ASC`** nos pending — mais justo que LIFO, previsível.
6. **Dependency injection no HTTP client**: `dispatch_pending_alerts(...,
   http_client=X)`. Testes injetam `_MockClient` que grava chamadas.
   Produção usa `httpx.Client` default.

### Trade-offs

- **Sem rate limit**: Discord permite 30 req/min por canal. Com N alertas
  simultâneos pode levar 429. Mitigação futura: fila de envio com
  `asyncio.sleep` ou retry backoff.
- **Sem agrupamento**: cada alerta vira 1 webhook. 10 regras disparando =
  10 pings. Para redução de ruído, agrupar por `rule_id` em um único
  embed seria a próxima iteração.
- **Payload inclui dict cru do alerta** (modo genérico) — vazamento de
  info interna. Em produção filtraria campos sensíveis.

---

## 8c. API + Dashboard (FastAPI + Jinja + HTMX)

### Decisões

1. **FastAPI + Jinja + HTMX, sem SPA.** Toolchain curta: zero build step,
   zero npm, HTML renderizado no server. HTMX faz polling a cada 5s em
   fragmentos (`/partials/alerts`, `/partials/events`). Chart.js via CDN.
2. **Separação clara entre `/api/*` (JSON) e `/` (HTML).** O dashboard é
   um consumidor da API; qualquer cliente externo (curl, outro frontend)
   usa os mesmos endpoints JSON. Dois contratos, uma lógica.
3. **Dependency injection do SQLite:** `get_conn()` é um FastAPI dep que
   abre conexão por request e fecha no finally. WAL mode permite múltiplos
   leitores (API) com o writer concorrente (collector).
4. **`lifespan` em vez de `@app.on_event`:** forma recomendada moderna,
   contexto único para startup/shutdown. Chama `init_db` no startup
   (idempotente — safe mesmo em DB existente).
5. **Timeline em buckets de 1 min via SQL puro:** `substr(timestamp,1,16)`
   agrupa por minuto, `GROUP BY bucket`. Zero libs, zero pandas.
6. **Search com `LIKE %q%`** no `message_raw`. FTS5 do SQLite seria upgrade
   óbvio para datasets maiores — e está citado como melhoria.

### Endpoints

```
GET  /                    dashboard HTML
GET  /partials/alerts     fragmento HTMX (table de alertas)
GET  /partials/events     fragmento HTMX (table de eventos)
GET  /api/events          JSON: filtros since/ip/user/source/limit
GET  /api/alerts          JSON: filtros since/rule/severity/limit
GET  /api/search          JSON: q=TEXT no message_raw
GET  /api/stats           JSON: counts 24h, top IPs, severity mix, timeline 1h
```

### Trade-offs

- **Sem autenticação**: dashboard é local-only. Em produção: Basic Auth no
  nginx reverse-proxy, ou OAuth2 via FastAPI dep. Citado como melhoria.
- **Polling em vez de WebSocket**: mais simples, cache-friendly, funciona
  atrás de qualquer proxy. Para 100+ eventos/segundo em tempo real,
  WebSocket faria sentido.
- **Chart.js e HTMX via CDN**: requer internet para o dashboard. Vendorar
  localmente é 2 arquivos extras — trivial se precisar offline.
- **Sem paginação nos endpoints JSON**: só `limit`. Em datasets grandes
  seria `limit + offset` ou cursor-based. Para MVP tudo bem.

### Como demonstrar

```bash
mini-siem serve                   # http://localhost:8000
curl -s http://localhost:8000/api/stats | jq
curl -s "http://localhost:8000/api/search?q=.env" | jq
```

---

## 9. CLI design

```
mini-siem version
mini-siem init-db [--db PATH]
mini-siem parse  --source <auth|nginx> <path>              # JSONL ECS
mini-siem run    --tail SRC:PATH [--syslog PORT[:SRC]]     # daemon
mini-siem query  [--since 1h] [--ip X] [--user Y] ...      # eventos
mini-siem detect [--rules DIR] [--since 1h] [--notify]     # roda regras
mini-siem alerts [--since 1h] [--rule X] [--severity Y]    # alertas
mini-siem notify [--webhook-url URL] [--provider ...]      # retry de envios
mini-siem serve  [--host 0.0.0.0] [--port 8000]            # API + dashboard
```

### Decisões

- **argparse em vez de click/typer**: stdlib, sem dependência extra.
- **Subcomandos com `set_defaults(func=...)`**: cada handler é testável
  isolado.
- **Flags curtas e explícitas**: `--since 15m` em vez de `--since-minutes 15`
  — ergonomia > exatidão.
- **Saída JSONL para `parse`/`query`/`alerts`**: pipe-friendly, consumível
  por `jq`, qualquer outro tool.
- **`[info] ... → stderr`**, dados → stdout: respeita convenção Unix.

---

## 10. Testes

### Estado atual: 77 testes passando

| Área | Arquivo | Testes |
|---|---|---|
| Smoke | test_smoke.py | 3 |
| Parser auth.log | test_parser_auth_log.py | 11 |
| Parser Nginx | test_parser_nginx.py | 7 |
| Storage queries | test_storage_queries.py | 8 |
| Collector file_tail | test_collector_file_tail.py | 5 |
| Collector syslog UDP | test_collector_syslog.py | 4 |
| Detection (4 regras + dedupe + load + segurança) | test_detection.py | 13 |
| Alerting (formatter, dispatcher, migração) | test_alerting.py | 13 |
| API (JSON + HTML + search + stats) | test_api.py | 13 |

### Princípios

1. **Testes em módulos puros são a prioridade** (parsers, queries, dedupe) —
   onde regressão é fácil e o custo baixo.
2. **Fixtures com casos reais e ruído**: `auth_sample.log` tem SSH failures,
   publickey, sudo, CRON (ignorado), pam_unix (ignorado), preauth (ignorado).
3. **Threads nos testes**: `file_tail` e `syslog_server` rodam em thread com
   `stop_event`, timeout de join, `_wait_until(predicate, timeout)` para
   evitar flakiness.
4. **E2E manual** (`run` + `detect` + `alerts`) cobre o que teste unitário
   não cobre — mas documentado no README.

---

## 11. Trade-offs — tabela rápida

| Escolha | Ganho | Trade-off |
|---|---|---|
| SQLite | Zero infra, demo em 1 comando | Não escala horizontal; 1 writer. |
| Queue in-memory | Backpressure natural, código simples | Perde eventos em crash; sem persistência. |
| Regras YAML + motor próprio | Transparente, defensável linha-a-linha | Reinventa Sigma — melhoria futura. |
| Batch detection | Idempotente, simples | Latência de detecção = intervalo de execução. |
| Janela fixa (não sliding) | SQL barato | Falsos negativos nas bordas. |
| FastAPI + Jinja + HTMX (Etapa 6) | Dashboard em 1 arquivo HTML | Visual simples; sem SPA. |
| 1 writer thread | Zero contenção SQLite | Único ponto de serialização. |
| Parsers nunca lançam | Collector não precisa envolver try | Erros silenciados (contrabalançar com testes). |

---

## 12. Limitações conhecidas (cite antes do entrevistador perguntar!)

1. **Ano implícito em syslog clássico.** `auth.log` RFC3164 não tem ano;
   assumo `datetime.now().year`. Logs cruzando virada de ano = aproximação.
   Journald/RFC5425 resolveria.
2. **UTC assumido em `auth.log`.** Em sistemas com timezone local, deveria
   converter de local → UTC. Documentado; para portfólio é aceitável.
3. **Sem persistência da queue.** Crash entre `queue.put` e insert = perda.
   Em produção: Redis Streams / Kafka.
4. **Sem autenticação na API** (Etapa 6). Dashboard local-only. Em prod:
   OAuth / mTLS.
5. **Sliding window aproximado** — ver §8.
6. **Dedupe granular**: um `dedupe_key` perfeito para `threshold` seria o
   bucket exato da janela deslizante. Com janela fixa, dois bursts em
   janelas adjacentes podem virar 1 ou 2 alertas dependendo do alinhamento.
7. **Sem rate-limiting no syslog UDP.** Flood = fila cheia = producer
   bloqueado. Vale colocar no roadmap de hardening.
8. **GeoIP, threat intel, user context** = Etapa de enriquecimento futura
   (ver §13).

---

## 13. Melhorias futuras (3 que vou propor no README final)

1. **Correlação cross-source**: encadear `ssh_bruteforce` → `login_success`
   → `sudo` do mesmo IP/sessão = **incident chain**, não 3 alertas soltos.
2. **Suporte a regras Sigma**: parser Sigma → formato interno. Mostra
   conhecimento do padrão de facto da indústria SOC.
3. **Enriquecimento**:
   - GeoIP (MaxMind GeoLite2 free) → country/ASN no evento
   - Reputação de IP (AbuseIPDB / AlienVault OTX) → score
   - Contexto de usuário (último login conhecido, horário habitual)
   → eleva sinal/ruído.

---

## 14. Perguntas prováveis + respostas curtas

### "Por que SQLite e não Postgres/Elastic?"
> "Para portfólio, SQLite elimina overhead de infra sem comprometer o
> aprendizado. O módulo `storage/queries.py` isola o DB — trocar é mudar
> uma camada. Para dezenas de milhões de eventos ou busca full-text, migraria
> para OpenSearch."

### "Como você detecta rotação de log?"
> "Comparo o inode do caminho a cada ciclo. Se o inode muda, reabro — é
> como o próprio logrotate sinaliza arquivo novo. Comparar tamanho dá falso
> positivo em truncate."

### "Por que não escrever direto no SQLite de cada thread coletora?"
> "SQLite tem lock de escrita global. Múltiplos writers = contenção +
> complexidade de retry. Um writer único via `queue.Queue` é o padrão
> producer-consumer textbook: zero contenção e backpressure natural."

### "Como você faz dedupe de alertas?"
> "Dois níveis. **Persistência**: `UNIQUE(dedupe_key)` no DB — chave inclui
> `rule_id`, `entity` e bucket temporal específico do tipo de regra; rodar
> `detect` 10× é idempotente. **Envio**: coluna `notified_at`; `NULL` =
> ainda não notificado. Se o webhook falha, o alerta permanece pendente e
> o próximo `notify` tenta de novo. Zero perda, retry grátis."

### "E se o Discord ficar fora do ar?"
> "O `send()` nunca lança — retorna `False`. O dispatcher não atualiza
> `notified_at` nesse caso, então o alerta continua pendente. Um cron
> executando `mini-siem notify` a cada minuto reenvia automaticamente
> quando a conexão volta. Teste cobre: `test_retry_after_failure_eventually_succeeds`."

### "Como você evita SQL injection via YAML?"
> "Campos de `filter` e `group_by` passam por whitelist antes de virarem
> SQL. Nome fora da whitelist levanta `ValueError`. Valores sempre vão como
> parâmetros bindados, nunca interpolados. Teste
> `test_filter_rejects_arbitrary_sql_fields` cobre."

### "Por que YAML e não Sigma direto?"
> "Didático: motor próprio me força a entender o que uma regra realmente
> é. Sigma está no roadmap — basta um parser Sigma → formato interno."

### "Qual é a latência de detecção?"
> "Batch, portanto = intervalo entre execuções. Em um cron de 1 min, latência
> p99 ≈ 1 min + tempo de query. Para streaming real: motor incremental em
> cima do collector, usando a mesma `queue.Queue` + ring buffers por regra."

### "Como você faria para escalar?"
> "Três eixos:
> 1. Storage: SQLite → Postgres (upsert concorrente) ou OpenSearch
>    (full-text + agregações).
> 2. Fila: `queue.Queue` → Redis Streams/Kafka para persistência + múltiplos
>    consumers.
> 3. Detection: batch → streaming com estado por regra em memória
>    (ou Flink/ksqlDB)."

### "O que você faz com UTF-8 inválido no log?"
> "Abro arquivos com `errors='replace'`. UDP com `decode('utf-8',
> errors='replace')`. Parser nunca lança — se não entender a linha, retorna
> `None` e o collector segue."

### "Como você garantiria entrega mesmo com crash?"
> "A `queue.Queue` em memória é o ponto frágil. Para at-least-once:
> trocar por Redis Streams com ack após insert. Para exactly-once: idempotência
> no insert (upsert por hash de `message_raw`) — mas custo de hash em todo
> evento. Depende do SLA."

---

## 15. Como demonstrar ao vivo (roteiro 10 min)

1. **Mostrar o repo e PLAN.md** (30s): "Projeto em 8 etapas, 4 feitas."
2. **`make test`** (30s): 51 passed. "Testes em cada módulo."
3. **`python -m mini_siem parse --source auth tests/fixtures/auth_sample.log`**
   (1 min): "Normalização ECS; JSONL pipe-friendly."
4. **Rodar `run` com `--tail /var/log/auth.log` em um terminal** (1 min).
   Em outro terminal: SSH loopback com senha errada 6× → mostrar
   `mini-siem query --ip 127.0.0.1`.
5. **`mini-siem detect`** (1 min): "5 regras aplicadas, 2 alertas gerados."
   Mostrar que a 2ª execução não duplica (dedupe).
6. **`mini-siem alerts --severity critical`**: trazer o alerta `login_after_failures`
   e explicar a correlação sequence (3 falhas → 1 sucesso).
7. **Abrir uma regra YAML** (1 min): explicar mapping para MITRE
   (`T1110.001`), por que `window_minutes=10`, por que `min_count=3`.
8. **Mostrar `tests/test_detection.py::test_filter_rejects_arbitrary_sql_fields`**
   (30s): "Pensei em segurança de supply chain do próprio arquivo de regra."
9. **Mencionar o que falta** (30s): alerting webhook, API/dashboard, gerador
   sintético, polimento + CI.
10. **Terminar com as 3 melhorias futuras** (§13).

---

## 16. Linha do tempo (etapas e artefatos)

| # | Etapa | Entregáveis | Status |
|---|---|---|---|
| 1 | Fundação | `schema.py` (Pydantic), `storage/db.py` (SQLite + WAL + migração), Dockerfile, compose, Makefile, requirements, pytest.ini, smoke test | ✅ |
| 2 | Parsers | `parser/auth_log.py`, `parser/nginx.py`, `parser/__init__.py` (registry), fixtures reais, CLI `parse`, 18 testes | ✅ |
| 3 | Collector + storage | `collector/file_tail.py` (inode rotation), `collector/syslog_server.py` (UDP), `collector/__init__.py` (CollectorRunner), `storage/queries.py`, CLI `run`/`query`, 17 testes | ✅ |
| 4 | Detecção | `detection/rules.py` (4 handlers), `detection/engine.py` (load + dispatch), 5 regras YAML com ATT&CK, `storage.insert_alert` + dedupe, CLI `detect`/`alerts`, 13 testes | ✅ |
| 5 | Alerting | `alerting/formatter.py` (Discord/Slack/generic), `alerting/webhook.py` (nunca lança), `alerting/dispatch_pending_alerts` (FIFO + retry), schema v2 com migração idempotente, CLI `--notify`/`notify`, 13 testes | ✅ |
| 6 | API + Dashboard | `api/app.py` (FastAPI com lifespan + 7 rotas), templates Jinja (base + dashboard + partials HTMX), Chart.js timeline, `search` LIKE, CLI `serve`, 13 testes | ✅ |
| 7 | Gerador de logs | `tools/log_generator.py`, cenário por regra, `make demo` | — |
| 8 | Polimento | README completo, screenshots, GitHub Actions CI | — |
