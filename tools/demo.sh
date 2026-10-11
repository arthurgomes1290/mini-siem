#!/usr/bin/env bash
# Demo end-to-end do mini-SIEM — gera logs sintéticos, ingere, detecta,
# lista alertas. Reproduz as 5 regras em < 10 segundos.
#
# Rodagem local (fora do container):
#   ./tools/demo.sh
#
# Variáveis:
#   PYTHON      interpretador (default: .venv/bin/python, fallback python3)
#   SIEM_DB_PATH  caminho do SQLite (default: ./data/demo.db)
#   KEEP_DB     se "1", não apaga o banco antes de rodar

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -z "${PYTHON:-}" ]]; then
    if [[ -x "$ROOT/.venv/bin/python" ]]; then
        PYTHON="$ROOT/.venv/bin/python"
    else
        PYTHON="python3"
    fi
fi

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

DB="${SIEM_DB_PATH:-$ROOT/data/demo.db}"
SYNTH="$ROOT/data/synthetic"
RULES="$ROOT/config/rules"

mkdir -p "$(dirname "$DB")" "$SYNTH"

if [[ "${KEEP_DB:-0}" != "1" ]]; then
    rm -f "$DB"
fi
rm -f "$SYNTH/auth.log" "$SYNTH/nginx.log"

echo "[demo] db=$DB"
echo "[demo] 1/4 inicializando schema"
"$PYTHON" -m mini_siem init-db --db "$DB"

echo "[demo] 2/4 gerando logs sintéticos"
"$PYTHON" "$ROOT/tools/log_generator.py" --out-dir "$SYNTH"

echo "[demo] 3/4 ingerindo (coletor roda ~3s e para)"
"$PYTHON" -m mini_siem run \
    --tail "auth:$SYNTH/auth.log" \
    --tail "nginx:$SYNTH/nginx.log" \
    --db "$DB" &
RUN_PID=$!
# Dá tempo para o tail abrir e drenar os arquivos.
sleep 3
# SIGTERM é tratado em main.py; aguarda shutdown gracioso.
kill -TERM "$RUN_PID" 2>/dev/null || true
wait "$RUN_PID" 2>/dev/null || true

echo
echo "[demo] 4/4 rodando detecção"
"$PYTHON" -m mini_siem detect --rules "$RULES" --db "$DB"

echo
echo "[demo] alertas gerados:"
"$PYTHON" -m mini_siem alerts --limit 20 --db "$DB"
