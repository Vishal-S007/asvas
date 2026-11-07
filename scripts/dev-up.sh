#!/usr/bin/env bash
# Start the full local stack (development only). Requires: PostgreSQL 16 + Redis running locally,
# `uv`, Go >= 1.26, and the OPA binary in .tools/ (see README). Logs go to var/logs/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p var/logs var/run
set -a; [ -f .env ] && . ./.env || . ./.env.example; set +a
export ASVAS_POLICY_DIR="$ROOT/policies"
[ -f var/certs/executor.crt ] || ./scripts/dev-certs.sh >/dev/null
# Relative TLS paths in .env are resolved from the repository root.
for v in ASVAS_KEYRING_FILE ASVAS_TLS_CA ASVAS_TLS_CERT ASVAS_TLS_KEY ASVAS_EXECUTOR_TLS_CA ASVAS_EXECUTOR_TLS_CERT ASVAS_EXECUTOR_TLS_KEY; do
  val="${!v:-}"; [ -n "$val" ] && [ "${val#/}" = "$val" ] && export "$v=$ROOT/$val"
done

start() { # name, cmd...
  local name=$1; shift
  if [ -f "var/run/$name.pid" ] && kill -0 "$(cat var/run/$name.pid)" 2>/dev/null; then echo "$name already running"; return; fi
  nohup "$@" > "var/logs/$name.log" 2>&1 &
  echo $! > "var/run/$name.pid"; echo "started $name (pid $!)"
}

OPA="${OPA_BIN:-$ROOT/.tools/opa}"
if [ -x "$ROOT/.tools/neo4j/bin/neo4j" ] && [ -n "${ASVAS_NEO4J_URI:-}" ]; then
  "$ROOT/.tools/neo4j/bin/neo4j" status >/dev/null 2>&1 || "$ROOT/.tools/neo4j/bin/neo4j" start >/dev/null 2>&1
  echo "neo4j started (graph projection enabled)"
fi
start opa "$OPA" run --server --addr 127.0.0.1:8181 --log-level error "$ROOT/policies/asvas/decision.rego"
(cd control-plane && uv run asvas migrate >/dev/null && uv run asvas seed-dev >/dev/null)
start target python3 test-target/target.py
start api bash -c "cd control-plane && exec uv run asvas api"
start orchestrator bash -c "cd control-plane && exec uv run asvas orchestrator"
start report-worker bash -c "cd control-plane && exec uv run asvas report-worker"
(cd execution-plane && go build -o bin/asvas-executor ./cmd/asvas-executor && chmod 755 bin/asvas-executor)
if [ "$(id -u)" = "0" ]; then
  start executor execution-plane/bin/asvas-executor
else
  echo "NOTE: executor not root -> no per-UID sandbox and no nftables egress (degraded; shown in dashboard)."
  start executor execution-plane/bin/asvas-executor
fi
echo "API http://127.0.0.1:8000/api/v1/health   dashboard: cd dashboard && npm run dev"
