#!/usr/bin/env bash
# Start the full local stack (development only). Requires: PostgreSQL 16 + Redis running locally,
# `uv`, Go >= 1.26, and the OPA binary in .tools/ (see README). Logs go to var/logs/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p var/logs var/run
set -a; [ -f .env ] && . ./.env || . ./.env.example; set +a
export ASVAS_POLICY_DIR="$ROOT/policies"
[ -f var/certs/services.crt ] || ./scripts/dev-certs.sh >/dev/null
if [ "${ASVAS_REDIS_URL:-}" != "${ASVAS_REDIS_URL#rediss}" ] && ! (exec 3<>/dev/tcp/127.0.0.1/6380) 2>/dev/null; then
  if [ "$(id -u)" = "0" ]; then ./scripts/dev-tls-services.sh; else echo "TLS Redis not running: run sudo scripts/dev-tls-services.sh"; exit 1; fi
fi
# Relative TLS paths in .env are resolved from the repository root.
for v in ASVAS_OIDC_CA_FILE ASVAS_KEYRING_FILE ASVAS_REDIS_CA_FILE ASVAS_REDIS_CA ASVAS_OPA_CA_FILE ASVAS_API_TLS_CERT ASVAS_API_TLS_KEY ASVAS_TLS_CA ASVAS_TLS_CERT ASVAS_TLS_KEY ASVAS_EXECUTOR_TLS_CA ASVAS_EXECUTOR_TLS_CERT ASVAS_EXECUTOR_TLS_KEY; do
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
if [ -n "${ASVAS_OIDC_ISSUER:-}" ] && [ -x "$ROOT/.tools/keycloak/bin/kc.sh" ] && ! curl -sf --cacert var/certs/ca.crt "$ASVAS_OIDC_ISSUER" >/dev/null; then
  ./scripts/keycloak-dev.sh start && ./scripts/keycloak-dev.sh setup >/dev/null
fi
if [ "${ASVAS_OPA_URL:-}" != "${ASVAS_OPA_URL#https}" ]; then
  start opa "$OPA" run --server --addr 127.0.0.1:8181 --log-level error --tls-cert-file "$ROOT/var/certs/services.crt" \
    --tls-private-key-file "$ROOT/var/certs/services.key" --min-tls-version 1.3 "$ROOT/policies/asvas/decision.rego"
else
  start opa "$OPA" run --server --addr 127.0.0.1:8181 --log-level error "$ROOT/policies/asvas/decision.rego"
fi
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
if [ -n "${ASVAS_API_TLS_CERT:-}" ]; then
  echo "API https://localhost:8000/api/v1/health (dev CA: var/certs/ca.crt)"
  echo "dashboard: cd dashboard && NODE_EXTRA_CA_CERTS=../var/certs/ca.crt ASVAS_API_URL=https://localhost:8000 npm run dev"
else
  echo "API http://127.0.0.1:8000/api/v1/health   dashboard: cd dashboard && npm run dev"
fi
