#!/usr/bin/env bash
# Local Qdrant for DA-04 long-term memory. DEVELOPMENT ONLY. TLS (dev services certificate) + API key
# (random, var/qdrant/api-key, 0600). Binary: .tools/qdrant (v1.15.5 release build).
#   scripts/qdrant-dev.sh start|stop
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
D="$ROOT/var/qdrant"; mkdir -p "$D/storage" "$D/snapshots" var/logs var/run && chmod 700 "$D"
case "${1:-}" in
start)
  [ -x .tools/qdrant ] || { echo "Qdrant missing: put the qdrant binary into .tools/ (see README)"; exit 1; }
  [ -f "$D/api-key" ] || (umask 077; openssl rand -hex 24 > "$D/api-key")
  cat > "$D/config.yaml" <<Y
storage: { storage_path: $D/storage, snapshots_path: $D/snapshots }
service: { host: 127.0.0.1, http_port: 6333, grpc_port: null, enable_tls: true, api_key: $(cat "$D/api-key") }
tls: { cert: $ROOT/var/certs/services.crt, key: $ROOT/var/certs/services.key }
telemetry_disabled: true
Y
  chmod 600 "$D/config.yaml"
  nohup .tools/qdrant --config-path "$D/config.yaml" > var/logs/qdrant.log 2>&1 &
  echo $! > var/run/qdrant.pid
  for _ in $(seq 30); do curl -sf --cacert var/certs/ca.crt https://localhost:6333/readyz >/dev/null && { echo "qdrant up: https://localhost:6333"; exit 0; }; sleep 1; done
  echo "qdrant did not start; see var/logs/qdrant.log"; exit 1 ;;
stop) [ -f var/run/qdrant.pid ] && kill "$(cat var/run/qdrant.pid)" 2>/dev/null || true ;;
*) echo "usage: $0 start|stop"; exit 2 ;;
esac
