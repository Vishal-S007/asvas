#!/usr/bin/env bash
# Turn on TLS for the LOCAL development PostgreSQL 16 cluster and run Redis TLS-only (requirement CP-10).
# Needs root (edits the local cluster config). DEVELOPMENT ONLY — production uses managed TLS endpoints.
#  - PostgreSQL: certificate from var/certs (dev CA), TLS 1.3 minimum, plaintext TCP to the asvas databases rejected.
#  - Redis: TLS on 127.0.0.1:6380, plaintext port disabled.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
C="$ROOT/var/certs"
[ -f "$C/services.crt" ] || "$ROOT/scripts/dev-certs.sh" >/dev/null
PGDIR=/etc/postgresql/16/main
install -d -o postgres -g postgres -m 700 "$PGDIR/asvas-tls"
install -o postgres -g postgres -m 600 "$C/services.crt" "$PGDIR/asvas-tls/server.crt"
install -o postgres -g postgres -m 600 "$C/services.key" "$PGDIR/asvas-tls/server.key"
su postgres -c "psql -q -c \"ALTER SYSTEM SET ssl = on\" \
  -c \"ALTER SYSTEM SET ssl_cert_file = '$PGDIR/asvas-tls/server.crt'\" \
  -c \"ALTER SYSTEM SET ssl_key_file = '$PGDIR/asvas-tls/server.key'\" \
  -c \"ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.3'\""
HBA="$PGDIR/pg_hba.conf"
if ! grep -q "asvas-tls-begin" "$HBA"; then
  tmp=$(mktemp)
  { echo "# asvas-tls-begin (scripts/dev-tls-services.sh)"
    echo "hostnossl asvas,asvas_test all 0.0.0.0/0 reject"
    echo "hostnossl asvas,asvas_test all ::/0 reject"
    echo "hostssl   asvas,asvas_test all 127.0.0.1/32 scram-sha-256"
    echo "hostssl   asvas,asvas_test all ::1/128 scram-sha-256"
    echo "# asvas-tls-end"
    cat "$HBA"; } > "$tmp"
  install -o postgres -g postgres -m 640 "$tmp" "$HBA" && rm -f "$tmp"
fi
su postgres -c "psql -q -c 'SELECT pg_reload_conf()'" >/dev/null
redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true
redis-cli --tls --cacert "$C/ca.crt" -p 6380 shutdown nosave >/dev/null 2>&1 || true
redis-server --port 0 --tls-port 6380 --bind 127.0.0.1 --tls-cert-file "$C/services.crt" --tls-key-file "$C/services.key" \
  --tls-ca-cert-file "$C/ca.crt" --tls-auth-clients no --tls-protocols TLSv1.3 --daemonize yes \
  --logfile "$ROOT/var/logs/redis.log" >/dev/null
echo "PostgreSQL: TLS 1.3 required for asvas databases; Redis: rediss://localhost:6380 (TLS 1.3 only)"
