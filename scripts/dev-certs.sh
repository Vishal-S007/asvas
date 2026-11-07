#!/usr/bin/env bash
# Development PKI for the control-plane <-> executor gRPC channel (mutual TLS 1.3).
# Creates a private CA, an executor server certificate and a control-plane client certificate in var/certs/
# (git-ignored). DEVELOPMENT ONLY: production must use a managed CA with short-lived certificates (spec p.68).
set -euo pipefail
OUT="${1:-$(cd "$(dirname "$0")/.." && pwd)/var/certs}"
mkdir -p "$OUT" && cd "$OUT" && umask 077
key() { openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"; }
[ -f ca.key ] || { key ca; openssl req -x509 -new -key ca.key -sha256 -days 30 -subj "/CN=asvas-dev-ca" -out ca.crt; }
issue() { # name, CN, extendedKeyUsage, SAN
  key "$1"
  openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr"
  printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%s\n" "$3" "$4" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 7 -sha256 -extfile "$1.ext" -out "$1.crt" 2>/dev/null
  rm -f "$1.csr" "$1.ext"
}
issue executor asvas-executor serverAuth "DNS:localhost,IP:127.0.0.1"
issue control-plane asvas-control-plane clientAuth "URI:spiffe://asvas.local/control-plane"
chmod 600 ./*.key
chmod 644 ./*.crt
echo "certificates in $OUT (CA valid 30 days, leaf 7 days)"
