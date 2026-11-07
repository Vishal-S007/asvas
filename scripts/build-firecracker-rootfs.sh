#!/usr/bin/env bash
# Build the read-only ext4 root filesystem for Firecracker job VMs (PO-10): only the static guest agent (as init),
# the CA bundle the TLS check validates against, and empty mount points. No shell, no package manager.
#   scripts/build-firecracker-rootfs.sh [out.ext4]      (default var/fc/rootfs.ext4; needs mkfs.ext4 >= 1.43, no root)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/var/fc/rootfs.ext4}"
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$(dirname "$OUT")" "$STAGE"/{sbin,etc/ssl/certs,dev,proc,sys,tmp,run}
(cd "$ROOT/execution-plane" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$STAGE/sbin/asvas-guest-agent" ./cmd/asvas-guest-agent)
CA=/etc/ssl/certs/ca-certificates.crt; [ -f "$CA" ] || CA=/etc/pki/tls/certs/ca-bundle.crt
cp "$CA" "$STAGE/etc/ssl/certs/ca-certificates.crt"
chmod 0555 "$STAGE/sbin/asvas-guest-agent"; chmod 0444 "$STAGE/etc/ssl/certs/ca-certificates.crt"
rm -f "$OUT"
mkfs.ext4 -q -F -L asvas-rootfs -O ^has_journal -E root_owner=0:0 -d "$STAGE" "$OUT" 64M
e2fsck -fn "$OUT" >/dev/null
sha256sum "$OUT" | tee "$OUT.sha256"
echo "rootfs: $OUT (attach read-only; init=/sbin/asvas-guest-agent)"
