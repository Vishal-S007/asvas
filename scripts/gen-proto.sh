#!/usr/bin/env bash
# Regenerate Go and Python code from proto/. Generated code is committed so builds need no protoc.
# Requires: control-plane dev deps (grpcio-tools bundles protoc) and Go; plugin versions are pinned below.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/.tools/bin"
mkdir -p "$BIN"
GOBIN="$BIN" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
GOBIN="$BIN" go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
PROTO=proto/asvasrpc/execution/v1/execution.proto
cd "$ROOT/control-plane"
rm -rf asvasrpc && mkdir -p asvasrpc
uv run python -m grpc_tools.protoc -I "$ROOT/proto" --python_out=. --pyi_out=. --grpc_python_out=. "$ROOT/$PROTO"
find asvasrpc -type d -exec touch {}/__init__.py \;
cd "$ROOT"
rm -rf execution-plane/gen && mkdir -p execution-plane/gen
(cd control-plane && uv run python -m grpc_tools.protoc -I "$ROOT/proto" \
  --plugin=protoc-gen-go="$BIN/protoc-gen-go" --plugin=protoc-gen-go-grpc="$BIN/protoc-gen-go-grpc" \
  --go_out="$ROOT/execution-plane/gen" --go_opt=module=github.com/asvas/execution-plane/gen \
  --go-grpc_out="$ROOT/execution-plane/gen" --go-grpc_opt=module=github.com/asvas/execution-plane/gen \
  "$ROOT/$PROTO")
echo "generated: control-plane/asvasrpc, execution-plane/gen"
