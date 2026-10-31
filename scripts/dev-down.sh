#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for f in "$ROOT"/var/run/*.pid; do
  [ -f "$f" ] || continue
  pid=$(cat "$f"); kill "$pid" 2>/dev/null && echo "stopped $(basename "$f" .pid)"; rm -f "$f"
done
pkill -f "test-target/target.py" 2>/dev/null || true
[ -x "$ROOT/.tools/neo4j/bin/neo4j" ] && "$ROOT/.tools/neo4j/bin/neo4j" stop >/dev/null 2>&1 || true
