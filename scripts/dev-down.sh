#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for f in "$ROOT"/var/run/*.pid; do
  [ -f "$f" ] || continue
  pid=$(cat "$f"); kill "$pid" 2>/dev/null && echo "stopped $(basename "$f" .pid)"; rm -f "$f"
done
pkill -f "test-target/target.py" 2>/dev/null || true
