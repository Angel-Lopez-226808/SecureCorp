#!/usr/bin/env bash
# Detiene los servicios iniciados con scripts/iniciar_servidor.sh
cd "$(dirname "$0")/.."
for f in run/*.pid; do
  [[ -f "$f" ]] || continue
  pid="$(cat "$f")"
  if kill "$pid" 2>/dev/null; then echo "  detenido $(basename "$f" .pid) (pid $pid)"; fi
  rm -f "$f"
done
