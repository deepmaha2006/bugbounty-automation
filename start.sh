#!/usr/bin/env bash
# HydraX — Bug Bounty Automation Platform
# Starts the FastAPI web server.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV="$SCRIPT_DIR/.venv-linux"
UVICORN="$VENV/bin/uvicorn"

if [ ! -f "$UVICORN" ]; then
  echo "Error: venv not found at $VENV"
  echo "Run: python3 -m venv .venv-linux && .venv-linux/bin/pip install -r requirements.txt"
  exit 1
fi

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"

echo "============================================"
echo "  HydraX — Bug Bounty Automation Platform"
echo "============================================"
echo "  Server: http://${HOST}:${PORT}"
echo "  API docs: http://${HOST}:${PORT}/docs"
echo "  API: http://${HOST}:${PORT}/api/"
echo "============================================"

exec "$UVICORN" webapp.main:app --host "$HOST" --port "$PORT" --reload
