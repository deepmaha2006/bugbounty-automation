#!/usr/bin/env bash
# HydraX — Production Launch Script (Linux / macOS)
# Authorized security testing only.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p runtime

# Prefer a local .venv if present
if [[ -x ".venv/bin/python" ]]; then
    PYTHON=".venv/bin/python"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
else
    PYTHON="python"
fi

echo "==================================================="
echo "  HydraX — Threat Intelligence Platform"
echo "  Authorized security testing only."
echo "==================================================="
echo ""

exec "$PYTHON" main.py "$@" 2>>"runtime/hydrax.log"
