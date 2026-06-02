#!/usr/bin/env bash
# Launch the apifuzz web UI on http://127.0.0.1:5000

set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [ ! -d .venv ]; then
  echo "No .venv found. Run ./setup.sh first."
  exit 1
fi

# shellcheck disable=SC1091
source .venv/bin/activate

HOST="${APIFUZZ_HOST:-127.0.0.1}"
PORT="${APIFUZZ_PORT:-5000}"

echo "[+] Starting apifuzz on http://${HOST}:${PORT}"
exec python app.py --host "$HOST" --port "$PORT" "$@"
