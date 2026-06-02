#!/usr/bin/env bash
# Set up a local Python venv for apifuzz on Kali Linux.
# PEP 668 in Kali blocks system pip installs, so we use a venv.

set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found. Install with: sudo apt update && sudo apt install -y python3 python3-venv"
  exit 1
fi

# Make sure python3-venv is available (Kali sometimes ships without it).
if ! python3 -c "import venv" 2>/dev/null; then
  echo "python3-venv is missing. Install with: sudo apt update && sudo apt install -y python3-venv"
  exit 1
fi

if [ ! -d .venv ]; then
  echo "[+] Creating virtualenv at .venv"
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "[+] Upgrading pip"
python -m pip install --upgrade pip >/dev/null

echo "[+] Installing dependencies"
pip install -r requirements.txt

echo
echo "[+] Setup complete. Run the server with: ./run.sh"
