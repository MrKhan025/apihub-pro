#!/usr/bin/env bash
# Termux-compatible development setup script for API-Hub-Pro (apihub-pro) v2.0
set -euo pipefail

echo "[*] Setting up API-Hub-Pro (apihub-pro) v2.0 for Android Termux..."

if command -v pkg >/dev/null 2>&1; then
  pkg update -y
  pkg install -y python git sqlite redis
fi

python3 -m venv .venv --system-site-packages
source .venv/bin/activate

pip install --upgrade pip
pip install fastapi uvicorn pydantic httpx

if [ ! -f .env ]; then
  cp .env.example .env
  echo "[*] Created .env from .env.example (using local SQLite + Redis fallback)"
fi

PYTHONPATH=. python3 main.py migrate
PYTHONPATH=. python3 main.py seed-demo
PYTHONPATH=. python3 main.py security-audit

echo "[+] Setup complete! Run: PYTHONPATH=. python3 main.py serve --host 127.0.0.1 --port 8000"
