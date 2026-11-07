#!/usr/bin/env bash
# webrecon setup — creates a virtualenv, installs deps, fetches Chromium.
set -euo pipefail

PYTHON="${PYTHON:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"

echo "[*] Creating virtualenv in ${VENV_DIR}"
"${PYTHON}" -m venv "${VENV_DIR}"

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

echo "[*] Upgrading pip"
python -m pip install --upgrade pip >/dev/null

echo "[*] Installing webrecon (editable) + dependencies"
pip install -e .

echo "[*] Installing Chromium for Playwright (JS rendering)"
python -m playwright install chromium

echo
echo "[+] Done. Activate the environment and run:"
echo "      source ${VENV_DIR}/bin/activate"
echo "      webrecon https://example.com"
