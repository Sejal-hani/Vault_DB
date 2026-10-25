#!/usr/bin/env bash
set -e

echo "======================================================================"
echo " Launching VaultDB (Universal Cross-Platform Mode for macOS / Linux)"
echo "======================================================================"

if [ -f "venv/bin/python" ]; then
    PYTHON_EXE="venv/bin/python"
elif command -v python3 &> /dev/null; then
    PYTHON_EXE="python3"
else
    PYTHON_EXE="python"
fi

$PYTHON_EXE server.py
