#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if ! python3 -c "import customtkinter" >/dev/null 2>&1; then
    echo "Installing required UI package (customtkinter)..."
    python3 -m pip install -r requirements.txt
fi

python3 main.py
