#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "============================================================"
echo "  BinShield Standalone Linux Builder (GUI + CLI)"
echo "============================================================"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if [ ! -x ".venv/bin/python" ]; then
    echo "[*] Creating virtual environment in .venv..."
    "$PYTHON_BIN" -m venv .venv
fi

.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo "[*] Building BinShield-GUI-Linux (with self-contained ONNX Runtime AI)..."
.venv/bin/pyinstaller \
    --noconsole \
    --onefile \
    --name "BinShield-GUI-Linux" \
    --collect-all customtkinter \
    --collect-all onnxruntime \
    --exclude-module torch --exclude-module transformers --exclude-module accelerate \
    --exclude-module sympy --exclude-module safetensors --exclude-module tokenizers \
    --clean main.py

echo "[*] Building BinShield-CLI-Linux (with self-contained ONNX Runtime AI)..."
.venv/bin/pyinstaller \
    --console \
    --onefile \
    --name "BinShield-CLI-Linux" \
    --collect-all onnxruntime \
    --exclude-module customtkinter --exclude-module tkinter \
    --exclude-module torch --exclude-module transformers --exclude-module accelerate \
    --exclude-module sympy --exclude-module safetensors --exclude-module tokenizers \
    --clean cli.py

chmod +x dist/BinShield-GUI-Linux dist/BinShield-CLI-Linux
echo "[+] Build complete:"
ls -lh dist/BinShield-*-Linux
