#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "============================================================"
echo "  BinShield Standalone macOS Builder (GUI + CLI)"
echo "============================================================"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if [ ! -x ".venv/bin/python" ]; then
    echo "[*] Creating virtual environment in .venv..."
    "$PYTHON_BIN" -m venv .venv
fi

.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo "[*] Building BinShield-GUI-macOS (with self-contained ONNX Runtime AI)..."
.venv/bin/pyinstaller \
    --windowed \
    --onefile \
    --name "BinShield-GUI-macOS" \
    --collect-all customtkinter \
    --collect-all onnxruntime \
    --exclude-module torch --exclude-module transformers --exclude-module accelerate \
    --exclude-module sympy --exclude-module safetensors --exclude-module tokenizers \
    --clean main.py

echo "[*] Building BinShield-CLI-macOS (with self-contained ONNX Runtime AI)..."
.venv/bin/pyinstaller \
    --console \
    --onefile \
    --name "BinShield-CLI-macOS" \
    --collect-all onnxruntime \
    --exclude-module customtkinter --exclude-module tkinter \
    --exclude-module torch --exclude-module transformers --exclude-module accelerate \
    --exclude-module sympy --exclude-module safetensors --exclude-module tokenizers \
    --clean cli.py

chmod +x dist/BinShield-CLI-macOS
echo "[+] Build complete:"
ls -lh dist/
