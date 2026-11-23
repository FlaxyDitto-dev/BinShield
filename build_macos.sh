#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "============================================================"
echo "  GhidraGuard Standalone macOS Builder (GUI + CLI)"
echo "============================================================"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if [ ! -x ".venv/bin/python" ]; then
    echo "[*] Creating virtual environment in .venv..."
    "$PYTHON_BIN" -m venv .venv
fi

.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo "[*] Building GhidraGuard-GUI-macOS (with self-contained ONNX Runtime AI)..."
.venv/bin/pyinstaller \
    --windowed \
    --onefile \
    --name "GhidraGuard-GUI-macOS" \
    --collect-all customtkinter \
    --collect-all onnxruntime \
    --exclude-module torch --exclude-module transformers --exclude-module accelerate \
    --exclude-module sympy --exclude-module safetensors --exclude-module tokenizers \
    --clean main.py

echo "[*] Building GhidraGuard-CLI-macOS (with self-contained ONNX Runtime AI)..."
.venv/bin/pyinstaller \
    --console \
    --onefile \
    --name "GhidraGuard-CLI-macOS" \
    --collect-all onnxruntime \
    --exclude-module customtkinter --exclude-module tkinter \
    --exclude-module torch --exclude-module transformers --exclude-module accelerate \
    --exclude-module sympy --exclude-module safetensors --exclude-module tokenizers \
    --clean cli.py

chmod +x dist/GhidraGuard-CLI-macOS
echo "[+] Build complete:"
ls -lh dist/
