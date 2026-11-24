#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "============================================================"
echo "  OpcodeShield Standalone Linux Builder (GUI + CLI)"
echo "============================================================"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if [ ! -x ".venv/bin/python" ]; then
    echo "[*] Creating virtual environment in .venv..."
    "$PYTHON_BIN" -m venv .venv
fi

.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo "[*] Building OpcodeShield-GUI-Linux (with self-contained ONNX Runtime AI)..."
.venv/bin/pyinstaller \
    --noconsole \
    --onefile \
    --name "OpcodeShield-GUI-Linux" \
    --collect-all customtkinter \
    --collect-all onnxruntime \
    --exclude-module torch --exclude-module transformers --exclude-module accelerate \
    --exclude-module sympy --exclude-module safetensors --exclude-module tokenizers \
    --clean main.py

echo "[*] Building OpcodeShield-CLI-Linux (with self-contained ONNX Runtime AI)..."
.venv/bin/pyinstaller \
    --console \
    --onefile \
    --name "OpcodeShield-CLI-Linux" \
    --collect-all onnxruntime \
    --exclude-module customtkinter --exclude-module tkinter \
    --exclude-module torch --exclude-module transformers --exclude-module accelerate \
    --exclude-module sympy --exclude-module safetensors --exclude-module tokenizers \
    --clean cli.py

chmod +x dist/OpcodeShield-GUI-Linux dist/OpcodeShield-CLI-Linux
echo "[+] Build complete:"
ls -lh dist/OpcodeShield-*-Linux
