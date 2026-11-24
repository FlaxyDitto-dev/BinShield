#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "============================================================"
echo "  OpcodeShield Standalone macOS Builder (GUI + CLI)"
echo "============================================================"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if [ ! -x ".venv/bin/python" ]; then
    echo "[*] Creating virtual environment in .venv..."
    "$PYTHON_BIN" -m venv .venv
fi

.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt onnxruntime capstone unicorn

echo "[*] Building OpcodeShield-GUI-macOS (self-contained SecNet-v3 ONNX + Capstone + Unicorn)..."
.venv/bin/pyinstaller \
    --windowed \
    --onefile \
    --name "OpcodeShield-GUI-macOS" \
    --add-data "models/OpcodeShield-SecNet-v3:models/OpcodeShield-SecNet-v3" \
    --add-data "rules:rules" \
    --collect-all customtkinter \
    --collect-all onnxruntime \
    --collect-all capstone \
    --collect-all unicorn \
    --exclude-module torch --exclude-module transformers --exclude-module accelerate \
    --exclude-module sympy --exclude-module safetensors --exclude-module tokenizers \
    --clean main.py

echo "[*] Building OpcodeShield-CLI-macOS (self-contained SecNet-v3 ONNX + Capstone + Unicorn)..."
.venv/bin/pyinstaller \
    --console \
    --onefile \
    --name "OpcodeShield-CLI-macOS" \
    --add-data "models/OpcodeShield-SecNet-v3:models/OpcodeShield-SecNet-v3" \
    --add-data "rules:rules" \
    --collect-all onnxruntime \
    --collect-all capstone \
    --collect-all unicorn \
    --exclude-module customtkinter --exclude-module tkinter \
    --exclude-module torch --exclude-module transformers --exclude-module accelerate \
    --exclude-module sympy --exclude-module safetensors --exclude-module tokenizers \
    --clean cli.py

chmod +x dist/OpcodeShield-CLI-macOS
echo "[+] Build complete:"
ls -lh dist/
