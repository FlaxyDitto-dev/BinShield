#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
rm -rf ~/gg_linux_build
mkdir -p ~/gg_linux_build/models/GhidraGuard-SecNet-v2
cp /mnt/c/GhidraGuard/*.py /mnt/c/GhidraGuard/requirements.txt ~/gg_linux_build/
cp -r /mnt/c/GhidraGuard/rules ~/gg_linux_build/
cp /mnt/c/GhidraGuard/models/GhidraGuard-SecNet-v2/GhidraGuard-SecNet-v2-int8.onnx \
   /mnt/c/GhidraGuard/models/GhidraGuard-SecNet-v2/GhidraGuard-SecNet-v2-vocab.json \
   ~/gg_linux_build/models/GhidraGuard-SecNet-v2/
cd ~/gg_linux_build
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/pyinstaller --console --onefile --name GhidraGuard-CLI-Linux \
  --add-data "models/GhidraGuard-SecNet-v2:models/GhidraGuard-SecNet-v2" \
  --add-data "rules:rules" --collect-all onnxruntime --collect-all capstone \
  --exclude-module customtkinter --exclude-module tkinter --exclude-module torch \
  --exclude-module transformers --exclude-module accelerate --exclude-module sympy \
  --exclude-module safetensors --exclude-module tokenizers --clean cli.py
.venv/bin/pyinstaller --noconsole --onefile --name GhidraGuard-GUI-Linux \
  --add-data "models/GhidraGuard-SecNet-v2:models/GhidraGuard-SecNet-v2" \
  --add-data "rules:rules" --collect-all customtkinter --collect-all onnxruntime --collect-all capstone \
  --exclude-module torch --exclude-module transformers --exclude-module accelerate \
  --exclude-module sympy --exclude-module safetensors --exclude-module tokenizers --clean main.py
cp dist/GhidraGuard-CLI-Linux dist/GhidraGuard-GUI-Linux /mnt/c/GhidraGuard/dist/
rm -rf ~/.ghidraguard/models
/mnt/c/GhidraGuard/dist/GhidraGuard-CLI-Linux ai-scan /mnt/c/RetroArch-Win64/retroarch.exe
