#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
rm -rf ~/gg_linux_build
mkdir -p ~/gg_linux_build/models/BinShield-SecNet-v2
cp /mnt/c/BinShield/*.py /mnt/c/BinShield/requirements.txt ~/gg_linux_build/
cp -r /mnt/c/BinShield/rules ~/gg_linux_build/
cp /mnt/c/BinShield/models/BinShield-SecNet-v2/BinShield-SecNet-v2-int8.onnx \
   /mnt/c/BinShield/models/BinShield-SecNet-v2/BinShield-SecNet-v2-vocab.json \
   ~/gg_linux_build/models/BinShield-SecNet-v2/
cd ~/gg_linux_build
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/pyinstaller --console --onefile --name BinShield-CLI-Linux \
  --add-data "models/BinShield-SecNet-v2:models/BinShield-SecNet-v2" \
  --add-data "rules:rules" --collect-all onnxruntime --collect-all capstone \
  --exclude-module customtkinter --exclude-module tkinter --exclude-module torch \
  --exclude-module transformers --exclude-module accelerate --exclude-module sympy \
  --exclude-module safetensors --exclude-module tokenizers --clean cli.py
.venv/bin/pyinstaller --noconsole --onefile --name BinShield-GUI-Linux \
  --add-data "models/BinShield-SecNet-v2:models/BinShield-SecNet-v2" \
  --add-data "rules:rules" --collect-all customtkinter --collect-all onnxruntime --collect-all capstone \
  --exclude-module torch --exclude-module transformers --exclude-module accelerate \
  --exclude-module sympy --exclude-module safetensors --exclude-module tokenizers --clean main.py
cp dist/BinShield-CLI-Linux dist/BinShield-GUI-Linux /mnt/c/BinShield/dist/
rm -rf ~/.binshield/models
/mnt/c/BinShield/dist/BinShield-CLI-Linux ai-scan /mnt/c/RetroArch-Win64/retroarch.exe
