#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
SRC="/mnt/c/GhidraGuard"
rm -rf ~/gg_linux_build
mkdir -p ~/gg_linux_build/models/OpcodeShield-SecNet-v3
cp "$SRC"/*.py "$SRC"/requirements.txt ~/gg_linux_build/
cp -r "$SRC"/rules ~/gg_linux_build/
cp "$SRC"/models/OpcodeShield-SecNet-v3/OpcodeShield-SecNet-v3-int8.onnx \
   "$SRC"/models/OpcodeShield-SecNet-v3/OpcodeShield-SecNet-v3-vocab.json \
   ~/gg_linux_build/models/OpcodeShield-SecNet-v3/
cd ~/gg_linux_build
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements.txt pyinstaller onnxruntime capstone unicorn
.venv/bin/pyinstaller --console --onefile --name OpcodeShield-CLI-Linux \
  --add-data "models/OpcodeShield-SecNet-v3:models/OpcodeShield-SecNet-v3" \
  --add-data "rules:rules" --collect-all onnxruntime --collect-all capstone --collect-all unicorn \
  --exclude-module customtkinter --exclude-module tkinter --exclude-module torch \
  --exclude-module transformers --exclude-module accelerate --exclude-module sympy \
  --exclude-module safetensors --exclude-module tokenizers --clean cli.py
.venv/bin/pyinstaller --noconsole --onefile --name OpcodeShield-GUI-Linux \
  --add-data "models/OpcodeShield-SecNet-v3:models/OpcodeShield-SecNet-v3" \
  --add-data "rules:rules" --collect-all customtkinter --collect-all onnxruntime --collect-all capstone --collect-all unicorn \
  --exclude-module torch --exclude-module transformers --exclude-module accelerate \
  --exclude-module sympy --exclude-module safetensors --exclude-module tokenizers --clean main.py
cp dist/OpcodeShield-CLI-Linux dist/OpcodeShield-GUI-Linux "$SRC"/dist/
"$SRC"/dist/OpcodeShield-CLI-Linux --version
ls -lh "$SRC"/dist/OpcodeShield-*-Linux
