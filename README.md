# GhidraGuard (`v1.1.0`)

**GhidraGuard** is a **100% free, local, offline** security scanner, reverse-engineering assistant, and surgical binary sanitizer for **Windows, Linux, macOS, Google Colab, and Android** (`.exe`, `.dll`, `.apk`, `.so`).

- **Custom Trained AI Model (`GhidraGuard-SecNet-v1`):** Custom 13.9M-parameter 6-layer Transformer trained specifically for GhidraGuard on NVIDIA RTX 5060 Ti (`100%` validation accuracy across 12 threat categories & 8 surgical patch strategies). Only **26.5 MB** FP16 safetensors — **auto-downloads on first use** from GitHub Releases' Fastly Global CDN and runs on CUDA, Apple MPS, Google Colab GPUs, or CPU.
- **Built-In Auto-Updater:** Automatically checks for updates on Windows/Linux/macOS GUI, Android, and Google Colab. The CLI never auto-updates silently and uses an explicit `update` command instead.
- **Prebuilt Releases:** Download `GhidraGuard-GUI.exe`, `GhidraGuard-CLI.exe`, Linux/macOS binaries, custom AI model weights, and source archives from the [Releases page](https://github.com/FlaxyDitto-dev/GhidraGuard/releases/latest).
- **Google Colab:** Open [`GhidraGuard_Colab.ipynb`](https://colab.research.google.com/github/FlaxyDitto-dev/GhidraGuard/blob/main/GhidraGuard_Colab.ipynb) directly in Colab with free GPU acceleration.

---

## How to Use

### 1. Windows GUI (`GhidraGuard-GUI.exe` or `main.py`)
1. Launch **`GhidraGuard-GUI.exe`** (runs elevated with UAC for process/DLL/registry/scheduled-task inspection) or run from source:
   ```powershell
   python main.py
   ```
2. **Threat Scanner:** Run a full system scan (processes, loaded DLLs, startup registry keys, scheduled tasks) or pick a single `.exe` / `.dll` or game/app folder to scan recursively.
3. **AI Decompile & Patch Lab:**
   - Select any flagged binary to decompile with **Ghidra Headless** (auto-discovered under `C:\*`, or click **Auto-Setup** to install JDK 21 + Ghidra automatically).
   - Audit pseudo-C with the local CUDA + Flash Attention AI model (`Qwen/Qwen2.5-Coder-3B-Instruct` by default) and apply surgical `.text` patches with automatic Authenticode stripping, PE `CheckSum` recalculation, and `.bak` backup creation.
4. **Quarantine Vault:** Safely isolate unpatchable threats with XOR neutralization (restore or permanently delete at any time).
5. **Live Network Monitor:** Inspect active TCP/UDP connections mapped to PIDs and executable paths.

### 2. Windows Headless CLI (`GhidraGuard-CLI.exe` or `cli.py`)
Works on Windows PE binaries (`.exe`, `.dll`, `.sys`, `.scr`, `.asi`, `.ocx`), Android `.apk` files, and entire folders.

```powershell
# Scan a single file (.exe, .dll, or .apk)
.\GhidraGuard-CLI.exe scan "C:\path\to\app.exe"

# Recursively scan a folder (add --json for machine-readable output)
.\GhidraGuard-CLI.exe scan "C:\path\to\game_folder" --json

# Sanitize an infected binary to a clean output file (never overwrites original unless specified)
.\GhidraGuard-CLI.exe sanitize "C:\path\to\infected.exe" -o "C:\path\to\cleaned.exe"
.\GhidraGuard-CLI.exe sanitize "C:\path\to\infected.apk" -o "C:\path\to\cleaned.apk"

# Verify structural integrity (PE headers/sections/CheckSum or APK ZIP/AXML/DEX/ELF)
.\GhidraGuard-CLI.exe verify "C:\path\to\cleaned.exe"
.\GhidraGuard-CLI.exe verify "C:\path\to\cleaned.apk"

# Run custom trained GhidraGuard-SecNet-v1 AI model (auto-downloads ~26.5 MB on first run)
.\GhidraGuard-CLI.exe ai-scan "C:\path\to\app.exe"

# Explicit CLI update command (CLI never auto-updates on normal commands)
.\GhidraGuard-CLI.exe update --check
.\GhidraGuard-CLI.exe update
```

*(If running from Python source instead of the compiled `.exe`, replace `.\GhidraGuard-CLI.exe` with `python cli.py`.)*

### 3. Android App (`GhidraGuard` APK)
1. Install the built APK on Android 8.0+ (API 26+). The app requests **zero `INTERNET` permission** and works 100% offline.
2. **Scanner Tab:** Scan installed apps, pick a manual `.apk`, or pick a Windows `.exe` / `.dll` file from device storage.
3. **Patch Lab Tab:** Inspect flagged native `.so` ELF libraries or Windows PE `.text` sections, run on-device MediaPipe LLM auditing (optional `.task`/`.litertlm`/`.bin` model) or the built-in static analyzer, and export a sanitized copy.
4. **Network & Vault Tabs:** Review device security posture and manage XOR-neutralized quarantined files.

---

## How to Build the Windows `.exe` Binaries

### Prerequisites
- **Windows 10/11 (64-bit)**
- **Python 3.11–3.13** (`py -3.13` recommended)
- Optional (for local AI decompile/audit in GUI): **NVIDIA CUDA GPU** + PyTorch CUDA (`requirements-cuda.txt`) and **Ghidra** (or run `python auto_setup.py`)

### Option A: One-Click Build (`build.bat`)
```powershell
git clone https://github.com/FlaxyDitto-dev/GhidraGuard.git
cd GhidraGuard
.\build.bat
```
This automatically creates `.venv`, installs dependencies from `requirements.txt`, and builds both standalone executables:
- `dist\GhidraGuard-GUI.exe` (desktop GUI with UAC manifest)
- `dist\GhidraGuard-CLI.exe` (headless CLI)

### Option B: Manual PyInstaller Build
```powershell
pip install -r requirements.txt

# Build GUI executable
pyinstaller --noconsole --onefile --uac-admin --name "GhidraGuard-GUI" ^
  --collect-all customtkinter ^
  --exclude-module torch --exclude-module transformers --exclude-module accelerate ^
  --exclude-module sympy --exclude-module numpy --exclude-module safetensors --exclude-module tokenizers ^
  --clean main.py

# Build CLI executable
pyinstaller --console --onefile --name "GhidraGuard-CLI" ^
  --exclude-module customtkinter --exclude-module tkinter ^
  --exclude-module torch --exclude-module transformers --exclude-module accelerate ^
  --exclude-module sympy --exclude-module numpy --exclude-module safetensors --exclude-module tokenizers ^
  --clean cli.py
```

*(To run from source with CUDA + Flash Attention AI enabled:)*
```powershell
pip install -r requirements.txt
pip install --index-url https://download.pytorch.org/whl/cu128 torch
pip install -r requirements-cuda.txt
python main.py
```

---

## How to Build for Linux & macOS

### Linux (`build_linux.sh`)
```bash
sudo apt-get install -y python3-tk   # required for CustomTkinter GUI
chmod +x build_linux.sh
./build_linux.sh
```
Outputs `dist/GhidraGuard-GUI-Linux` and `dist/GhidraGuard-CLI-Linux`.

### macOS (`build_macos.sh`)
```bash
chmod +x build_macos.sh
./build_macos.sh
```
Outputs `dist/GhidraGuard-GUI-macOS.app` and `dist/GhidraGuard-CLI-macOS`.

### Google Colab
Open `GhidraGuard_Colab.ipynb` in Google Colab — Cell 1 automatically updates GhidraGuard and downloads `GhidraGuard-SecNet-v1` onto the Colab GPU, and Cell 2 lets you upload, scan, AI-audit, sanitize, and download cleaned `.exe`/`.dll`/`.apk` files.

---

## How to Build the Android `.apk`

### Prerequisites
- **JDK 17 or JDK 21** (`JAVA_HOME` set)
- **Android SDK** (API 36 / Build-Tools) with `ANDROID_HOME` or `android/local.properties` (`sdk.dir=...`) configured

### Build Debug APK
```powershell
cd android
.\gradlew.bat assembleDebug
```
Output APK:
```text
android\app\build\outputs\apk\debug\app-debug.apk
```

### Build Release APK
```powershell
cd android
.\gradlew.bat assembleRelease
```
Output APK:
```text
android\app\build\outputs\apk\release\app-release-unsigned.apk
```
*(Sign the release APK with `apksigner` or your keystore in Android Studio before installing on a device.)*

---

## Running the Automated Test Suites

### Windows / Cross-Platform 210-Sample QA Suite (`.exe`, `.dll`, `.apk`)
Requires `gcc` on `PATH` and Python 3.11–3.13 (`pefile`, `psutil`):
```powershell
python tests\batch_qa_suite.py
```
Compiles and tests 210 real binaries (`75 .exe`, `65 .dll`, `70 .apk`), verifying detection accuracy, sanitization clearance, structural integrity, and real runtime execution, and writes reports to `tests/QA_BATCH_REPORT.md` and `tests/qa_batch_report.json`.

### Android Kotlin Unit Tests
```powershell
cd android
.\gradlew.bat testDebugUnitTest
```

---

## Project Structure

| File / Folder | Purpose |
| --- | --- |
| `main.py` | Windows dark-mode `CustomTkinter` desktop GUI |
| `cli.py` | Headless CLI (`scan`, `sanitize`, `verify`, `--json`) |
| `scanner.py` | Windows process/DLL/registry/task/folder scanner & deep PE anomaly detector |
| `binary_patcher.py` | Surgical PE `.text` patcher, structural sanitizer, CheckSum fixer & Quarantine Vault |
| `apk_engine.py` | Pure-Python offline Android `.apk` analyzer, AXML/DEX/ELF sanitizer & integrity verifier |
| `ghidra_engine.py` | Ghidra Headless auto-discovery & Java pseudo-C export bridge |
| `ai_auditor.py` / `cuda_engine.py` | Direct in-process PyTorch CUDA + Flash Attention multi-pass AI auditor |
| `auto_setup.py` | Automatic bootstrapper for JDK 21, Ghidra, and PyTorch CUDA |
| `build.bat` | One-click PyInstaller builder for `GhidraGuard-GUI.exe` & `GhidraGuard-CLI.exe` |
| `android/` | 100% offline native Kotlin + Jetpack Compose Android edition |
| `tests/batch_qa_suite.py` | Automated 210-sample real binary QA validation pipeline |
