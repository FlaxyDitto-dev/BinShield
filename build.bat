@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================================
echo   OpcodeShield Standalone Windows Builder - PyInstaller
echo ============================================================

where py >nul 2>&1
if %errorlevel%==0 (
    set "PY_CMD=py -3.13"
    py -3.13 --version >nul 2>&1
    if errorlevel 1 set "PY_CMD=python"
) else (
    set "PY_CMD=python"
)

echo [*] Using Python: %PY_CMD%
if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating isolated build virtual environment in .venv...
    %PY_CMD% -m venv .venv
    if errorlevel 1 (
        echo [!] Failed to create virtual environment.
        exit /b 1
    )
)

echo [*] Installing dependencies from requirements.txt...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo [!] Dependency installation failed.
    exit /b 1
)

echo [*] Compiling OpcodeShield-GUI.exe with UAC Administrator manifest + ONNX Runtime AI...
".venv\Scripts\pyinstaller.exe" ^
    --noconsole ^
    --onefile ^
    --uac-admin ^
    --name "OpcodeShield-GUI" ^
    --collect-all customtkinter ^
    --collect-all onnxruntime ^
    --exclude-module torch ^
    --exclude-module transformers ^
    --exclude-module accelerate ^
    --exclude-module sympy ^
    --exclude-module safetensors ^
    --exclude-module tokenizers ^
    --clean ^
    main.py

if errorlevel 1 (
    echo [!] PyInstaller GUI build failed.
    exit /b 1
)

echo [*] Compiling OpcodeShield-CLI.exe (headless CLI + self-contained ONNX Runtime AI)...
".venv\Scripts\pyinstaller.exe" ^
    --console ^
    --onefile ^
    --name "OpcodeShield-CLI" ^
    --collect-all onnxruntime ^
    --exclude-module customtkinter ^
    --exclude-module tkinter ^
    --exclude-module torch ^
    --exclude-module transformers ^
    --exclude-module accelerate ^
    --exclude-module sympy ^
    --exclude-module safetensors ^
    --exclude-module tokenizers ^
    --clean ^
    cli.py

if errorlevel 1 (
    echo [!] PyInstaller CLI build failed.
    exit /b 1
)

echo.
echo [+] Build succeeded! Standalone executables created at:
echo     %cd%\dist\OpcodeShield-GUI.exe
echo     %cd%\dist\OpcodeShield-CLI.exe
echo.
endlocal
