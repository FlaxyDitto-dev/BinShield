@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================================
echo   GhidraGuard Standalone Windows Builder - PyInstaller
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

echo [*] Compiling GhidraGuard.exe with UAC Administrator manifest...
".venv\Scripts\pyinstaller.exe" ^
    --noconsole ^
    --onefile ^
    --uac-admin ^
    --name "GhidraGuard" ^
    --collect-all customtkinter ^
    --exclude-module torch ^
    --exclude-module transformers ^
    --exclude-module accelerate ^
    --exclude-module sympy ^
    --exclude-module numpy ^
    --exclude-module safetensors ^
    --exclude-module tokenizers ^
    --clean ^
    main.py

if errorlevel 1 (
    echo [!] PyInstaller build failed.
    exit /b 1
)

echo.
echo [+] Build succeeded! Standalone executable created at:
echo     %cd%\dist\GhidraGuard.exe
echo.
endlocal
