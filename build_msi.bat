@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo   GhidraGuard Windows MSI Installer Builder (WiX v4)
echo ============================================================
if not exist "dist\GhidraGuard-GUI.exe" (
    echo [!] dist\GhidraGuard-GUI.exe not found. Run build.bat first.
    exit /b 1
)
if not exist "dist\GhidraGuard-CLI.exe" (
    echo [!] dist\GhidraGuard-CLI.exe not found. Run build.bat first.
    exit /b 1
)
wix build installer\GhidraGuard.wxs -arch x64 -o dist\GhidraGuard-v2.1.0-Setup-x64.msi
if errorlevel 1 (
    echo [!] WiX MSI build failed.
    exit /b 1
)
echo [+] Created Windows Installer: dist\GhidraGuard-v2.1.0-Setup-x64.msi
endlocal
