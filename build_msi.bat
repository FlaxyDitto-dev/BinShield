@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo   BinShield Windows MSI Installer Builder (WiX v4)
echo ============================================================
if not exist "dist\BinShield-GUI.exe" (
    echo [!] dist\BinShield-GUI.exe not found. Run build.bat first.
    exit /b 1
)
if not exist "dist\BinShield-CLI.exe" (
    echo [!] dist\BinShield-CLI.exe not found. Run build.bat first.
    exit /b 1
)
wix build installer\BinShield.wxs -arch x64 -o dist\BinShield-v4.0.0-Setup-x64.msi
if errorlevel 1 (
    echo [!] WiX MSI build failed.
    exit /b 1
)
echo [+] Created Windows Installer: dist\BinShield-v4.0.0-Setup-x64.msi
endlocal
