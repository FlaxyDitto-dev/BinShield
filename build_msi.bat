@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo   OpcodeShield Windows MSI Installer Builder (WiX v4)
echo ============================================================
if not exist "dist\OpcodeShield-GUI.exe" (
    echo [!] dist\OpcodeShield-GUI.exe not found. Run build.bat first.
    exit /b 1
)
if not exist "dist\OpcodeShield-CLI.exe" (
    echo [!] dist\OpcodeShield-CLI.exe not found. Run build.bat first.
    exit /b 1
)
wix build installer\OpcodeShield.wxs -arch x64 -o dist\OpcodeShield-v4.1.1-Setup-x64.msi
if errorlevel 1 (
    echo [!] WiX MSI build failed.
    exit /b 1
)
echo [+] Created Windows Installer: dist\OpcodeShield-v4.1.1-Setup-x64.msi
endlocal
