"""
BinShield v4.0.0 — Windows File Explorer Right-Click Context Menu Registration.
Registers "Scan & Disinfect with BinShield" under HKCU\\Software\\Classes\\*\\shell\\BinShieldScan
(no admin required for per-user install, and also wired into the .msi installer for all users).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Tuple


def get_binshield_executable() -> str:
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve())
    return f'"{sys.executable}" "{Path(__file__).resolve().parent / "main.py"}"'


def register_context_menu(exe_path: str = "") -> Tuple[bool, str]:
    if os.name != "nt":
        return False, "Explorer context menu is Windows-only."
    try:
        import winreg
        target = exe_path or get_binshield_executable()
        cmd = f'"{target}" "%1"' if not target.startswith('"') else f'{target} "%1"'
        base_key = r"Software\Classes\*\shell\BinShieldScan"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base_key) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "Scan & Disinfect with BinShield")
            if Path(target).exists():
                winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, f"{target},0")
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base_key + r"\command") as ck:
            winreg.SetValueEx(ck, "", 0, winreg.REG_SZ, cmd)
        return True, "Registered 'Scan & Disinfect with BinShield' in Windows Explorer right-click menu."
    except Exception as exc:
        return False, f"Context menu registration failed: {exc}"


def unregister_context_menu() -> Tuple[bool, str]:
    if os.name != "nt":
        return False, "Explorer context menu is Windows-only."
    try:
        import winreg
        for sub in (r"Software\Classes\*\shell\BinShieldScan\command", r"Software\Classes\*\shell\BinShieldScan"):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
            except FileNotFoundError:
                pass
        return True, "Removed BinShield from Windows Explorer right-click menu."
    except Exception as exc:
        return False, f"Context menu removal failed: {exc}"
