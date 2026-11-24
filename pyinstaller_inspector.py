"""
OpcodeShield v4.1.0 — Static PyInstaller (.exe / ELF) CArchive Inspector & RAT Detector.
100% static (NEVER executes the binary):
  - Detects PyInstaller MEI CArchive cookie (MEI\\x0c\\x0b\\x0a\\x0b\\x0e)
  - Parses CArchive header & TOC (v20 & v21)
  - Decompresses embedded entry-point scripts ('s') and inspects PYZ ('z') module tables
  - Safely extracts Python bytecode constants, co_names, URLs, Discord/Telegram webhooks,
    C2 IPs, and RAT/stealer imports without running a single byte of untrusted code.
"""

from __future__ import annotations

import marshal
import re
import struct
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PYINSTALLER_COOKIE = b"MEI\x0c\x0b\x0a\x0b\x0e"

RAT_PYTHON_MODULES = {
    "pynput": ("Keylogger / Input Capture", 28),
    "keyboard": ("Keylogger / Input Capture", 24),
    "mss": ("Screen Surveillance / RAT", 20),
    "pyautogui": ("Remote Desktop / Input Control", 18),
    "browser_cookie3": ("Browser Credential Stealer", 32),
    "rookiepy": ("Browser Credential Stealer", 32),
    "win32crypt": ("Windows DPAPI Credential Stealer", 26),
    "pycryptodome": ("Crypto / Stealer", 14),
    "discord_webhook": ("Discord Webhook Exfiltration", 28),
    "telebot": ("Telegram Bot C2 / RAT", 26),
    "paramiko": ("SSH Tunnel / Remote Access", 16),
    "cv2": ("Webcam / Screen Capture", 12),
    "sounddevice": ("Microphone Surveillance", 16),
    "pyaudio": ("Microphone Surveillance", 16),
    "pyperclip": ("Clipboard Hijacker / Stealer", 16),
}

RAT_BYTECODE_PATTERNS: List[Tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"discord(?:app)?\.com/api/webhooks/\d+", re.I), "Discord Webhook Exfiltration URL", 38),
    (re.compile(r"api\.telegram\.org/bot[0-9A-Za-z:_-]+", re.I), "Telegram Bot C2 Endpoint", 36),
    (re.compile(r"(?:Login Data|Local State|Web Data|CryptUnprotectData)", re.I), "Browser Credential / Cookie Stealer", 34),
    (re.compile(r"(?:SetWindowsHookEx|GetAsyncKeyState|GetKeyState)", re.I), "Win32 Keylogger Hook API", 30),
    (re.compile(r"(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection)", re.I), "Process Injection API Chain", 34),
    (re.compile(r"(?:CurrentVersion\\Run|schtasks\s+/create|Add-MpPreference|DisableRealtimeMonitoring)", re.I), "Persistence / Defender Tampering", 32),
    (re.compile(r"(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete)", re.I), "Ransomware Shadow-Copy Wiper", 40),
    (re.compile(r"(?:MetaMask|Electrum|Exodus|AtomicWallet|phantom)", re.I), "Crypto Wallet Stealer Target", 26),
]

IOC_URL_RE = re.compile(r"https?://[^\s\"'<>]{6,140}", re.I)
IOC_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b")


def _extract_code_strings(code_obj: Any, out_strings: List[str], out_names: List[str], depth: int = 0) -> None:
    """Recursively walk a marshaled Python code object safely (no execution)."""
    if depth > 6 or not hasattr(code_obj, "co_consts"):
        return
    for name in getattr(code_obj, "co_names", ()):
        if isinstance(name, str) and name not in out_names:
            out_names.append(name)
    for const in getattr(code_obj, "co_consts", ()):
        if isinstance(const, str):
            if 3 <= len(const) <= 300 and const not in out_strings:
                out_strings.append(const)
        elif isinstance(const, bytes):
            try:
                s = const.decode("utf-8", errors="ignore")
                if 4 <= len(s) <= 300 and s not in out_strings:
                    out_strings.append(s)
            except Exception:
                pass
        elif hasattr(const, "co_consts"):
            _extract_code_strings(const, out_strings, out_names, depth + 1)


def _try_parse_pyc_bytes(raw: bytes) -> Tuple[List[str], List[str]]:
    """Safely extract strings & symbol names from raw .pyc or headerless PyInstaller script bytes."""
    strings: List[str] = []
    names: List[str] = []
    # Try common Python .pyc header offsets (0 for headerless PyInstaller 's', 16 for Python 3.7+, 12 for 3.3-3.6)
    for off in (0, 16, 12, 8):
        if off >= len(raw):
            continue
        try:
            obj = marshal.loads(raw[off:])
            if hasattr(obj, "co_consts"):
                _extract_code_strings(obj, strings, names)
                if strings or names:
                    return strings, names
        except Exception:
            continue
    # Fallback: printable ASCII strings from bytecode buffer
    for m in re.findall(rb"[\x20-\x7e]{5,180}", raw):
        s = m.decode("ascii", errors="ignore").strip()
        if s and s not in strings:
            strings.append(s)
            if len(strings) >= 120:
                break
    return strings, names


def _parse_pyz_toc(pyz_bytes: bytes) -> List[str]:
    """Extract bundled module names from a PyInstaller PYZ archive without executing anything."""
    if len(pyz_bytes) < 16 or pyz_bytes[:4] != b"PYZ\x00":
        return []
    try:
        toc_pos = struct.unpack("!i", pyz_bytes[8:12])[0]
        if 12 <= toc_pos < len(pyz_bytes):
            toc = marshal.loads(pyz_bytes[toc_pos:])
            if isinstance(toc, dict):
                return [str(k) for k in toc.keys()]
            if isinstance(toc, (list, tuple)):
                return [str(item[0]) for item in toc if isinstance(item, (list, tuple)) and item]
    except Exception:
        pass
    return []


def inspect_pyinstaller_binary(path: str | Path) -> Dict[str, Any]:
    """Detect and statically inspect a PyInstaller-built .exe / ELF for RATs, stealers, and hidden payloads."""
    data = Path(path).read_bytes()
    return inspect_pyinstaller_bytes(data, Path(path).name)


def inspect_pyinstaller_bytes(data: bytes, filename: str = "sample.exe") -> Dict[str, Any]:
    cookie_pos = data.rfind(PYINSTALLER_COOKIE)
    if cookie_pos == -1:
        return {"is_pyinstaller": False, "filename": filename}

    # Parse CArchive cookie: v21 (88 bytes: 8sIIII64s) vs v20 (24 bytes: 8sIIII)
    pyver = 0
    pylib = ""
    pkg_len = 0
    toc_offset = 0
    toc_len = 0
    cookie_size = 0

    if cookie_pos + 88 <= len(data):
        magic, pkg_len, toc_offset, toc_len, pyver, pylib_raw = struct.unpack("!8sIIII64s", data[cookie_pos : cookie_pos + 88])
        if magic == PYINSTALLER_COOKIE and 0 < pkg_len <= len(data) and toc_len < pkg_len:
            cookie_size = 88
            pylib = pylib_raw.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")

    if cookie_size == 0 and cookie_pos + 24 <= len(data):
        magic, pkg_len, toc_offset, toc_len, pyver = struct.unpack("!8sIIII", data[cookie_pos : cookie_pos + 24])
        if magic == PYINSTALLER_COOKIE and 0 < pkg_len <= len(data):
            cookie_size = 24

    if cookie_size == 0:
        return {"is_pyinstaller": True, "filename": filename, "parse_error": "Malformed PyInstaller cookie", "risk_score": 15}

    overlay_start = (cookie_pos + cookie_size) - pkg_len
    if overlay_start < 0:
        overlay_start = 0
    toc_start = overlay_start + toc_offset
    toc_end = min(toc_start + toc_len, len(data))

    entries: List[Dict[str, Any]] = []
    entry_scripts: List[str] = []
    pyz_modules: List[str] = []
    extracted_strings: List[str] = []
    extracted_names: List[str] = []

    pos = toc_start
    while pos + 18 <= toc_end:
        entry_size, dpos, dlen, ulen, cflag, tcode = struct.unpack("!IIIIBB", data[pos : pos + 18])
        if entry_size < 18 or pos + entry_size > toc_end:
            break
        name_raw = data[pos + 18 : pos + entry_size]
        name = name_raw.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
        tchar = chr(tcode) if 32 <= tcode <= 126 else "?"
        entries.append({"name": name, "type": tchar, "size": ulen, "compressed": bool(cflag)})

        abs_dpos = overlay_start + dpos
        if abs_dpos + dlen <= len(data) and dlen <= 32 * 1024 * 1024:
            blob = data[abs_dpos : abs_dpos + dlen]
            if cflag == 1:
                try:
                    blob = zlib.decompress(blob)
                except Exception:
                    blob = b""
            if tchar == "s" and blob:
                entry_scripts.append(name)
                if not name.startswith("pyi_") and not name.startswith("pyiboot"):
                    s_list, n_list = _try_parse_pyc_bytes(blob)
                    extracted_strings.extend(s_list)
                    extracted_names.extend(n_list)
            elif tchar == "z" and blob:
                pyz_modules.extend(_parse_pyz_toc(blob))
        pos += entry_size

    # Score RAT / Stealer indicators
    risk = 0
    indicators: List[str] = []
    rat_modules_found: List[str] = []
    iocs: List[str] = []

    all_mod_names = {m.split(".")[0].lower() for m in pyz_modules} | {e["name"].split(".")[0].lower() for e in entries}
    for mod, (desc, pts) in RAT_PYTHON_MODULES.items():
        if mod in all_mod_names:
            rat_modules_found.append(f"{mod} ({desc})")
            indicators.append(f"PyInstaller bundles RAT/stealer module '{mod}': {desc}")
            risk += pts

    corpus = "\n".join(extracted_strings + extracted_names)
    for pat, desc, pts in RAT_BYTECODE_PATTERNS:
        if pat.search(corpus):
            indicators.append(f"PyInstaller entry bytecode contains {desc}")
            risk += pts

    # Classic Python reverse shell combo inside entry script bytecode
    names_set = set(extracted_names)
    has_socket = bool({"socket", "connect", "AF_INET"} & names_set)
    has_exec = bool({"Popen", "subprocess", "system", "exec", "eval"} & names_set)
    has_b64 = bool({"b64decode", "decompress", "loads"} & names_set)
    if has_socket and has_exec:
        indicators.append("PyInstaller entry script combines socket networking + subprocess/exec (Reverse Shell / RAT pattern)")
        risk += 42
    if has_exec and has_b64:
        indicators.append("PyInstaller entry script combines base64/zlib decoding + dynamic exec/eval (Obfuscated Stager)")
        risk += 32

    for s in extracted_strings:
        for u in IOC_URL_RE.findall(s):
            if u not in iocs:
                iocs.append(u)
        for ip in IOC_IP_RE.findall(s):
            if ip not in iocs:
                iocs.append(ip)

    risk = min(100, risk)
    severity = "CRITICAL" if risk >= 75 else ("HIGH" if risk >= 50 else ("MEDIUM" if risk >= 25 else "LOW"))

    return {
        "is_pyinstaller": True,
        "filename": filename,
        "python_version": f"{pyver // 100}.{pyver % 100}" if pyver >= 100 else str(pyver),
        "pylib": pylib,
        "toc_entry_count": len(entries),
        "entry_scripts": entry_scripts[:20],
        "pyz_module_count": len(pyz_modules),
        "rat_modules_found": rat_modules_found,
        "extracted_symbols": extracted_names[:40],
        "iocs": iocs[:25],
        "indicators": indicators,
        "risk_score": risk,
        "severity": severity,
    }
