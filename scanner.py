"""
OpcodeShield - System, Process, DLL, Registry, Scheduled Task & PE Heuristic Scanner
100% local/offline Windows security scanner using psutil, winreg, pefile, and Win32 APIs.
"""

from __future__ import annotations

import csv
import ctypes
import hashlib
import io
import math
import os
import re
import shlex
import subprocess
try:
    import winreg  # type: ignore
except ImportError:
    winreg = None  # Linux / macOS / Google Colab
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import struct

import pefile
import psutil


# ---------------------------------------------------------------------------
# Threat Indicators & Heuristics Databases
# ---------------------------------------------------------------------------

SUSPICIOUS_API_CATEGORIES: Dict[str, Set[str]] = {
    "Keylogger / Spyware": {
        "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
        "GetKeyState", "GetForegroundWindow", "GetWindowTextA",
        "GetWindowTextW", "GetClipboardData", "BitBlt", "capCreateCaptureWindowA",
        "capCreateCaptureWindowW", "AttachThreadInput",
    },
    "Process Injection / RAT": {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "CreateRemoteThreadEx", "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "QueueUserAPC", "SetThreadContext", "ResumeThread", "OpenProcess",
        "NtCreateThreadEx", "RtlCreateUserThread", "VirtualProtectEx",
    },
    "C2 / Network Dropper": {
        "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA",
        "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
        "InternetConnectA", "InternetConnectW", "HttpSendRequestA",
        "HttpSendRequestW", "WinHttpOpen", "WinHttpConnect", "WSAStartup",
        "connect", "send", "recv",
    },
    "Persistence / Privilege": {
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
        "RegCreateKeyExW", "CreateServiceA", "CreateServiceW",
        "StartServiceA", "StartServiceW", "AdjustTokenPrivileges",
        "LookupPrivilegeValueA", "LookupPrivilegeValueW",
    },
    "Execution / Shell": {
        "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA",
        "ShellExecuteExW", "CreateProcessA", "CreateProcessW",
    },
    "Anti-Debug / Anti-VM": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
    },
    "Crypto / Obfuscation": {
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA",
        "CryptAcquireContextW", "BCryptEncrypt", "BCryptDecrypt",
    },
}

ALL_SUSPICIOUS_APIS: Dict[str, str] = {
    api.lower(): cat
    for cat, apis in SUSPICIOUS_API_CATEGORIES.items()
    for api in apis
}

SYSTEM_BINARY_NAMES: Set[str] = {
    "svchost.exe", "csrss.exe", "lsass.exe", "smss.exe", "services.exe",
    "wininit.exe", "winlogon.exe", "explorer.exe", "conhost.exe",
    "taskhostw.exe", "dllhost.exe", "rundll32.exe", "spoolsv.exe",
    "dwm.exe", "sihost.exe", "ctfmon.exe", "SearchIndexer.exe".lower(),
}

# Common Windows / game proxy DLL names frequently abused for DLL sideloading / hijacking
PROXY_SIDELOAD_DLL_NAMES: Set[str] = {
    "version.dll", "dinput8.dll", "dxgi.dll", "d3d11.dll", "d3d12.dll",
    "winmm.dll", "dbghelp.dll", "xinput1_3.dll", "xinput1_4.dll",
    "wsock32.dll", "winhttp.dll", "cryptbase.dll", "msimg32.dll",
    "uxtheme.dll", "wtsapi32.dll", "dwmapi.dll", "bink2w64.dll",
}

PE_SCAN_EXTENSIONS: Tuple[str, ...] = (".exe", ".dll", ".asi", ".flt", ".ocx", ".scr", ".sys")

# Standard legitimate executable PE section names produced by MSVC, MinGW/GCC, Clang, Delphi, Go, Rust
STANDARD_EXEC_SECTION_NAMES: Set[str] = {
    ".text", "text", "code", ".code", "init", "page", ".itext", ".textbss", ".text0", ".text1",
}

# Section names strongly associated with packers or unauthorized code injection
SUSPICIOUS_INJECTED_SECTION_PREFIXES: Tuple[str, ...] = (
    ".inject", ".shell", ".stub", ".evil", ".payload", ".mal", ".crypt",
    ".hook", ".cave", ".drop", ".rat", ".backd", ".hide", ".z",
)

# Exported function name fragments strongly indicative of unauthorized/malicious helpers
SUSPICIOUS_EXPORT_FRAGMENTS: Tuple[str, ...] = (
    "malicious", "keylog", "c2_beacon", "beacon_loop", "inject_payload",
    "process_inject", "payload_drop", "steal_cred", "dump_cred", "ransom_",
    "clipboard_spy", "reverse_shell", "backdoor", "exfiltrat", "shellcode",
)

PACKER_SECTION_PREFIXES: Tuple[str, ...] = (
    "UPX", "ASPACK", "VMP", "THEMIDA", ".ENIGMA", "MEW", "PECOMPACT", "MPRESS",
)

# High-confidence shellcode byte signatures (x86/x64 PEB walks, GetPC stubs, egg/loader prologues)
SHELLCODE_PATTERNS: List[Tuple[bytes, str]] = [
    (b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00", "x64 PEB walk (mov rax, gs:[0x60])"),
    (b"\x65\x48\x8B\x0C\x25\x60\x00\x00\x00", "x64 PEB walk (mov rcx, gs:[0x60])"),
    (b"\x64\xA1\x30\x00\x00\x00", "x86 PEB walk (mov eax, fs:[0x30])"),
    (b"\x64\x8B\x35\x30\x00\x00\x00", "x86 PEB walk (mov esi, fs:[0x30])"),
    (b"\xFC\x48\x83\xE4\xF0", "x64 shellcode prologue (cld; and rsp, -16)"),
    (b"\xE8\x00\x00\x00\x00\x58", "GetPC shellcode stub (call $+5; pop rax/eax)"),
    (b"\xE8\x00\x00\x00\x00\x5B", "GetPC shellcode stub (call $+5; pop rbx/ebx)"),
    (b"\xE8\x00\x00\x00\x00\x59", "GetPC shellcode stub (call $+5; pop rcx/ecx)"),
]

# High-confidence malicious IOC strings inside PE sections or overlays
HIGH_CONFIDENCE_IOC_STRINGS: Tuple[Tuple[bytes, str], ...] = (
    (b"discord.com/api/webhooks", "Discord webhook exfiltration IOC"),
    (b"api.telegram.org/bot", "Telegram bot C2/exfiltration IOC"),
    (b"vssadmin delete shadows", "Ransomware shadow-copy deletion command"),
    (b"add-mppreference", "Windows Defender exclusion tampering"),
    (b"powershell -enc", "Encoded PowerShell execution"),
    (b"powershell -nop -w hidden", "Hidden PowerShell execution"),
    (b"invoke-expression", "PowerShell IEX dropper indicator"),
    (b"currentversion\\run", "Registry Run persistence path"),
    (b"mimikatz", "Credential dumper signature"),
    (b"meterpreter", "Meterpreter RAT signature"),
    (b"reverse_shell", "Reverse shell marker"),
    (b"c2_beacon", "C2 beacon payload marker"),
    (b"keylogger_hook", "Keylogger hook marker"),
    (b"gg_injected_payload", "Injected payload marker"),
    (b"gg_shellcode_cave", "Injected code-cave shellcode marker"),
    (b"gg_tls_payload", "Injected TLS callback payload marker"),
    (b"gg_overlay_payload", "Injected overlay payload marker"),
)

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

SUSPICIOUS_PATH_FRAGMENTS: Tuple[str, ...] = (
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\downloads\\",
)

RUN_REGISTRY_KEYS: List[Tuple[int, str, str]] = (
    [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\WOW6432\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\WOW6432\\RunOnce"),
    ]
    if winreg is not None
    else []
)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class ThreatFinding:
    name: str
    path: str
    source: str  # "Process", "Loaded DLL", "Registry", "Scheduled Task", "Manual File"
    risk_score: int
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    pid: Optional[int] = None
    signed: bool = False
    is_packed: bool = False
    max_entropy: float = 0.0
    sha256: str = ""
    categories: List[str] = field(default_factory=list)
    suspicious_imports: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    persistence_ref: str = ""
    anomalies: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class NetworkConnectionInfo:
    pid: int
    process_name: str
    exe_path: str
    protocol: str
    local_addr: str
    remote_addr: str
    status: str
    is_external: bool


# ---------------------------------------------------------------------------
# Low-level PE & Windows Helpers
# ---------------------------------------------------------------------------

def compute_sha256(file_path: str) -> str:
    """Stream-compute SHA-256 hash of any file in 1 MB chunks (no file size limit)."""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def is_pe_signed(file_path: str, pe_obj: Optional[pefile.PE] = None) -> bool:
    """
    Check if a PE file carries an Authenticode signature via PE Security Directory
    and Windows WinVerifyTrust (when available).
    """
    has_security_dir = False
    try:
        pe = pe_obj or pefile.PE(file_path, fast_load=True)
        sec_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_idx:
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_idx]
            if sec_dir.VirtualAddress != 0 and sec_dir.Size > 0:
                has_security_dir = True
        if pe_obj is None:
            pe.close()
    except Exception:
        return False

    if not has_security_dir:
        return False

    # Verify via WinVerifyTrust (best-effort; falls back to security dir presence)
    try:
        return _win_verify_trust(file_path)
    except Exception:
        return has_security_dir


def _win_verify_trust(file_path: str) -> bool:
    """Invoke Windows WinVerifyTrust API to verify embedded Authenticode signature."""
    if os.name != "nt" or not hasattr(ctypes, "windll"):
        return False
    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", ctypes.c_ulong),
            ("Data2", ctypes.c_ushort),
            ("Data3", ctypes.c_ushort),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("pcwszFilePath", ctypes.c_wchar_p),
            ("hFile", ctypes.c_void_p),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", ctypes.c_ulong),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", ctypes.c_ulong),
            ("fdwRevocationChecks", ctypes.c_ulong),
            ("dwUnionChoice", ctypes.c_ulong),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", ctypes.c_ulong),
            ("hWVTStateData", ctypes.c_void_p),
            ("pwszURLReference", ctypes.c_wchar_p),
            ("dwProvFlags", ctypes.c_ulong),
            ("dwUIContext", ctypes.c_ulong),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    # WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    action_guid = GUID(
        0x00AAC56B, 0xCD44, 0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )

    file_info = WINTRUST_FILE_INFO(
        cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO),
        pcwszFilePath=file_path,
        hFile=None,
        pgKnownSubject=None,
    )

    # WTD_UI_NONE=2, WTD_REVOKE_NONE=0 (offline!), WTD_CHOICE_FILE=1,
    # WTD_STATEACTION_VERIFY=1, WTD_CACHE_ONLY_URL_RETRIEVAL=0x1000
    wtd = WINTRUST_DATA(
        cbStruct=ctypes.sizeof(WINTRUST_DATA),
        dwUIChoice=2,
        fdwRevocationChecks=0,
        dwUnionChoice=1,
        pFile=ctypes.pointer(file_info),
        dwStateAction=1,
        dwProvFlags=0x1000,
    )

    wintrust = ctypes.windll.wintrust
    status = wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd))

    # Clean up state handle
    wtd.dwStateAction = 2  # WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wtd))
    return status == 0


def extract_executable_path(command_line: str) -> Optional[str]:
    """Extract the target .exe / .dll path from a registry Run value or scheduled task command."""
    if not command_line:
        return None
    expanded = os.path.expandvars(command_line.strip())
    if not expanded:
        return None

    # Quoted path at beginning
    if expanded.startswith('"'):
        end = expanded.find('"', 1)
        if end > 1:
            candidate = expanded[1:end]
            if os.path.isfile(candidate):
                return candidate

    # Try regex for Windows path ending in .exe/.dll/.scr/.com
    match = re.search(r'([A-Za-z]:\\[^"<>|*?]+?\.(?:exe|dll|scr|com))', expanded, re.IGNORECASE)
    if match:
        candidate = match.group(1).strip()
        if os.path.isfile(candidate):
            return candidate

    # Fallback shlex split
    try:
        parts = shlex.split(expanded, posix=False)
        if parts:
            cand = parts[0].strip('"')
            if os.path.isfile(cand):
                return cand
    except ValueError:
        pass

    return None


def _is_in_legit_windows_dir(file_path: str) -> bool:
    norm = os.path.normpath(file_path).lower()
    win_dir = os.path.normpath(os.environ.get("SystemRoot", r"C:\Windows")).lower()
    allowed = (
        os.path.join(win_dir, "system32") + "\\",
        os.path.join(win_dir, "syswow64") + "\\",
        win_dir + "\\",
    )
    return any(norm.startswith(prefix) for prefix in allowed)


def _is_in_suspicious_dir(file_path: str) -> bool:
    norm = os.path.normpath(file_path).lower()
    return any(frag in norm for frag in SUSPICIOUS_PATH_FRAGMENTS)


def _severity_from_score(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _detect_oep_return_rva(stub_bytes: bytes, stub_rva: int, text_rva_start: int, text_rva_end: int) -> Optional[int]:
    """
    Scan an OEP-hijack stub for a relative JMP rel32 (E9 xx xx xx xx) that jumps
    back into the legitimate .text section, returning the recovered original OEP RVA.
    """
    for i in range(0, max(0, len(stub_bytes) - 4)):
        if stub_bytes[i] == 0xE9:
            rel32 = struct.unpack_from("<i", stub_bytes, i + 1)[0]
            target_rva = (stub_rva + i + 5 + rel32) & 0xFFFFFFFF
            if text_rva_start <= target_rva < text_rva_end:
                return target_rva
    return None


def _find_section_for_rva(pe: pefile.PE, rva: int) -> Optional[Any]:
    for sec in pe.sections:
        vstart = sec.VirtualAddress
        vsize = max(sec.Misc_VirtualSize, sec.SizeOfRawData)
        if vstart <= rva < vstart + vsize:
            return sec
    return None


def _is_standard_exec_section(sec_name: str) -> bool:
    low = sec_name.strip().lower()
    if low in STANDARD_EXEC_SECTION_NAMES:
        return True
    # MinGW / GCC long section names like "/4" are debug/DWARF, never executable
    return False


def _inspect_pe_anomalies(
    pe: pefile.PE,
    file_path: str,
    file_size: int,
) -> Tuple[List[Dict[str, Any]], List[str], Set[str], int, bool, float]:
    """
    Deep structural PE analysis detecting:
    - RWX and non-standard/injected executable sections
    - Entry-point (OEP) hijacking & trampoline redirection
    - Unauthorized / injected TLS callbacks
    - Code-cave shellcode injections inside .text padding
    - Malicious PE overlays (appended PE/ELF/dropper/C2 payloads)
    - High-confidence malicious IOC strings
    Returns (anomalies, indicators, categories, added_score, is_packed, max_entropy).
    """
    anomalies: List[Dict[str, Any]] = []
    indicators: List[str] = []
    categories: Set[str] = set()
    added_score = 0
    is_packed = False
    max_entropy = 0.0

    image_base = pe.OPTIONAL_HEADER.ImageBase
    is_pe32_plus = pe.OPTIONAL_HEADER.Magic == 0x20B
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # Identify primary .text section bounds
    text_sec = None
    for sec in pe.sections:
        sname = sec.Name.rstrip(b"\x00").decode("utf-8", errors="ignore").strip().lower()
        if sname in (".text", "text", "code", ".code"):
            text_sec = sec
            break
    text_rva_start = text_sec.VirtualAddress if text_sec else 0
    text_rva_end = (
        text_sec.VirtualAddress + max(text_sec.Misc_VirtualSize, text_sec.SizeOfRawData)
        if text_sec
        else 0
    )

    injected_sec_names: Set[str] = set()
    seen_iocs: Set[str] = set()
    pe_raw_end = 0

    # 1. Section-by-section inspection (entropy, RWX, injected exec sections, code caves, IOCs)
    for idx, sec in enumerate(pe.sections):
        sec_name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="ignore")
        sec_low = sec_name.strip().lower()
        raw_ptr = int(sec.PointerToRawData or 0)
        raw_size = int(sec.SizeOfRawData or 0)
        if raw_ptr + raw_size > pe_raw_end:
            pe_raw_end = raw_ptr + raw_size

        sample_len = min(raw_size, 512 * 1024)
        data = sec.get_data(length=sample_len) if sample_len > 0 else b""
        ent = _shannon_entropy(data[: 256 * 1024]) if data else 0.0
        # Only track packer entropy on executable sections (non-executable .rsrc/.rdata/.data
        # legitimately hold compressed shaders, icons, PNGs, and game assets)
        if bool(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) and ent > max_entropy:
            max_entropy = ent

        chars = int(sec.Characteristics or 0)
        is_exec = bool(chars & IMAGE_SCN_MEM_EXECUTE)
        is_write = bool(chars & IMAGE_SCN_MEM_WRITE)

        # Packer section check
        if sec_name.upper().startswith(PACKER_SECTION_PREFIXES):
            is_packed = True
            added_score += 20
            categories.add("Packed / Obfuscated")
            indicators.append(f"Packer section detected: {sec_name}")

        # Injected / non-standard executable or RWX section check
        is_suspicious_name = sec_low.startswith(SUSPICIOUS_INJECTED_SECTION_PREFIXES)
        is_nonstandard_exec = is_exec and not _is_standard_exec_section(sec_name)
        is_rwx = is_exec and is_write

        if is_suspicious_name or is_rwx or is_nonstandard_exec:
            injected_sec_names.add(sec_name)
            reason_parts = []
            if is_rwx:
                reason_parts.append("RWX (Writable+Executable)")
            if is_nonstandard_exec:
                reason_parts.append("non-standard executable section")
            if is_suspicious_name:
                reason_parts.append("suspicious injection section name")
            added_score += 35 if (is_rwx or is_suspicious_name) else 25
            categories.add("Code Injection")
            indicators.append(f"Injected/unsafe section '{sec_name}' ({', '.join(reason_parts)})")
            anomalies.append({
                "type": "INJECTED_SECTION",
                "section_name": sec_name,
                "section_index": idx,
                "file_offset": raw_ptr,
                "raw_size": raw_size,
                "virtual_address": sec.VirtualAddress,
                "is_rwx": is_rwx,
                "is_last_section": idx == len(pe.sections) - 1,
                "reason": ", ".join(reason_parts),
            })

        # Code-cave shellcode scan inside executable sections
        if is_exec and data:
            # Check for shellcode byte signatures
            for sig, sig_desc in SHELLCODE_PATTERNS:
                pos = data.find(sig)
                if pos != -1:
                    cave_off = raw_ptr + pos
                    # Avoid flagging standard .text unless preceded by null padding or in injected section
                    preceding_nulls = pos >= 16 and data[pos - 16 : pos] == b"\x00" * 16
                    if sec_name in injected_sec_names or preceding_nulls or pos > max(0, len(data) - 4096):
                        added_score += 35
                        categories.add("Shellcode Injection")
                        indicators.append(f"Shellcode signature in '{sec_name}' @ {hex(cave_off)}: {sig_desc}")
                        anomalies.append({
                            "type": "CODE_CAVE_SHELLCODE",
                            "section_name": sec_name,
                            "file_offset": cave_off,
                            "va": image_base + sec.VirtualAddress + pos,
                            "size": min(256, len(data) - pos),
                            "signature": sig_desc,
                        })
                        break

        # High-confidence IOC string scan across section data
        if data:
            low_data = data.lower()
            for ioc_bytes, ioc_desc in HIGH_CONFIDENCE_IOC_STRINGS:
                if ioc_bytes in low_data and ioc_desc not in seen_iocs:
                    seen_iocs.add(ioc_desc)
                    added_score += 28
                    categories.add("Malicious Payload / IOC")
                    indicators.append(f"Malicious IOC string in '{sec_name}': {ioc_desc}")
                    pos = low_data.find(ioc_bytes)
                    anomalies.append({
                        "type": "SUSPICIOUS_IOC",
                        "section_name": sec_name,
                        "file_offset": raw_ptr + pos if pos >= 0 else raw_ptr,
                        "ioc": ioc_bytes.decode("ascii", errors="ignore"),
                        "description": ioc_desc,
                    })

    if max_entropy >= 7.25:
        is_packed = True
        added_score += 15
        indicators.append(f"High section entropy ({max_entropy:.2f}) — possibly packed/encrypted")

    # 2. Entry-Point (OEP) Hijacking Detection
    if ep_rva > 0:
        ep_sec = _find_section_for_rva(pe, ep_rva)
        if ep_sec is not None:
            ep_sec_name = ep_sec.Name.rstrip(b"\x00").decode("utf-8", errors="ignore")
            ep_file_off = pe.get_offset_from_rva(ep_rva)
            if ep_sec_name in injected_sec_names or not _is_standard_exec_section(ep_sec_name):
                recovered_oep = None
                if ep_file_off is not None and ep_file_off >= 0:
                    try:
                        with open(file_path, "rb") as f:
                            f.seek(ep_file_off)
                            stub = f.read(512)
                        if text_sec is not None:
                            recovered_oep = _detect_oep_return_rva(stub, ep_rva, text_rva_start, text_rva_end)
                    except OSError:
                        pass
                added_score += 40
                categories.add("Entry-Point Hijack")
                oep_note = f" (recoverable OEP={hex(recovered_oep)})" if recovered_oep else ""
                indicators.append(
                    f"Hijacked EntryPoint {hex(ep_rva)} points to non-standard section '{ep_sec_name}'{oep_note}"
                )
                anomalies.append({
                    "type": "OEP_HIJACK",
                    "section_name": ep_sec_name,
                    "current_oep_rva": ep_rva,
                    "current_oep_file_offset": ep_file_off or 0,
                    "recovered_oep_rva": recovered_oep,
                })
            elif ep_file_off is not None and ep_file_off >= 0:
                # Check if OEP in .text starts with an immediate JMP rel32 into an injected section
                try:
                    with open(file_path, "rb") as f:
                        f.seek(ep_file_off)
                        ep_head = f.read(16)
                    if len(ep_head) >= 5 and ep_head[0] == 0xE9:
                        rel32 = struct.unpack_from("<i", ep_head, 1)[0]
                        jmp_target_rva = (ep_rva + 5 + rel32) & 0xFFFFFFFF
                        jmp_sec = _find_section_for_rva(pe, jmp_target_rva)
                        if jmp_sec is not None:
                            jmp_sec_name = jmp_sec.Name.rstrip(b"\x00").decode("utf-8", errors="ignore")
                            if jmp_sec_name in injected_sec_names:
                                added_score += 35
                                categories.add("Entry-Point Hijack")
                                indicators.append(
                                    f"EntryPoint trampoline at {hex(ep_rva)} redirects to injected section '{jmp_sec_name}'"
                                )
                                anomalies.append({
                                    "type": "OEP_TRAMPOLINE",
                                    "section_name": jmp_sec_name,
                                    "oep_file_offset": ep_file_off,
                                    "target_rva": jmp_target_rva,
                                })
                except OSError:
                    pass

    # 3. TLS Callback Injection Detection
    try:
        tls_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > tls_idx:
            tls_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[tls_idx]
            if tls_dir.VirtualAddress != 0 and tls_dir.Size > 0:
                tls_file_off = pe.get_offset_from_rva(tls_dir.VirtualAddress)
                if tls_file_off is not None and tls_file_off >= 0:
                    with open(file_path, "rb") as f:
                        f.seek(tls_file_off)
                        tls_raw = f.read(40 if is_pe32_plus else 24)
                        if (is_pe32_plus and len(tls_raw) >= 32) or (not is_pe32_plus and len(tls_raw) >= 16):
                            cb_va = (
                                struct.unpack_from("<Q", tls_raw, 24)[0]
                                if is_pe32_plus
                                else struct.unpack_from("<I", tls_raw, 12)[0]
                            )
                            if cb_va > image_base:
                                cb_table_rva = cb_va - image_base
                                cb_table_off = pe.get_offset_from_rva(cb_table_rva)
                                ptr_size = 8 if is_pe32_plus else 4
                                ptr_fmt = "<Q" if is_pe32_plus else "<I"
                                if cb_table_off is not None and cb_table_off >= 0:
                                    f.seek(cb_table_off)
                                    table_bytes = f.read(ptr_size * 32)
                                    for cb_i in range(len(table_bytes) // ptr_size):
                                        fn_va = struct.unpack_from(ptr_fmt, table_bytes, cb_i * ptr_size)[0]
                                        if fn_va == 0:
                                            break
                                        if fn_va <= image_base:
                                            continue
                                        fn_rva = fn_va - image_base
                                        fn_sec = _find_section_for_rva(pe, fn_rva)
                                        fn_off = pe.get_offset_from_rva(fn_rva)
                                        if fn_sec is None or fn_off is None:
                                            continue
                                        fn_sec_name = fn_sec.Name.rstrip(b"\x00").decode("utf-8", errors="ignore")
                                        # Check if callback targets injected/RWX section or contains shellcode/IOCs
                                        is_mal_cb = fn_sec_name in injected_sec_names or not _is_standard_exec_section(fn_sec_name)
                                        if not is_mal_cb:
                                            f.seek(fn_off)
                                            cb_code = f.read(128)
                                            cb_low = cb_code.lower()
                                            if any(sig in cb_code for sig, _ in SHELLCODE_PATTERNS) or any(
                                                ioc in cb_low for ioc, _ in HIGH_CONFIDENCE_IOC_STRINGS
                                            ):
                                                is_mal_cb = True
                                        if is_mal_cb:
                                            added_score += 38
                                            categories.add("TLS Callback Injection")
                                            indicators.append(
                                                f"Unauthorized TLS callback #{cb_i} -> {hex(fn_va)} in '{fn_sec_name}'"
                                            )
                                            anomalies.append({
                                                "type": "MALICIOUS_TLS_CALLBACK",
                                                "callback_index": cb_i,
                                                "callback_table_offset": cb_table_off,
                                                "callback_entry_offset": cb_table_off + cb_i * ptr_size,
                                                "ptr_size": ptr_size,
                                                "callback_va": fn_va,
                                                "callback_file_offset": fn_off,
                                                "section_name": fn_sec_name,
                                            })
    except Exception:
        pass

    # 4. Malicious PE Overlay Detection (excluding valid Authenticode cert table)
    try:
        cert_off = 0
        cert_size = 0
        sec_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_idx:
            sdir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_idx]
            cert_off = int(sdir.VirtualAddress or 0)
            cert_size = int(sdir.Size or 0)

        overlay_start = pe_raw_end
        overlay_end = cert_off if (cert_off >= pe_raw_end and cert_size > 0) else file_size
        overlay_size = max(0, overlay_end - overlay_start)

        if overlay_size >= 64:
            with open(file_path, "rb") as f:
                f.seek(overlay_start)
                ov_sample = f.read(min(overlay_size, 256 * 1024))
            ov_low = ov_sample.lower()
            ov_reasons: List[str] = []
            if b"MZ" in ov_sample[:64] and b"PE\x00\x00" in ov_sample[:1024]:
                ov_reasons.append("embedded PE executable in overlay")
            if ov_sample[:4] == b"\x7fELF":
                ov_reasons.append("embedded ELF binary in overlay")
            for ioc_bytes, ioc_desc in HIGH_CONFIDENCE_IOC_STRINGS:
                if ioc_bytes in ov_low:
                    ov_reasons.append(ioc_desc)
                    break
            for sig, sig_desc in SHELLCODE_PATTERNS:
                if sig in ov_sample:
                    ov_reasons.append(sig_desc)
                    break
            if not ov_reasons and overlay_size >= 1024:
                ov_ent = _shannon_entropy(ov_sample)
                if ov_ent >= 7.5 and (b"http://" in ov_low or b"powershell" in ov_low or b"payload" in ov_low):
                    ov_reasons.append(f"high-entropy payload overlay ({ov_ent:.2f})")

            if ov_reasons:
                added_score += 32
                categories.add("Malicious Overlay")
                indicators.append(
                    f"Malicious PE overlay ({overlay_size} bytes @ {hex(overlay_start)}): {'; '.join(ov_reasons)}"
                )
                anomalies.append({
                    "type": "MALICIOUS_OVERLAY",
                    "overlay_offset": overlay_start,
                    "overlay_size": overlay_size,
                    "reasons": ov_reasons,
                })
    except Exception:
        pass

    # 5. Suspicious Exported Functions (for surgical .text neutralization on DLLs)
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if not exp.name:
                    continue
                exp_name = exp.name.decode("utf-8", errors="ignore")
                exp_low = exp_name.lower()
                if any(frag in exp_low for frag in SUSPICIOUS_EXPORT_FRAGMENTS):
                    exp_rva = int(exp.address or 0)
                    exp_off = pe.get_offset_from_rva(exp_rva) if exp_rva > 0 else None
                    if exp_off is not None and exp_off >= 0:
                        # Check if already neutralized (starts with 31 C0 C3 or C3)
                        with open(file_path, "rb") as f:
                            f.seek(exp_off)
                            head = f.read(3)
                        if head != b"\x31\xC0\xC3" and head[:1] != b"\xC3":
                            added_score += 30
                            categories.add("Malicious Exported Function")
                            indicators.append(f"Suspicious exported function '{exp_name}' @ {hex(exp_off)}")
                            anomalies.append({
                                "type": "MALICIOUS_EXPORT_FUNC",
                                "function_name": exp_name,
                                "rva": exp_rva,
                                "va": image_base + exp_rva,
                                "file_offset": exp_off,
                            })
    except Exception:
        pass

    return anomalies, indicators, categories, added_score, is_packed, max_entropy


# ---------------------------------------------------------------------------
# PE Static Heuristic Inspector
# ---------------------------------------------------------------------------

def analyze_pe_file(
    file_path: str,
    source: str = "Manual File",
    pid: Optional[int] = None,
    persistence_ref: str = "",
) -> Optional[ThreatFinding]:
    """
    Perform fast static PE analysis on a Windows binary (.exe / .dll).
    Detects suspicious APIs, masquerading, proxy DLL sideloading, RWX/injected sections,
    OEP hijacking, unauthorized TLS callbacks, code-cave shellcode, malicious overlays,
    and high-confidence IOC strings.
    Returns a ThreatFinding with heuristic score, indicators, and structured anomalies.
    """
    if not file_path or not os.path.isfile(file_path):
        return None

    name = os.path.basename(file_path)
    norm_lower = os.path.normpath(file_path).lower()
    file_size = os.path.getsize(file_path)
    score = 0
    indicators: List[str] = []
    categories: Set[str] = set()
    suspicious_imports: List[str] = []
    anomalies: List[Dict[str, Any]] = []
    signed = False
    is_packed = False
    max_entropy = 0.0

    # 1. Masquerading system binary name check
    if name.lower() in SYSTEM_BINARY_NAMES and not _is_in_legit_windows_dir(file_path):
        score += 45
        indicators.append(f"Masquerading system binary '{name}' outside Windows directory")
        categories.add("Masquerading")

    # 2. Suspicious directory check (light weight alone; amplified if actual threat indicators exist)
    in_suspicious_dir = _is_in_suspicious_dir(file_path)
    if in_suspicious_dir:
        score += 8
        indicators.append("Located in user-writable/temp directory")

    # 3. Parse PE headers, imports, signature, and deep structural anomalies
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
            ]
        )

        signed = is_pe_signed(file_path, pe_obj=pe)
        if not signed:
            score += 8
            indicators.append("Binary is not digitally signed")

        # Inspect imports
        benign_overlap_only = False
        imported_dlls: Set[str] = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            found_apis: Set[str] = set()
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll:
                    imported_dlls.add(entry.dll.decode("utf-8", errors="ignore").lower())
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode("utf-8", errors="ignore")
                        cat = ALL_SUSPICIOUS_APIS.get(api_name.lower())
                        if cat and api_name not in found_apis:
                            found_apis.add(api_name)
                            suspicious_imports.append(api_name)
                            categories.add(cat)

            if suspicious_imports:
                high_risk_cats = {"Keylogger / Spyware", "Process Injection / RAT"}
                # Single benign-overlap API (e.g. IsDebuggerPresent in CRT, or WSAStartup/connect in clean net client)
                # should not cause false positives on clean tools without additional indicators.
                benign_overlap_only = set(a.lower() for a in suspicious_imports).issubset({
                    "isdebuggerpresent", "wsastartup", "connect", "send", "recv",
                    "cryptacquirecontexta", "cryptacquirecontextw", "openprocess",
                }) and len(suspicious_imports) <= 3
                if categories & high_risk_cats and not benign_overlap_only:
                    score += min(40, 18 + 6 * len(suspicious_imports))
                elif benign_overlap_only:
                    score += 6
                else:
                    score += min(30, 10 + 4 * len(suspicious_imports))
                preview = ", ".join(suspicious_imports[:6])
                suffix = f" (+{len(suspicious_imports) - 6} more)" if len(suspicious_imports) > 6 else ""
                indicators.append(f"Suspicious APIs: {preview}{suffix}")

        # Deep structural PE injection & anomaly analysis
        pe_anomalies, anom_indicators, anom_cats, anom_score, is_packed, max_entropy = _inspect_pe_anomalies(
            pe, file_path, file_size
        )
        anomalies.extend(pe_anomalies)
        indicators.extend(anom_indicators)
        categories.update(anom_cats)
        score += anom_score

        # Amplify unsigned + temp/AppData risk ONLY when real threat signals are present
        has_real_threat_signal = bool(
            anomalies
            or is_packed
            or (not benign_overlap_only and (categories - {"Anti-Debug / Anti-VM"}))
        )
        if not signed and in_suspicious_dir and has_real_threat_signal:
            score += 18
            indicators.append("Unsigned PE with threat indicators in Temp/AppData/Public folder")

        # DLL Sideloading / Proxy DLL check (common attack vector in leaked game folders)
        if name.lower() in PROXY_SIDELOAD_DLL_NAMES and not _is_in_legit_windows_dir(file_path):
            high_risk_proxy_cats = {
                "Keylogger / Spyware", "Process Injection / RAT", "C2 / Network Dropper",
                "Persistence / Privilege", "Execution / Shell", "Code Injection",
                "Shellcode Injection", "Entry-Point Hijack", "TLS Callback Injection",
                "Malicious Overlay", "Malicious Payload / IOC",
            }
            if not signed and (categories & high_risk_proxy_cats):
                score += 25
                categories.add("DLL Sideloading / Proxy")
                indicators.append(f"Unsigned proxy/sideloaded DLL '{name}' with high-risk indicators")
                anomalies.append({
                    "type": "PROXY_SIDELOAD",
                    "dll_name": name,
                    "reason": "Unsigned proxy DLL with malicious indicators",
                })
            elif not signed:
                indicators.append(f"Unsigned proxy DLL '{name}' (verify if legitimate mod/loader)")

        # Legitimate Desktop GUI / Game / Emulator App Calibration:
        # Large multimedia/GUI/emulator binaries (SDL2, wxWidgets, Qt, ImGui, ReShade/DXGI)
        # legitimately import keyboard/window hooks (SetWindowsHookExW), thread-context (JIT),
        # and updater HTTP APIs. If a binary has ZERO structural anomalies, ZERO packer section
        # names, is NOT masquerading, is NOT in a temp/AppData folder, and has NO hard-malware
        # process-injection / dropper chain (VirtualAllocEx+WriteProcessMemory, CreateRemoteThread,
        # NtUnmapViewOfSection, URLDownloadToFile), cap its static heuristic score below threshold.
        gui_media_dlls = {
            "opengl32.dll", "d3d11.dll", "d3d12.dll", "d3d9.dll", "dxgi.dll", "vulkan-1.dll",
            "sdl2.dll", "qt6core.dll", "qt5core.dll", "qt6gui.dll", "qt5gui.dll",
            "winmm.dll", "xinput1_3.dll", "xinput1_4.dll", "dinput8.dll", "dwmapi.dll",
            "gdi32.dll", "comctl32.dll", "comdlg32.dll", "ole32.dll", "uxtheme.dll",
            "user32.dll",
        }
        imp_lower = {a.lower() for a in suspicious_imports}
        has_hard_injection_chain = (
            {"virtualallocex", "writeprocessmemory"}.issubset(imp_lower)
            or "createremotethread" in imp_lower
            or "createremotethreadex" in imp_lower
            or "ntunmapviewofsection" in imp_lower
            or "urldownloadtofilea" in imp_lower
            or "urldownloadtofilew" in imp_lower
        )
        has_packer_section = "Packed / Obfuscated" in categories
        structural_anomalies = [a for a in anomalies if a.get("type") != "PROXY_SIDELOAD"]
        is_masquerading = name.lower() in SYSTEM_BINARY_NAMES and not _is_in_legit_windows_dir(file_path)
        has_rich_gui_media = len(imported_dlls & gui_media_dlls) >= 2 or (
            file_size >= 2 * 1024 * 1024 and bool(imported_dlls & gui_media_dlls)
        )
        if (
            has_rich_gui_media
            and not structural_anomalies
            and not has_packer_section
            and not is_masquerading
            and not in_suspicious_dir
            and not has_hard_injection_chain
        ):
            score = min(score, 18)
            anomalies = [a for a in anomalies if a.get("type") != "PROXY_SIDELOAD"]
            indicators.append("Calibrated: clean desktop/game/emulator profile (0 structural anomalies)")

        pe.close()
    except pefile.PEFormatError:
        return None
    except PermissionError:
        indicators.append("Access denied reading PE (run as Administrator)")
    except Exception as exc:
        indicators.append(f"PE parse warning: {exc}")

    # Signed binaries in standard system/Program Files locations get a trust discount
    if signed and not (name.lower() in SYSTEM_BINARY_NAMES and not _is_in_legit_windows_dir(file_path)):
        if norm_lower.startswith((r"c:\windows\\", r"c:\program files\\", r"c:\program files (x86)\\")):
            score = max(0, score - 35)

    # Persistence bonus if unsigned & suspicious
    if source in ("Registry", "Scheduled Task") and not signed and score >= 20:
        score += 12
        indicators.append(f"Auto-start persistence ({source})")

    score = min(100, max(0, score))

    return ThreatFinding(
        name=name,
        path=file_path,
        source=source,
        risk_score=score,
        severity=_severity_from_score(score),
        pid=pid,
        signed=signed,
        is_packed=is_packed,
        max_entropy=round(max_entropy, 2),
        sha256=compute_sha256(file_path) if score >= 25 or source == "Manual File" else "",
        categories=sorted(categories),
        suspicious_imports=sorted(suspicious_imports),
        indicators=indicators,
        persistence_ref=persistence_ref,
        anomalies=anomalies,
    )


# ---------------------------------------------------------------------------
# System Scanner Orchestrator
# ---------------------------------------------------------------------------

class SystemScanner:
    """Scans running processes, loaded DLLs, startup registry keys, and scheduled tasks."""

    def __init__(self, log_callback: Optional[Callable[[str], None]] = None):
        self._log = log_callback or (lambda msg: None)
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run_full_scan(
        self,
        min_score: int = 25,
        scan_dlls: bool = True,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> List[ThreatFinding]:
        """Run complete process, DLL, registry, and scheduled task scan."""
        self._cancel = False
        findings: List[ThreatFinding] = []
        seen_keys: Set[Tuple[str, str]] = set()
        pe_cache: Dict[str, Optional[ThreatFinding]] = {}

        def _cached_analyze(path: str, source: str, pid: Optional[int] = None, pref: str = "") -> Optional[ThreatFinding]:
            norm = os.path.normpath(path).lower()
            if norm in pe_cache:
                base = pe_cache[norm]
                if base is None:
                    return None
                return ThreatFinding(
                    name=base.name,
                    path=base.path,
                    source=source,
                    risk_score=base.risk_score,
                    severity=base.severity,
                    pid=pid,
                    signed=base.signed,
                    is_packed=base.is_packed,
                    max_entropy=base.max_entropy,
                    sha256=base.sha256,
                    categories=list(base.categories),
                    suspicious_imports=list(base.suspicious_imports),
                    indicators=list(base.indicators),
                    persistence_ref=pref,
                    anomalies=list(base.anomalies),
                )
            res = analyze_pe_file(path, source=source, pid=pid, persistence_ref=pref)
            pe_cache[norm] = res
            return res

        # --- Stage 1: Running Processes & Loaded DLLs ---
        self._log("[SCAN] Stage 1/3: Scanning running processes and loaded DLLs...")
        procs = list(psutil.process_iter(["pid", "name", "exe"]))
        total_procs = max(1, len(procs))

        for idx, proc in enumerate(procs):
            if self._cancel:
                self._log("[SCAN] Scan cancelled by user.")
                return findings
            if progress_callback and idx % 5 == 0:
                progress_callback(0.55 * (idx / total_procs), f"Scanning process {idx + 1}/{total_procs}...")

            try:
                pid = proc.info["pid"]
                exe = proc.info.get("exe")
                if exe and os.path.isfile(exe):
                    key = (os.path.normpath(exe).lower(), "Process")
                    if key not in seen_keys:
                        seen_keys.add(key)
                        f = _cached_analyze(exe, source="Process", pid=pid)
                        if f and f.risk_score >= min_score:
                            findings.append(f)

                # Scan non-system loaded DLLs in user-writable folders
                if scan_dlls:
                    try:
                        for mmap in proc.memory_maps():
                            dll_path = mmap.path
                            if dll_path and dll_path.lower().endswith(".dll") and _is_in_suspicious_dir(dll_path):
                                dkey = (os.path.normpath(dll_path).lower(), "Loaded DLL")
                                if dkey not in seen_keys and os.path.isfile(dll_path):
                                    seen_keys.add(dkey)
                                    df = _cached_analyze(
                                        dll_path,
                                        source="Loaded DLL",
                                        pid=pid,
                                        pref=f"Loaded by {proc.info.get('name', 'PID ' + str(pid))}",
                                    )
                                    if df and df.risk_score >= min_score:
                                        findings.append(df)
                    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                        pass
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                continue

        # --- Stage 2: Startup Registry Keys (Windows only) ---
        if not self._cancel and winreg is not None:
            if progress_callback:
                progress_callback(0.65, "Scanning Windows startup registry keys...")
            self._log("[SCAN] Stage 2/3: Scanning HKCU/HKLM Run persistence keys...")
            for hive, subkey, label in RUN_REGISTRY_KEYS:
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key_handle:
                        count = winreg.QueryInfoKey(key_handle)[1]
                        for i in range(count):
                            val_name, val_data, _ = winreg.EnumValue(key_handle, i)
                            if isinstance(val_data, str):
                                exe_path = extract_executable_path(val_data)
                                if exe_path:
                                    rkey = (os.path.normpath(exe_path).lower(), "Registry")
                                    if rkey not in seen_keys:
                                        seen_keys.add(rkey)
                                        rf = _cached_analyze(
                                            exe_path,
                                            source="Registry",
                                            persistence_ref=f"{label}\\{val_name}",
                                        )
                                        if rf and rf.risk_score >= min_score:
                                            findings.append(rf)
                except OSError:
                    continue

        # --- Stage 3: Scheduled Tasks (Windows only) ---
        if not self._cancel and os.name == "nt":
            if progress_callback:
                progress_callback(0.82, "Scanning Windows Scheduled Tasks...")
            self._log("[SCAN] Stage 3/3: Scanning Windows Scheduled Tasks...")
            task_entries = self._enumerate_scheduled_tasks()
            for task_name, task_cmd in task_entries:
                if self._cancel:
                    break
                exe_path = extract_executable_path(task_cmd)
                if exe_path:
                    tkey = (os.path.normpath(exe_path).lower(), "Scheduled Task")
                    if tkey not in seen_keys:
                        seen_keys.add(tkey)
                        tf = _cached_analyze(
                            exe_path,
                            source="Scheduled Task",
                            persistence_ref=task_name,
                        )
                        if tf and tf.risk_score >= min_score:
                            findings.append(tf)

        findings.sort(key=lambda x: x.risk_score, reverse=True)
        if progress_callback:
            progress_callback(1.0, f"Scan complete: {len(findings)} suspicious item(s) found.")
        self._log(f"[SCAN] Complete. Identified {len(findings)} suspicious artifact(s) (threshold >= {min_score}).")
        return findings

    def scan_directory(
        self,
        folder_path: str,
        min_score: int = 0,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ) -> Tuple[List[ThreatFinding], Dict[str, int]]:
        """
        Recursively scan a game or application folder for ALL Windows PE binaries
        (.exe, .dll, .asi, .flt, .ocx, .scr, .sys), including unsigned proxy/sideloaded DLLs.
        Allows normal same-folder file access while flagging credential theft, C2,
        persistence, injection, keyloggers, and malicious proxy DLLs.
        """
        self._cancel = False
        root = Path(folder_path)
        if not root.is_dir():
            raise NotADirectoryError(f"Folder not found: {folder_path}")

        self._log(f"[SCAN] Scanning game/app folder recursively for .exe / .dll binaries: {folder_path}")
        if progress_callback:
            progress_callback(0.05, f"Discovering .exe / .dll files in {root.name}...")

        candidates: List[str] = []
        for dirpath, _dirnames, filenames in os.walk(folder_path):
            if self._cancel:
                break
            for fn in filenames:
                if fn.lower().endswith(PE_SCAN_EXTENSIONS):
                    candidates.append(os.path.join(dirpath, fn))

        total = max(1, len(candidates))
        exe_count = sum(1 for c in candidates if c.lower().endswith(".exe"))
        dll_count = sum(1 for c in candidates if c.lower().endswith((".dll", ".asi", ".flt", ".ocx")))
        findings: List[ThreatFinding] = []
        flagged_count = 0

        for idx, fpath in enumerate(candidates):
            if self._cancel:
                break
            if progress_callback:
                progress_callback(
                    0.08 + 0.90 * ((idx + 1) / total),
                    f"Auditing {os.path.basename(fpath)} ({idx + 1}/{len(candidates)})...",
                )
            rel_parent = os.path.relpath(os.path.dirname(fpath), folder_path)
            src_label = "Game Folder (.exe)" if fpath.lower().endswith(".exe") else "Game Folder (.dll)"
            res = analyze_pe_file(
                fpath,
                source=src_label,
                persistence_ref=f".\\{rel_parent}" if rel_parent != "." else "Root Folder",
            )
            if res is None:
                continue
            if res.risk_score >= 25:
                flagged_count += 1
            if res.risk_score >= min_score:
                findings.append(res)

        findings.sort(key=lambda x: x.risk_score, reverse=True)
        stats = {
            "total_pe": len(candidates),
            "exe_count": exe_count,
            "dll_count": dll_count,
            "flagged_count": flagged_count,
            "clean_count": max(0, len(candidates) - flagged_count),
        }
        msg = (
            f"Folder scan complete: {len(candidates)} PE file(s) "
            f"({exe_count} .exe, {dll_count} .dll) — {stats['clean_count']} clean, {flagged_count} flagged."
        )
        if progress_callback:
            progress_callback(1.0, msg)
        self._log(f"[SCAN] {msg}")
        return findings, stats

    def _enumerate_scheduled_tasks(self) -> List[Tuple[str, str]]:
        """Query Windows Scheduled Tasks via schtasks CSV output."""
        tasks: List[Tuple[str, str]] = []
        try:
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            proc = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True,
                text=True,
                timeout=25,
                creationflags=creation_flags,
                errors="ignore",
            )
            if proc.returncode != 0 or not proc.stdout:
                return tasks

            reader = csv.DictReader(io.StringIO(proc.stdout))
            for row in reader:
                task_name = (row.get("TaskName") or "").strip()
                task_cmd = (row.get("Task To Run") or "").strip()
                if not task_name or not task_cmd or task_name == "TaskName":
                    continue
                # Skip standard Microsoft inbox tasks for performance
                if task_name.lower().startswith("\\microsoft\\windows\\"):
                    continue
                tasks.append((task_name, task_cmd))
        except Exception as exc:
            self._log(f"[SCAN] Scheduled tasks query warning: {exc}")
        return tasks


# ---------------------------------------------------------------------------
# Live Network Monitor Helper
# ---------------------------------------------------------------------------

def get_active_connections() -> List[NetworkConnectionInfo]:
    """Enumerate active TCP/UDP connections mapped to PIDs and executable paths."""
    results: List[NetworkConnectionInfo] = []
    proc_cache: Dict[int, Tuple[str, str]] = {}

    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return results

    for c in conns:
        pid = c.pid or 0
        if pid not in proc_cache:
            if pid == 0:
                proc_cache[pid] = ("System Idle / Kernel", "")
            else:
                try:
                    p = psutil.Process(pid)
                    proc_cache[pid] = (p.name(), p.exe() or "")
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    proc_cache[pid] = (f"PID {pid}", "")

        pname, exe_path = proc_cache[pid]
        proto = "TCP" if c.type == 1 else "UDP"
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
        status = c.status or ("OPEN" if proto == "UDP" else "-")

        is_external = False
        if c.raddr and c.raddr.ip:
            ip = c.raddr.ip
            if not (
                ip.startswith("127.")
                or ip == "::1"
                or ip == "0.0.0.0"
                or ip.startswith("192.168.")
                or ip.startswith("10.")
                or ip.startswith("169.254.")
            ):
                is_external = True

        results.append(
            NetworkConnectionInfo(
                pid=pid,
                process_name=pname,
                exe_path=exe_path,
                protocol=proto,
                local_addr=laddr,
                remote_addr=raddr,
                status=status,
                is_external=is_external,
            )
        )

    # Sort external established connections to the top
    results.sort(key=lambda x: (not x.is_external, x.status != "ESTABLISHED", x.process_name.lower()))
    return results
