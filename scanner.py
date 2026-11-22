"""
GhidraGuard - System, Process, DLL, Registry, Scheduled Task & PE Heuristic Scanner
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
import winreg
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

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
        "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW",
        "GetTickCount64", "QueryPerformanceCounter",
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

SUSPICIOUS_PATH_FRAGMENTS: Tuple[str, ...] = (
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\downloads\\",
)

RUN_REGISTRY_KEYS: List[Tuple[int, str, str]] = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\WOW6432\\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\WOW6432\\RunOnce"),
]


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
    Returns a ThreatFinding with heuristic score and indicators.
    """
    if not file_path or not os.path.isfile(file_path):
        return None

    name = os.path.basename(file_path)
    norm_lower = os.path.normpath(file_path).lower()
    score = 0
    indicators: List[str] = []
    categories: Set[str] = set()
    suspicious_imports: List[str] = []
    signed = False
    is_packed = False
    max_entropy = 0.0

    # 1. Masquerading system binary name check
    if name.lower() in SYSTEM_BINARY_NAMES and not _is_in_legit_windows_dir(file_path):
        score += 45
        indicators.append(f"Masquerading system binary '{name}' outside Windows directory")
        categories.add("Masquerading")

    # 2. Suspicious directory check
    in_suspicious_dir = _is_in_suspicious_dir(file_path)
    if in_suspicious_dir:
        score += 18
        indicators.append("Located in user-writable/temp directory")

    # 3. Parse PE headers, imports, signature, and section entropy
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            ]
        )

        signed = is_pe_signed(file_path, pe_obj=pe)
        if not signed:
            if in_suspicious_dir:
                score += 22
                indicators.append("Unsigned PE in Temp/AppData/Public folder")
            else:
                score += 8
                indicators.append("Binary is not digitally signed")

        # Inspect imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            found_apis: Set[str] = set()
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode("utf-8", errors="ignore")
                        cat = ALL_SUSPICIOUS_APIS.get(api_name.lower())
                        if cat and api_name not in found_apis:
                            found_apis.add(api_name)
                            suspicious_imports.append(api_name)
                            categories.add(cat)

            if suspicious_imports:
                # Weight injection & keylogger APIs higher
                high_risk_cats = {"Keylogger / Spyware", "Process Injection / RAT"}
                if categories & high_risk_cats:
                    score += min(35, 12 + 5 * len(suspicious_imports))
                else:
                    score += min(25, 6 + 3 * len(suspicious_imports))
                preview = ", ".join(suspicious_imports[:6])
                suffix = f" (+{len(suspicious_imports) - 6} more)" if len(suspicious_imports) > 6 else ""
                indicators.append(f"Suspicious APIs: {preview}{suffix}")

        # Section entropy (packer / obfuscation indicator)
        for sec in pe.sections:
            sec_name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="ignore")
            data = sec.get_data()
            ent = _shannon_entropy(data)
            if ent > max_entropy:
                max_entropy = ent
            if sec_name.upper().startswith(("UPX", "ASPACK", "VMP", "THEMIDA", ".ENIGMA")):
                is_packed = True
                score += 20
                indicators.append(f"Packer section detected: {sec_name}")

        if max_entropy >= 7.25:
            is_packed = True
            score += 15
            indicators.append(f"High section entropy ({max_entropy:.2f}) — possibly packed/encrypted")

        pe.close()
    except pefile.PEFormatError:
        # Not a valid PE file
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

        # --- Stage 2: Startup Registry Keys ---
        if not self._cancel:
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

        # --- Stage 3: Scheduled Tasks ---
        if not self._cancel:
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
