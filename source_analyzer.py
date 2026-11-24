"""
OpcodeShield v4.1.0 — Universal Any-File & Source Code RAT / Stealer Analyzer.
Supports inspecting ANY file type:
  - Python (.py, .pyw) via deep Python AST inspection (never executes code!)
  - Rust (.rs), JavaScript/TypeScript (.js, .ts, .mjs), PowerShell (.ps1),
    Batch (.bat, .cmd), Shell (.sh), C/C++ (.c, .cpp, .h), Go (.go),
    Java/Kotlin (.java, .kt), C# (.cs), PHP (.php), Ruby (.rb), VBScript (.vbs),
    and arbitrary unknown/raw files.
Pinpoints exact malicious line numbers, auto-decodes Base64/PowerShell `-enc` payloads,
and supports surgical source-code disinfection (commenting out / neutralizing malicious lines).
"""

from __future__ import annotations

import ast
import base64
import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

SOURCE_EXT_MAP = {
    ".py": "python", ".pyw": "python",
    ".rs": "rust",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript",
    ".ps1": "powershell", ".psm1": "powershell",
    ".bat": "batch", ".cmd": "batch",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".go": "go",
    ".java": "java", ".kt": "kotlin", ".cs": "csharp",
    ".php": "php", ".rb": "ruby", ".vbs": "vbscript", ".hta": "hta",
}

# Universal RAT / Stealer / Reverse-Shell / Persistence rules across all languages & files
UNIVERSAL_RAT_RULES: List[Tuple[str, re.Pattern[str], str, int]] = [
    ("RAT_Discord_Webhook", re.compile(r"discord(?:app)?\.com/api/webhooks/\d+", re.I), "Hardcoded Discord webhook exfiltration URL", 38),
    ("RAT_Telegram_Bot_C2", re.compile(r"api\.telegram\.org/bot[0-9A-Za-z:_-]+", re.I), "Hardcoded Telegram Bot C2 endpoint", 36),
    ("RAT_Bash_DevTcp_Shell", re.compile(r"/dev/tcp/[^\s\"']+", re.I), "Unix /dev/tcp reverse shell connection", 45),
    ("RAT_Netcat_Shell", re.compile(r"\b(?:nc|ncat|netcat)\b[^\n]{0,40}\s-[ec]\s", re.I), "Netcat reverse shell execution", 42),
    ("RAT_PowerShell_TcpClient", re.compile(r"Net\.Sockets\.TCPClient|Invoke-Expression|\bIEX\b\s*\(", re.I), "PowerShell reverse shell / IEX stager", 40),
    ("RAT_PowerShell_Encoded", re.compile(r"powershell[^\n]{0,40}(?:-e|-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{16,})", re.I), "Obfuscated PowerShell encoded command", 38),
    ("RAT_Defender_Tamper", re.compile(r"Add-MpPreference\s+-ExclusionPath|DisableRealtimeMonitoring\s+\$true", re.I), "Windows Defender exclusion / tampering", 40),
    ("RAT_Registry_Run_Persist", re.compile(r"CurrentVersion\\Run|schtasks\s+/create", re.I), "Windows persistence mechanism (Run key / Scheduled Task)", 28),
    ("RAT_Browser_Stealer", re.compile(r"Login Data|Local State|CryptUnprotectData|browser_cookie3", re.I), "Browser password / cookie stealer", 36),
    ("RAT_Keylogger_API", re.compile(r"SetWindowsHookEx|GetAsyncKeyState|pynput\.keyboard|keyboard\.on_press", re.I), "Keylogger / keystroke capture", 34),
    ("RAT_Process_Injection", re.compile(r"VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection", re.I), "Remote process memory injection", 40),
    ("RAT_Rust_Reverse_Shell", re.compile(r"TcpStream::connect[\s\S]{0,400}Command::new\s*\(\s*\"(?:cmd|powershell|sh|/bin/sh|bash)", re.I), "Rust TcpStream + Command reverse shell RAT", 58),
    ("RAT_Rust_Shellcode_Exec", re.compile(r"(?:std::mem::transmute[\s\S]{0,140}extern\s+\"C\"\s+fn|extern\s+\"C\"\s+fn[\s\S]{0,140}std::mem::transmute)", re.I), "Rust unsafe shellcode function-pointer transmutation", 42),
    ("RAT_JS_ChildProcess_Shell", re.compile(r"child_process[\s\S]{0,300}(?:net\.Socket|net\.connect|ws://|wss://)", re.I), "Node.js reverse shell / WebSocket RAT", 45),
    ("RAT_Ransomware_Wiper", re.compile(r"vssadmin\s+delete\s+shadows|wbadmin\s+delete", re.I), "Ransomware shadow-copy wiper", 45),
    ("RAT_Eval_Base64_Stager", re.compile(r"(?:exec|eval)\s*\(\s*(?:base64\.b64decode|atob|Buffer\.from|zlib\.decompress)", re.I), "Base64/compressed obfuscated dynamic payload execution", 38),
]

IOC_RE = re.compile(r"(?:https?://[^\s\"'<>`]{6,140}|\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b)", re.I)


def _analyze_python_ast(text: str) -> Tuple[int, List[Dict[str, Any]], List[str]]:
    """Deep static Python AST inspection — finds RATs, keyloggers, stealers, and obfuscated stagers."""
    findings: List[Dict[str, Any]] = []
    imports: set[str] = set()
    score = 0
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return 0, [], []

    has_socket = False
    has_subproc = False
    has_exec_eval = False
    has_decode = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0].lower())
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0].lower())
        elif isinstance(node, ast.Call):
            fn_name = ""
            if isinstance(node.func, ast.Name):
                fn_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                fn_name = node.func.attr
            lineno = getattr(node, "lineno", 0)
            if fn_name in ("connect", "create_connection"):
                has_socket = True
            elif fn_name in ("Popen", "system", "check_output", "run", "spawn"):
                has_subproc = True
            elif fn_name in ("exec", "eval", "compile", "__import__"):
                has_exec_eval = True
                findings.append({"line": lineno, "rule": "PY_AST_DynamicExec", "detail": f"Dynamic code execution call `{fn_name}()`", "severity": "HIGH"})
                score += 18
            elif fn_name in ("b64decode", "decompress", "loads"):
                has_decode = True
            elif fn_name in ("SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"):
                findings.append({"line": lineno, "rule": "PY_AST_Win32Abuse", "detail": f"Direct Win32 ctypes call `{fn_name}`", "severity": "CRITICAL"})
                score += 32

    if "socket" in imports and (has_subproc or "subprocess" in imports or "pty" in imports):
        findings.append({"line": 1, "rule": "PY_AST_ReverseShell", "detail": "Python script combines `socket` networking with `subprocess`/`pty` shell execution (RAT)", "severity": "CRITICAL"})
        score += 44
    if has_exec_eval and has_decode:
        findings.append({"line": 1, "rule": "PY_AST_ObfuscatedLoader", "detail": "Python script decodes obfuscated data (`base64`/`zlib`/`marshal`) and passes it to `exec`/`eval`", "severity": "CRITICAL"})
        score += 36
    for risky_mod, desc, pts in [
        ("pynput", "Keylogger library `pynput` imported", 28),
        ("keyboard", "Global keyboard hook library `keyboard` imported", 24),
        ("mss", "Screen capture library `mss` imported", 16),
        ("browser_cookie3", "Browser credential/cookie stealer `browser_cookie3` imported", 34),
        ("win32crypt", "Windows DPAPI credential decryption `win32crypt` imported", 28),
    ]:
        if risky_mod in imports:
            findings.append({"line": 1, "rule": f"PY_AST_Import_{risky_mod}", "detail": desc, "severity": "HIGH"})
            score += pts

    return min(100, score), findings, sorted(imports)


def analyze_any_file(path: str | Path) -> Dict[str, Any]:
    p = Path(path)
    return analyze_any_bytes(p.read_bytes(), p.name)


def analyze_any_bytes(data: bytes, filename: str = "sample.bin") -> Dict[str, Any]:
    sha256 = hashlib.sha256(data).hexdigest()
    ext = Path(filename).suffix.lower()
    lang = SOURCE_EXT_MAP.get(ext, "")

    # Detect text vs binary
    sample_slice = data[:65536]
    null_ratio = sample_slice.count(0) / max(1, len(sample_slice))
    is_text = bool(lang) or (null_ratio < 0.02 and len(data) <= 10 * 1024 * 1024)

    text = data.decode("utf-8", errors="replace") if is_text else data.decode("latin-1", errors="ignore")
    lines = text.splitlines() if is_text else []

    score = 0
    findings: List[Dict[str, Any]] = []
    indicators: List[str] = []
    iocs: List[str] = []
    decoded_payloads: List[str] = []

    # 1. Deep Python AST if Python source
    py_imports: List[str] = []
    if lang == "python":
        ast_score, ast_findings, py_imports = _analyze_python_ast(text)
        score += ast_score
        findings.extend(ast_findings)
        for f in ast_findings:
            indicators.append(f"Line {f['line']}: {f['detail']}")

    # 2. Universal RAT / Stealer / Reverse-Shell rules (works on ANY file: Rust, JS, PS1, C, Go, raw binary)
    for rule_name, pat, desc, pts in UNIVERSAL_RAT_RULES:
        m = pat.search(text)
        if m:
            lineno = text[: m.start()].count("\n") + 1 if is_text else 0
            findings.append({"line": lineno, "rule": rule_name, "detail": desc, "severity": "CRITICAL" if pts >= 38 else "HIGH"})
            loc = f"Line {lineno}: " if lineno > 0 else ""
            indicators.append(f"{loc}{rule_name} — {desc}")
            score += pts
            # Auto-decode PowerShell -EncodedCommand base64 (UTF-16LE)
            if rule_name == "RAT_PowerShell_Encoded" and m.lastindex:
                try:
                    raw_b64 = base64.b64decode(m.group(1) + "===")
                    dec = raw_b64.decode("utf-16le", errors="ignore").strip()
                    if dec:
                        decoded_payloads.append(dec[:240])
                        indicators.append(f"Decoded PowerShell payload: {dec[:120]}")
                except Exception:
                    pass

    # 3. Extract IOCs (URLs, C2 IP:Port)
    for m in IOC_RE.findall(text[:2_000_000]):
        if m not in iocs:
            iocs.append(m)
            if len(iocs) >= 25:
                break

    score = min(100, score)
    severity = "CRITICAL" if score >= 75 else ("HIGH" if score >= 50 else ("MEDIUM" if score >= 25 else "LOW"))
    file_kind = lang if lang else ("text" if is_text else "generic_binary")

    ai_feature_text = (
        f"FILE_SCAN name={filename} lang={file_kind} score={score} severity={severity} "
        f"findings={','.join(f['rule'] for f in findings) or 'none'} "
        f"indicators={'; '.join(indicators[:5]) or 'none'}"
    )

    return {
        "filename": filename,
        "size": len(data),
        "sha256": sha256,
        "type": file_kind,
        "is_source_code": bool(lang) or is_text,
        "line_count": len(lines),
        "risk_score": score,
        "severity": severity,
        "findings": findings,
        "indicators": indicators,
        "iocs": iocs,
        "decoded_payloads": decoded_payloads,
        "imports": py_imports,
        "ai_feature_text": ai_feature_text,
    }


def sanitize_source_code(text: str, findings: List[Dict[str, Any]], lang: str = "python") -> Tuple[str, int]:
    """Surgically comment out / neutralize flagged malicious lines in source code while preserving clean logic."""
    comment_prefix = "#" if lang in ("python", "shell", "powershell", "ruby") else ("REM " if lang == "batch" else "//")
    flagged_lines = {int(f["line"]) for f in findings if int(f.get("line", 0)) > 1}
    if not flagged_lines:
        return text, 0
    out_lines = []
    patched = 0
    for idx, line in enumerate(text.splitlines(), start=1):
        if idx in flagged_lines:
            out_lines.append(f"{comment_prefix} [OPCODESHIELD NEUTRALIZED] {line}")
            patched += 1
        else:
            out_lines.append(line)
    return "\n".join(out_lines) + "\n", patched
