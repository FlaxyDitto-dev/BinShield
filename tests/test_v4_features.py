"""
BinShield v4.0.0 — End-to-End Automated Verification Suite.
Verifies:
  1. Unified Native Rust Core DLL (PE/ELF analysis, IOC extraction, CFG graph, surgical patching)
  2. Unicorn Engine Safe CPU Emulation (XOR-encrypted C2 URL decryption in isolated virtual CPU)
  3. Exportable HTML & SARIF 2.1.0 Security Reports + Offline SHA-256 Bloom Filter
  4. BinShield-SecNet-v3 INT8 ONNX 5-Head Multi-Label AI Inference (clean vs keylogger vs shellcode)
  5. WebAssembly Core (`docs/wasm/binshield_core.wasm`) + PWA assets (`manifest.json`, `sw.js`)
  6. Windows Explorer Context Menu registration module
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from custom_model import BinShieldSecNetClient
from report_exporter import ThreatHashBloomFilter, export_html_report, export_sarif
from rust_core import get_rust_core
from unicorn_emulator import UnicornEmulator


def main() -> None:
    # 1. Native Rust Core DLL
    rc = get_rust_core()
    assert rc.available, "Native Rust core DLL should be loaded"
    sample = (
        b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00PE\x00\x00\x64\x86\x00\x00" + b"\x00" * 64
        + b"\x55\x48\x89\xe5SetWindowsHookEx https://discord.com/api/webhooks/1/2 \x65\x48\x8b\x04\x25\x60\x00\x00\x00"
    )
    res = rc.analyze_bytes(sample, "test_v4_keylogger.exe")
    assert res["risk_score"] >= 70, f"Expected high risk score, got {res['risk_score']}"
    assert len(res["cfg"]["nodes"]) >= 3 and len(res["cfg"]["edges"]) >= 2, "CFG graph missing nodes/edges"
    assert any("discord.com/api/webhooks" in x for x in res["iocs"]), "IOC URL not extracted"
    patch_res, patched = rc.patch_bytes(sample, 0x80, "RET_ZERO", 3)
    assert patch_res["ok"] and patch_res["new_hex"] == "31 C0 C3" and patched[0x80:0x83] == b"\x31\xC0\xC3"
    print(f"[PASS] 1. Unified Rust Core DLL (score={res['risk_score']}, CFG={len(res['cfg']['nodes'])} nodes, patch=31 C0 C3)")

    # 2. Unicorn Safe CPU Emulation (XOR-decrypt a hidden C2 URL in isolated virtual CPU)
    emu = UnicornEmulator()
    assert emu.is_available(), "Unicorn Engine should be installed"
    secret = b"https://evil-c2.example/stage2\x00"
    enc = bytes(b ^ 0x5A for b in secret)
    # x86_64 decrypt loop: rdi = data_addr, rcx = len, xor byte [rdi], 0x5A; inc rdi; loop
    stub = (
        b"\x48\xc7\xc1" + len(enc).to_bytes(4, "little")  # mov rcx, len
        + b"\x80\x37\x5a"                                  # xor byte ptr [rdi], 0x5a
        + b"\x48\xff\xc7"                                  # inc rdi
        + b"\xe2\xf8"                                      # loop -8
        + b"\x90"                                          # nop
    )
    emu_res = emu.emulate_code(stub, arch="x86_64", data_buffer=enc)
    assert emu_res["ok"], f"Unicorn failed: {emu_res}"
    assert any("evil-c2.example" in s for s in emu_res["iocs"]), f"Decrypted C2 URL not found: {emu_res}"
    print(f"[PASS] 2. Unicorn Safe CPU Emulator (decrypted hidden C2 IOC: {emu_res['iocs'][0]})")

    # 3. HTML / SARIF Report Export + Offline SHA-256 Bloom Filter
    bf = ThreatHashBloomFilter.default_seed()
    assert bf.contains("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"), "EICAR SHA-256 should match Bloom filter"
    assert not bf.contains("0" * 64), "Zero hash should not match Bloom filter"
    with tempfile.TemporaryDirectory() as td:
        sarif_p = export_sarif([res], Path(td) / "report.sarif.json")
        html_p = export_html_report(res, Path(td) / "report.html")
        sarif_data = json.loads(sarif_p.read_text(encoding="utf-8"))
        assert sarif_data["version"] == "2.1.0" and len(sarif_data["runs"][0]["results"]) == 1
        assert "BinShield v4.0.0 Security Audit Report" in html_p.read_text(encoding="utf-8")
    print("[PASS] 3. HTML / SARIF 2.1.0 Report Exporter & Offline SHA-256 Bloom Filter")

    # 4. BinShield-SecNet-v3 INT8 ONNX 5-Head Multi-Label AI
    client = BinShieldSecNetClient(device="onnx", model_dir=Path("models/BinShield-SecNet-v3"))
    clean_pred = client.predict("PE_SCAN name=retroarch.exe score=4 severity=LOW signed=true packed=false anoms=none yara=none apis=none indicators=none")
    mal_pred = client.predict(res["ai_feature_text"])
    assert not clean_pred["is_malicious"], f"Clean FP: {clean_pred}"
    assert mal_pred["is_malicious"] and len(mal_pred["behaviors"]) >= 1, f"Malicious FN/missing behaviors: {mal_pred}"
    print(f"[PASS] 4. BinShield-SecNet-v3 INT8 ONNX (clean=CLN, mal={mal_pred['category']}, behaviors={mal_pred['behaviors']}, urgency={mal_pred['patch_urgency']}%)")

    # 5. WebAssembly + PWA Artifacts
    for req_file in [
        "docs/index.html", "docs/app.js", "docs/styles.css", "docs/manifest.json", "docs/sw.js",
        "docs/wasm/binshield_core.wasm", "docs/models/BinShield-SecNet-v3-int8.onnx", "docs/models/BinShield-SecNet-v3-vocab.json",
    ]:
        assert Path(req_file).exists(), f"Missing PWA/WASM file: {req_file}"
    print("[PASS] 5. Compact PWA & WebAssembly Assets Verified")

    # 6. Explorer Context Menu module import check
    import context_menu
    assert callable(context_menu.register_context_menu) and callable(context_menu.unregister_context_menu)
    print("[PASS] 6. Windows Explorer Right-Click Context Menu Module Verified")

    print("\nALL 6/6 BINSHIELD v4.0.0 FEATURE & MAJOR UPGRADE TESTS PASSED 100%!")


if __name__ == "__main__":
    main()
