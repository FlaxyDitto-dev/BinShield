"""
BinShield v2.0.0 CLI - Headless Scanner, Sanitizer, Disassembler, Sandbox, Folder Guard & Rollback
Supports Windows PE (.exe/.dll/.sys/.scr/.asi/.ocx), Android (.apk), Linux ELF (.so/.elf),
and macOS Mach-O (.dylib) binaries.

Commands:
    scan       <file_or_folder> [--json]
    sanitize   <input> [-o <output>] [--resign] [--no-backup] [--json]
    verify     <file> [--json]
    ai-scan    <file> [--device auto|gpu|npu|cpu|onnx|torch] [--json]
    disasm     <file> [--offset 0x...] [--count 30] [--json]
    sandbox    <file> [--timeout 5] [--json]
    watch      <folder> [--auto-quarantine] [--duration 10]
    diff       <before> <after> [--json]
    rollback   <file> [--snapshot <id>]
    update     [--check] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List

from apk_engine import analyze_apk_file, sanitize_apk, verify_apk_integrity
from apk_signer import sign_apk
from binary_patcher import BinaryPatcher
from disasm_unpacker import disassemble_pe_entrypoint, is_upx_packed, try_auto_unpack_upx
from folder_guard import FolderGuard
from rollback_manager import RollbackManager, generate_patch_diff
from sandbox_runner import run_in_sandbox
from scanner import PE_SCAN_EXTENSIONS, analyze_pe_file
from unix_binary_engine import (
    analyze_unix_binary,
    detect_unix_format,
    sanitize_unix_binary,
    verify_unix_integrity,
)
from updater import APP_VERSION, apply_self_update, check_for_updates, download_update
from yara_engine import YaraRuleEngine

ALL_SUPPORTED_EXTS = PE_SCAN_EXTENSIONS + (".apk", ".so", ".elf", ".dylib")
_YARA = YaraRuleEngine()


def _scan_one(path: Path) -> Dict[str, Any]:
    low = path.name.lower()
    yara_hits = [asdict(m) for m in _YARA.scan_file(str(path))]

    if low.endswith(".apk"):
        res = analyze_apk_file(str(path))
        if res is None:
            return {"path": str(path), "type": "apk", "error": "Invalid APK"}
        d = asdict(res)
        d["type"] = "apk"
        d["yara_matches"] = yara_hits
        return d

    unix_fmt = detect_unix_format(str(path))
    if unix_fmt is not None:
        ures = analyze_unix_binary(str(path))
        if ures is None:
            return {"path": str(path), "type": unix_fmt.lower(), "error": f"Invalid {unix_fmt}"}
        d = asdict(ures)
        d["type"] = unix_fmt.lower()
        d["yara_matches"] = yara_hits
        return d

    res = analyze_pe_file(str(path), source="CLI Scan")
    if res is None:
        return {"path": str(path), "type": "pe", "error": "Invalid PE/ELF/Mach-O/APK"}
    d = asdict(res)
    d["type"] = "pe"
    d["yara_matches"] = yara_hits
    if yara_hits and d.get("risk_score", 0) < 25 and not any("Calibrated:" in i for i in d.get("indicators", [])):
        d["risk_score"] = min(100, d["risk_score"] + 25)
    return d


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"Error: path not found: {target}", file=sys.stderr)
        return 2

    files: List[Path] = []
    if target.is_file():
        files.append(target)
    else:
        for root, _dirs, fnames in os.walk(target):
            for fn in fnames:
                if fn.lower().endswith(ALL_SUPPORTED_EXTS):
                    files.append(Path(root) / fn)

    results = [_scan_one(f) for f in files]
    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    flagged = 0
    for r in results:
        if "error" in r:
            print(f"[SKIP] {r['path']} ({r['error']})")
            continue
        score = r.get("risk_score", 0)
        sev = r.get("severity", "LOW")
        if score >= 25:
            flagged += 1
        y_cnt = len(r.get("yara_matches") or [])
        print(f"[{sev:8s}] score={score:3d} | {r['type'].upper():6s} | {r['name']} ({len(r.get('anomalies', []))} anomalies, {y_cnt} YARA)")
        for ind in r.get("indicators", [])[:5]:
            print(f"           - {ind}")
        for ym in (r.get("yara_matches") or [])[:3]:
            print(f"           - [YARA:{ym['severity']}] {ym['rule_name']}: {ym['description']}")
    print(f"\nScanned {len(results)} file(s): {flagged} flagged (>= 25), {len(results) - flagged} clean.")
    return 0


def cmd_sanitize(args: argparse.Namespace) -> int:
    src = Path(args.input)
    if not src.is_file():
        print(f"Error: input file not found: {src}", file=sys.stderr)
        return 2

    dst = Path(args.output) if args.output else src.with_name(f"{src.stem}_sanitized{src.suffix}")

    snap_id = ""
    if not args.no_backup:
        snap = RollbackManager().create_snapshot(str(src), note=f"Pre-sanitize backup -> {dst.name}")
        snap_id = snap.snapshot_id

    low = src.name.lower()
    if low.endswith(".apk"):
        before = analyze_apk_file(str(src))
        rep = sanitize_apk(str(src), str(dst), finding=before)
        sign_note = ""
        if rep.integrity_ok and args.resign:
            s_ok, s_method = sign_apk(str(dst))
            sign_note = f"re-signed ({s_method})" if s_ok else "re-sign skipped"
        after = analyze_apk_file(str(dst)) if dst.is_file() else None
        payload = {
            "type": "apk",
            "snapshot_id": snap_id,
            "before_score": before.risk_score if before else -1,
            "after_score": after.risk_score if after else -1,
            "sign_note": sign_note,
            "report": asdict(rep),
        }
    elif detect_unix_format(str(src)) is not None:
        before = analyze_unix_binary(str(src))
        rep = sanitize_unix_binary(str(src), str(dst), finding=before)
        after = analyze_unix_binary(str(dst)) if dst.is_file() else None
        payload = {
            "type": before.binary_format.lower() if before else "unix",
            "snapshot_id": snap_id,
            "before_score": before.risk_score if before else -1,
            "after_score": after.risk_score if after else -1,
            "report": asdict(rep),
        }
    else:
        work_src = str(src)
        if is_upx_packed(str(src)):
            unpacked = dst.with_suffix(".unpacked.tmp")
            u_ok, _ = try_auto_unpack_upx(str(src), str(unpacked))
            if u_ok:
                work_src = str(unpacked)
        patcher = BinaryPatcher()
        before = analyze_pe_file(work_src, source="CLI Sanitize")
        rep = patcher.sanitize_pe_binary(work_src, str(dst), finding=before)
        after = analyze_pe_file(str(dst), source="CLI Sanitize") if dst.is_file() else None
        payload = {
            "type": "pe",
            "snapshot_id": snap_id,
            "before_score": before.risk_score if before else -1,
            "after_score": after.risk_score if after else -1,
            "report": asdict(rep),
        }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        r = payload["report"]
        print(f"Sanitized : {src} -> {dst}")
        if snap_id:
            print(f"Rollback  : snapshot={snap_id}")
        print(f"Risk Score: {payload['before_score']} -> {payload['after_score']}")
        print(f"Integrity : {'PASS' if r['integrity_ok'] else 'FAIL'}")
        if payload.get("sign_note"):
            print(f"APK Sign  : {payload['sign_note']}")
        for act in r.get("actions_taken", []):
            print(f"  + {act}")
        for err in r.get("integrity_errors", []):
            print(f"  ! {err}")

    return 0 if payload["report"]["integrity_ok"] else 1


def cmd_verify(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.is_file():
        print(f"Error: file not found: {target}", file=sys.stderr)
        return 2

    if target.name.lower().endswith(".apk"):
        ok, errs = verify_apk_integrity(str(target))
        out = {"path": str(target), "type": "apk", "integrity_ok": ok, "errors": errs}
    elif detect_unix_format(str(target)) is not None:
        ok, errs = verify_unix_integrity(str(target))
        out = {"path": str(target), "type": detect_unix_format(str(target)), "integrity_ok": ok, "errors": errs}
    else:
        ok, errs, csum_ok = BinaryPatcher.verify_pe_integrity(str(target))
        out = {"path": str(target), "type": "pe", "integrity_ok": ok, "checksum_valid": csum_ok, "errors": errs}

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"[{'PASS' if ok else 'FAIL'}] {target.name} ({str(out['type']).upper()})")
        for e in errs:
            print(f"  ! {e}")
    return 0 if ok else 1


def cmd_ai_scan(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.is_file():
        print(f"Error: file not found: {target}", file=sys.stderr)
        return 2

    from custom_model import BinShieldSecNetClient, format_scan_for_ai

    static_res = _scan_one(target)
    summary_text = format_scan_for_ai(static_res, filename=target.name)

    client = BinShieldSecNetClient(device=args.device, log_callback=(None if args.json else print))
    ai_pred = client.predict(summary_text)
    payload = {"file": str(target), "static_score": static_res.get("risk_score", 0), "ai": ai_pred}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"[AI] Model    : {ai_pred['model']} ({ai_pred['device']})")
        print(f"[AI] Verdict  : {'MALICIOUS' if ai_pred['is_malicious'] else 'CLEAN'} (prob={ai_pred['malicious_probability']*100:.1f}%)")
        print(f"[AI] Category : {ai_pred['category']} ({ai_pred['category_confidence']*100:.1f}%)")
        print(f"[AI] Strategy : {ai_pred['patch_strategy']} ({ai_pred['strategy_confidence']*100:.1f}%)")
    return 0


def cmd_disasm(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.is_file():
        print(f"Error: file not found: {target}", file=sys.stderr)
        return 2
    off = int(args.offset, 0) if args.offset else None
    res = disassemble_pe_entrypoint(str(target), file_offset=off, max_insns=args.count)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"Disassembly of {res['file']} ({res['arch']}) @ offset {res['file_offset']} (VA {res['base_va']}):")
        for ins in res["instructions"]:
            print(f"  {ins['va']:<14} {ins['bytes']:<24} {ins['mnemonic']:<8} {ins['op_str']}")
    return 0


def cmd_sandbox(args: argparse.Namespace) -> int:
    res = run_in_sandbox(args.target, timeout_seconds=args.timeout)
    if args.json:
        print(json.dumps(asdict(res), indent=2))
    else:
        print(f"[SANDBOX] {Path(res.target_path).name} -> {res.verdict} ({res.elapsed_seconds}s)")
        if res.stdout_preview:
            print(f"  stdout : {res.stdout_preview}")
        if res.created_files:
            print(f"  dropped: {', '.join(res.created_files)}")
    return 0 if not res.crashed else 1


def cmd_watch(args: argparse.Namespace) -> int:
    guard = FolderGuard(
        watch_dirs=[args.folder],
        auto_quarantine=args.auto_quarantine,
        log_callback=print,
    )
    guard.start(scan_existing=args.scan_existing)
    try:
        if args.duration > 0:
            time.sleep(args.duration)
        else:
            print("[GUARD] Press Ctrl+C to stop watching...")
            while True:
                time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        guard.stop()
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    d = generate_patch_diff(args.before, args.after)
    if args.json:
        print(json.dumps(d, indent=2))
    else:
        print(f"Size: {d['before_size']} -> {d['after_size']} bytes (delta={d['size_delta']:+d})")
        print(f"Changed regions ({len(d['changed_regions'])}):")
        for r in d["changed_regions"]:
            print(f"  @ {r['offset']} ({r['length']}B): [{r['before_hex']}] -> [{r['after_hex']}]")
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    ok, msg = RollbackManager().rollback(args.target, snapshot_id=args.snapshot)
    print(f"[{'OK' if ok else 'FAIL'}] {msg}")
    return 0 if ok else 1


def cmd_update(args: argparse.Namespace) -> int:
    """Explicit CLI update command (CLI never auto-updates on normal commands)."""
    res = check_for_updates(variant="cli")
    out: Dict[str, Any] = asdict(res)
    if res.error:
        print(json.dumps(out, indent=2) if args.json else f"[UPDATE] Check failed: {res.error}", file=sys.stderr if not args.json else sys.stdout)
        return 1
    if not res.update_available:
        print(json.dumps(out, indent=2) if args.json else f"[UPDATE] BinShield CLI v{res.current_version} is already up to date.")
        return 0
    if args.check:
        print(json.dumps(out, indent=2) if args.json else f"[UPDATE] New version available: v{res.latest_version} (current v{res.current_version})")
        return 0
    dl_path = download_update(res, log_callback=(None if args.json else print))
    swapped, msg = apply_self_update(dl_path, relaunch=False, log_callback=(None if args.json else print))
    out["downloaded_path"] = str(dl_path)
    out["self_update_applied"] = swapped
    out["note"] = msg
    print(json.dumps(out, indent=2) if args.json else f"[UPDATE] {msg}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="binshield",
        description=f"BinShield v{APP_VERSION} Headless Security CLI (PE / APK / ELF / Mach-O)",
    )
    parser.add_argument("--version", action="version", version=f"BinShield {APP_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a PE/APK/ELF/Mach-O file or folder (+ YARA)")
    p_scan.add_argument("target")
    p_scan.add_argument("--json", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    p_san = sub.add_parser("sanitize", help="Sanitize an infected PE/APK/ELF/Mach-O binary")
    p_san.add_argument("input")
    p_san.add_argument("-o", "--output")
    p_san.add_argument("--resign", action="store_true", default=True, help="Auto re-sign sanitized APKs")
    p_san.add_argument("--no-backup", action="store_true", help="Skip creating rollback snapshot")
    p_san.add_argument("--json", action="store_true")
    p_san.set_defaults(func=cmd_sanitize)

    p_ver = sub.add_parser("verify", help="Verify structural integrity of a PE/APK/ELF/Mach-O binary")
    p_ver.add_argument("target")
    p_ver.add_argument("--json", action="store_true")
    p_ver.set_defaults(func=cmd_verify)

    p_ai = sub.add_parser("ai-scan", help="Classify a binary using custom trained BinShield-SecNet-v2 AI")
    p_ai.add_argument("target")
    p_ai.add_argument("--device", default="auto", choices=["auto", "gpu", "npu", "cpu", "onnx", "torch"])
    p_ai.add_argument("--json", action="store_true")
    p_ai.set_defaults(func=cmd_ai_scan)

    p_dis = sub.add_parser("disasm", help="Direct Ghidra-free Capstone disassembly of a PE entrypoint/offset")
    p_dis.add_argument("target")
    p_dis.add_argument("--offset", default="")
    p_dis.add_argument("--count", type=int, default=30)
    p_dis.add_argument("--json", action="store_true")
    p_dis.set_defaults(func=cmd_disasm)

    p_sbx = sub.add_parser("sandbox", help="Run an executable safely in an isolated Job-Object sandbox")
    p_sbx.add_argument("target")
    p_sbx.add_argument("--timeout", type=float, default=5.0)
    p_sbx.add_argument("--json", action="store_true")
    p_sbx.set_defaults(func=cmd_sandbox)

    p_w = sub.add_parser("watch", help="Real-time Folder & Download Guard watcher")
    p_w.add_argument("folder")
    p_w.add_argument("--auto-quarantine", action="store_true")
    p_w.add_argument("--scan-existing", action="store_true")
    p_w.add_argument("--duration", type=float, default=0.0)
    p_w.set_defaults(func=cmd_watch)

    p_df = sub.add_parser("diff", help="Show hex byte diff between original and patched binary")
    p_df.add_argument("before")
    p_df.add_argument("after")
    p_df.add_argument("--json", action="store_true")
    p_df.set_defaults(func=cmd_diff)

    p_rb = sub.add_parser("rollback", help="Restore a binary from its SHA-256-verified rollback snapshot")
    p_rb.add_argument("target")
    p_rb.add_argument("--snapshot", default=None)
    p_rb.set_defaults(func=cmd_rollback)

    p_upd = sub.add_parser("update", help="Explicitly check for and apply the latest BinShield CLI release")
    p_upd.add_argument("--check", action="store_true")
    p_upd.add_argument("--json", action="store_true")
    p_upd.set_defaults(func=cmd_update)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
