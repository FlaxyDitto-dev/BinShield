"""
GhidraGuard CLI - Headless Scanner, Sanitizer & Integrity Verifier
Supports Windows PE (.exe, .dll, .sys, .scr, .asi, .ocx) and Android (.apk) binaries.

Usage:
    python cli.py scan <file_or_folder> [--json]
    python cli.py sanitize <input_file> [-o <output_file>] [--json]
    python cli.py verify <file> [--json]
    python cli.py update [--check] [--json]
    python cli.py ai-scan <file> [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List

from apk_engine import analyze_apk_file, sanitize_apk, verify_apk_integrity
from binary_patcher import BinaryPatcher
from scanner import PE_SCAN_EXTENSIONS, analyze_pe_file
from updater import APP_VERSION, check_for_updates, download_update

ALL_SUPPORTED_EXTS = PE_SCAN_EXTENSIONS + (".apk",)


def _scan_one(path: Path) -> Dict[str, Any]:
    low = path.name.lower()
    if low.endswith(".apk"):
        res = analyze_apk_file(str(path))
        if res is None:
            return {"path": str(path), "type": "apk", "error": "Invalid APK"}
        d = asdict(res)
        d["type"] = "apk"
        return d
    res = analyze_pe_file(str(path), source="CLI Scan")
    if res is None:
        return {"path": str(path), "type": "pe", "error": "Invalid PE"}
    d = asdict(res)
    d["type"] = "pe"
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
        print(f"[{sev:8s}] score={score:3d} | {r['type'].upper():3s} | {r['name']} ({len(r.get('anomalies', []))} anomalies)")
        for ind in r.get("indicators", [])[:5]:
            print(f"           - {ind}")
    print(f"\nScanned {len(results)} file(s): {flagged} flagged (>= 25), {len(results) - flagged} clean.")
    return 0


def cmd_sanitize(args: argparse.Namespace) -> int:
    src = Path(args.input)
    if not src.is_file():
        print(f"Error: input file not found: {src}", file=sys.stderr)
        return 2

    if args.output:
        dst = Path(args.output)
    else:
        dst = src.with_name(f"{src.stem}_sanitized{src.suffix}")

    low = src.name.lower()
    if low.endswith(".apk"):
        before = analyze_apk_file(str(src))
        rep = sanitize_apk(str(src), str(dst), finding=before)
        after = analyze_apk_file(str(dst)) if dst.is_file() else None
        payload = {
            "type": "apk",
            "before_score": before.risk_score if before else -1,
            "after_score": after.risk_score if after else -1,
            "report": asdict(rep),
        }
    else:
        patcher = BinaryPatcher()
        before = analyze_pe_file(str(src), source="CLI Sanitize")
        rep = patcher.sanitize_pe_binary(str(src), str(dst), finding=before)
        after = analyze_pe_file(str(dst), source="CLI Sanitize") if dst.is_file() else None
        payload = {
            "type": "pe",
            "before_score": before.risk_score if before else -1,
            "after_score": after.risk_score if after else -1,
            "report": asdict(rep),
        }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        r = payload["report"]
        print(f"Sanitized: {src} -> {dst}")
        print(f"Risk Score: {payload['before_score']} -> {payload['after_score']}")
        print(f"Integrity : {'PASS' if r['integrity_ok'] else 'FAIL'}")
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
    else:
        ok, errs, csum_ok = BinaryPatcher.verify_pe_integrity(str(target))
        out = {"path": str(target), "type": "pe", "integrity_ok": ok, "checksum_valid": csum_ok, "errors": errs}

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"[{'PASS' if ok else 'FAIL'}] {target.name} ({out['type'].upper()})")
        for e in errs:
            print(f"  ! {e}")
    return 0 if ok else 1


def cmd_update(args: argparse.Namespace) -> int:
    """Explicit CLI update command (CLI never auto-updates on normal commands)."""
    res = check_for_updates(variant="cli")
    out: Dict[str, Any] = asdict(res)
    if res.error:
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            print(f"[UPDATE] Check failed: {res.error}", file=sys.stderr)
        return 1

    if not res.update_available:
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            print(f"[UPDATE] GhidraGuard CLI v{res.current_version} is already up to date.")
        return 0

    if args.check:
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            print(f"[UPDATE] New version available: v{res.latest_version} (current v{res.current_version})")
            print(f"         Run `ghidraguard update` to download ({res.release_url})")
        return 0

    try:
        dl_path = download_update(res, log_callback=(None if args.json else print))
        out["downloaded_path"] = str(dl_path)
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            print(f"[UPDATE] Ready at: {dl_path}")
        return 0
    except Exception as exc:
        out["download_error"] = str(exc)
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            print(f"[UPDATE] Download failed: {exc}", file=sys.stderr)
        return 1


def cmd_ai_scan(args: argparse.Namespace) -> int:
    """Run custom trained GhidraGuard-SecNet-v1 AI model (auto-downloads on first run)."""
    target = Path(args.target)
    if not target.is_file():
        print(f"Error: file not found: {target}", file=sys.stderr)
        return 2

    from custom_model import GhidraGuardSecNetClient, format_scan_for_ai

    static_res = _scan_one(target)
    summary_text = format_scan_for_ai(static_res, filename=target.name)

    client = GhidraGuardSecNetClient(device=args.device, log_callback=(None if args.json else print))
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


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ghidraguard",
        description=f"GhidraGuard v{APP_VERSION} Headless Security CLI (Windows / Linux / macOS / Colab)",
    )
    parser.add_argument("--version", action="version", version=f"GhidraGuard {APP_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a PE/APK file or folder recursively")
    p_scan.add_argument("target", help="File or directory path")
    p_scan.add_argument("--json", action="store_true", help="Output JSON")
    p_scan.set_defaults(func=cmd_scan)

    p_san = sub.add_parser("sanitize", help="Sanitize an infected PE or APK binary")
    p_san.add_argument("input", help="Input .exe/.dll/.apk file")
    p_san.add_argument("-o", "--output", help="Output sanitized file path")
    p_san.add_argument("--json", action="store_true", help="Output JSON")
    p_san.set_defaults(func=cmd_sanitize)

    p_ver = sub.add_parser("verify", help="Verify structural integrity of a PE or APK binary")
    p_ver.add_argument("target", help="Target .exe/.dll/.apk file")
    p_ver.add_argument("--json", action="store_true", help="Output JSON")
    p_ver.set_defaults(func=cmd_verify)

    p_upd = sub.add_parser("update", help="Check for and download the latest GhidraGuard CLI release")
    p_upd.add_argument("--check", action="store_true", help="Check only without downloading")
    p_upd.add_argument("--json", action="store_true", help="Output JSON")
    p_upd.set_defaults(func=cmd_update)

    p_ai = sub.add_parser("ai-scan", help="Classify a binary using custom trained GhidraGuard-SecNet-v1 AI")
    p_ai.add_argument("target", help="Target .exe/.dll/.apk file")
    p_ai.add_argument("--device", default="auto", choices=["auto", "gpu", "npu", "cpu", "onnx", "torch"], help="Accelerator backend")
    p_ai.add_argument("--json", action="store_true", help="Output JSON")
    p_ai.set_defaults(func=cmd_ai_scan)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
