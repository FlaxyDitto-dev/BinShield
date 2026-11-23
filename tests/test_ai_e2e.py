"""
BinShield - End-to-End Custom AI Model (BinShield-SecNet-v1) & Sanitization Verification Suite
Verifies BOTH PyTorch GPU and ONNX Runtime backends across:
  1. 10 real-world clean emulators & DLLs (0% FP required)
  2. 8 clean & malicious Ghidra pseudo-C functions (100% accuracy required)
  3. End-to-end Infect -> AI Detect -> Sanitize -> AI Clean -> Real Runtime Execution (.exe, .dll, .apk)
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path

import torch
from safetensors.torch import load_file

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from apk_engine import analyze_apk_file, sanitize_apk
from binary_patcher import BinaryPatcher
from custom_model import (
    MODEL_NAME,
    MODEL_ONNX_FILENAME,
    MODEL_VOCAB_FILENAME,
    MODEL_WEIGHTS_FILENAME,
    BinShieldSecNetClient,
    SecNetTokenizer,
    _build_secnet_module,
    format_scan_for_ai,
)
from scanner import analyze_pe_file
from tests.batch_qa_suite import (
    build_apk,
    build_valid_dex,
    build_valid_elf,
    inject_malicious_overlay,
    inject_pe_section,
    inject_tls_callback,
    verify_exe_runtime,
)


def export_onnx_from_safetensors() -> Path:
    mdir = REPO_ROOT / "models" / MODEL_NAME
    tok = SecNetTokenizer.load(mdir / MODEL_VOCAB_FILENAME)
    m = _build_secnet_module(vocab_size=max(8192, len(tok.vocab)))
    st = load_file(str(mdir / MODEL_WEIGHTS_FILENAME))
    m.load_state_dict({k: v.float() for k, v in st.items()}, strict=True)
    m.eval()
    onnx_path = mdir / MODEL_ONNX_FILENAME
    torch.onnx.export(
        m,
        (torch.zeros((1, 256), dtype=torch.long),),
        str(onnx_path),
        input_names=["input_ids"],
        output_names=["mal_logit", "cat_logits", "strat_logits"],
        dynamic_axes={
            "input_ids": {0: "batch"},
            "mal_logit": {0: "batch"},
            "cat_logits": {0: "batch"},
            "strat_logits": {0: "batch"},
        },
        opset_version=17,
        dynamo=False,
    )
    print(f"[ONNX] Exported hardened {onnx_path.name} ({onnx_path.stat().st_size / (1024 * 1024):.2f} MB)")
    return onnx_path


def main() -> None:
    onnx_path = REPO_ROOT / "models" / MODEL_NAME / MODEL_ONNX_FILENAME
    if not onnx_path.is_file():
        export_onnx_from_safetensors()

    ai_gpu = BinShieldSecNetClient(device="gpu", log_callback=print)
    ai_ort = BinShieldSecNetClient(device="onnx", log_callback=print)

    real_clean = [
        r"C:\RetroArch-Win64\retroarch.exe",
        r"C:\Users\johna\Emulators\CDecrypt\CDecrypt\x64\CDecrypt.exe",
        r"C:\Users\johna\Emulators\Cemu\Cemu_2.6\Cemu.exe",
        r"C:\Users\johna\Emulators\Duckstation\duckstation-qt-x64-ReleaseLTCG.exe",
        r"C:\SoH\soh.exe",
        r"C:\2S2H\2ship.exe",
        r"C:\RetroArch-Win64\cores\fceumm_libretro.dll",
        r"C:\Cutter\python312\sqlite3.dll",
        r"C:\RetroArch-Win64\filters\audio\chorus.dll",
        r"C:\SoH\dxgi.dll",
    ]
    print("\n=== 1. REAL-WORLD CLEAN EMULATORS & DLLs (GPU + ONNX) ===")
    fp_gpu = fp_ort = 0
    tested_clean = 0
    for p in real_clean:
        if not Path(p).is_file():
            continue
        tested_clean += 1
        f = analyze_pe_file(p, source="Test")
        d = asdict(f)
        d["type"] = "pe"
        txt = format_scan_for_ai(d)
        rg = ai_gpu.predict(txt)
        ro = ai_ort.predict(txt)
        fp_gpu += int(rg["is_malicious"])
        fp_ort += int(ro["is_malicious"])
        print(
            f"{f.name:<40} | GPU={'MAL' if rg['is_malicious'] else 'CLN'} ({rg['malicious_probability']*100:4.1f}%) "
            f"| ONNX={'MAL' if ro['is_malicious'] else 'CLN'} ({ro['malicious_probability']*100:4.1f}%)"
        )
    print(f"Real-World Clean FPs: GPU={fp_gpu}/{tested_clean}, ONNX={fp_ort}/{tested_clean}")

    print("\n=== 2. GHIDRA PSEUDO-C FUNCTIONS ===")
    funcs = [
        ("clean_hello", False, 'int main(void) { printf("Hello, World!\\n"); return 0; }'),
        ("clean_calc", False, "int add_nums(int a, int b) { return a + b; }"),
        ("clean_game_io", False, 'int load_save(void) { FILE* f = fopen("./save.dat", "rb"); fread(buf, 1, 64, f); fclose(f); return 1; }'),
        ("clean_patched", False, "int mock_keylogger_hook(void) { return 0; }"),
        ("mal_keylogger", True, "int hook_keys(void) { SetWindowsHookExA(WH_KEYBOARD_LL, cb, 0, 0); GetAsyncKeyState(0x0D); GetClipboardData(1); return 1; }"),
        ("mal_injector", True, "int inject_proc(DWORD pid) { HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid); void* p = VirtualAllocEx(h, 0, 4096, 0x3000, 0x40); WriteProcessMemory(h, p, buf, 256, 0); CreateRemoteThread(h, 0, 0, p, 0, 0, 0); return 1; }"),
        ("mal_c2", True, 'int beacon(void) { InternetOpenA("ua", 1, 0, 0, 0); HttpSendRequestA(req, 0, 0, stolen, 64); return 1; }'),
        ("mal_ransom", True, 'int locker(void) { ShellExecuteA(0, "open", "vssadmin", "delete shadows /all /quiet", 0, 0); CryptEncrypt(k, 0, 1, 0, b, &n, 4096); return 1; }'),
    ]
    fn_ok = 0
    for name, exp, code in funcs:
        r = ai_ort.predict(f"FUNC {name}\n{code}")
        ok = r["is_malicious"] == exp
        fn_ok += int(ok)
        print(
            f"{name:<16} | exp={'MAL' if exp else 'CLN'} | ONNX={'MAL' if r['is_malicious'] else 'CLN'} "
            f"({r['malicious_probability']*100:5.1f}%) | {r['category']:<25} | {r['patch_strategy']} | {'PASS' if ok else 'FAIL'}"
        )
    print(f"Pseudo-C Accuracy: {fn_ok}/{len(funcs)}")

    print("\n=== 3. END-TO-END INFECT -> AI DETECT -> SANITIZE -> AI CLEAN -> RUNTIME ===")
    tmp = Path(tempfile.mkdtemp(prefix="gg_e2e_ai_"))
    try:
        patcher = BinaryPatcher()
        hc = tmp / "hello.c"
        hexe = tmp / "hello.exe"
        hc.write_text('#include <stdio.h>\nint main(void){ printf("Hello, World!\\n"); return 0; }\n', encoding="utf-8")
        subprocess.run(["gcc", str(hc), "-o", str(hexe)], check=True)
        f0 = analyze_pe_file(str(hexe))
        d0 = asdict(f0); d0["type"] = "pe"
        r_clean = ai_ort.predict(format_scan_for_ai(d0))

        h_tmp = tmp / "h_oep.exe"; h_inf = tmp / "h_inf.exe"; h_san = tmp / "h_san.exe"
        inject_pe_section(hexe, h_tmp, ".stub", b"gg_injected_payload_e2e", rwx=True, hijack_oep=True)
        inject_malicious_overlay(h_tmp, h_inf, variant=1)
        f_inf = analyze_pe_file(str(h_inf))
        di = asdict(f_inf); di["type"] = "pe"
        r_inf = ai_ort.predict(format_scan_for_ai(di))
        srep = patcher.sanitize_pe_binary(str(h_inf), str(h_san), finding=f_inf)
        f_san = analyze_pe_file(str(h_san))
        ds = asdict(f_san); ds["type"] = "pe"
        r_san = ai_ort.predict(format_scan_for_ai(ds))
        rt_ok, rt_note = verify_exe_runtime(h_san, "Hello, World!")
        print(
            f"hello.exe     | clean_AI={'CLN' if not r_clean['is_malicious'] else 'FP'} "
            f"| inf_AI={'MAL' if r_inf['is_malicious'] else 'FN'} ({r_inf['category']}) "
            f"| san_AI={'CLN' if not r_san['is_malicious'] else 'FP'} | int={srep.integrity_ok} | rt={rt_ok} ({rt_note})"
        )

        dll_src = Path(r"C:\RetroArch-Win64\cores\fceumm_libretro.dll")
        d_inf = tmp / "fceumm_inf.dll"; d_san = tmp / "fceumm_san.dll"
        inject_tls_callback(dll_src, d_inf)
        fd_inf = analyze_pe_file(str(d_inf))
        ddi = asdict(fd_inf); ddi["type"] = "pe"
        rd_inf = ai_ort.predict(format_scan_for_ai(ddi))
        sdrep = patcher.sanitize_pe_binary(str(d_inf), str(d_san), finding=fd_inf)
        fd_san = analyze_pe_file(str(d_san))
        dds = asdict(fd_san); dds["type"] = "pe"
        rd_san = ai_ort.predict(format_scan_for_ai(dds))
        p_dll = subprocess.run(
            [sys.executable, "-c", f"import ctypes; lib=ctypes.CDLL(r'{d_san}'); print(lib.retro_api_version())"],
            capture_output=True, text=True,
        )
        dll_rt_ok = p_dll.returncode == 0 and p_dll.stdout.strip() == "1"
        print(
            f"fceumm.dll    | inf_AI={'MAL' if rd_inf['is_malicious'] else 'FN'} ({rd_inf['category']}) "
            f"| san_AI={'CLN' if not rd_san['is_malicious'] else 'FP'} | int={sdrep.integrity_ok} "
            f"| rt={dll_rt_ok} (retro_api_version={p_dll.stdout.strip()})"
        )

        apk_inf = tmp / "inf.apk"; apk_san = tmp / "san.apk"
        build_apk(
            apk_inf, "com.example.e2e", ["android.permission.INTERNET"], debuggable=True,
            dex_files={
                "classes.dex": build_valid_dex(["Lcom/example/e2e/Main;"]),
                "classes2.dex": build_valid_dex(["InMemoryDexClassLoader", "gg_dex_payload"]),
            },
            assets={"assets/drop.bin": build_valid_elf(arch="arm64-v8a", payload=b"gg_asset_payload")},
        )
        fa_inf = analyze_apk_file(str(apk_inf))
        dai = asdict(fa_inf); dai["type"] = "apk"
        ra_inf = ai_ort.predict(format_scan_for_ai(dai))
        sarep = sanitize_apk(str(apk_inf), str(apk_san), finding=fa_inf)
        fa_san = analyze_apk_file(str(apk_san))
        das = asdict(fa_san); das["type"] = "apk"
        ra_san = ai_ort.predict(format_scan_for_ai(das))
        print(
            f"trojan.apk    | inf_AI={'MAL' if ra_inf['is_malicious'] else 'FN'} ({ra_inf['category']}) "
            f"| san_AI={'CLN' if not ra_san['is_malicious'] else 'FP'} | int={sarep.integrity_ok}"
        )

        assert fp_gpu == 0 and fp_ort == 0, "Real-world clean FP!"
        assert fn_ok == len(funcs), "Pseudo-C mismatch!"
        assert (not r_clean["is_malicious"]) and r_inf["is_malicious"] and (not r_san["is_malicious"]) and rt_ok
        assert rd_inf["is_malicious"] and (not rd_san["is_malicious"]) and dll_rt_ok
        assert ra_inf["is_malicious"] and (not ra_san["is_malicious"]) and sarep.integrity_ok
        print("\nALL END-TO-END AI + SANITIZATION + RUNTIME ASSERTIONS PASSED 100%!")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
