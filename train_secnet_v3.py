"""
Train OpcodeShield-SecNet-v3 (v4.0.0) on NVIDIA CUDA GPU (RTX 5060 Ti).
Upgrades SecNet-v2 with:
  - 5 output heads:
      1. mal_logit       [B]     (binary malicious vs benign)
      2. cat_logits      [B, 12] (threat category)
      3. strat_logits    [B, 8]  (surgical patch strategy)
      4. behavior_logits [B, 8]  (multi-label behavioral tags)
      5. priority_logit  [B]     (offset-patch urgency / localization confidence)
  - Exports FP16 .safetensors + INT8 quantized ONNX (<16 MB) for Desktop, Mobile & WebAssembly!
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
from torch.utils.data import DataLoader, TensorDataset

from custom_model import PATCH_STRATEGIES, THREAT_CATEGORIES, SecNetTokenizer

BEHAVIOR_LABELS = [
    "Keylogging / Input Capture",
    "Process Injection / Hollowing",
    "C2 / Network Exfiltration",
    "Persistence / Privilege Escalation",
    "Crypto / Ransomware",
    "Structural PE/ELF/Mach-O Anomaly",
    "Shellcode / PEB Walk",
    "Packed / Obfuscated",
]


class OpcodeShieldSecNetV3(nn.Module):
    def __init__(self, vocab_size: int = 8192, d_model: int = 384, nhead: int = 6, num_layers: int = 6, dim_ff: int = 1536, max_len: int = 256):
        super().__init__()
        self.tok_emb = nn.Embedding(vocab_size, d_model, padding_idx=0)
        self.pos_emb = nn.Embedding(max_len, d_model)
        enc_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=dim_ff, dropout=0.1, activation="gelu", batch_first=True, norm_first=True
        )
        self.encoder = nn.TransformerEncoder(enc_layer, num_layers=num_layers)
        self.norm = nn.LayerNorm(d_model)
        self.mal_head = nn.Linear(d_model, 1)
        self.cat_head = nn.Linear(d_model, len(THREAT_CATEGORIES))
        self.strat_head = nn.Linear(d_model, len(PATCH_STRATEGIES))
        self.behavior_head = nn.Linear(d_model, len(BEHAVIOR_LABELS))
        self.priority_head = nn.Linear(d_model, 1)

    def forward(self, input_ids: torch.Tensor):
        b, t = input_ids.shape
        pos = torch.arange(t, device=input_ids.device).unsqueeze(0).expand(b, t)
        x = self.tok_emb(input_ids) + self.pos_emb(pos)
        pad_mask = input_ids == 0
        x = self.encoder(x, src_key_padding_mask=pad_mask)
        cls = self.norm(x[:, 0, :])
        return (
            self.mal_head(cls).squeeze(-1),
            self.cat_head(cls),
            self.strat_head(cls),
            self.behavior_head(cls),
            self.priority_head(cls).squeeze(-1),
        )


def build_dataset(n_train: int = 24000, n_val: int = 2400) -> Tuple[List, List]:
    rng = random.Random(4042)
    clean_names = [
        "retroarch.exe", "cemu.exe", "duckstation.exe", "soh.exe", "2ship.exe",
        "dxgi.dll", "d3d11.dll", "vulkan-1.dll", "ffmpeg.exe", "git.exe",
        "python313.dll", "notepad.exe", "calculator.apk", "libz.so", "clang",
        "hello_world_clean.exe", "vscode.exe", "obs64.exe", "vlc.exe", "7z.exe",
    ]
    clean_apis = ["none", "CreateFileW,ReadFile", "LoadLibraryW,GetProcAddress", "VirtualAlloc,VirtualProtect", "IsDebuggerPresent"]
    clean_funcs = [
        "FUNC render_frame\nSDL_RenderClear(renderer); SDL_RenderPresent(renderer); return 0;",
        "FUNC parse_config\nFILE *f = fopen(path, \"r\"); fread(buf, 1, 512, f); fclose(f); return 1;",
        "FUNC audio_mix\nfor (int i=0; i<len; i++) out[i] = clamp(a[i] + b[i]); return len;",
        "FUNC compute_sha256\nsha256_update(&ctx, data, size); sha256_final(&ctx, digest); return 0;",
        "DISASM x86_64\nxor eax, eax; ret",
        "DISASM x86_64\npush rbp; mov rbp, rsp; lea eax, [rdi+rsi]; pop rbp; ret",
        "DISASM x86_64\nmov rax, rdi; rep movsb; ret",
        "DISASM arm64\nstp x29, x30, [sp, #-16]!; add x0, x0, x1; ldp x29, x30, [sp], #16; ret",
    ]
    clean_indicators = [
        "none",
        "Binary is not digitally signed",
        "Located in user-writable/temp directory; Binary is not digitally signed",
        "Located in user-writable/temp directory",
    ]

    mal_templates = [
        # (cat_idx, strat_idx, behaviors, priority, kind, apis, yara, anoms, ind)
        (1, 1, [1, 0, 1, 0, 0, 0, 0, 0], 1, "PE_SCAN", "SetWindowsHookEx,GetAsyncKeyState,GetKeyState", "BS_Keylogger_Log_Marker,BS_Webhook_Exfiltration", "none", "Keylogger hook + Discord webhook exfil"),
        (2, 1, [0, 1, 0, 0, 0, 1, 1, 0], 1, "PE_SCAN", "OpenProcess,VirtualAllocEx,WriteProcessMemory,CreateRemoteThread", "BS_x64_PEB_Walk_Shellcode", "RWX_SECTION", "Remote thread process injection into explorer.exe"),
        (3, 1, [0, 0, 1, 0, 0, 0, 0, 0], 1, "PE_SCAN", "URLDownloadToFile,WinExec,ShellExecute", "BS_Webhook_Exfiltration,BS_Telegram_Bot_C2", "none", "C2 dropper downloading stage2 payload"),
        (4, 2, [0, 0, 0, 1, 0, 0, 0, 0], 1, "PE_SCAN", "RegSetValueEx,OpenProcess,AdjustTokenPrivileges", "BS_PowerShell_Encoded", "none", "Registry Run persistence and UAC bypass"),
        (5, 1, [0, 0, 0, 0, 1, 0, 0, 1], 1, "PE_SCAN", "CryptEncrypt,CryptGenKey,FindFirstFileW", "BS_ShadowCopy_Wiper", "SUSPICIOUS_SECTION", "Ransomware encrypting files and deleting shadow copies"),
        (6, 4, [0, 1, 0, 0, 0, 1, 0, 1], 1, "PE_SCAN", "VirtualProtect,GetProcAddress", "BS_UPX_Packed_Header", "OEP_OUTSIDE_TEXT,RWX_SECTION", "Entry point hijacked outside .text section"),
        (7, 5, [0, 1, 0, 0, 0, 1, 1, 0], 1, "PE_SCAN", "IsDebuggerPresent,NtSetInformationThread", "BS_x64_PEB_Walk_Shellcode", "TLS_CALLBACK", "Malicious TLS callback executing pre-OEP"),
        (8, 6, [0, 1, 0, 0, 0, 1, 1, 0], 1, "PE_SCAN", "VirtualAllocEx,SetThreadContext,ResumeThread", "BS_x64_PEB_Walk_Shellcode", "RWX_SECTION", "Code-cave shellcode injection"),
        (9, 6, [0, 0, 1, 0, 0, 1, 0, 1], 1, "PE_SCAN", "URLDownloadToFile,CreateProcessW", "BS_PowerShell_Encoded", "SUSPICIOUS_OVERLAY", "High-entropy malicious PE overlay payload"),
        (10, 1, [0, 1, 0, 1, 0, 1, 0, 0], 1, "PE_SCAN", "LoadLibraryA,GetProcAddress,CreateRemoteThread", "none", "SUSPICIOUS_SECTION", "Proxy DLL sideloading hijack"),
        (11, 7, [1, 1, 1, 1, 0, 1, 0, 0], 1, "APK_SCAN", "BIND_ACCESSIBILITY_SERVICE,READ_SMS,DexClassLoader", "BS_Telegram_Bot_C2", "ELF_RWX_SEGMENT", "Malicious Android APK accessibility & SMS stealer"),
        (11, 1, [0, 1, 1, 1, 0, 1, 1, 0], 1, "ELF_SCAN", "ptrace,mprotect,execve", "BS_LD_PRELOAD_Hijack,BS_Reverse_Shell_Bash", "ELF_RWX_SEGMENT", "Linux ELF RWX segment + /dev/tcp reverse shell"),
        (11, 1, [0, 1, 0, 1, 0, 1, 0, 0], 1, "MACHO_SCAN", "dlopen,dlsym", "none", "DYLIB_HIJACK", "macOS Mach-O DYLD_INSERT_LIBRARIES hijack"),
    ]

    mal_funcs = [
        ("FUNC inject_remote_thread\nVirtualAllocEx(h,0,4096,0x3000,0x40); WriteProcessMemory(h,m,sc,256,0); CreateRemoteThread(h,0,0,m,0,0,0);", 2, 1, [0, 1, 0, 0, 0, 0, 1, 0]),
        ("FUNC hook_keys\nSetWindowsHookExA(13, kb_proc, 0, 0); GetAsyncKeyState(vk); send_discord_webhook(buf);", 1, 1, [1, 0, 1, 0, 0, 0, 0, 0]),
        ("FUNC wipe_shadows\nsystem(\"vssadmin delete shadows /all /quiet\"); CryptEncrypt(hKey, 0, 1, 0, buf, &len, 4096);", 5, 1, [0, 0, 0, 0, 1, 0, 0, 0]),
        ("DISASM x86_64\nmov rax, qword ptr gs:[0x60]; mov rax, [rax+0x18]; call rbx", 8, 6, [0, 1, 0, 0, 0, 0, 1, 0]),
    ]

    def gen_one():
        if rng.random() < 0.45:
            # Benign
            if rng.random() < 0.25:
                txt = rng.choice(clean_funcs)
            else:
                kind = rng.choice(["PE_SCAN", "PE_SCAN", "ELF_SCAN", "APK_SCAN", "MACHO_SCAN"])
                name = rng.choice(clean_names + ["hello.exe", "app.exe", "tool.exe"])
                score = rng.randint(0, 24)
                signed = rng.choice(["true", "false"])
                apis = rng.choice(clean_apis)
                ind = rng.choice(clean_indicators)
                txt = f"{kind} name={name} score={score} severity=LOW signed={signed} packed=false anoms=none yara=none apis={apis} indicators={ind}"
            return (txt, 0, 0, 0, [0] * 8, 0)
        else:
            if rng.random() < 0.22:
                txt, cat, strat, beh = rng.choice(mal_funcs)
                return (txt, 1, cat, strat, beh, 1)
            cat, strat, beh, prio, kind, apis, yara, anoms, ind = rng.choice(mal_templates)
            score = rng.randint(52, 100)
            sev = "CRITICAL" if score >= 75 else "HIGH"
            name = rng.choice(["keylogger.exe", "dropper.bin", "payload.dll", "update_patch.exe", "evil.elf", "spy.apk", "inject.dylib"])
            packed = "true" if beh[7] else "false"
            ind_full = ind + ("; Binary is not digitally signed" if rng.random() < 0.6 else "")
            txt = f"{kind} name={name} score={score} severity={sev} signed=false packed={packed} anoms={anoms} yara={yara} apis={apis} indicators={ind_full}"
            return (txt, 1, cat, strat, beh, prio)

    train = [gen_one() for _ in range(n_train)]
    val = [gen_one() for _ in range(n_val)]
    return train, val


def main() -> None:
    t0 = time.time()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[SecNet-v3] Training on: {device}" + (f" ({torch.cuda.get_device_name(0)})" if device.type == "cuda" else ""))

    train_data, val_data = build_dataset()
    tok = SecNetTokenizer.fit([x[0] for x in train_data], max_vocab=8192, max_len=256)

    def to_tensors(items):
        ids = torch.tensor([tok.encode(x[0]) for x in items], dtype=torch.long)
        mal = torch.tensor([x[1] for x in items], dtype=torch.float32)
        cat = torch.tensor([x[2] for x in items], dtype=torch.long)
        strat = torch.tensor([x[3] for x in items], dtype=torch.long)
        beh = torch.tensor([x[4] for x in items], dtype=torch.float32)
        prio = torch.tensor([x[5] for x in items], dtype=torch.float32)
        return TensorDataset(ids, mal, cat, strat, beh, prio)

    train_loader = DataLoader(to_tensors(train_data), batch_size=128, shuffle=True)
    val_loader = DataLoader(to_tensors(val_data), batch_size=256)

    model = OpcodeShieldSecNetV3(vocab_size=max(8192, len(tok.vocab))).to(device)
    params = sum(p.numel() for p in model.parameters())
    print(f"[SecNet-v3] Parameters: {params:,}")

    opt = torch.optim.AdamW(model.parameters(), lr=3e-4, weight_decay=0.01)
    bce = nn.BCEWithLogitsLoss()
    ce = nn.CrossEntropyLoss()
    scaler = torch.amp.GradScaler("cuda", enabled=(device.type == "cuda"))

    for epoch in range(1, 5):
        model.train()
        total_loss = 0.0
        for ids, mal, cat, strat, beh, prio in train_loader:
            ids, mal, cat, strat, beh, prio = ids.to(device), mal.to(device), cat.to(device), strat.to(device), beh.to(device), prio.to(device)
            opt.zero_grad(set_to_none=True)
            with torch.amp.autocast("cuda", enabled=(device.type == "cuda")):
                ml, cl, sl, bl, pl = model(ids)
                loss = bce(ml, mal) + ce(cl, cat) + ce(sl, strat) + bce(bl, beh) + 0.5 * bce(pl, prio)
            scaler.scale(loss).backward()
            scaler.step(opt)
            scaler.update()
            total_loss += float(loss.item())

        model.eval()
        m_ok = c_ok = s_ok = b_ok = total = 0
        with torch.inference_mode():
            for ids, mal, cat, strat, beh, prio in val_loader:
                ids, mal, cat, strat, beh = ids.to(device), mal.to(device), cat.to(device), strat.to(device), beh.to(device)
                ml, cl, sl, bl, _ = model(ids)
                m_ok += int(((torch.sigmoid(ml) >= 0.5).float() == mal).sum().item())
                c_ok += int((cl.argmax(-1) == cat).sum().item())
                s_ok += int((sl.argmax(-1) == strat).sum().item())
                b_ok += int(((torch.sigmoid(bl) >= 0.5).float() == beh).all(dim=-1).sum().item())
                total += ids.size(0)
        print(f"Epoch {epoch}/4 | loss={total_loss/len(train_loader):.4f} | mal={m_ok/total*100:.2f}% cat={c_ok/total*100:.2f}% strat={s_ok/total*100:.2f}% beh={b_ok/total*100:.2f}%")

    out_dir = Path("models/OpcodeShield-SecNet-v3")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Save vocab with behavior_labels
    vocab_path = out_dir / "OpcodeShield-SecNet-v3-vocab.json"
    vocab_payload = {
        "model_name": "OpcodeShield-SecNet-v3",
        "max_len": tok.max_len,
        "vocab_size": len(tok.vocab),
        "categories": THREAT_CATEGORIES,
        "strategies": PATCH_STRATEGIES,
        "behaviors": BEHAVIOR_LABELS,
        "vocab": tok.vocab,
    }
    vocab_path.write_text(json.dumps(vocab_payload), encoding="utf-8")

    # Save FP16 safetensors
    from safetensors.torch import save_file
    st_path = out_dir / "OpcodeShield-SecNet-v3.safetensors"
    save_file({k: v.detach().cpu().half() for k, v in model.state_dict().items()}, str(st_path))

    # Export ONNX & INT8 quantize
    model_cpu = model.cpu().float().eval()
    fp32_onnx = out_dir / "OpcodeShield-SecNet-v3-fp32.onnx"
    int8_onnx = out_dir / "OpcodeShield-SecNet-v3-int8.onnx"
    dummy = torch.ones((1, 256), dtype=torch.long)
    torch.onnx.export(
        model_cpu,
        (dummy,),
        str(fp32_onnx),
        input_names=["input_ids"],
        output_names=["mal_logit", "cat_logits", "strat_logits", "behavior_logits", "priority_logit"],
        opset_version=17,
        dynamo=False,
    )
    from onnxruntime.quantization import QuantType, quantize_dynamic
    quantize_dynamic(str(fp32_onnx), str(int8_onnx), weight_type=QuantType.QUInt8)
    fp32_onnx.unlink(missing_ok=True)

    elapsed = round(time.time() - t0, 2)
    card = {
        "model_name": "OpcodeShield-SecNet-v3",
        "revision": "v4.0.0-multilabel",
        "parameters": params,
        "onnx_mb": round(int8_onnx.stat().st_size / (1024 * 1024), 2),
        "safetensors_mb": round(st_path.stat().st_size / (1024 * 1024), 2),
        "val_malicious_acc_pct": round(m_ok / total * 100, 2),
        "val_category_acc_pct": round(c_ok / total * 100, 2),
        "val_strategy_acc_pct": round(s_ok / total * 100, 2),
        "val_behavior_exact_pct": round(b_ok / total * 100, 2),
        "onnx_sha256": hashlib.sha256(int8_onnx.read_bytes()).hexdigest(),
        "trained_on": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU",
        "elapsed_seconds": elapsed,
    }
    (out_dir / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    print("[SecNet-v3] DONE:", json.dumps(card, indent=2))


if __name__ == "__main__":
    main()
