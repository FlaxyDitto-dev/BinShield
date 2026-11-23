"""
GhidraGuard - Direct Ghidra-Free Disassembler (Capstone) & UPX Auto-Unpacker
Disassembles x86/x64/ARM64/ARMv7 machine code directly in milliseconds without requiring
Ghidra Headless, and automatically detects & unpacks UPX-packed binaries before sanitization.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pefile

try:
    import capstone  # type: ignore
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


def disassemble_bytes(
    code: bytes,
    arch: str = "x86_64",
    base_va: int = 0x1000,
    max_insns: int = 40,
) -> List[Dict[str, str]]:
    """Disassemble raw machine code using Capstone (x86_64, x86, arm64, arm)."""
    if not HAS_CAPSTONE:
        return [{"va": hex(base_va), "bytes": code[:16].hex(" ").upper(), "mnemonic": "raw", "op_str": "(install capstone for disassembly)"}]

    arch_low = arch.lower()
    if arch_low in ("x86_64", "amd64", "x64"):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif arch_low in ("x86", "i386", "386"):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    elif arch_low in ("arm64", "aarch64", "arm64-v8a"):
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    elif arch_low in ("arm", "armeabi-v7a", "armv7"):
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    insns: List[Dict[str, str]] = []
    for insn in md.disasm(code, base_va):
        insns.append({
            "va": hex(insn.address),
            "bytes": insn.bytes.hex(" ").upper(),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
        })
        if len(insns) >= max_insns:
            break
    return insns


def disassemble_pe_entrypoint(
    pe_path: str,
    file_offset: Optional[int] = None,
    max_insns: int = 35,
) -> Dict[str, Any]:
    """Disassemble a PE binary at its Entry Point (or a specified file offset) in milliseconds."""
    pe = pefile.PE(pe_path, fast_load=True)
    try:
        is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B
        arch = "x86_64" if is_64 else "x86"
        img_base = pe.OPTIONAL_HEADER.ImageBase
        if file_offset is None or file_offset < 0:
            ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            file_offset = pe.get_offset_from_rva(ep_rva)
            base_va = img_base + ep_rva
        else:
            rva = pe.get_rva_from_offset(file_offset) or 0
            base_va = img_base + rva
    finally:
        pe.close()

    with open(pe_path, "rb") as f:
        f.seek(max(0, file_offset))
        raw = f.read(512)

    insns = disassemble_bytes(raw, arch=arch, base_va=base_va, max_insns=max_insns)
    return {
        "file": os.path.basename(pe_path),
        "arch": arch,
        "file_offset": hex(file_offset),
        "base_va": hex(base_va),
        "capstone_available": HAS_CAPSTONE,
        "instructions": insns,
    }


def is_upx_packed(file_path: str) -> bool:
    try:
        with open(file_path, "rb") as f:
            head = f.read(65536)
        return (b"UPX0" in head and b"UPX1" in head) or b"UPX!" in head
    except OSError:
        return False


def try_auto_unpack_upx(input_path: str, output_path: str) -> Tuple[bool, str]:
    """Automatically unpack UPX-packed binaries using `upx -d` if UPX is installed."""
    if not is_upx_packed(input_path):
        return False, "Binary is not UPX-packed"
    upx_bin = shutil.which("upx")
    if not upx_bin:
        return False, "UPX packed binary detected, but `upx` CLI is not installed on PATH"
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(input_path, output_path)
    proc = subprocess.run([upx_bin, "-d", "-f", output_path], capture_output=True, text=True, timeout=30)
    if proc.returncode == 0:
        return True, f"Unpacked UPX binary -> {output_path}"
    return False, f"UPX unpack failed: {proc.stderr.strip()[:120]}"
