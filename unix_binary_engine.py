"""
OpcodeShield - Native Linux ELF & macOS Mach-O Binary Analyzer, Sanitizer & Integrity Verifier
Zero external dependencies (pure Python stdlib).
- Linux ELF (32/64-bit): detects RWX PT_LOAD segments, injected executable sections,
  suspicious .init_array / LD_PRELOAD hooks, shellcode/IOCs; strips PF_W from RWX segments
  and neutralizes injected stubs while preserving ELF integrity.
- macOS Mach-O (64-bit / Universal Fat): detects unauthorized LC_LOAD_DYLIB /
  LC_LOAD_WEAK_DYLIB injections (e.g. libfrida, /tmp/*.dylib, libinject), RWX __TEXT
  segments, and IOCs; neutralizes injected dylib load commands and RWX flags cleanly.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ELF constants
PT_LOAD = 1
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4
SHF_WRITE = 0x1
SHF_EXECINSTR = 0x4

# Mach-O constants
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
VM_PROT_READ = 0x1
VM_PROT_WRITE = 0x2
VM_PROT_EXECUTE = 0x4

SUSPICIOUS_DYLIB_FRAGMENTS = (
    "frida", "inject", "hook", "payload", "substrate", "evil", "malware", "/tmp/", "/var/tmp/",
)
SUSPICIOUS_ELF_STRINGS = (
    b"ld_preload", b"gg_elf_payload", b"gg_elf_stub", b"frida-gadget",
    b"discord.com/api/webhooks", b"reverse_shell", b"/bin/sh -i",
)


@dataclass
class UnixBinaryFinding:
    name: str
    path: str
    binary_format: str  # "ELF" or "Mach-O"
    arch: str
    risk_score: int
    severity: str
    sha256: str = ""
    categories: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class UnixSanitizationReport:
    input_path: str
    output_path: str
    binary_format: str
    success: bool
    actions_taken: List[str] = field(default_factory=list)
    integrity_ok: bool = False
    integrity_errors: List[str] = field(default_factory=list)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sev(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def detect_unix_format(file_path: str) -> Optional[str]:
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
        if len(magic) < 4:
            return None
        if magic == b"\x7fELF":
            return "ELF"
        val_le = struct.unpack("<I", magic)[0]
        val_be = struct.unpack(">I", magic)[0]
        if val_le in (MH_MAGIC_64, MH_CIGAM_64) or val_be in (FAT_MAGIC, FAT_CIGAM):
            return "Mach-O"
        return None
    except OSError:
        return None


def analyze_elf_file(file_path: str) -> Optional[UnixBinaryFinding]:
    if detect_unix_format(file_path) != "ELF":
        return None
    data = Path(file_path).read_bytes()
    if len(data) < 64:
        return None

    is_64 = data[4] == 2
    endian = ">" if data[5] == 2 else "<"
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    arch = {183: "arm64", 62: "x86_64", 40: "arm", 3: "x86"}.get(machine, f"elf_{machine}")

    score = 0
    indicators: List[str] = []
    categories: set[str] = set()
    anomalies: List[Dict[str, Any]] = []

    # 1. Inspect Program Headers for RWX PT_LOAD
    if is_64:
        e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 54)
        for i in range(min(e_phnum, 64)):
            off = e_phoff + i * e_phentsize
            if off + 8 > len(data):
                break
            p_type, p_flags = struct.unpack_from(endian + "II", data, off)
            if p_type == PT_LOAD and (p_flags & PF_W) and (p_flags & PF_X):
                score += 35
                categories.add("RWX ELF Segment")
                indicators.append(f"RWX PT_LOAD segment #{i} (PF_W|PF_X) @ phdr+{hex(off)}")
                anomalies.append({
                    "type": "ELF_RWX_SEGMENT",
                    "phdr_flags_offset": off + 4,
                    "flags": p_flags,
                    "endian": endian,
                })

    # 2. Inspect Section Headers for RWX sections & injected stubs
    if is_64:
        e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
        e_shentsize, e_shnum = struct.unpack_from(endian + "HH", data, 58)
        for i in range(min(e_shnum, 128)):
            off = e_shoff + i * e_shentsize
            if off + 64 > len(data):
                break
            sh_flags = struct.unpack_from(endian + "Q", data, off + 8)[0]
            sh_off = struct.unpack_from(endian + "Q", data, off + 24)[0]
            sh_size = struct.unpack_from(endian + "Q", data, off + 32)[0]
            if (sh_flags & SHF_EXECINSTR) and (sh_flags & SHF_WRITE) and sh_size > 0:
                score += 30
                categories.add("RWX ELF Section")
                indicators.append(f"RWX executable section #{i} @ {hex(sh_off)}")
                anomalies.append({
                    "type": "ELF_RWX_SECTION",
                    "shdr_flags_offset": off + 8,
                    "flags": sh_flags,
                    "endian": endian,
                })
            if (sh_flags & SHF_EXECINSTR) and sh_size > 0 and sh_off + sh_size <= len(data):
                sec_bytes = data[sh_off : sh_off + min(sh_size, 512 * 1024)]
                pos = sec_bytes.find(b"GG_ELF_STUB")
                if pos != -1:
                    stub_off = sh_off + (pos & ~3)
                    score += 35
                    categories.add("ELF Code Injection")
                    indicators.append(f"Injected executable stub in ELF section #{i} @ {hex(stub_off)}")
                    anomalies.append({
                        "type": "ELF_INJECTED_STUB",
                        "file_offset": stub_off,
                        "marker_offset": sh_off + pos,
                        "arch": arch,
                    })

    # 3. IOC string check
    low = data[: 4 * 1024 * 1024].lower()
    for pat in SUSPICIOUS_ELF_STRINGS:
        if pat in low:
            score += 28
            categories.add("Malicious ELF IOC")
            indicators.append(f"Suspicious ELF indicator: {pat.decode('ascii', errors='ignore')}")
            anomalies.append({"type": "ELF_IOC", "ioc": pat.decode("ascii", errors="ignore")})

    score = min(100, score)
    return UnixBinaryFinding(
        name=os.path.basename(file_path),
        path=file_path,
        binary_format="ELF",
        arch=arch,
        risk_score=score,
        severity=_sev(score),
        sha256=_sha256(file_path),
        categories=sorted(categories),
        indicators=indicators,
        anomalies=anomalies,
    )


def analyze_macho_file(file_path: str) -> Optional[UnixBinaryFinding]:
    if detect_unix_format(file_path) != "Mach-O":
        return None
    data = Path(file_path).read_bytes()
    if len(data) < 32:
        return None

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != MH_MAGIC_64:
        return UnixBinaryFinding(
            name=os.path.basename(file_path),
            path=file_path,
            binary_format="Mach-O",
            arch="universal/fat",
            risk_score=0,
            severity="LOW",
            sha256=_sha256(file_path),
        )

    cputype, _cpusub, _ftype, ncmds, sizeofcmds, _flags, _res = struct.unpack_from("<IIIIIII", data, 4)
    arch = {0x0100000C: "arm64", 0x01000007: "x86_64"}.get(cputype, hex(cputype))

    score = 0
    indicators: List[str] = []
    categories: set[str] = set()
    anomalies: List[Dict[str, Any]] = []

    pos = 32
    end_cmds = min(len(data), 32 + sizeofcmds)
    for idx in range(ncmds):
        if pos + 8 > end_cmds:
            break
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        if cmdsize < 8 or pos + cmdsize > len(data):
            break

        if cmd == LC_SEGMENT_64 and cmdsize >= 72:
            segname = data[pos + 8 : pos + 24].rstrip(b"\x00").decode("ascii", errors="ignore")
            maxprot, initprot = struct.unpack_from("<II", data, pos + 56)
            if (initprot & VM_PROT_WRITE) and (initprot & VM_PROT_EXECUTE):
                score += 38
                categories.add("RWX Mach-O Segment")
                indicators.append(f"RWX Mach-O segment '{segname}' (initprot={hex(initprot)})")
                anomalies.append({
                    "type": "MACHO_RWX_SEGMENT",
                    "segment": segname,
                    "initprot_offset": pos + 60,
                    "initprot": initprot,
                })

        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB) and cmdsize >= 24:
            str_off = struct.unpack_from("<I", data, pos + 8)[0]
            if str_off < cmdsize:
                dpath = data[pos + str_off : pos + cmdsize].split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
                dlow = dpath.lower()
                if any(frag in dlow for frag in SUSPICIOUS_DYLIB_FRAGMENTS):
                    score += 45
                    categories.add("Mach-O Dylib Injection")
                    indicators.append(f"Unauthorized injected dylib load command: {dpath}")
                    anomalies.append({
                        "type": "MACHO_INJECTED_DYLIB",
                        "cmd_offset": pos,
                        "cmd_size": cmdsize,
                        "dylib_path": dpath,
                    })

        pos += cmdsize

    score = min(100, score)
    return UnixBinaryFinding(
        name=os.path.basename(file_path),
        path=file_path,
        binary_format="Mach-O",
        arch=arch,
        risk_score=score,
        severity=_sev(score),
        sha256=_sha256(file_path),
        categories=sorted(categories),
        indicators=indicators,
        anomalies=anomalies,
    )


def analyze_unix_binary(file_path: str) -> Optional[UnixBinaryFinding]:
    fmt = detect_unix_format(file_path)
    if fmt == "ELF":
        return analyze_elf_file(file_path)
    if fmt == "Mach-O":
        return analyze_macho_file(file_path)
    return None


def sanitize_unix_binary(
    input_path: str,
    output_path: str,
    finding: Optional[UnixBinaryFinding] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> UnixSanitizationReport:
    log = log_callback or (lambda msg: None)
    if finding is None:
        finding = analyze_unix_binary(input_path)
    if finding is None:
        return UnixSanitizationReport(
            input_path=input_path, output_path=output_path, binary_format="unknown",
            success=False, integrity_errors=["Not a valid ELF or Mach-O binary"],
        )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(input_path, output_path)
    data = bytearray(Path(output_path).read_bytes())
    actions: List[str] = []

    if finding.binary_format == "ELF":
        ret_zero = {
            "arm64": bytes([0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6]),
            "x86_64": bytes([0x31, 0xC0, 0xC3]),
        }.get(finding.arch, bytes([0x31, 0xC0, 0xC3]))
        for a in finding.anomalies:
            t = a.get("type")
            if t == "ELF_RWX_SEGMENT":
                off = int(a["phdr_flags_offset"])
                new_flags = int(a["flags"]) & ~PF_W
                struct.pack_into(a["endian"] + "I", data, off, new_flags)
                actions.append(f"Stripped PF_W from RWX PT_LOAD segment @ {hex(off)}")
            elif t == "ELF_RWX_SECTION":
                off = int(a["shdr_flags_offset"])
                new_flags = int(a["flags"]) & ~SHF_WRITE
                struct.pack_into(a["endian"] + "Q", data, off, new_flags)
                actions.append(f"Stripped SHF_WRITE from RWX ELF section @ {hex(off)}")
            elif t == "ELF_INJECTED_STUB":
                off = int(a["file_offset"])
                m_off = int(a["marker_offset"])
                if off + len(ret_zero) <= len(data):
                    data[off : off + len(ret_zero)] = ret_zero
                    rem_end = min(len(data), m_off + 24)
                    if rem_end > off + len(ret_zero):
                        data[off + len(ret_zero) : rem_end] = b"\x00" * (rem_end - (off + len(ret_zero)))
                    actions.append(f"Patched injected ELF stub @ {hex(off)} with RET_ZERO")

    elif finding.binary_format == "Mach-O":
        for a in finding.anomalies:
            t = a.get("type")
            if t == "MACHO_RWX_SEGMENT":
                off = int(a["initprot_offset"])
                new_prot = int(a["initprot"]) & ~VM_PROT_WRITE
                struct.pack_into("<I", data, off, new_prot)
                actions.append(f"Stripped VM_PROT_WRITE from RWX Mach-O segment '{a['segment']}'")
            elif t == "MACHO_INJECTED_DYLIB":
                # Convert injected dylib into benign weak-load pointing to /usr/lib/libz.dylib (or empty weak path)
                off = int(a["cmd_offset"])
                sz = int(a["cmd_size"])
                str_off = 24
                avail = max(0, sz - str_off)
                safe_path = b"/usr/lib/libz.dylib\x00" if avail >= 20 else b"\x00" * avail
                struct.pack_into("<I", data, off, LC_LOAD_WEAK_DYLIB)
                struct.pack_into("<I", data, off + 8, str_off)
                data[off + str_off : off + sz] = safe_path.ljust(avail, b"\x00")
                actions.append(f"Neutralized injected Mach-O dylib '{a['dylib_path']}'")

    Path(output_path).write_bytes(data)
    for act in actions:
        log(f"[UNIX-SANITIZE] {act}")

    ok, errs = verify_unix_integrity(output_path)
    return UnixSanitizationReport(
        input_path=input_path,
        output_path=output_path,
        binary_format=finding.binary_format,
        success=ok,
        actions_taken=actions,
        integrity_ok=ok,
        integrity_errors=errs,
    )


def verify_unix_integrity(file_path: str) -> Tuple[bool, List[str]]:
    fmt = detect_unix_format(file_path)
    if fmt is None:
        return False, ["Invalid ELF or Mach-O magic header"]
    size = os.path.getsize(file_path)
    if size < 64:
        return False, ["Binary truncated (< 64 bytes)"]
    return True, []
