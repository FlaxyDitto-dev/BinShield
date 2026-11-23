"""
GhidraGuard - PE Binary Patcher, Signature Stripper, Checksum Fixer & Quarantine Vault
Performs surgical byte-level patching on Windows PE (.exe / .dll) executable sections
using pefile (with optional LIEF integration), strips invalidated Authenticode signatures,
recalculates PE header checksums, and manages backups and an isolated Quarantine Vault.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import pefile
import psutil

try:
    import lief  # type: ignore
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False


# ---------------------------------------------------------------------------
# x86/x64 Conditional Jump Flip Lookup Tables
# ---------------------------------------------------------------------------

SHORT_JCC_FLIP: Dict[int, Tuple[int, str]] = {
    0x70: (0x71, "JO -> JNO"),
    0x71: (0x70, "JNO -> JO"),
    0x72: (0x73, "JB -> JAE"),
    0x73: (0x72, "JAE -> JB"),
    0x74: (0x75, "JZ -> JNZ"),
    0x75: (0x74, "JNZ -> JZ"),
    0x76: (0x77, "JBE -> JA"),
    0x77: (0x76, "JA -> JBE"),
    0x78: (0x79, "JS -> JNS"),
    0x79: (0x78, "JNS -> JS"),
    0x7C: (0x7D, "JL -> JGE"),
    0x7D: (0x7C, "JGE -> JL"),
    0x7E: (0x7F, "JLE -> JG"),
    0x7F: (0x7E, "JG -> JLE"),
}

NEAR_JCC_FLIP: Dict[int, Tuple[int, str]] = {
    0x80: (0x81, "JO near -> JNO near"),
    0x81: (0x80, "JNO near -> JO near"),
    0x82: (0x83, "JB near -> JAE near"),
    0x83: (0x82, "JAE near -> JB near"),
    0x84: (0x85, "JZ near -> JNZ near"),
    0x85: (0x84, "JNZ near -> JZ near"),
    0x86: (0x87, "JBE near -> JA near"),
    0x87: (0x86, "JA near -> JBE near"),
    0x88: (0x89, "JS near -> JNS near"),
    0x89: (0x88, "JNS near -> JS near"),
    0x8C: (0x8D, "JL near -> JGE near"),
    0x8D: (0x8C, "JGE near -> JL near"),
    0x8E: (0x8F, "JLE near -> JG near"),
    0x8F: (0x8E, "JG near -> JLE near"),
}

IMAGE_SCN_MEM_EXECUTE = 0x20000000
QUARANTINE_XOR_KEY = 0x5A


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class PatchInstruction:
    function_name: str
    strategy: str  # RET_EARLY, RET_ZERO, RET_ONE, NOP_SLED, FLIP_JUMP, CUSTOM_BYTES
    va: int = 0
    file_offset: int = -1
    length: int = 1
    custom_hex: str = ""
    reason: str = ""
    category: str = ""


@dataclass
class PatchRecord:
    pass_number: int
    function_name: str
    section_name: str
    va: str
    file_offset: str
    strategy: str
    before_hex: str
    after_hex: str
    reason: str
    note: str = ""


@dataclass
class QuarantineEntry:
    entry_id: str
    original_path: str
    vault_filename: str
    sha256: str
    reason: str
    timestamp: str


@dataclass
class PESanitizationReport:
    input_path: str
    output_path: str
    success: bool
    actions_taken: List[str] = field(default_factory=list)
    oep_restored: bool = False
    sections_stripped: List[str] = field(default_factory=list)
    sections_neutralized: List[str] = field(default_factory=list)
    tls_callbacks_neutralized: int = 0
    caves_neutralized: int = 0
    exports_neutralized: List[str] = field(default_factory=list)
    overlay_stripped: bool = False
    signatures_stripped: bool = False
    checksum_valid: bool = False
    integrity_ok: bool = False
    integrity_errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Binary Patcher
# ---------------------------------------------------------------------------

class BinaryPatcher:
    """Applies verified byte-level patches to PE binaries and fixes signatures/checksums."""

    def __init__(self, log_callback: Optional[Callable[[str], None]] = None):
        self._log = log_callback or (lambda msg: None)

    def resolve_file_offset(self, pe: pefile.PE, inst: PatchInstruction) -> Tuple[int, int, str]:
        """
        Resolve and validate (file_offset, va, section_name) inside an executable section.
        Raises ValueError if the target does not map inside an executable PE section.
        """
        image_base = pe.OPTIONAL_HEADER.ImageBase
        file_offset = inst.file_offset
        va = inst.va

        if file_offset < 0 and va > image_base:
            rva = va - image_base
            file_offset = pe.get_offset_from_rva(rva)
        elif file_offset >= 0 and va == 0:
            rva = pe.get_rva_from_offset(file_offset)
            if rva is not None:
                va = image_base + rva

        if file_offset is None or file_offset < 0:
            raise ValueError(f"Could not resolve valid PE file offset for {inst.function_name} (VA={hex(va)})")

        # Confirm offset falls inside an executable section (.text, etc.)
        for sec in pe.sections:
            raw_start = sec.PointerToRawData
            raw_end = raw_start + sec.SizeOfRawData
            if raw_start <= file_offset < raw_end:
                sec_name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="ignore")
                if not (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE):
                    raise ValueError(
                        f"Refusing to patch non-executable section '{sec_name}' at offset {hex(file_offset)}"
                    )
                return file_offset, va, sec_name

        raise ValueError(f"Offset {hex(file_offset)} does not fall inside any PE section")

    def compute_patch_bytes(
        self, raw_data: bytearray, offset: int, inst: PatchInstruction
    ) -> Tuple[bytes, str]:
        """Compute the exact replacement bytes for a given patch strategy."""
        strat = inst.strategy.upper().strip()

        if strat in ("RET_EARLY", "RET"):
            return b"\xC3", "RET (early return)"

        if strat in ("RET_ZERO", "RETURN_ZERO", "RETURN_FALSE"):
            return b"\x31\xC0\xC3", "XOR EAX, EAX; RET (return 0)"

        if strat in ("RET_ONE", "RETURN_ONE", "RETURN_TRUE"):
            return b"\xB8\x01\x00\x00\x00\xC3", "MOV EAX, 1; RET (return 1)"

        if strat in ("NOP_SLED", "NOP_RANGE", "NOP"):
            length = max(1, min(64, int(inst.length or 5)))
            return b"\x90" * length, f"NOP sled ({length} bytes)"

        if strat in ("FLIP_JUMP", "FLIP_JCC", "INVERT_JUMP"):
            if offset >= len(raw_data):
                raise ValueError(f"Offset {hex(offset)} out of file bounds")
            op0 = raw_data[offset]
            if op0 in SHORT_JCC_FLIP:
                new_op, desc = SHORT_JCC_FLIP[op0]
                return bytes([new_op]), f"Flipped short jump ({desc})"
            if op0 == 0x0F and offset + 1 < len(raw_data):
                op1 = raw_data[offset + 1]
                if op1 in NEAR_JCC_FLIP:
                    new_op1, desc = NEAR_JCC_FLIP[op1]
                    return bytes([0x0F, new_op1]), f"Flipped near jump ({desc})"
            # Fallback: scan next 16 bytes for a conditional jump instruction
            for delta in range(1, 16):
                pos = offset + delta
                if pos >= len(raw_data):
                    break
                b0 = raw_data[pos]
                if b0 in SHORT_JCC_FLIP:
                    new_op, desc = SHORT_JCC_FLIP[b0]
                    # Patch at pos instead? Better to fallback safely to RET_ZERO if exact offset isn't Jcc
                    break
            raise ValueError(
                f"Byte 0x{op0:02X} at {hex(offset)} is not a conditional jump (Jcc); cannot FLIP_JUMP safely."
            )

        if strat == "CUSTOM_BYTES":
            cleaned = inst.custom_hex.replace("0x", "").replace(" ", "").replace(",", "")
            if not cleaned or len(cleaned) % 2 != 0 or len(cleaned) > 128:
                raise ValueError(f"Invalid custom_hex payload: {inst.custom_hex!r}")
            patch_bytes = bytes.fromhex(cleaned)
            return patch_bytes, f"Custom bytes ({len(patch_bytes)}B)"

        # Default safe neutralization
        return b"\x31\xC0\xC3", "Default XOR EAX, EAX; RET"

    def apply_patches(
        self,
        input_binary: str,
        output_binary: str,
        instructions: List[PatchInstruction],
        pass_number: int = 1,
    ) -> List[PatchRecord]:
        """
        Apply a list of PatchInstructions to input_binary using streaming / seek-based I/O
        (no file size limit, constant O(1) RAM even on multi-GB binaries), write output_binary,
        strip invalidated Authenticode signature, and recalculate PE checksum.
        """
        if not os.path.isfile(input_binary):
            raise FileNotFoundError(f"Input binary not found: {input_binary}")

        file_size = os.path.getsize(input_binary)
        pe = pefile.PE(input_binary, fast_load=True)
        Path(output_binary).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(input_binary, output_binary)
        records: List[PatchRecord] = []

        with open(output_binary, "r+b") as fh:
            for inst in instructions:
                try:
                    file_off, va, sec_name = self.resolve_file_offset(pe, inst)
                    if file_off >= file_size:
                        self._log(f"[PATCH] Skipping {inst.function_name}: offset exceeds file size.")
                        continue

                    fh.seek(file_off)
                    window = bytearray(fh.read(64))
                    patch_bytes, note = self.compute_patch_bytes(window, 0, inst)

                    if file_off + len(patch_bytes) > file_size:
                        self._log(f"[PATCH] Skipping {inst.function_name}: patch exceeds file size.")
                        continue

                    before_bytes = bytes(window[: len(patch_bytes)])
                    if before_bytes == patch_bytes:
                        self._log(f"[PATCH] {inst.function_name} @ {hex(file_off)} already patched; skipping.")
                        continue

                    fh.seek(file_off)
                    fh.write(patch_bytes)

                    rec = PatchRecord(
                        pass_number=pass_number,
                        function_name=inst.function_name,
                        section_name=sec_name,
                        va=hex(va),
                        file_offset=hex(file_off),
                        strategy=inst.strategy.upper(),
                        before_hex=before_bytes.hex(" ").upper(),
                        after_hex=patch_bytes.hex(" ").upper(),
                        reason=inst.reason,
                        note=note,
                    )
                    records.append(rec)
                    self._log(
                        f"[PATCH] Pass {pass_number}: Patched {inst.function_name} ({sec_name} @ {rec.file_offset}) "
                        f"[{rec.before_hex}] -> [{rec.after_hex}] ({note})"
                    )
                except Exception as exc:
                    self._log(f"[PATCH] Warning: could not apply patch to {inst.function_name}: {exc}")

        pe.close()

        if not records:
            return records

        self._strip_signature_and_fix_checksum(output_binary)
        return records

    def _strip_signature_and_fix_checksum(self, binary_path: str) -> None:
        """
        Strip embedded Authenticode digital signature (invalidated after patching)
        and recalculate the PE OptionalHeader CheckSum using streaming 1 MB chunks
        (no file size limit).
        """
        import struct

        stripped = False
        file_size = os.path.getsize(binary_path)
        with open(binary_path, "r+b") as f:
            dos = f.read(64)
            if len(dos) < 64 or dos[:2] != b"MZ":
                return
            pe_off = struct.unpack_from("<I", dos, 0x3C)[0]
            f.seek(pe_off)
            pe_hdr = f.read(24 + 240)
            if len(pe_hdr) < 24 + 96 or pe_hdr[:4] != b"PE\x00\x00":
                return

            opt_off = pe_off + 24
            opt_magic = struct.unpack_from("<H", pe_hdr, 24)[0]
            is_pe32_plus = opt_magic == 0x20B
            data_dir_rel = 24 + (112 if is_pe32_plus else 96)
            sec_dir_off = pe_off + data_dir_rel + (4 * 8)

            if data_dir_rel + 40 <= len(pe_hdr):
                cert_offset, cert_size = struct.unpack_from("<II", pe_hdr, data_dir_rel + 32)
                if cert_offset != 0 and cert_size > 0:
                    f.seek(sec_dir_off)
                    f.write(b"\x00" * 8)
                    stripped = True
                    self._log(
                        f"[PATCH] Stripped invalidated Authenticode signature "
                        f"(offset={hex(cert_offset)}, size={cert_size} bytes)."
                    )
                    if cert_offset + cert_size >= file_size - 16 and cert_offset < file_size:
                        f.truncate(cert_offset)
                        file_size = cert_offset

            # Stream-compute standard Windows PE CheckSum (16-bit fold + file size)
            csum_off = opt_off + 64
            f.seek(csum_off)
            old_csum = struct.unpack("<I", f.read(4))[0]
            f.seek(csum_off)
            f.write(b"\x00\x00\x00\x00")
            f.flush()

            f.seek(0)
            checksum = 0
            chunk_size = 64 * 1024  # 64 KB even multiple of 2 bytes; guarantees < 2^32 before fold
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                if len(chunk) & 1:
                    chunk += b"\x00"
                # Fast word sum using memoryview('H') + exact 16-bit ones'-complement fold
                checksum += sum(memoryview(chunk).cast("H"))
                while checksum > 0xFFFF:
                    checksum = (checksum & 0xFFFF) + (checksum >> 16)

            new_csum = (checksum + file_size) & 0xFFFFFFFF
            f.seek(csum_off)
            f.write(struct.pack("<I", new_csum))

        self._log(
            f"[PATCH] Recalculated PE CheckSum: {hex(old_csum)} -> {hex(new_csum)}"
            + (" (signature stripped)" if stripped else "")
            + (f" [LIEF available={HAS_LIEF}]" if HAS_LIEF else "")
        )

    @staticmethod
    def _align_up(value: int, alignment: int) -> int:
        if alignment <= 0:
            return value
        rem = value % alignment
        return value if rem == 0 else value + (alignment - rem)

    def sanitize_pe_binary(
        self,
        input_binary: str,
        output_binary: str,
        finding: Optional[Any] = None,
    ) -> PESanitizationReport:
        """
        Cleanly strip or neutralize structural PE injections while preserving binary integrity:
        - Restores hijacked AddressOfEntryPoint (OEP) when original OEP is recoverable
        - Removes/neutralizes unauthorized TLS callbacks while preserving legitimate CRT callbacks
        - Clears code-cave shellcode injections inside .text padding
        - Strips trailing injected PE sections (updating NumberOfSections, SizeOfImage, and truncating)
          or neutralizes non-trailing injected/RWX sections in-place (zeroing payload & clearing W/X flags)
        - Strips malicious PE overlays
        - Strips invalidated Authenticode signatures and recalculates PE OptionalHeader CheckSum
        - Runs post-patch PE structural integrity verification
        """
        report = PESanitizationReport(
            input_path=input_binary,
            output_path=output_binary,
            success=False,
        )
        if not os.path.isfile(input_binary):
            report.integrity_errors.append(f"Input binary not found: {input_binary}")
            return report

        if finding is None:
            from scanner import analyze_pe_file
            finding = analyze_pe_file(input_binary, source="Manual File")
        if finding is None:
            report.integrity_errors.append("Input is not a valid PE binary")
            return report

        anomalies: List[Dict[str, Any]] = list(getattr(finding, "anomalies", []) or [])
        Path(output_binary).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(input_binary, output_binary)

        # Read PE header offsets once
        with open(output_binary, "r+b") as fh:
            dos = fh.read(64)
            if len(dos) < 64 or dos[:2] != b"MZ":
                report.integrity_errors.append("Invalid DOS MZ header")
                return report
            pe_off = struct.unpack_from("<I", dos, 0x3C)[0]
            fh.seek(pe_off)
            coff_hdr = fh.read(24)
            if len(coff_hdr) < 24 or coff_hdr[:4] != b"PE\x00\x00":
                report.integrity_errors.append("Invalid PE signature")
                return report

            num_sections = struct.unpack_from("<H", coff_hdr, 6)[0]
            opt_hdr_size = struct.unpack_from("<H", coff_hdr, 20)[0]
            opt_off = pe_off + 24
            sec_table_off = opt_off + opt_hdr_size

            fh.seek(opt_off)
            opt_hdr = fh.read(opt_hdr_size)
            sec_alignment = struct.unpack_from("<I", opt_hdr, 32)[0] if len(opt_hdr) >= 36 else 0x1000
            ep_rva = struct.unpack_from("<I", opt_hdr, 16)[0] if len(opt_hdr) >= 20 else 0

            # 1. Restore hijacked OEP first (so any injected section at the end becomes unreferenced)
            for anom in anomalies:
                if anom.get("type") == "OEP_HIJACK":
                    recovered = anom.get("recovered_oep_rva")
                    if recovered and isinstance(recovered, int) and recovered > 0:
                        fh.seek(opt_off + 16)
                        fh.write(struct.pack("<I", recovered))
                        ep_rva = recovered
                        report.oep_restored = True
                        msg = f"Restored hijacked EntryPoint: {hex(anom['current_oep_rva'])} -> {hex(recovered)}"
                        report.actions_taken.append(msg)
                        self._log(f"[SANITIZE] {msg}")

            # 2. Neutralize unauthorized TLS callbacks (preserve any other legitimate CRT callbacks)
            tls_anoms = [a for a in anomalies if a.get("type") == "MALICIOUS_TLS_CALLBACK"]
            if tls_anoms:
                # Group by callback_table_offset to cleanly compact each table
                by_table: Dict[int, List[Dict[str, Any]]] = {}
                for ta in tls_anoms:
                    by_table.setdefault(int(ta["callback_table_offset"]), []).append(ta)

                for table_off, items in by_table.items():
                    ptr_size = int(items[0].get("ptr_size", 8))
                    ptr_fmt = "<Q" if ptr_size == 8 else "<I"
                    mal_vas = {int(it["callback_va"]) for it in items}

                    fh.seek(table_off)
                    raw_tbl = fh.read(ptr_size * 32)
                    existing_vas: List[int] = []
                    for i in range(len(raw_tbl) // ptr_size):
                        v = struct.unpack_from(ptr_fmt, raw_tbl, i * ptr_size)[0]
                        if v == 0:
                            break
                        existing_vas.append(v)

                    kept_vas = [v for v in existing_vas if v not in mal_vas]
                    # Rewrite compacted table + trailing zeros
                    new_tbl = bytearray(ptr_size * (len(existing_vas) + 1))
                    for idx_v, v in enumerate(kept_vas):
                        struct.pack_into(ptr_fmt, new_tbl, idx_v * ptr_size, v)
                    fh.seek(table_off)
                    fh.write(new_tbl)

                    # Also RET-patch malicious callback entry points if in-file
                    for it in items:
                        cb_off = int(it.get("callback_file_offset", -1))
                        if cb_off > 0:
                            fh.seek(cb_off)
                            fh.write(b"\xC3")
                        report.tls_callbacks_neutralized += 1
                        msg = f"Neutralized malicious TLS callback #{it['callback_index']} ({hex(it['callback_va'])})"
                        report.actions_taken.append(msg)
                        self._log(f"[SANITIZE] {msg}")

            # 3. Neutralize code-cave shellcode inside .text padding
            for anom in anomalies:
                if anom.get("type") == "CODE_CAVE_SHELLCODE":
                    cave_off = int(anom.get("file_offset", -1))
                    cave_sz = int(anom.get("size", 0))
                    if cave_off > 0 and cave_sz > 0:
                        fh.seek(cave_off)
                        fh.write(b"\x00" * cave_sz)
                        report.caves_neutralized += 1
                        msg = f"Cleared code-cave shellcode ({cave_sz}B @ {hex(cave_off)}) in {anom.get('section_name')}"
                        report.actions_taken.append(msg)
                        self._log(f"[SANITIZE] {msg}")

            # 3b. Surgically neutralize suspicious exported functions in .text (RET_ZERO: 31 C0 C3)
            for anom in anomalies:
                if anom.get("type") == "MALICIOUS_EXPORT_FUNC":
                    exp_off = int(anom.get("file_offset", -1))
                    exp_name = str(anom.get("function_name", "unknown"))
                    if exp_off > 0:
                        fh.seek(exp_off)
                        before = fh.read(3)
                        if before != b"\x31\xC0\xC3":
                            fh.seek(exp_off)
                            fh.write(b"\x31\xC0\xC3")
                            report.exports_neutralized.append(exp_name)
                            msg = f"Surgically neutralized exported function '{exp_name}' @ {hex(exp_off)} [{before.hex(' ').upper()} -> 31 C0 C3]"
                            report.actions_taken.append(msg)
                            self._log(f"[SANITIZE] {msg}")

            # 4. Strip trailing injected sections OR neutralize non-trailing injected sections in-place
            # Read current section table entries
            sections_meta: List[Dict[str, Any]] = []
            for idx in range(num_sections):
                s_hdr_off = sec_table_off + idx * 40
                fh.seek(s_hdr_off)
                sh = fh.read(40)
                if len(sh) < 40:
                    break
                sname = sh[:8].rstrip(b"\x00").decode("utf-8", errors="ignore")
                vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", sh, 8)
                chars = struct.unpack_from("<I", sh, 36)[0]
                sections_meta.append({
                    "index": idx,
                    "hdr_off": s_hdr_off,
                    "name": sname,
                    "vsize": vsize,
                    "vaddr": vaddr,
                    "rsize": rsize,
                    "rptr": rptr,
                    "chars": chars,
                })

            injected_indices = {
                int(a["section_index"])
                for a in anomalies
                if a.get("type") == "INJECTED_SECTION"
            }

            # Strip trailing injected sections from the end backwards (only if EP does not point into them)
            stripped_any_tail = False
            while sections_meta and sections_meta[-1]["index"] in injected_indices:
                last_sec = sections_meta[-1]
                sec_vstart = last_sec["vaddr"]
                sec_vend = sec_vstart + max(last_sec["vsize"], last_sec["rsize"])
                if sec_vstart <= ep_rva < sec_vend:
                    # OEP still points here (unrecoverable OEP) -> cannot safely strip section header
                    break
                # Zero section header in table
                fh.seek(last_sec["hdr_off"])
                fh.write(b"\x00" * 40)
                sections_meta.pop()
                injected_indices.discard(last_sec["index"])
                stripped_any_tail = True
                report.sections_stripped.append(last_sec["name"])
                msg = f"Stripped trailing injected PE section '{last_sec['name']}' (raw={last_sec['rsize']}B)"
                report.actions_taken.append(msg)
                self._log(f"[SANITIZE] {msg}")

            if stripped_any_tail and sections_meta:
                new_num_sections = len(sections_meta)
                fh.seek(pe_off + 6)
                fh.write(struct.pack("<H", new_num_sections))

                # Recalculate SizeOfImage aligned to SectionAlignment
                max_vend = max(
                    s["vaddr"] + max(s["vsize"], s["rsize"], 1) for s in sections_meta
                )
                new_size_of_image = self._align_up(max_vend, sec_alignment)
                fh.seek(opt_off + 56)
                fh.write(struct.pack("<I", new_size_of_image))

                # Clear any DataDirectory entries (e.g. injected TLS directory) whose RVA
                # pointed into the stripped trailing section(s)
                opt_magic = struct.unpack_from("<H", opt_hdr, 0)[0] if len(opt_hdr) >= 2 else 0x10B
                dd_rel = 112 if opt_magic == 0x20B else 96
                for dd_idx in (9,):  # IMAGE_DIRECTORY_ENTRY_TLS = 9
                    if dd_rel + (dd_idx + 1) * 8 <= len(opt_hdr):
                        dd_rva, dd_sz = struct.unpack_from("<II", opt_hdr, dd_rel + dd_idx * 8)
                        if dd_rva >= new_size_of_image and dd_sz > 0:
                            fh.seek(opt_off + dd_rel + dd_idx * 8)
                            fh.write(b"\x00" * 8)
                            msg = f"Cleared injected TLS DataDirectory pointing to stripped RVA {hex(dd_rva)}"
                            report.actions_taken.append(msg)
                            self._log(f"[SANITIZE] {msg}")

                # Truncate raw bytes of stripped trailing sections
                new_raw_end = max(s["rptr"] + s["rsize"] for s in sections_meta)
                fh.truncate(new_raw_end)

            # Neutralize any remaining non-trailing injected sections in-place
            for sec in sections_meta:
                if sec["index"] in injected_indices:
                    sec_vstart = sec["vaddr"]
                    sec_vend = sec_vstart + max(sec["vsize"], sec["rsize"])
                    if sec_vstart <= ep_rva < sec_vend:
                        continue
                    if sec["rptr"] > 0 and sec["rsize"] > 0:
                        fh.seek(sec["rptr"])
                        fh.write(b"\x00" * sec["rsize"])
                    # Clear EXECUTE (0x20000000) and WRITE (0x80000000) flags, keep READ (0x40000000)
                    new_chars = (sec["chars"] & ~(0x20000000 | 0x80000000)) | 0x40000000
                    fh.seek(sec["hdr_off"] + 36)
                    fh.write(struct.pack("<I", new_chars))
                    report.sections_neutralized.append(sec["name"])
                    msg = f"Neutralized injected PE section '{sec['name']}' in-place (zeroed + cleared RWX)"
                    report.actions_taken.append(msg)
                    self._log(f"[SANITIZE] {msg}")

            # 5. Strip malicious PE overlays
            if any(a.get("type") == "MALICIOUS_OVERLAY" for a in anomalies) and sections_meta:
                pe_raw_end = max(s["rptr"] + s["rsize"] for s in sections_meta)
                fh.seek(0, os.SEEK_END)
                cur_size = fh.tell()
                if cur_size > pe_raw_end:
                    fh.truncate(pe_raw_end)
                    report.overlay_stripped = True
                    msg = f"Stripped malicious PE overlay ({cur_size - pe_raw_end} bytes @ {hex(pe_raw_end)})"
                    report.actions_taken.append(msg)
                    self._log(f"[SANITIZE] {msg}")

        # 6. Strip invalidated Authenticode signature & recalculate PE CheckSum
        if report.actions_taken:
            self._strip_signature_and_fix_checksum(output_binary)
            report.signatures_stripped = True

        # 7. Post-sanitization PE structural integrity verification
        ok, errs, csum_ok = self.verify_pe_integrity(output_binary)
        report.integrity_ok = ok
        report.integrity_errors = errs
        report.checksum_valid = csum_ok
        report.success = ok
        return report

    @staticmethod
    def verify_pe_integrity(binary_path: str) -> Tuple[bool, List[str], bool]:
        """
        Verify structural integrity of a Windows PE (.exe / .dll) binary:
        - Valid DOS MZ + PE\\0\\0 headers
        - NumberOfSections matches section table and >= 1
        - All section raw ranges fall within file size
        - SizeOfImage >= max section virtual end
        - AddressOfEntryPoint (if non-zero) falls inside a valid executable section
        - Import/Export directories parse cleanly
        - OptionalHeader CheckSum matches calculated PE checksum (if non-zero)
        Returns (is_valid, error_list, checksum_valid).
        """
        errors: List[str] = []
        checksum_valid = False
        if not os.path.isfile(binary_path):
            return False, ["File does not exist"], False

        file_size = os.path.getsize(binary_path)
        pe: Optional[pefile.PE] = None
        try:
            pe = pefile.PE(binary_path, fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
                ]
            )
            if pe.FILE_HEADER.NumberOfSections != len(pe.sections) or len(pe.sections) == 0:
                errors.append(
                    f"Section count mismatch: header={pe.FILE_HEADER.NumberOfSections}, parsed={len(pe.sections)}"
                )

            max_vend = 0
            for sec in pe.sections:
                sname = sec.Name.rstrip(b"\x00").decode("utf-8", errors="ignore")
                if sec.PointerToRawData + sec.SizeOfRawData > file_size:
                    errors.append(
                        f"Section '{sname}' raw range ({hex(sec.PointerToRawData + sec.SizeOfRawData)}) exceeds file size ({hex(file_size)})"
                    )
                vend = sec.VirtualAddress + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
                if vend > max_vend:
                    max_vend = vend

            if pe.OPTIONAL_HEADER.SizeOfImage < max_vend:
                errors.append(
                    f"SizeOfImage ({hex(pe.OPTIONAL_HEADER.SizeOfImage)}) < max section virtual end ({hex(max_vend)})"
                )

            ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            if ep_rva != 0:
                ep_in_exec = False
                for sec in pe.sections:
                    vstart = sec.VirtualAddress
                    vend = vstart + max(sec.Misc_VirtualSize, sec.SizeOfRawData)
                    if vstart <= ep_rva < vend:
                        if sec.Characteristics & IMAGE_SCN_MEM_EXECUTE:
                            ep_in_exec = True
                        break
                if not ep_in_exec:
                    errors.append(f"AddressOfEntryPoint ({hex(ep_rva)}) does not point into an executable section")

            # Verify PE CheckSum directly against on-disk bytes (avoids pefile fast_load=False bug on >20MB PEs)
            csum_off = pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum")
            hdr_csum = pe.OPTIONAL_HEADER.CheckSum
            if hdr_csum == 0:
                checksum_valid = True
            else:
                checksum = 0
                pos = 0
                with open(binary_path, "rb") as f:
                    while True:
                        chunk = f.read(64 * 1024)
                        if not chunk:
                            break
                        c_end = pos + len(chunk)
                        if pos <= csum_off < c_end or pos < csum_off + 4 <= c_end:
                            buf = bytearray(chunk)
                            for b_i in range(max(pos, csum_off), min(c_end, csum_off + 4)):
                                buf[b_i - pos] = 0
                            chunk = bytes(buf)
                        if len(chunk) & 1:
                            chunk += b"\x00"
                        checksum += sum(memoryview(chunk).cast("H"))
                        while checksum > 0xFFFF:
                            checksum = (checksum & 0xFFFF) + (checksum >> 16)
                        pos = c_end
                calc_csum = (checksum + file_size) & 0xFFFFFFFF
                checksum_valid = hdr_csum == calc_csum
                if not checksum_valid:
                    errors.append(f"PE CheckSum mismatch: header={hex(hdr_csum)}, calculated={hex(calc_csum)}")

        except Exception as exc:
            errors.append(f"PE parse failure: {exc}")
        finally:
            if pe is not None:
                pe.close()

        return len(errors) == 0, errors, checksum_valid


# ---------------------------------------------------------------------------
# Backup & Quarantine Vault Manager
# ---------------------------------------------------------------------------

class QuarantineManager:
    """Manages safe backups, XOR-neutralized Quarantine Vault, restoration, and deletion."""

    def __init__(
        self,
        base_dir: Optional[str] = None,
        log_callback: Optional[Callable[[str], None]] = None,
    ):
        self._log = log_callback or (lambda msg: None)
        root = Path(
            base_dir
            or os.path.join(os.environ.get("LOCALAPPDATA", tempfile.gettempdir()), "GhidraGuard")
        )
        self.quarantine_dir = root / "quarantine"
        self.backup_dir = root / "backups"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.quarantine_dir / "vault.json"

    def _load_manifest(self) -> List[Dict[str, Any]]:
        if not self.manifest_path.is_file():
            return []
        try:
            return json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _save_manifest(self, items: List[Dict[str, Any]]) -> None:
        self.manifest_path.write_text(json.dumps(items, indent=2), encoding="utf-8")

    def list_quarantined(self) -> List[QuarantineEntry]:
        entries: List[QuarantineEntry] = []
        for item in self._load_manifest():
            try:
                entries.append(QuarantineEntry(**item))
            except TypeError:
                continue
        return entries

    def terminate_processes_using_file(self, file_path: str) -> int:
        """Terminate running processes whose executable matches file_path."""
        norm = os.path.normpath(file_path).lower()
        killed = 0
        for proc in psutil.process_iter(["pid", "exe"]):
            try:
                exe = proc.info.get("exe")
                if exe and os.path.normpath(exe).lower() == norm:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except psutil.TimeoutExpired:
                        proc.kill()
                    killed += 1
                    self._log(f"[VAULT] Terminated process PID {proc.info['pid']} holding {os.path.basename(file_path)}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
        return killed

    def create_backup(self, file_path: str) -> str:
        """Create a timestamped backup copy of a binary prior to replacing it."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Cannot back up missing file: {file_path}")
        stamp = time.strftime("%Y%m%d_%H%M%S")
        dest = self.backup_dir / f"{Path(file_path).name}.{stamp}.bak"
        shutil.copy2(file_path, dest)
        self._log(f"[VAULT] Created backup: {dest}")
        return str(dest)

    def quarantine_file(self, file_path: str, reason: str = "User quarantine") -> QuarantineEntry:
        """
        Neutralize (XOR first 4KB MZ/PE header so it cannot execute), move into
        Quarantine Vault, and remove the original file from disk.
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found for quarantine: {file_path}")

        self.terminate_processes_using_file(file_path)

        entry_id = uuid.uuid4().hex[:12]
        vault_filename = f"{entry_id}_{Path(file_path).name}.ggquar"
        vault_path = self.quarantine_dir / vault_filename

        # Stream-copy in 1 MB chunks while computing SHA-256 and XOR-neutralizing first 4KB (no file size limit)
        h = hashlib.sha256()
        written = 0
        with open(file_path, "rb") as src, open(vault_path, "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
                if written < 4096:
                    buf = bytearray(chunk)
                    limit = min(4096 - written, len(buf))
                    for i in range(limit):
                        buf[i] ^= QUARANTINE_XOR_KEY
                    dst.write(buf)
                else:
                    dst.write(chunk)
                written += len(chunk)
        sha256 = h.hexdigest()

        # Remove original file
        os.remove(file_path)

        entry = QuarantineEntry(
            entry_id=entry_id,
            original_path=file_path,
            vault_filename=vault_filename,
            sha256=sha256,
            reason=reason,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        items = self._load_manifest()
        items.append(asdict(entry))
        self._save_manifest(items)

        self._log(f"[VAULT] Quarantined '{file_path}' -> {vault_filename} ({reason})")
        return entry

    def restore_quarantined(self, entry_id: str) -> str:
        """Restore a quarantined file back to its original path."""
        items = self._load_manifest()
        target = next((x for x in items if x.get("entry_id") == entry_id), None)
        if not target:
            raise KeyError(f"Quarantine entry not found: {entry_id}")

        vault_path = self.quarantine_dir / target["vault_filename"]
        if not vault_path.is_file():
            raise FileNotFoundError(f"Vault file missing: {vault_path}")

        orig_path = Path(target["original_path"])
        orig_path.parent.mkdir(parents=True, exist_ok=True)

        # Stream-restore in 1 MB chunks while un-XORing first 4KB (no file size limit)
        written = 0
        with open(vault_path, "rb") as src, open(orig_path, "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                if written < 4096:
                    buf = bytearray(chunk)
                    limit = min(4096 - written, len(buf))
                    for i in range(limit):
                        buf[i] ^= QUARANTINE_XOR_KEY
                    dst.write(buf)
                else:
                    dst.write(chunk)
                written += len(chunk)
        vault_path.unlink(missing_ok=True)

        items = [x for x in items if x.get("entry_id") != entry_id]
        self._save_manifest(items)
        self._log(f"[VAULT] Restored quarantined file to: {orig_path}")
        return str(orig_path)

    def delete_quarantined(self, entry_id: str) -> None:
        """Permanently delete a file from the Quarantine Vault."""
        items = self._load_manifest()
        target = next((x for x in items if x.get("entry_id") == entry_id), None)
        if target:
            vault_path = self.quarantine_dir / target["vault_filename"]
            vault_path.unlink(missing_ok=True)
            items = [x for x in items if x.get("entry_id") != entry_id]
            self._save_manifest(items)
            self._log(f"[VAULT] Permanently deleted quarantined item: {target['original_path']}")

    def delete_file_permanently(self, file_path: str) -> None:
        """Terminate processes holding file_path and delete it permanently."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        self.terminate_processes_using_file(file_path)
        os.remove(file_path)
        self._log(f"[VAULT] Permanently deleted: {file_path}")

    def deploy_patched_binary(self, patched_path: str, original_path: str) -> str:
        """Back up original_path and replace it with patched_path."""
        backup_path = self.create_backup(original_path)
        self.terminate_processes_using_file(original_path)
        shutil.copy2(patched_path, original_path)
        self._log(f"[VAULT] Deployed patched binary to {original_path} (backup at {backup_path})")
        return backup_path
