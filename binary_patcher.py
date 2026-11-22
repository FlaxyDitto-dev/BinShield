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
        Apply a list of PatchInstructions to input_binary, write output_binary,
        strip invalidated Authenticode signature, and recalculate PE checksum.
        """
        if not os.path.isfile(input_binary):
            raise FileNotFoundError(f"Input binary not found: {input_binary}")

        pe = pefile.PE(input_binary, fast_load=False)
        raw_data = bytearray(pe.__data__)
        records: List[PatchRecord] = []

        for inst in instructions:
            try:
                file_off, va, sec_name = self.resolve_file_offset(pe, inst)
                patch_bytes, note = self.compute_patch_bytes(raw_data, file_off, inst)

                if file_off + len(patch_bytes) > len(raw_data):
                    self._log(f"[PATCH] Skipping {inst.function_name}: patch exceeds file size.")
                    continue

                before_bytes = bytes(raw_data[file_off : file_off + len(patch_bytes)])
                if before_bytes == patch_bytes:
                    self._log(f"[PATCH] {inst.function_name} @ {hex(file_off)} already patched; skipping.")
                    continue

                raw_data[file_off : file_off + len(patch_bytes)] = patch_bytes

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
            shutil.copy2(input_binary, output_binary)
            return records

        # Write raw patched bytes first, then strip Authenticode signature & fix PE CheckSum
        Path(output_binary).parent.mkdir(parents=True, exist_ok=True)
        with open(output_binary, "wb") as f:
            f.write(raw_data)

        self._strip_signature_and_fix_checksum(output_binary)
        return records

    def _strip_signature_and_fix_checksum(self, binary_path: str) -> None:
        """
        Strip embedded Authenticode digital signature (invalidated after patching)
        and recalculate the PE OptionalHeader CheckSum.
        """
        pe = pefile.PE(binary_path, fast_load=False)
        stripped = False

        sec_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_idx:
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_idx]
            cert_offset = sec_dir.VirtualAddress  # For SECURITY dir, VA is actually a file offset
            cert_size = sec_dir.Size
            if cert_offset != 0 and cert_size > 0:
                sec_dir.VirtualAddress = 0
                sec_dir.Size = 0
                stripped = True
                self._log(
                    f"[PATCH] Stripped invalidated Authenticode signature "
                    f"(offset={hex(cert_offset)}, size={cert_size} bytes)."
                )
                # Rebuild and truncate trailing certificate blob if at EOF
                new_bytes = bytearray(pe.write())
                if cert_offset + cert_size >= len(new_bytes) - 16 and cert_offset < len(new_bytes):
                    new_bytes = new_bytes[:cert_offset]
                pe.close()
                with open(binary_path, "wb") as f:
                    f.write(new_bytes)
                pe = pefile.PE(binary_path, fast_load=False)

        # Recalculate PE header checksum
        old_csum = pe.OPTIONAL_HEADER.CheckSum
        new_csum = pe.generate_checksum()
        pe.OPTIONAL_HEADER.CheckSum = new_csum
        final_bytes = pe.write()
        pe.close()

        with open(binary_path, "wb") as f:
            f.write(final_bytes)

        self._log(
            f"[PATCH] Recalculated PE CheckSum: {hex(old_csum)} -> {hex(new_csum)}"
            + (" (signature stripped)" if stripped else "")
            + (f" [LIEF available={HAS_LIEF}]" if HAS_LIEF else "")
        )


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

        raw = Path(file_path).read_bytes()
        sha256 = hashlib.sha256(raw).hexdigest()

        # Neutralize header bytes so quarantined sample cannot be executed accidentally
        buf = bytearray(raw)
        limit = min(4096, len(buf))
        for i in range(limit):
            buf[i] ^= QUARANTINE_XOR_KEY

        entry_id = uuid.uuid4().hex[:12]
        vault_filename = f"{entry_id}_{Path(file_path).name}.ggquar"
        vault_path = self.quarantine_dir / vault_filename
        vault_path.write_bytes(buf)

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

        buf = bytearray(vault_path.read_bytes())
        limit = min(4096, len(buf))
        for i in range(limit):
            buf[i] ^= QUARANTINE_XOR_KEY

        orig_path = Path(target["original_path"])
        orig_path.parent.mkdir(parents=True, exist_ok=True)
        orig_path.write_bytes(buf)
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
