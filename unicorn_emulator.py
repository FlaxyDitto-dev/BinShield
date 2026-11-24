"""
OpcodeShield v4.0.0 — Safe CPU Emulation Engine (Unicorn Engine).
Safely emulates suspicious x86 / x86_64 / ARM64 shellcode or decryptor stubs inside an
isolated virtual CPU (zero host OS execution) to unpack XOR/ROT/AES-obfuscated strings,
C2 URLs, and runtime payloads.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

IOC_RE = re.compile(
    r"(?:https?://[^\s\"'<>]{6,120}|(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?|cmd\.exe[^\s\"']{0,60}|powershell[^\s\"']{0,80}|/dev/tcp/[^\s\"']{4,60})",
    re.IGNORECASE,
)


class UnicornEmulator:
    """Safe virtual CPU emulator for shellcode & obfuscated string decryption."""

    BASE_ADDR = 0x00400000
    STACK_ADDR = 0x00800000
    MEM_SIZE = 2 * 1024 * 1024

    def __init__(self, max_instructions: int = 25000, timeout_us: int = 1_000_000) -> None:
        self.max_instructions = max_instructions
        self.timeout_us = timeout_us

    @staticmethod
    def is_available() -> bool:
        try:
            import unicorn  # noqa: F401
            return True
        except Exception:
            return False

    def emulate_code(
        self,
        code: bytes,
        arch: str = "x86_64",
        data_buffer: bytes = b"",
    ) -> Dict[str, Any]:
        """Emulate raw machine code in an isolated Unicorn virtual CPU and extract decrypted memory strings."""
        try:
            from unicorn import Uc, UC_ARCH_X86, UC_ARCH_ARM64, UC_MODE_64, UC_MODE_32, UC_MODE_ARM
            from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_ESP, UC_X86_REG_RDI, UC_X86_REG_RCX, UC_X86_REG_RAX
            from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0
        except Exception as exc:
            return {"ok": False, "error": f"Unicorn Engine not installed: {exc}", "decrypted_strings": [], "iocs": []}

        arch_low = arch.lower()
        if "arm64" in arch_low or "aarch64" in arch_low:
            uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            is_arm64 = True
        elif arch_low in ("x86", "i386", "32", "pe32"):
            uc = Uc(UC_ARCH_X86, UC_MODE_32)
            is_arm64 = False
        else:
            uc = Uc(UC_ARCH_X86, UC_MODE_64)
            is_arm64 = False

        uc.mem_map(self.BASE_ADDR, self.MEM_SIZE)
        uc.mem_map(self.STACK_ADDR, self.MEM_SIZE)
        uc.mem_write(self.BASE_ADDR, code[: self.MEM_SIZE - 4096])

        data_addr = self.BASE_ADDR + 0x100000
        if data_buffer:
            uc.mem_write(data_addr, data_buffer[: 512 * 1024])

        if is_arm64:
            uc.reg_write(UC_ARM64_REG_SP, self.STACK_ADDR + self.MEM_SIZE // 2)
            uc.reg_write(UC_ARM64_REG_X0, data_addr)
        elif arch_low in ("x86", "i386", "32", "pe32"):
            uc.reg_write(UC_X86_REG_ESP, self.STACK_ADDR + self.MEM_SIZE // 2)
        else:
            uc.reg_write(UC_X86_REG_RSP, self.STACK_ADDR + self.MEM_SIZE // 2)
            uc.reg_write(UC_X86_REG_RDI, data_addr)
            uc.reg_write(UC_X86_REG_RCX, data_addr)

        end_addr = self.BASE_ADDR + len(code)
        stop_reason = "completed"
        try:
            uc.emu_start(self.BASE_ADDR, end_addr, timeout=self.timeout_us, count=self.max_instructions)
        except Exception as exc:
            stop_reason = f"halted ({exc})"

        # Dump modified code + data + stack regions and extract newly revealed printable strings
        dumped = bytearray()
        dumped.extend(uc.mem_read(self.BASE_ADDR, min(len(code) + 4096, 65536)))
        if data_buffer:
            dumped.extend(uc.mem_read(data_addr, min(len(data_buffer) + 256, 65536)))
        dumped.extend(uc.mem_read(self.STACK_ADDR + self.MEM_SIZE // 2 - 4096, 8192))

        raw_before = set(re.findall(rb"[\x20-\x7e]{5,120}", code + data_buffer))
        raw_after = set(re.findall(rb"[\x20-\x7e]{5,120}", bytes(dumped)))
        newly_decrypted = sorted({s.decode("ascii", errors="ignore").strip() for s in (raw_after - raw_before) if len(s.strip()) >= 5})

        iocs: List[str] = []
        for s in newly_decrypted:
            for m in IOC_RE.findall(s):
                if m not in iocs:
                    iocs.append(m)

        return {
            "ok": True,
            "arch": arch,
            "stop_reason": stop_reason,
            "decrypted_strings": newly_decrypted[:40],
            "iocs": iocs[:20],
            "rax": int(uc.reg_read(UC_X86_REG_RAX)) if (not is_arm64 and arch_low not in ("x86", "i386", "32", "pe32")) else 0,
        }
