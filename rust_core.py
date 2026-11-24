"""
OpcodeShield v4.0.0 — Unified Native Rust Core Python Bridge (`opcodeshield_core.dll` / `libopcodeshield_core.so`).
Provides 10-50x faster native PE/ELF/Mach-O/APK analysis, SHA-256, IOC extraction,
CFG/Call-Graph extraction, and surgical in-memory patching via ctypes, with automatic fallback.
"""

from __future__ import annotations

import ctypes
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def _find_native_lib() -> Optional[Path]:
    lib_name = "opcodeshield_core.dll" if os.name == "nt" else ("libopcodeshield_core.dylib" if sys.platform == "darwin" else "libopcodeshield_core.so")
    candidates = []
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / "native" / lib_name)
        candidates.append(Path(sys.executable).resolve().parent / "native" / lib_name)
    candidates.append(Path(__file__).resolve().parent / "native" / lib_name)
    for c in candidates:
        if c.exists():
            return c
    return None


class RustCoreEngine:
    """Zero-overhead ctypes wrapper around the compiled OpcodeShield Rust Core."""

    def __init__(self) -> None:
        self.lib_path = _find_native_lib()
        self._lib: Optional[ctypes.CDLL] = None
        if self.lib_path is not None:
            try:
                lib = ctypes.CDLL(str(self.lib_path))
                lib.wasm_analyze_binary.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
                lib.wasm_analyze_binary.restype = ctypes.c_size_t
                lib.wasm_patch_at.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_size_t]
                lib.wasm_patch_at.restype = ctypes.c_size_t
                lib.wasm_result_ptr.argtypes = []
                lib.wasm_result_ptr.restype = ctypes.c_void_p
                lib.wasm_result_len.argtypes = []
                lib.wasm_result_len.restype = ctypes.c_size_t
                self._lib = lib
            except Exception:
                self._lib = None

    @property
    def available(self) -> bool:
        return self._lib is not None

    def analyze_bytes(self, data: bytes, filename: str = "sample.bin") -> Dict[str, Any]:
        if not self._lib:
            raise RuntimeError("Native Rust core library not found.")
        name_b = filename.encode("utf-8", errors="replace")
        rlen = self._lib.wasm_analyze_binary(data, len(data), name_b, len(name_b))
        rptr = self._lib.wasm_result_ptr()
        raw = ctypes.string_at(rptr, rlen)
        return json.loads(raw.decode("utf-8"))

    def analyze_file(self, path: str | Path) -> Dict[str, Any]:
        p = Path(path)
        return self.analyze_bytes(p.read_bytes(), p.name)

    def patch_bytes(self, data: bytes, offset: int, strategy: str = "RET_ZERO", patch_len: int = 8) -> Tuple[Dict[str, Any], bytes]:
        if not self._lib:
            raise RuntimeError("Native Rust core library not found.")
        strat_map = {"RET_ZERO": 0, "RET_ONE": 1, "RET_EARLY": 2, "NOP_SLED": 3}
        code = strat_map.get(strategy.upper(), 3)
        buf = ctypes.create_string_buffer(data, len(data))
        rlen = self._lib.wasm_patch_at(ctypes.addressof(buf), len(data), offset, code, patch_len)
        rptr = self._lib.wasm_result_ptr()
        res = json.loads(ctypes.string_at(rptr, rlen).decode("utf-8"))
        return res, buf.raw


_SINGLETON: Optional[RustCoreEngine] = None


def get_rust_core() -> RustCoreEngine:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = RustCoreEngine()
    return _SINGLETON
