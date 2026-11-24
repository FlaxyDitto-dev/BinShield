"""
OpcodeShield - Cross-Platform Android APK (.apk) Analyzer, Sanitizer & Integrity Verifier
100% offline, zero external dependencies (pure Python stdlib: zipfile, struct, hashlib, zlib).
Parses binary AXML AndroidManifest.xml, DEX headers/checksums/strings, native ELF (.so)
libraries (ARM64, ARMv7, x86, x86_64), and assets/ droppers; surgically strips or patches
unauthorized injections while preserving APK structural integrity.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Constants & Threat Indicators
# ---------------------------------------------------------------------------

DANGEROUS_PERMISSIONS: Dict[str, int] = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 28,
    "android.permission.BIND_DEVICE_ADMIN": 25,
    "android.permission.REQUEST_INSTALL_PACKAGES": 18,
    "android.permission.SYSTEM_ALERT_WINDOW": 14,
    "android.permission.RECEIVE_SMS": 18,
    "android.permission.READ_SMS": 18,
    "android.permission.SEND_SMS": 20,
    "android.permission.READ_CALL_LOG": 14,
    "android.permission.RECORD_AUDIO": 12,
    "android.permission.READ_CONTACTS": 10,
    "android.permission.MANAGE_EXTERNAL_STORAGE": 12,
    "android.permission.QUERY_ALL_PACKAGES": 8,
    "android.permission.RECEIVE_BOOT_COMPLETED": 6,
}

# Benign permissions commonly found in normal apps (never penalized alone)
BENIGN_COMMON_PERMISSIONS: Set[str] = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.WAKE_LOCK",
    "android.permission.VIBRATE",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.FOREGROUND_SERVICE",
}

APK_HIGH_CONFIDENCE_IOCS: Tuple[Tuple[bytes, str], ...] = (
    (b"frida-server", "Frida instrumentation / hook artifact"),
    (b"frida-gadget", "Frida gadget injection library"),
    (b"xposedbridge", "Xposed framework hook artifact"),
    (b"discord.com/api/webhooks", "Discord webhook exfiltration IOC"),
    (b"api.telegram.org/bot", "Telegram bot C2/exfiltration IOC"),
    (b"/system/bin/su", "Root su execution path"),
    (b"/system/xbin/su", "Root xbin su execution path"),
    (b"inmemorydexclassloader", "In-memory DEX dynamic payload loader"),
    (b"c2_beacon", "C2 beacon payload marker"),
    (b"keylogger_hook", "Keylogger hook payload marker"),
    (b"gg_dex_payload", "Injected secondary DEX payload marker"),
    (b"gg_elf_payload", "Injected native ELF payload marker"),
    (b"gg_asset_payload", "Injected asset dropper payload marker"),
    (b"gg_elf_stub", "Injected ELF executable stub marker"),
    (b"reverse_shell", "Reverse shell marker"),
    (b"meterpreter", "Meterpreter RAT signature"),
    (b"ransom_encrypt", "Ransomware encryption routine marker"),
)

APK_SUSPICIOUS_API_STRINGS: Tuple[bytes, ...] = (
    b"DexClassLoader",
    b"Runtime.getRuntime",
    b"ProcessBuilder",
    b"SmsManager",
    b"sendTextMessage",
    b"performGlobalAction",
    b"MediaProjection",
    b"deletePackage",
    b"setComponentEnabledSetting",
)

SUSPICIOUS_INJECTED_SO_NAMES: Set[str] = {
    "libfrida-gadget.so",
    "libfrida.so",
    "libgadget.so",
    "libinject.so",
    "libhook.so",
    "libpayload.so",
    "libmalware.so",
    "libevil.so",
    "libdropper.so",
    "libbackdoor.so",
    "libsubstrate.so",
    "libxposed.so",
}

# ELF architecture constants
EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183
SHF_WRITE = 0x1
SHF_EXECINSTR = 0x4
PT_LOAD = 1
PF_X = 0x1
PF_W = 0x2

# Architecture-specific RET_ZERO machine code sequences
ELF_RET_ZERO_MAP: Dict[str, bytes] = {
    "arm64-v8a": bytes([0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6]),  # mov x0, #0; ret
    "armeabi-v7a": bytes([0x00, 0x00, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1]),  # mov r0, #0; bx lr
    "x86_64": bytes([0x31, 0xC0, 0xC3]),  # xor eax, eax; ret
    "x86": bytes([0x31, 0xC0, 0xC3]),  # xor eax, eax; ret
}

# AXML chunk types & resource IDs
RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_ELEMENT_TYPE = 0x0102
ANDROID_ATTR_DEBUGGABLE = 0x0101000F


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class ApkFinding:
    name: str
    path: str
    package_name: str
    risk_score: int
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    is_debuggable: bool = False
    dex_count: int = 0
    native_lib_count: int = 0
    max_entropy: float = 0.0
    sha256: str = ""
    permissions: List[str] = field(default_factory=list)
    dangerous_permissions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    anomalies: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ApkSanitizationReport:
    input_path: str
    output_path: str
    success: bool
    actions_taken: List[str] = field(default_factory=list)
    removed_entries: List[str] = field(default_factory=list)
    patched_entries: List[str] = field(default_factory=list)
    manifest_patched: bool = False
    signatures_stripped: bool = False
    integrity_ok: bool = False
    integrity_errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Low-level Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / length
            ent -= p * math.log2(p)
    return round(ent, 2)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _severity_from_score(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Binary AXML (AndroidManifest.xml) Parser & Sanitizer
# ---------------------------------------------------------------------------

def parse_axml_manifest(data: bytes) -> Dict[str, Any]:
    """
    Parse Android Binary XML (AXML) or plain XML AndroidManifest.xml.
    Extracts package_name, permissions, is_debuggable, debuggable_value_offset, and strings.
    """
    result: Dict[str, Any] = {
        "valid": False,
        "format": "unknown",
        "package_name": "",
        "permissions": [],
        "is_debuggable": False,
        "debuggable_value_offset": -1,
        "strings": [],
    }
    if not data or len(data) < 8:
        return result

    # Plain XML fallback (e.g., unpacked/test manifests)
    stripped = data.lstrip()
    if stripped.startswith(b"<?xml") or stripped.startswith(b"<manifest"):
        try:
            text = data.decode("utf-8", errors="ignore")
            result["valid"] = True
            result["format"] = "xml"
            pkg_m = re.search(r'package\s*=\s*["\']([^"\']+)["\']', text)
            if pkg_m:
                result["package_name"] = pkg_m.group(1)
            perms = re.findall(r'android\.permission\.[A-Z0-9_]+', text)
            result["permissions"] = sorted(set(perms))
            if re.search(r'android:debuggable\s*=\s*["\']true["\']', text, re.IGNORECASE):
                result["is_debuggable"] = True
            return result
        except Exception:
            return result

    # Binary AXML format
    chunk_type, hdr_size, file_size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != RES_XML_TYPE or hdr_size < 8 or file_size > len(data) + 64:
        return result

    result["valid"] = True
    result["format"] = "axml"
    strings: List[str] = []
    res_ids: List[int] = []
    pos = hdr_size

    while pos + 8 <= len(data):
        c_type, c_hdr_size, c_size = struct.unpack_from("<HHI", data, pos)
        if c_size < 8 or pos + c_size > len(data):
            break

        if c_type == RES_STRING_POOL_TYPE and c_size >= 28:
            str_count, _style_count, flags, str_start, _style_start = struct.unpack_from(
                "<IIIII", data, pos + 8
            )
            is_utf8 = bool(flags & (1 << 8))
            offsets_base = pos + c_hdr_size
            pool_base = pos + str_start
            for i in range(min(str_count, 10000)):
                if offsets_base + (i + 1) * 4 > pos + c_size:
                    break
                s_off = struct.unpack_from("<I", data, offsets_base + i * 4)[0]
                abs_off = pool_base + s_off
                if abs_off >= pos + c_size:
                    strings.append("")
                    continue
                try:
                    if is_utf8:
                        # Skip char length (1 or 2 bytes) and byte length (1 or 2 bytes)
                        p = abs_off
                        b0 = data[p]
                        p += 2 if (b0 & 0x80) else 1
                        b1 = data[p]
                        if b1 & 0x80:
                            byte_len = ((b1 & 0x7F) << 8) | data[p + 1]
                            p += 2
                        else:
                            byte_len = b1
                            p += 1
                        s = data[p : p + byte_len].decode("utf-8", errors="ignore")
                    else:
                        if abs_off + 2 > pos + c_size:
                            s = ""
                        else:
                            char_len = struct.unpack_from("<H", data, abs_off)[0]
                            p = abs_off + 2
                            if char_len & 0x8000:
                                char_len = ((char_len & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
                                p += 2
                            s = data[p : p + char_len * 2].decode("utf-16le", errors="ignore")
                    strings.append(s)
                except Exception:
                    strings.append("")

        elif c_type == RES_XML_RESOURCE_MAP_TYPE:
            count = (c_size - c_hdr_size) // 4
            for i in range(count):
                rid = struct.unpack_from("<I", data, pos + c_hdr_size + i * 4)[0]
                res_ids.append(rid)

        elif c_type == RES_XML_START_ELEMENT_TYPE and c_size >= 36:
            # ResXMLTree_node (16B) + ResXMLTree_attrExt (20B) + attrs (20B each)
            elem_name_idx = struct.unpack_from("<i", data, pos + 20)[0]
            attr_start = struct.unpack_from("<H", data, pos + 24)[0]
            attr_size = struct.unpack_from("<H", data, pos + 26)[0]
            attr_count = struct.unpack_from("<H", data, pos + 28)[0]
            elem_name = strings[elem_name_idx] if 0 <= elem_name_idx < len(strings) else ""
            attrs_base = pos + 16 + attr_start
            if attr_size >= 20:
                for a_i in range(attr_count):
                    a_off = attrs_base + a_i * attr_size
                    if a_off + 20 > pos + c_size:
                        break
                    _ns, name_idx, raw_val_idx = struct.unpack_from("<iii", data, a_off)
                    val_type = data[a_off + 15]
                    val_data = struct.unpack_from("<I", data, a_off + 16)[0]
                    attr_name = strings[name_idx] if 0 <= name_idx < len(strings) else ""
                    attr_res_id = res_ids[name_idx] if 0 <= name_idx < len(res_ids) else 0

                    if elem_name == "manifest" and attr_name == "package":
                        if 0 <= raw_val_idx < len(strings):
                            result["package_name"] = strings[raw_val_idx]
                        elif val_type == 0x03 and 0 <= val_data < len(strings):
                            result["package_name"] = strings[val_data]

                    if attr_name == "debuggable" or attr_res_id == ANDROID_ATTR_DEBUGGABLE:
                        # TYPE_INT_BOOLEAN = 0x12
                        if val_data != 0:
                            result["is_debuggable"] = True
                            result["debuggable_value_offset"] = a_off + 16

        pos += c_size

    result["strings"] = strings
    perms = sorted({s for s in strings if s.startswith("android.permission.")})
    result["permissions"] = perms
    if not result["package_name"]:
        for s in strings:
            if "." in s and not s.startswith("android.") and re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+){1,6}$", s):
                result["package_name"] = s
                break
    return result


def sanitize_axml_manifest(data: bytes) -> Tuple[bytes, bool]:
    """
    Safely patch AndroidManifest.xml to disable android:debuggable="true"
    while keeping AXML chunk headers, string pool, and size fields 100% intact.
    """
    parsed = parse_axml_manifest(data)
    if not parsed["valid"] or not parsed["is_debuggable"]:
        return data, False

    if parsed["format"] == "axml" and parsed["debuggable_value_offset"] >= 0:
        buf = bytearray(data)
        off = parsed["debuggable_value_offset"]
        if off + 4 <= len(buf):
            struct.pack_into("<I", buf, off, 0)  # false
            return bytes(buf), True
    elif parsed["format"] == "xml":
        text = data.decode("utf-8", errors="ignore")
        patched = re.sub(
            r'(android:debuggable\s*=\s*["\'])true(["\'])',
            r'\1false\2',
            text,
            flags=re.IGNORECASE,
        )
        if patched != text:
            return patched.encode("utf-8"), True

    return data, False


# ---------------------------------------------------------------------------
# DEX Validation & Checksum/SHA-1 Recalculation
# ---------------------------------------------------------------------------

def verify_dex_integrity(dex_bytes: bytes) -> Tuple[bool, str]:
    """Verify DEX magic, header size, file size, SHA-1 signature, and Adler-32 checksum."""
    if len(dex_bytes) < 0x70:
        return False, "DEX too small (< 112 bytes)"
    if dex_bytes[:4] != b"dex\n" or dex_bytes[7:8] != b"\x00":
        return False, "Invalid DEX magic"
    stored_checksum = struct.unpack_from("<I", dex_bytes, 8)[0]
    stored_sha1 = dex_bytes[12:32]
    declared_size = struct.unpack_from("<I", dex_bytes, 32)[0]
    header_size = struct.unpack_from("<I", dex_bytes, 36)[0]
    if header_size != 0x70:
        return False, f"Unexpected DEX header_size {hex(header_size)}"
    if declared_size != len(dex_bytes):
        return False, f"DEX file_size mismatch ({declared_size} != {len(dex_bytes)})"
    calc_sha1 = hashlib.sha1(dex_bytes[32:]).digest()
    if calc_sha1 != stored_sha1:
        return False, "DEX SHA-1 signature mismatch"
    calc_checksum = zlib.adler32(dex_bytes[12:]) & 0xFFFFFFFF
    if calc_checksum != stored_checksum:
        return False, "DEX Adler-32 checksum mismatch"
    return True, "OK"


def fix_dex_header(dex_bytes: bytes) -> bytes:
    """Recalculate DEX file_size, SHA-1 signature, and Adler-32 checksum."""
    if len(dex_bytes) < 0x70 or dex_bytes[:4] != b"dex\n":
        return dex_bytes
    buf = bytearray(dex_bytes)
    struct.pack_into("<I", buf, 32, len(buf))
    sha1 = hashlib.sha1(buf[32:]).digest()
    buf[12:32] = sha1
    checksum = zlib.adler32(buf[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 8, checksum)
    return bytes(buf)


# ---------------------------------------------------------------------------
# ELF Native Library (.so) Inspection & Surgical Patching
# ---------------------------------------------------------------------------

def inspect_elf_bytes(elf_bytes: bytes) -> Dict[str, Any]:
    """Parse ELF32/ELF64 headers, architecture, executable sections, and RWX anomalies."""
    info: Dict[str, Any] = {
        "valid": False,
        "arch": "unknown",
        "is_64": False,
        "has_rwx": False,
        "exec_sections": [],
        "stub_offsets": [],
    }
    if len(elf_bytes) < 64 or elf_bytes[:4] != b"\x7fELF":
        return info

    is_64 = elf_bytes[4] == 2
    endian = ">" if elf_bytes[5] == 2 else "<"
    machine = struct.unpack_from(endian + "H", elf_bytes, 18)[0]
    arch = {
        EM_AARCH64: "arm64-v8a",
        EM_ARM: "armeabi-v7a",
        EM_X86_64: "x86_64",
        EM_386: "x86",
    }.get(machine, f"elf_{machine}")

    info["valid"] = True
    info["arch"] = arch
    info["is_64"] = is_64

    # Check Program Headers for RWX PT_LOAD
    try:
        if is_64:
            e_phoff = struct.unpack_from(endian + "Q", elf_bytes, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", elf_bytes, 54)
            for i in range(min(e_phnum, 64)):
                off = e_phoff + i * e_phentsize
                if off + 8 > len(elf_bytes):
                    break
                p_type, p_flags = struct.unpack_from(endian + "II", elf_bytes, off)
                if p_type == PT_LOAD and (p_flags & PF_W) and (p_flags & PF_X):
                    info["has_rwx"] = True
        else:
            e_phoff = struct.unpack_from(endian + "I", elf_bytes, 28)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", elf_bytes, 42)
            for i in range(min(e_phnum, 64)):
                off = e_phoff + i * e_phentsize
                if off + 28 > len(elf_bytes):
                    break
                p_type = struct.unpack_from(endian + "I", elf_bytes, off)[0]
                p_flags = struct.unpack_from(endian + "I", elf_bytes, off + 24)[0]
                if p_type == PT_LOAD and (p_flags & PF_W) and (p_flags & PF_X):
                    info["has_rwx"] = True
    except Exception:
        pass

    # Check Section Headers for executable & RWX sections
    try:
        if is_64:
            e_shoff = struct.unpack_from(endian + "Q", elf_bytes, 40)[0]
            e_shentsize, e_shnum = struct.unpack_from(endian + "HH", elf_bytes, 58)
            for i in range(min(e_shnum, 128)):
                off = e_shoff + i * e_shentsize
                if off + 64 > len(elf_bytes):
                    break
                sh_flags = struct.unpack_from(endian + "Q", elf_bytes, off + 8)[0]
                sh_addr = struct.unpack_from(endian + "Q", elf_bytes, off + 16)[0]
                sh_off = struct.unpack_from(endian + "Q", elf_bytes, off + 24)[0]
                sh_size = struct.unpack_from(endian + "Q", elf_bytes, off + 32)[0]
                if (sh_flags & SHF_EXECINSTR) and sh_size > 0:
                    if sh_flags & SHF_WRITE:
                        info["has_rwx"] = True
                    info["exec_sections"].append({
                        "index": i,
                        "offset": sh_off,
                        "size": sh_size,
                        "vaddr": sh_addr,
                        "is_rwx": bool(sh_flags & SHF_WRITE),
                    })
        else:
            e_shoff = struct.unpack_from(endian + "I", elf_bytes, 32)[0]
            e_shentsize, e_shnum = struct.unpack_from(endian + "HH", elf_bytes, 46)
            for i in range(min(e_shnum, 128)):
                off = e_shoff + i * e_shentsize
                if off + 40 > len(elf_bytes):
                    break
                sh_flags = struct.unpack_from(endian + "I", elf_bytes, off + 8)[0]
                sh_addr = struct.unpack_from(endian + "I", elf_bytes, off + 12)[0]
                sh_off = struct.unpack_from(endian + "I", elf_bytes, off + 16)[0]
                sh_size = struct.unpack_from(endian + "I", elf_bytes, off + 20)[0]
                if (sh_flags & SHF_EXECINSTR) and sh_size > 0:
                    if sh_flags & SHF_WRITE:
                        info["has_rwx"] = True
                    info["exec_sections"].append({
                        "index": i,
                        "offset": sh_off,
                        "size": sh_size,
                        "vaddr": sh_addr,
                        "is_rwx": bool(sh_flags & SHF_WRITE),
                    })
    except Exception:
        pass

    # Detect injected executable payload stubs inside executable sections
    for sec in info["exec_sections"]:
        s_off = sec["offset"]
        s_end = min(len(elf_bytes), s_off + sec["size"])
        if s_off < s_end:
            sec_data = elf_bytes[s_off:s_end]
            for marker in (b"GG_ELF_STUB", b"gg_elf_stub"):
                pos = sec_data.find(marker)
                if pos != -1:
                    # Align stub patch start down to 4-byte boundary (ARM64/ARMv7 requirement)
                    stub_off = s_off + (pos & ~3)
                    info["stub_offsets"].append({
                        "file_offset": stub_off,
                        "marker_offset": s_off + pos,
                        "length": max(len(marker), 16),
                    })
                    break

    return info


# ---------------------------------------------------------------------------
# APK Static Analyzer
# ---------------------------------------------------------------------------

def analyze_apk_file(apk_path: str) -> Optional[ApkFinding]:
    """
    Analyze an Android .apk archive for unauthorized code injections, malicious payloads,
    tampered manifests, injected secondary DEX files, malicious native .so libraries,
    and hidden assets/ droppers.
    """
    if not apk_path or not os.path.isfile(apk_path):
        return None
    if not zipfile.is_zipfile(apk_path):
        return None

    name = os.path.basename(apk_path)
    score = 0
    indicators: List[str] = []
    categories: Set[str] = set()
    anomalies: List[Dict[str, Any]] = []
    package_name = name
    permissions: List[str] = []
    dangerous_perms: List[str] = []
    is_debuggable = False
    dex_count = 0
    native_lib_count = 0
    max_entropy = 0.0

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()

            # 1. AndroidManifest.xml inspection
            if "AndroidManifest.xml" in names:
                manifest_bytes = zf.read("AndroidManifest.xml")
                m_info = parse_axml_manifest(manifest_bytes)
                if m_info["valid"]:
                    package_name = m_info["package_name"] or name
                    permissions = m_info["permissions"]
                    is_debuggable = m_info["is_debuggable"]

                    for p in permissions:
                        if p in DANGEROUS_PERMISSIONS:
                            dangerous_perms.append(p)
                            score += DANGEROUS_PERMISSIONS[p]

                    if dangerous_perms:
                        short_p = ", ".join(p.split(".")[-1] for p in dangerous_perms[:4])
                        indicators.append(f"Dangerous permissions ({len(dangerous_perms)}): {short_p}")
                        categories.add("Excessive / Spyware Permissions")

                    pset = set(permissions)
                    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in pset and "android.permission.INTERNET" in pset:
                        score += 22
                        indicators.append("High-risk spyware combo: BIND_ACCESSIBILITY_SERVICE + INTERNET")
                        categories.add("Accessibility Spyware")
                    if "android.permission.RECEIVE_SMS" in pset and "android.permission.INTERNET" in pset:
                        score += 18
                        indicators.append("High-risk Trojan combo: RECEIVE_SMS + INTERNET")
                        categories.add("SMS Stealer")

                    if is_debuggable:
                        score += 26
                        indicators.append("Manifest tampered: android:debuggable=true enabled")
                        categories.add("Tampered Manifest")
                        anomalies.append({
                            "type": "MANIFEST_DEBUGGABLE",
                            "entry": "AndroidManifest.xml",
                            "reason": "android:debuggable=true allows runtime injection/debugging",
                        })

            # 2. Inspect DEX files, native ELF .so libs, and assets/ droppers
            for entry_name in names:
                low_entry = entry_name.lower()

                # DEX inspection
                if low_entry.endswith(".dex") and "/" not in entry_name:
                    dex_count += 1
                    dex_bytes = zf.read(entry_name)
                    ent = _shannon_entropy(dex_bytes[:262144])
                    if ent > max_entropy:
                        max_entropy = ent

                    low_dex = dex_bytes.lower()
                    ioc_hits = [desc for pat, desc in APK_HIGH_CONFIDENCE_IOCS if pat in low_dex]
                    api_hits = [api.decode("ascii") for api in APK_SUSPICIOUS_API_STRINGS if api in dex_bytes]

                    is_secondary = entry_name != "classes.dex"
                    if ioc_hits or (is_secondary and len(api_hits) >= 2):
                        score += 38 if is_secondary else 32
                        categories.add("Injected DEX Payload" if is_secondary else "Malicious DEX Code")
                        detail = "; ".join(ioc_hits[:3]) if ioc_hits else f"suspicious APIs: {', '.join(api_hits[:4])}"
                        indicators.append(f"Malicious indicators in {entry_name}: {detail}")
                        anomalies.append({
                            "type": "INJECTED_SECONDARY_DEX" if is_secondary else "MALICIOUS_PRIMARY_DEX",
                            "entry": entry_name,
                            "iocs": ioc_hits,
                            "apis": api_hits,
                            "removable": is_secondary,
                        })
                    elif len(api_hits) >= 3:
                        score += 22
                        categories.add("Dynamic Code / Suspicious APIs")
                        indicators.append(f"Multiple high-risk Android APIs in {entry_name}: {', '.join(api_hits[:4])}")

                # Native ELF .so inspection
                elif low_entry.startswith("lib/") and low_entry.endswith(".so"):
                    native_lib_count += 1
                    so_bytes = zf.read(entry_name)
                    ent = _shannon_entropy(so_bytes[:262144])
                    if ent > max_entropy:
                        max_entropy = ent
                    so_base = os.path.basename(entry_name).lower()
                    elf_info = inspect_elf_bytes(so_bytes)
                    low_so = so_bytes.lower()
                    so_iocs = [desc for pat, desc in APK_HIGH_CONFIDENCE_IOCS if pat in low_so]

                    is_injected_so = so_base in SUSPICIOUS_INJECTED_SO_NAMES
                    if is_injected_so or (elf_info["has_rwx"] and so_iocs) or (so_iocs and not elf_info["stub_offsets"]):
                        score += 40
                        categories.add("Injected Native Library")
                        reason = f"known injected lib '{so_base}'" if is_injected_so else "; ".join(so_iocs[:2])
                        indicators.append(f"Malicious native library '{entry_name}' ({elf_info['arch']}): {reason}")
                        anomalies.append({
                            "type": "INJECTED_NATIVE_SO",
                            "entry": entry_name,
                            "arch": elf_info["arch"],
                            "has_rwx": elf_info["has_rwx"],
                            "iocs": so_iocs,
                            "removable": True,
                        })
                    elif elf_info["stub_offsets"]:
                        score += 35
                        categories.add("Native ELF Code Injection")
                        indicators.append(
                            f"Injected executable stub in '{entry_name}' ({elf_info['arch']}) "
                            f"@ {hex(elf_info['stub_offsets'][0]['file_offset'])}"
                        )
                        anomalies.append({
                            "type": "ELF_INJECTED_STUB",
                            "entry": entry_name,
                            "arch": elf_info["arch"],
                            "stubs": elf_info["stub_offsets"],
                            "removable": False,
                        })
                    elif elf_info["has_rwx"]:
                        score += 28
                        categories.add("RWX Native Library")
                        indicators.append(f"RWX (Writable+Executable) native ELF library '{entry_name}'")
                        anomalies.append({
                            "type": "RWX_NATIVE_SO",
                            "entry": entry_name,
                            "arch": elf_info["arch"],
                            "removable": True,
                        })

                # Assets / res/raw hidden dropper payload inspection
                elif low_entry.startswith(("assets/", "res/raw/")) and not entry_name.endswith("/"):
                    asset_bytes = zf.read(entry_name)
                    if len(asset_bytes) >= 16:
                        low_asset = asset_bytes[:65536].lower()
                        asset_reasons: List[str] = []
                        if asset_bytes[:4] == b"\x7fELF":
                            asset_reasons.append("hidden ELF binary in assets")
                        elif asset_bytes[:4] == b"dex\n":
                            asset_reasons.append("hidden DEX payload in assets")
                        elif asset_bytes[:2] == b"MZ" and b"PE\x00\x00" in asset_bytes[:1024]:
                            asset_reasons.append("hidden PE executable in assets")
                        for pat, desc in APK_HIGH_CONFIDENCE_IOCS:
                            if pat in low_asset:
                                asset_reasons.append(desc)
                                break
                        if not asset_reasons and low_entry.endswith((".sh", ".bin", ".dat", ".so", ".dex")):
                            if b"chmod +x" in low_asset or b"/system/bin/su" in low_asset or b"curl http://" in low_asset:
                                asset_reasons.append("shell dropper script in assets")

                        if asset_reasons:
                            score += 36
                            categories.add("Asset Dropper Payload")
                            indicators.append(f"Malicious payload in '{entry_name}': {'; '.join(asset_reasons)}")
                            anomalies.append({
                                "type": "MALICIOUS_ASSET_PAYLOAD",
                                "entry": entry_name,
                                "reasons": asset_reasons,
                                "removable": True,
                            })

            if max_entropy >= 7.5:
                score += 15
                indicators.append(f"High entropy ({max_entropy}) suggests packed/encrypted payload")
    except Exception as exc:
        indicators.append(f"APK parse warning: {exc}")

    score = min(100, max(0, score))
    return ApkFinding(
        name=name,
        path=apk_path,
        package_name=package_name,
        risk_score=score,
        severity=_severity_from_score(score),
        is_debuggable=is_debuggable,
        dex_count=dex_count,
        native_lib_count=native_lib_count,
        max_entropy=max_entropy,
        sha256=_sha256_file(apk_path),
        permissions=permissions,
        dangerous_permissions=dangerous_perms,
        categories=sorted(categories),
        indicators=indicators,
        anomalies=anomalies,
    )


# ---------------------------------------------------------------------------
# APK Sanitizer & Structural Integrity Verifier
# ---------------------------------------------------------------------------

def sanitize_apk(
    input_apk: str,
    output_apk: str,
    finding: Optional[ApkFinding] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> ApkSanitizationReport:
    """
    Sanitize an Android APK by stripping unauthorized injected secondary DEX payloads,
    malicious assets/ droppers, unauthorized injected native .so libraries, surgically
    patching injected stubs inside legitimate .so files, disabling forced android:debuggable,
    stripping invalidated META-INF v1 signatures, and preserving ZIP storage modes
    (resources.arsc uncompressed) + structural integrity.
    """
    log = log_callback or (lambda msg: None)
    report = ApkSanitizationReport(input_path=input_apk, output_path=output_apk, success=False)

    if finding is None:
        finding = analyze_apk_file(input_apk)
    if finding is None:
        report.integrity_errors.append("Input is not a valid APK/ZIP file")
        return report

    entries_to_remove: Set[str] = set()
    elf_stubs_to_patch: Dict[str, List[Dict[str, Any]]] = {}
    patch_manifest = False

    for anom in finding.anomalies:
        atype = anom.get("type", "")
        entry = anom.get("entry", "")
        if atype in ("INJECTED_SECONDARY_DEX", "INJECTED_NATIVE_SO", "RWX_NATIVE_SO", "MALICIOUS_ASSET_PAYLOAD"):
            if entry and entry != "classes.dex" and entry != "AndroidManifest.xml":
                entries_to_remove.add(entry)
        elif atype == "ELF_INJECTED_STUB" and entry:
            elf_stubs_to_patch.setdefault(entry, []).extend(anom.get("stubs", []))
        elif atype == "MANIFEST_DEBUGGABLE":
            patch_manifest = True

    will_modify = bool(entries_to_remove or elf_stubs_to_patch or patch_manifest)
    Path(output_apk).parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(input_apk, "r") as zin:
        with zipfile.ZipFile(output_apk, "w") as zout:
            for item in zin.infolist():
                ename = item.filename

                # Strip invalidated v1 signature artifacts whenever APK content is modified
                if will_modify and ename.startswith("META-INF/") and ename.upper().endswith(
                    (".RSA", ".DSA", ".EC", ".SF")
                ):
                    report.signatures_stripped = True
                    continue

                # Remove injected malicious entries
                if ename in entries_to_remove:
                    report.removed_entries.append(ename)
                    report.actions_taken.append(f"Stripped injected entry: {ename}")
                    log(f"[APK-SANITIZE] Stripped injected entry: {ename}")
                    continue

                data = zin.read(ename)

                # Patch tampered AndroidManifest.xml (disable android:debuggable)
                if ename == "AndroidManifest.xml" and patch_manifest:
                    new_manifest, did_patch = sanitize_axml_manifest(data)
                    if did_patch:
                        data = new_manifest
                        report.manifest_patched = True
                        report.patched_entries.append(ename)
                        report.actions_taken.append("Patched AndroidManifest.xml: disabled android:debuggable")
                        log("[APK-SANITIZE] Patched AndroidManifest.xml: disabled android:debuggable")

                # Surgically patch injected executable stubs inside legitimate .so libs
                if ename in elf_stubs_to_patch:
                    elf_info = inspect_elf_bytes(data)
                    arch = elf_info["arch"]
                    ret_zero = ELF_RET_ZERO_MAP.get(arch, ELF_RET_ZERO_MAP["x86_64"])
                    buf = bytearray(data)
                    patched_any = False
                    for stub in elf_stubs_to_patch[ename]:
                        s_off = int(stub["file_offset"])
                        s_len = int(stub["length"])
                        if 0 <= s_off and s_off + len(ret_zero) <= len(buf):
                            buf[s_off : s_off + len(ret_zero)] = ret_zero
                            # Zero out remaining marker bytes after RET_ZERO so marker IOC is completely stripped
                            rem_start = s_off + len(ret_zero)
                            rem_end = min(len(buf), int(stub["marker_offset"]) + s_len)
                            if rem_end > rem_start:
                                buf[rem_start:rem_end] = b"\x00" * (rem_end - rem_start)
                            patched_any = True
                    if patched_any:
                        data = bytes(buf)
                        report.patched_entries.append(ename)
                        report.actions_taken.append(f"Surgically patched ELF stub in {ename} ({arch})")
                        log(f"[APK-SANITIZE] Surgically patched ELF stub in {ename} ({arch})")

                # Preserve storage mode (Android 11+ requires resources.arsc stored uncompressed)
                out_info = zipfile.ZipInfo(filename=ename, date_time=item.date_time)
                if ename == "resources.arsc" or item.compress_type == zipfile.ZIP_STORED:
                    out_info.compress_type = zipfile.ZIP_STORED
                else:
                    out_info.compress_type = zipfile.ZIP_DEFLATED
                out_info.external_attr = item.external_attr
                zout.writestr(out_info, data)

    ok, errs = verify_apk_integrity(output_apk)
    report.integrity_ok = ok
    report.integrity_errors = errs
    report.success = ok
    return report


def verify_apk_integrity(apk_path: str) -> Tuple[bool, List[str]]:
    """
    Verify structural integrity of a sanitized APK:
    - Valid ZIP archive (CRC check passes)
    - Valid AndroidManifest.xml (AXML or XML) with intact package name
    - Valid primary classes.dex (magic, file_size, SHA-1, Adler-32 checksum)
    - Valid ELF headers on all remaining lib/*/*.so libraries
    - resources.arsc (if present) stored uncompressed (ZIP_STORED)
    """
    errors: List[str] = []
    if not os.path.isfile(apk_path):
        return False, ["Output APK file does not exist"]

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            bad = zf.testzip()
            if bad is not None:
                errors.append(f"ZIP CRC error in entry: {bad}")

            names = set(zf.namelist())
            if "AndroidManifest.xml" not in names:
                errors.append("Missing AndroidManifest.xml")
            else:
                m_info = parse_axml_manifest(zf.read("AndroidManifest.xml"))
                if not m_info["valid"]:
                    errors.append("Corrupted AndroidManifest.xml")

            if "classes.dex" not in names:
                errors.append("Missing primary classes.dex")
            else:
                dex_ok, dex_msg = verify_dex_integrity(zf.read("classes.dex"))
                if not dex_ok:
                    errors.append(f"Primary classes.dex invalid: {dex_msg}")

            if "resources.arsc" in names:
                r_info = zf.getinfo("resources.arsc")
                if r_info.compress_type != zipfile.ZIP_STORED:
                    errors.append("resources.arsc is compressed (must be ZIP_STORED for Android 11+)")

            for ename in names:
                if ename.startswith("lib/") and ename.endswith(".so"):
                    so_bytes = zf.read(ename)
                    if not inspect_elf_bytes(so_bytes)["valid"]:
                        errors.append(f"Corrupted native ELF library: {ename}")
    except Exception as exc:
        errors.append(f"ZIP/APK exception: {exc}")

    return len(errors) == 0, errors
