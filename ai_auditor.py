"""
GhidraGuard - Local AI Multi-Pass Malware Auditor & Iterative Disinfection Loop
Connects exclusively to local LLM endpoints (Ollama http://localhost:11434 or
OpenAI-compatible local llama.cpp server), audits Ghidra pseudo-C, parses strict
JSON patch plans, applies byte-level patches, and iteratively re-verifies up to 5 passes.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

import requests

from binary_patcher import BinaryPatcher, PatchInstruction, PatchRecord, QuarantineManager
from ghidra_engine import GhidraAnalysisResult, GhidraEngine


# ---------------------------------------------------------------------------
# Default Small Local Model (< 4GB, CPU-friendly, strong at C & JSON)
# ---------------------------------------------------------------------------

DEFAULT_AUTO_MODEL = "qwen2.5-coder:3b"  # ~1.9 GB Q4_K_M on Ollama

# Functions that must NEVER be patched (entrypoints, CRT/libs, stdio/prints, GUI frameworks)
PROTECTED_EXACT_NAMES = {
    "entry", "main", "_main", "wmain", "winmain", "wwinmain", "dllmain",
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    "puts", "putchar", "fputs", "fwrite", "fread", "fopen", "fclose",
    "malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset",
    "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat",
    "wndproc", "dialogproc", "defwindowproca", "defwindowprocw",
    "atexit", "_atexit", "exit", "_exit", "abort",
}

PROTECTED_NAME_PREFIXES = (
    "__mingw_", "___mingw_", "__crt", "_crt", "__security_", "___chkstk",
    "__tmaincrt", "maincrtstartup", "winmaincrtstartup", "_initterm",
    "__p_", "_acrt_", "mingw_", "std::", "qt_", "wx", "gtk_", "tk_", "tcl_",
    "imgui", "sdl_", "glfw", "createwindow", "showwindow", "updatewindow",
    "dispatchmessage", "translatemessage", "getmessage", "peekmessage",
    "messagebox", "drawtext", "paint", "render", "log_", "print_", "debug_print",
)


def is_protected_function(func_name: str, pseudo_c: str = "") -> Optional[str]:
    """
    Guardrail preventing surgical patches from ever hitting entry points,
    CRT/standard libraries, print/logging helpers, or GUI/window callbacks.
    Returns a human-readable reason if protected, else None.
    """
    low = (func_name or "").strip().lower()
    if not low:
        return "empty function name"
    if low in PROTECTED_EXACT_NAMES:
        return f"protected symbol '{func_name}' (entrypoint/stdio/CRT/GUI)"
    if any(low.startswith(pref) for pref in PROTECTED_NAME_PREFIXES):
        return f"protected library/GUI/print prefix '{func_name}'"
    # Protect pure GUI window message loops (DefWindowProc + TranslateMessage/DispatchMessage without malware APIs)
    if pseudo_c:
        pc_low = pseudo_c.lower()
        gui_markers = ("defwindowproc", "beginpaint", "endpaint", "translatemessage", "dispatchmessage")
        if sum(1 for m in gui_markers if m in pc_low) >= 2:
            return f"GUI message/paint loop detected in '{func_name}'"
    return None


# ---------------------------------------------------------------------------
# System Prompt for Senior Reverse Engineering Local AI
# ---------------------------------------------------------------------------

RE_SYSTEM_PROMPT = """You are an expert Windows Reverse Engineer and Malware Analyst auditing Ghidra decompiled pseudo-C from a Windows PE binary.
Your job is to identify malicious (or simulated-malicious) functions such as RAT beacons, C2 callbacks, keylogger hooks, process injection, payload droppers, ransomware/crypto routines, clipboard/screen spyware, unauthorized persistence, or anti-debug/anti-VM checks, and output a STRICT JSON patch plan to neutralize them surgically.

CRITICAL RULES:
1. Respond ONLY with valid JSON matching the exact schema below. Do NOT wrap in markdown or add extra commentary.
2. NEVER flag `main`, `entry`, `WinMain`, `DllMain`, or harmless helper/math/calculator functions. Only flag individual malicious helper functions.
3. Look closely at each function's pseudo-C body: if a function has ALREADY been patched (e.g., its entire body is just `return 0;` or `return;` or starts with `31c0c3` / `c3` with no active malicious code left), it is ALREADY NEUTRALIZED — do NOT flag it!
4. If NO active malicious helper functions remain in the pseudo-C, set "is_clean": true and "malicious_functions": [].
5. If the binary appears heavily packed/encrypted with no readable code, set "unpatchable_or_packed": true.
6. For each malicious function, copy its EXACT "function_name", "va", and "file_offset" from the input metadata.
7. Choose the safest surgical "patch_strategy":
   - "RET_ZERO": writes `31 C0 C3` (xor eax, eax; ret) at function entry — best for neutralizing malicious helper functions returning int/BOOL/HANDLE.
   - "RET_EARLY": writes `C3` (ret) at function entry — best for void functions.
   - "RET_ONE": writes `B8 01 00 00 00 C3` (mov eax, 1; ret) — best when caller expects truthy success.
   - "NOP_SLED": writes `0x90` bytes (specify "length" between 1 and 32) at an exact offset.
   - "FLIP_JUMP": flips a conditional jump (`JZ` <-> `JNZ`) at an exact jump instruction offset.

REQUIRED JSON SCHEMA:
{
  "is_clean": false,
  "unpatchable_or_packed": false,
  "threat_summary": "Concise summary of findings in this pass.",
  "malicious_functions": [
    {
      "function_name": "FUN_00401200",
      "va": "0x401200",
      "file_offset": "0x600",
      "category": "Keylogger / C2 / Injection / Persistence / Anti-VM / Dropper / Ransomware / Spyware",
      "reason": "Why this function is malicious.",
      "patch_strategy": "RET_ZERO",
      "length": 3
    }
  ]
}
"""


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class PassAuditReport:
    pass_number: int
    status: str  # "PATCHED", "CLEAN", "UNPATCHABLE", "NO_VALID_PATCHES", "ERROR"
    threat_summary: str
    is_clean: bool
    unpatchable_or_packed: bool
    functions_analyzed: int
    malicious_findings: List[Dict[str, Any]] = field(default_factory=list)
    applied_patches: List[PatchRecord] = field(default_factory=list)
    decompiled_preview: str = ""
    raw_ai_response: str = ""


@dataclass
class DisinfectionResult:
    target_path: str
    final_status: str  # "CLEAN", "QUARANTINED_UNPATCHABLE", "QUARANTINED_MAX_PASSES", "ERROR"
    passes_completed: int
    final_patched_path: str = ""
    quarantine_id: str = ""
    all_patches: List[PatchRecord] = field(default_factory=list)
    pass_reports: List[PassAuditReport] = field(default_factory=list)
    summary: str = ""


# ---------------------------------------------------------------------------
# Localhost Validation & JSON Parsing Helpers
# ---------------------------------------------------------------------------

def validate_local_endpoint(url: str) -> str:
    """Strictly enforce local-only endpoints (100% offline / zero cloud APIs)."""
    cleaned = url.strip().rstrip("/")
    parsed = urlparse(cleaned)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in ("http", "https") or host not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError(
            f"Blocked non-local LLM endpoint '{url}'. GhidraGuard is 100% local/offline and only "
            f"permits localhost / 127.0.0.1 endpoints."
        )
    return cleaned


def extract_json_object(text: str) -> Dict[str, Any]:
    """Robustly parse JSON from local LLM output even if wrapped in markdown fences."""
    cleaned = text.strip()
    # Strip markdown fences if present
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL | re.IGNORECASE)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    # Fallback: locate outermost {...}
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        candidate = cleaned[start : end + 1]
        obj = json.loads(candidate)
        if isinstance(obj, dict):
            return obj

    raise ValueError("Local AI response did not contain a valid JSON object.")


def _parse_int_hex(val: Any, default: int = -1) -> int:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return default
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s, 0)
        except ValueError:
            try:
                return int(s, 16)
            except ValueError:
                return default
    return default


# ---------------------------------------------------------------------------
# Local LLM Client (Ollama & llama.cpp OpenAI-compatible)
# ---------------------------------------------------------------------------

class LocalLLMClient:
    """Client for local Ollama (localhost:11434) or OpenAI-compatible llama.cpp server."""

    def __init__(
        self,
        backend: str = "ollama",  # "ollama" or "llamacpp"
        base_url: str = "http://localhost:11434",
        model: str = "",
        timeout: int = 180,
    ):
        self.backend = backend.lower().strip()
        self.base_url = validate_local_endpoint(base_url)
        self.model = model
        self.timeout = timeout

    def list_models(self) -> List[str]:
        """Discover available local models via Ollama /api/tags or llama.cpp /v1/models."""
        if self.backend == "ollama":
            resp = requests.get(f"{self.base_url}/api/tags", timeout=8)
            resp.raise_for_status()
            data = resp.json()
            models = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
            return sorted(models)
        else:
            resp = requests.get(f"{self.base_url}/v1/models", timeout=8)
            resp.raise_for_status()
            data = resp.json()
            models = [m.get("id", "") for m in data.get("data", []) if m.get("id")]
            return sorted(models)

    def pull_model(
        self,
        model_name: str = DEFAULT_AUTO_MODEL,
        log_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Automatically pull a compact local model (< 4GB) into local Ollama."""
        log = log_callback or (lambda msg: None)
        if self.backend != "ollama":
            raise RuntimeError("Automatic model pull is supported on local Ollama (http://localhost:11434).")

        log(f"[AI] Auto-installing lightweight local model '{model_name}' (~1.9 GB) via Ollama...")
        last_pct = -1
        with requests.post(
            f"{self.base_url}/api/pull",
            json={"name": model_name, "stream": True},
            stream=True,
            timeout=900,
        ) as resp:
            resp.raise_for_status()
            for raw_line in resp.iter_lines(decode_unicode=True):
                if not raw_line:
                    continue
                try:
                    ev = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                if "error" in ev:
                    raise RuntimeError(f"Ollama pull error: {ev['error']}")
                status = str(ev.get("status", ""))
                total = int(ev.get("total", 0) or 0)
                completed = int(ev.get("completed", 0) or 0)
                if total > 0:
                    pct = int((completed * 100) / total)
                    if pct > last_pct and (pct >= last_pct + 10 or pct == 100):
                        last_pct = pct
                        mb_done = completed / (1024 * 1024)
                        mb_tot = total / (1024 * 1024)
                        log(f"[AI] Pulling {model_name}: {pct}% ({mb_done:.0f}/{mb_tot:.0f} MB)")
                elif status in ("verifying sha256 digest", "writing manifest", "success"):
                    log(f"[AI] Pulling {model_name}: {status}")

        self.model = model_name
        log(f"[AI] Local model '{model_name}' is installed and ready!")
        return model_name

    def ensure_model_ready(
        self,
        default_model: str = DEFAULT_AUTO_MODEL,
        log_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Ensure a local model is selected; auto-pull default compact model if Ollama has none."""
        log = log_callback or (lambda msg: None)
        models = self.list_models()
        if self.model and self.model in models:
            return self.model
        if models:
            self.model = models[0]
            return self.model
        if self.backend == "ollama":
            return self.pull_model(default_model, log_callback=log)
        raise RuntimeError(
            f"No local models found at {self.base_url}. Start your local llama.cpp server with a model."
        )

    def query_json(self, system_prompt: str, user_prompt: str) -> str:
        """Send an audit prompt to the local LLM and return raw text response."""
        if not self.model:
            self.ensure_model_ready()

        if self.backend == "ollama":
            payload = {
                "model": self.model,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.1, "num_ctx": 16384},
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            }
            resp = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return str(data.get("message", {}).get("content", ""))
        else:
            payload = {
                "model": self.model,
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            }
            resp = requests.post(
                f"{self.base_url}/v1/chat/completions",
                json=payload,
                timeout=self.timeout,
            )
            if resp.status_code == 400:
                # Some llama.cpp builds reject response_format; retry without it
                payload.pop("response_format", None)
                resp = requests.post(
                    f"{self.base_url}/v1/chat/completions",
                    json=payload,
                    timeout=self.timeout,
                )
            resp.raise_for_status()
            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                raise RuntimeError("llama.cpp server returned empty choices.")
            return str(choices[0].get("message", {}).get("content", ""))


# ---------------------------------------------------------------------------
# Multi-Pass Iterative AI Auditor & Patching Pipeline
# ---------------------------------------------------------------------------

class AIAuditorPipeline:
    """
    Executes the iterative Decompile -> Local AI Audit -> Binary Patch -> Re-Verify
    loop (max 5 passes) with automatic Quarantine fallback if unpatchable or packed.
    """

    def __init__(
        self,
        ghidra: GhidraEngine,
        llm: LocalLLMClient,
        patcher: BinaryPatcher,
        quarantine: QuarantineManager,
        max_passes: int = 5,
        log_callback: Optional[Callable[[str], None]] = None,
    ):
        self.ghidra = ghidra
        self.llm = llm
        self.patcher = patcher
        self.quarantine = quarantine
        self.max_passes = max(1, min(5, max_passes))
        self._log = log_callback or (lambda msg: None)
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def _build_audit_prompt(
        self,
        analysis: GhidraAnalysisResult,
        pass_num: int,
        prior_patches: List[PatchRecord],
    ) -> str:
        """Build structured reverse-engineering context for the local LLM."""
        lines: List[str] = [
            f"=== AUDIT PASS {pass_num} OF {self.max_passes} ===",
            f"Binary: {analysis.program_name}",
            f"Architecture: {analysis.arch} ({analysis.pointer_size * 8}-bit) | ImageBase: {hex(analysis.image_base)}",
            f"Suspicious Imports ({len(analysis.suspicious_imports)}): {', '.join(analysis.suspicious_imports) or 'None'}",
        ]

        if analysis.interesting_strings:
            lines.append("\n--- Interesting Strings & XREFs ---")
            for st in analysis.interesting_strings[:40]:
                xrefs = ", ".join(st.get("xrefs", [])[:5]) or "none"
                lines.append(f"  [{st.get('va')}] {st.get('value')!r} (xrefs: {xrefs})")

        if prior_patches:
            lines.append("\n--- Patches Already Applied in Earlier Passes ---")
            for p in prior_patches:
                lines.append(
                    f"  Pass {p.pass_number}: {p.function_name} @ VA={p.va} Offset={p.file_offset} "
                    f"({p.strategy}: {p.before_hex} -> {p.after_hex}) — {p.reason}"
                )

        lines.append(f"\n--- Decompiled Functions ({len(analysis.functions)}) ---")
        char_budget = 26000
        used = 0
        for fn in analysis.functions:
            block = (
                f"\nFUNCTION: {fn.name}\n"
                f"  VA: {hex(fn.va)} | RVA: {hex(fn.rva)} | FileOffset: {hex(fn.file_offset) if fn.file_offset >= 0 else 'UNKNOWN'} "
                f"| Size: {fn.size}B | FirstBytes: {fn.first_bytes}\n"
                f"  Triggers: {', '.join(fn.triggers)}\n"
                f"```c\n{fn.pseudo_c}\n```\n"
            )
            if used + len(block) > char_budget:
                lines.append("\n[Additional functions omitted to fit local LLM context window]")
                break
            lines.append(block)
            used += len(block)

        lines.append(
            "\nAnalyze the above decompiled pseudo-C and return ONLY the required JSON object."
        )
        return "\n".join(lines)

    def _build_preview_text(self, analysis: GhidraAnalysisResult) -> str:
        parts: List[str] = []
        for fn in analysis.functions[:8]:
            parts.append(
                f"// === {fn.name} | VA={hex(fn.va)} | FileOffset={hex(fn.file_offset) if fn.file_offset >= 0 else 'N/A'} ===\n"
                f"{fn.pseudo_c}\n"
            )
        return "\n".join(parts)

    def run_disinfection_pipeline(
        self,
        target_path: str,
        auto_quarantine_on_failure: bool = True,
        on_pass_complete: Optional[Callable[[PassAuditReport], None]] = None,
    ) -> DisinfectionResult:
        """
        Execute the full iterative Ghidra -> Local AI -> Binary Patch -> Re-Verify loop.
        """
        self._cancel = False
        if not os.path.isfile(target_path):
            raise FileNotFoundError(f"Target binary not found: {target_path}")

        work_dir = Path(
            os.environ.get("LOCALAPPDATA", tempfile.gettempdir()),
            "GhidraGuard",
            "patch_sessions",
            f"{Path(target_path).stem}_{int(time.time())}",
        )
        work_dir.mkdir(parents=True, exist_ok=True)

        current_bin = work_dir / f"pass0_{Path(target_path).name}"
        shutil.copy2(target_path, current_bin)

        all_patches: List[PatchRecord] = []
        pass_reports: List[PassAuditReport] = []

        # Ensure a local model is available (auto-installs compact <4GB model on Ollama if empty)
        self.llm.ensure_model_ready(log_callback=self._log)

        self._log(
            f"[PIPELINE] Starting Deep Decompile & Patch on '{target_path}' "
            f"(model={self.llm.model}, max_passes={self.max_passes})"
        )

        for pass_num in range(1, self.max_passes + 1):
            if self._cancel:
                self._log("[PIPELINE] Cancelled by user.")
                return DisinfectionResult(
                    target_path=target_path,
                    final_status="CANCELLED",
                    passes_completed=pass_num - 1,
                    all_patches=all_patches,
                    pass_reports=pass_reports,
                    summary="Disinfection pipeline cancelled by user.",
                )

            self._log(f"[PIPELINE] === Pass {pass_num}/{self.max_passes} ===")

            # Step 1: Headless Ghidra Decompilation
            analysis = self.ghidra.analyze_binary(str(current_bin), pass_index=pass_num)
            preview_text = self._build_preview_text(analysis)

            # Build lookup map from Ghidra functions to reliably resolve offsets
            fn_by_name = {f.name.lower(): f for f in analysis.functions}
            fn_by_va = {f.va: f for f in analysis.functions}

            # Step 2: Query Local LLM
            self._log(f"[AI] Pass {pass_num}: Sending {len(analysis.functions)} decompiled function(s) to local model '{self.llm.model}'...")
            prompt = self._build_audit_prompt(analysis, pass_num, all_patches)
            raw_resp = self.llm.query_json(RE_SYSTEM_PROMPT, prompt)
            parsed = extract_json_object(raw_resp)

            is_clean = bool(parsed.get("is_clean", False))
            unpatchable = bool(parsed.get("unpatchable_or_packed", False))
            threat_summary = str(parsed.get("threat_summary", "No summary provided."))
            mal_funcs = parsed.get("malicious_functions") or []
            if not isinstance(mal_funcs, list):
                mal_funcs = []

            # Filter out entrypoints (main/entry) and functions already neutralized in prior passes
            patched_offsets = {p.file_offset.lower() for p in all_patches}
            patched_names = {p.function_name.lower() for p in all_patches}
            filtered_mal: List[Dict[str, Any]] = []
            for item in mal_funcs:
                if not isinstance(item, dict):
                    continue
                fname = str(item.get("function_name", "")).strip()
                matched_fn = fn_by_name.get(fname.lower()) or fn_by_va.get(_parse_int_hex(item.get("va"), 0))
                prot_reason = is_protected_function(fname, matched_fn.pseudo_c if matched_fn else "")
                if prot_reason:
                    self._log(f"[GUARD] Blocked unsafe patch on '{fname}': {prot_reason}")
                    continue
                fo_parsed = _parse_int_hex(item.get("file_offset"), -1)
                fo_hex = hex(fo_parsed).lower() if fo_parsed >= 0 else ""
                if fname.lower() in patched_names or (fo_hex and fo_hex in patched_offsets):
                    self._log(f"[AI] Function '{fname}' was already neutralized in an earlier pass; skipping.")
                    continue
                if matched_fn:
                    fb = matched_fn.first_bytes.lower()
                    if fb.startswith(("31c0c3", "c3")) or hex(matched_fn.file_offset).lower() in patched_offsets:
                        self._log(f"[AI] Function '{fname}' is already neutralized ({fb[:6]}); skipping.")
                        continue
                filtered_mal.append(item)
            mal_funcs = filtered_mal

            self._log(
                f"[AI] Pass {pass_num} Verdict: is_clean={is_clean}, "
                f"unpatchable={unpatchable}, active_malicious_functions={len(mal_funcs)}"
            )

            # Check Clean Condition
            if is_clean or len(mal_funcs) == 0:
                report = PassAuditReport(
                    pass_number=pass_num,
                    status="CLEAN",
                    threat_summary=threat_summary,
                    is_clean=True,
                    unpatchable_or_packed=False,
                    functions_analyzed=len(analysis.functions),
                    malicious_findings=[],
                    applied_patches=[],
                    decompiled_preview=preview_text,
                    raw_ai_response=raw_resp,
                )
                pass_reports.append(report)
                if on_pass_complete:
                    on_pass_complete(report)

                self._log(
                    f"[PIPELINE] SUCCESS on Pass {pass_num}! Local AI confirmed 0 malicious behaviors remain."
                )
                return DisinfectionResult(
                    target_path=target_path,
                    final_status="CLEAN",
                    passes_completed=pass_num,
                    final_patched_path=str(current_bin),
                    all_patches=all_patches,
                    pass_reports=pass_reports,
                    summary=f"Disinfected cleanly in {pass_num} pass(es) with {len(all_patches)} surgical patch(es). {threat_summary}",
                )

            # Check Unpatchable / Packed Condition
            if unpatchable:
                report = PassAuditReport(
                    pass_number=pass_num,
                    status="UNPATCHABLE",
                    threat_summary=threat_summary,
                    is_clean=False,
                    unpatchable_or_packed=True,
                    functions_analyzed=len(analysis.functions),
                    malicious_findings=mal_funcs,
                    applied_patches=[],
                    decompiled_preview=preview_text,
                    raw_ai_response=raw_resp,
                )
                pass_reports.append(report)
                if on_pass_complete:
                    on_pass_complete(report)

                qid = ""
                if auto_quarantine_on_failure and os.path.isfile(target_path):
                    qentry = self.quarantine.quarantine_file(
                        target_path, reason=f"Auto-quarantined (unpatchable/packed): {threat_summary[:120]}"
                    )
                    qid = qentry.entry_id

                return DisinfectionResult(
                    target_path=target_path,
                    final_status="QUARANTINED_UNPATCHABLE",
                    passes_completed=pass_num,
                    quarantine_id=qid,
                    all_patches=all_patches,
                    pass_reports=pass_reports,
                    summary=f"Binary flagged as packed/unpatchable on Pass {pass_num}; auto-quarantined. {threat_summary}",
                )

            # Step 3: Translate AI findings into verified PatchInstructions
            instructions: List[PatchInstruction] = []
            for item in mal_funcs:
                if not isinstance(item, dict):
                    continue
                fname = str(item.get("function_name", "unknown"))
                va = _parse_int_hex(item.get("va"), default=0)
                fo = _parse_int_hex(item.get("file_offset"), default=-1)

                # Cross-check against Ghidra metadata if AI missed/mangled offset
                matched_fn = fn_by_name.get(fname.lower()) or fn_by_va.get(va)
                if matched_fn:
                    if va == 0:
                        va = matched_fn.va
                    if fo < 0 and matched_fn.file_offset >= 0:
                        fo = matched_fn.file_offset

                instructions.append(
                    PatchInstruction(
                        function_name=fname,
                        strategy=str(item.get("patch_strategy", "RET_ZERO")),
                        va=va,
                        file_offset=fo,
                        length=int(item.get("length", 3) or 3),
                        custom_hex=str(item.get("custom_hex", "")),
                        reason=str(item.get("reason", "Malicious behavior")),
                        category=str(item.get("category", "Malware")),
                    )
                )

            next_bin = work_dir / f"pass{pass_num}_{Path(target_path).name}"
            applied = self.patcher.apply_patches(
                str(current_bin), str(next_bin), instructions, pass_number=pass_num
            )
            all_patches.extend(applied)

            status = "PATCHED" if applied else "NO_VALID_PATCHES"
            report = PassAuditReport(
                pass_number=pass_num,
                status=status,
                threat_summary=threat_summary,
                is_clean=False,
                unpatchable_or_packed=False,
                functions_analyzed=len(analysis.functions),
                malicious_findings=mal_funcs,
                applied_patches=applied,
                decompiled_preview=preview_text,
                raw_ai_response=raw_resp,
            )
            pass_reports.append(report)
            if on_pass_complete:
                on_pass_complete(report)

            if not applied:
                self._log(
                    f"[PIPELINE] Pass {pass_num} yielded 0 applicable byte patches; escalating to Quarantine."
                )
                qid = ""
                if auto_quarantine_on_failure and os.path.isfile(target_path):
                    qentry = self.quarantine.quarantine_file(
                        target_path, reason="Auto-quarantined (no valid surgical patches could be applied)"
                    )
                    qid = qentry.entry_id
                return DisinfectionResult(
                    target_path=target_path,
                    final_status="QUARANTINED_UNPATCHABLE",
                    passes_completed=pass_num,
                    quarantine_id=qid,
                    all_patches=all_patches,
                    pass_reports=pass_reports,
                    summary="Could not apply safe byte-level patches; file automatically quarantined.",
                )

            current_bin = next_bin

        # Safety limit reached (5 passes) without achieving clean verdict -> Auto-Quarantine
        self._log(
            f"[PIPELINE] Max pass safety limit ({self.max_passes}) reached with residual threats. Auto-quarantining."
        )
        qid = ""
        if auto_quarantine_on_failure and os.path.isfile(target_path):
            qentry = self.quarantine.quarantine_file(
                target_path, reason=f"Auto-quarantined after {self.max_passes} passes (residual threats)"
            )
            qid = qentry.entry_id

        return DisinfectionResult(
            target_path=target_path,
            final_status="QUARANTINED_MAX_PASSES",
            passes_completed=self.max_passes,
            quarantine_id=qid,
            all_patches=all_patches,
            pass_reports=pass_reports,
            summary=f"Hit safety limit of {self.max_passes} passes with residual threats; original file quarantined.",
        )
