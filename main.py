"""
GhidraGuard - Local Offline Windows Security, Ghidra Decompiler & AI Binary Patching Suite
Dark-mode glassmorphic desktop UI built with CustomTkinter.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import tempfile
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any, Dict, List, Optional

import customtkinter as ctk
import psutil

from ai_auditor import (
    AIAuditorPipeline,
    DEFAULT_AUTO_MODEL,
    DirectLocalAIClient,
    DisinfectionResult,
    PassAuditReport,
)
from auto_setup import (
    check_environment,
    discover_all_ghidra_paths,
    ensure_ghidra,
    run_full_auto_setup,
)
from binary_patcher import BinaryPatcher, PatchRecord, QuarantineEntry, QuarantineManager
from cuda_engine import (
    CUDAFlashAttentionEngine,
    DEFAULT_LOCAL_MODEL,
    GPUHardwareInfo,
    detect_cuda_hardware,
    run_cuda_flash_benchmark,
)
from ghidra_engine import GhidraEngine, discover_ghidra_headless
from scanner import (
    NetworkConnectionInfo,
    SystemScanner,
    ThreatFinding,
    analyze_pe_file,
    get_active_connections,
)


# ---------------------------------------------------------------------------
# Glassmorphic Dark Theme Palette
# ---------------------------------------------------------------------------

BG_ROOT = "#090D16"
BG_SIDEBAR = "#0E1422"
BG_CARD = "#121A2B"
BG_CARD_ALT = "#162033"
BG_INPUT = "#0C1220"
BORDER_GLASS = "#22314D"
BORDER_ACCENT = "#38BDF8"
ACCENT_CYAN = "#0EA5E9"
ACCENT_CYAN_HOVER = "#0284C7"
ACCENT_PURPLE = "#8B5CF6"
ACCENT_GREEN = "#10B981"
ACCENT_RED = "#EF4444"
ACCENT_AMBER = "#F59E0B"
TEXT_PRIMARY = "#F1F5F9"
TEXT_SECONDARY = "#94A3B8"
TEXT_MUTED = "#64748B"

SEVERITY_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH": "#F97316",
    "MEDIUM": "#EAB308",
    "LOW": "#22C55E",
}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class SettingsStore:
    """Persists local GhidraGuard settings in %LOCALAPPDATA%\\GhidraGuard\\settings.json."""

    def __init__(self) -> None:
        base = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "GhidraGuard"
        base.mkdir(parents=True, exist_ok=True)
        self.path = base / "settings.json"
        self.data: Dict[str, Any] = {
            "ghidra_headless_path": "",
            "llm_model": DEFAULT_LOCAL_MODEL,
            "use_cuda": True,
            "flash_attention": True,
            "cuda_precision": "bf16",
            "num_ctx": 32768,
            "max_passes": 5,
            "ghidra_timeout": 300,
            "auto_quarantine": True,
        }
        self.load()

    def load(self) -> None:
        if self.path.is_file():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.data.update(loaded)
            except Exception:
                pass

    def save(self) -> None:
        try:
            self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main Application Window
# ---------------------------------------------------------------------------

class GhidraGuardApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("GhidraGuard v0.2.0-beta.1 — CUDA + Flash Attention Local RE & AI Binary Patcher")
        self.geometry("1360x860")
        self.minsize(1120, 720)
        self.configure(fg_color=BG_ROOT)

        self.settings = SettingsStore()
        self.gpu_info: GPUHardwareInfo = detect_cuda_hardware()
        self.quarantine_mgr = QuarantineManager(log_callback=self.log)
        self.scanner = SystemScanner(log_callback=self.log)
        self.patcher = BinaryPatcher(log_callback=self.log)

        # Auto-discover Ghidra (C:\ and %LOCALAPPDATA%\GhidraGuard\tools) on first launch
        if not self.settings.data.get("ghidra_headless_path"):
            discovered = discover_all_ghidra_paths()
            if discovered:
                self.settings.data["ghidra_headless_path"] = discovered[0]
                self.settings.save()

        self.ghidra_engine = GhidraEngine(
            headless_path=self.settings.data.get("ghidra_headless_path", ""),
            timeout_seconds=int(self.settings.data.get("ghidra_timeout", 300)),
            log_callback=self.log,
        )

        # Runtime state
        self.findings: List[ThreatFinding] = []
        self.active_target_path: str = ""
        self.active_pipeline: Optional[AIAuditorPipeline] = None
        self.direct_ai_client: Optional[DirectLocalAIClient] = None
        self.last_result: Optional[DisinfectionResult] = None
        self.pass_reports: List[PassAuditReport] = []
        self.net_auto_refresh = False
        self._net_timer_id: Optional[str] = None
        self._net_loading = False
        self._scanning = False
        self._patching = False

        self._build_layout()
        self._show_view("scanner")
        self.log("[SYSTEM] GhidraGuard v0.2.0 initialized (100% Local / Offline Mode).")
        if self.gpu_info.cuda_available:
            self.log(
                f"[CUDA] Detected {self.gpu_info.gpu_name} ({self.gpu_info.vram_total_gb} GB VRAM, "
                f"CUDA {self.gpu_info.cuda_version or 'N/A'}) | "
                f"FlashAttn={'Ready' if self.gpu_info.supports_flash_attention else 'Unavailable'} | "
                f"Backend={self.gpu_info.recommended_attn_backend}"
            )
        else:
            self.log("[CUDA] No NVIDIA CUDA GPU detected — running in CPU fallback mode.")
        if self.ghidra_engine.is_available():
            self.log(f"[GHIDRA] Detected: {self.ghidra_engine.headless_path}")
        else:
            self.log("[GHIDRA] analyzeHeadless.bat not auto-detected on C:\\ — configure in Settings.")
        self._refresh_models_async(silent=True)

    # -----------------------------------------------------------------------
    # Root Layout: Sidebar + Main Workspace + Persistent Terminal Console
    # -----------------------------------------------------------------------

    def _build_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)

        # Sidebar
        self.sidebar = ctk.CTkFrame(
            self, width=230, fg_color=BG_SIDEBAR, corner_radius=0, border_width=1, border_color=BORDER_GLASS
        )
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar.grid_propagate(False)

        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=18, pady=(20, 14))
        ctk.CTkLabel(
            brand, text="GHIDRAGUARD", font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color=BORDER_ACCENT,
        ).pack(anchor="w")
        ctk.CTkLabel(
            brand, text="Offline RE & AI Patch Suite", font=ctk.CTkFont(size=11), text_color=TEXT_MUTED
        ).pack(anchor="w")

        # Navigation buttons
        self.nav_buttons: Dict[str, ctk.CTkButton] = {}
        nav_items = [
            ("scanner", "Threat Scanner"),
            ("patch_lab", "AI Decompile & Patch Lab"),
            ("network", "Network Monitor"),
            ("repair", "System Repair & Vault"),
            ("settings", "Settings & Engines"),
        ]
        for key, label in nav_items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=label,
                height=40,
                anchor="w",
                corner_radius=10,
                fg_color="transparent",
                hover_color=BG_CARD_ALT,
                text_color=TEXT_PRIMARY,
                font=ctk.CTkFont(size=13, weight="bold"),
                command=lambda k=key: self._show_view(k),
            )
            btn.pack(fill="x", padx=12, pady=4)
            self.nav_buttons[key] = btn

        # Status Cards in Sidebar Footer
        status_box = ctk.CTkFrame(
            self.sidebar, fg_color=BG_CARD, corner_radius=12, border_width=1, border_color=BORDER_GLASS
        )
        status_box.pack(side="bottom", fill="x", padx=12, pady=16)

        admin_ok = is_admin()
        ctk.CTkLabel(
            status_box,
            text=f"Privileges: {'Administrator' if admin_ok else 'Standard User'}",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=ACCENT_GREEN if admin_ok else ACCENT_AMBER,
        ).pack(anchor="w", padx=12, pady=(10, 2))

        self.lbl_ghidra_status = ctk.CTkLabel(
            status_box,
            text=f"Ghidra: {'Ready' if self.ghidra_engine.is_available() else 'Not Found'}",
            font=ctk.CTkFont(size=11),
            text_color=ACCENT_GREEN if self.ghidra_engine.is_available() else ACCENT_RED,
        )
        self.lbl_ghidra_status.pack(anchor="w", padx=12, pady=2)

        self.lbl_ai_status = ctk.CTkLabel(
            status_box,
            text="Local AI: Checking...",
            font=ctk.CTkFont(size=11),
            text_color=TEXT_SECONDARY,
        )
        self.lbl_ai_status.pack(anchor="w", padx=12, pady=2)

        self.lbl_cuda_status = ctk.CTkLabel(
            status_box,
            text=self.gpu_info.short_badge(),
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=BORDER_ACCENT if self.gpu_info.cuda_available else TEXT_MUTED,
        )
        self.lbl_cuda_status.pack(anchor="w", padx=12, pady=(2, 10))

        # Main Content Container
        self.content_container = ctk.CTkFrame(self, fg_color=BG_ROOT, corner_radius=0)
        self.content_container.grid(row=0, column=1, sticky="nsew", padx=16, pady=(14, 8))
        self.content_container.grid_columnconfigure(0, weight=1)
        self.content_container.grid_rowconfigure(0, weight=1)

        # Persistent Real-Time Terminal Log Panel
        log_frame = ctk.CTkFrame(
            self, fg_color=BG_CARD, corner_radius=12, border_width=1, border_color=BORDER_GLASS, height=175
        )
        log_frame.grid(row=1, column=1, sticky="ew", padx=16, pady=(0, 14))
        log_frame.grid_propagate(False)
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(1, weight=1)

        log_hdr = ctk.CTkFrame(log_frame, fg_color="transparent", height=28)
        log_hdr.grid(row=0, column=0, sticky="ew", padx=12, pady=(6, 2))
        ctk.CTkLabel(
            log_hdr,
            text="REAL-TIME TERMINAL LOG",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=BORDER_ACCENT,
        ).pack(side="left")
        ctk.CTkButton(
            log_hdr,
            text="Clear",
            width=56,
            height=22,
            corner_radius=6,
            fg_color=BG_CARD_ALT,
            hover_color=BORDER_GLASS,
            font=ctk.CTkFont(size=11),
            command=self._clear_log,
        ).pack(side="right")

        self.log_box = ctk.CTkTextbox(
            log_frame,
            fg_color=BG_INPUT,
            text_color="#CBD5E1",
            font=ctk.CTkFont(family="Consolas", size=11),
            corner_radius=8,
            wrap="word",
        )
        self.log_box.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.log_box.configure(state="disabled")

        # Build all 5 views
        self.views: Dict[str, ctk.CTkFrame] = {}
        self.views["scanner"] = self._build_scanner_view()
        self.views["patch_lab"] = self._build_patch_lab_view()
        self.views["network"] = self._build_network_view()
        self.views["repair"] = self._build_repair_view()
        self.views["settings"] = self._build_settings_view()

    def _show_view(self, key: str) -> None:
        for k, frame in self.views.items():
            if k == key:
                frame.grid(row=0, column=0, sticky="nsew")
                self.nav_buttons[k].configure(fg_color=BG_CARD_ALT, text_color=BORDER_ACCENT)
            else:
                frame.grid_forget()
                self.nav_buttons[k].configure(fg_color="transparent", text_color=TEXT_PRIMARY)
        if key == "repair":
            self._refresh_quarantine_list()
        elif key == "network":
            self._refresh_network_connections()

    # -----------------------------------------------------------------------
    # Thread-Safe Logging
    # -----------------------------------------------------------------------

    def log(self, message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] {message}\n"

        def _append() -> None:
            self.log_box.configure(state="normal")
            self.log_box.insert("end", line)
            self.log_box.see("end")
            self.log_box.configure(state="disabled")

        self.after(0, _append)

    def _clear_log(self) -> None:
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    # -----------------------------------------------------------------------
    # VIEW 1: Threat Scanner
    # -----------------------------------------------------------------------

    def _build_scanner_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        # Header & Controls Card
        hdr = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=14, border_width=1, border_color=BORDER_GLASS)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        top_row = ctk.CTkFrame(hdr, fg_color="transparent")
        top_row.pack(fill="x", padx=16, pady=(14, 8))
        ctk.CTkLabel(
            top_row,
            text="System, Process & Persistence Scanner",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        self.btn_scan = ctk.CTkButton(
            top_row,
            text="Run Full System Scan",
            fg_color=ACCENT_CYAN,
            hover_color=ACCENT_CYAN_HOVER,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._start_full_scan,
        )
        self.btn_scan.pack(side="right", padx=(8, 0))

        ctk.CTkButton(
            top_row,
            text="Inspect Manual PE (.exe/.dll)",
            fg_color=BG_CARD_ALT,
            hover_color=BORDER_GLASS,
            border_width=1,
            border_color=BORDER_GLASS,
            command=self._inspect_manual_file,
        ).pack(side="right", padx=6)

        self.btn_cancel_scan = ctk.CTkButton(
            top_row,
            text="Cancel",
            width=80,
            fg_color="#334155",
            hover_color="#475569",
            state="disabled",
            command=self._cancel_scan,
        )
        self.btn_cancel_scan.pack(side="right", padx=6)

        # Options + Progress Row
        opt_row = ctk.CTkFrame(hdr, fg_color="transparent")
        opt_row.pack(fill="x", padx=16, pady=(0, 12))

        self.var_scan_dlls = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            opt_row,
            text="Scan loaded user-space DLLs",
            variable=self.var_scan_dlls,
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 18))

        ctk.CTkLabel(opt_row, text="Min Risk Score:", font=ctk.CTkFont(size=12), text_color=TEXT_SECONDARY).pack(
            side="left", padx=(0, 6)
        )
        self.var_min_score = tk.IntVar(value=25)
        self.lbl_min_score = ctk.CTkLabel(opt_row, text="25", width=28, font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_min_score.pack(side="left")
        ctk.CTkSlider(
            opt_row,
            from_=10,
            to=70,
            number_of_steps=12,
            width=140,
            variable=self.var_min_score,
            command=lambda v: self.lbl_min_score.configure(text=str(int(v))),
        ).pack(side="left", padx=(4, 18))

        self.lbl_scan_status = ctk.CTkLabel(
            opt_row, text="Ready to scan processes, DLLs, HKCU/HKLM Run keys & Scheduled Tasks.",
            font=ctk.CTkFont(size=12), text_color=TEXT_MUTED,
        )
        self.lbl_scan_status.pack(side="right")

        self.scan_progress = ctk.CTkProgressBar(frame, height=6, progress_color=BORDER_ACCENT, fg_color=BG_CARD)
        self.scan_progress.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        self.scan_progress.set(0)

        # Results Scrollable Container
        self.scanner_results = ctk.CTkScrollableFrame(
            frame, fg_color=BG_CARD, corner_radius=14, border_width=1, border_color=BORDER_GLASS
        )
        self.scanner_results.grid(row=2, column=0, sticky="nsew")
        ctk.CTkLabel(
            self.scanner_results,
            text="No scan results yet. Click 'Run Full System Scan' or 'Inspect Manual PE (.exe/.dll)'.",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(size=13),
        ).pack(pady=40)

        return frame

    def _start_full_scan(self) -> None:
        if self._scanning:
            return
        self._scanning = True
        self.btn_scan.configure(state="disabled")
        self.btn_cancel_scan.configure(state="normal")
        self.scan_progress.set(0.05)

        min_score = int(self.var_min_score.get())
        scan_dlls = bool(self.var_scan_dlls.get())

        def _worker() -> None:
            def _prog(val: float, text: str) -> None:
                self.after(0, lambda: (self.scan_progress.set(val), self.lbl_scan_status.configure(text=text)))

            results = self.scanner.run_full_scan(
                min_score=min_score, scan_dlls=scan_dlls, progress_callback=_prog
            )
            self.findings = results
            self.after(0, self._render_findings)
            self.after(0, self._finish_scan_ui)

        threading.Thread(target=_worker, daemon=True).start()

    def _cancel_scan(self) -> None:
        self.scanner.cancel()
        self.btn_cancel_scan.configure(state="disabled")

    def _finish_scan_ui(self) -> None:
        self._scanning = False
        self.btn_scan.configure(state="normal")
        self.btn_cancel_scan.configure(state="disabled")

    def _inspect_manual_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Windows PE Binary (.exe / .dll)",
            filetypes=[("Windows Binaries", "*.exe *.dll *.scr *.sys"), ("All Files", "*.*")],
        )
        if not path:
            return
        self.log(f"[SCAN] Running static PE heuristic analysis on: {path}")
        self.lbl_scan_status.configure(text=f"Analyzing {os.path.basename(path)}...")

        def _worker() -> None:
            finding = analyze_pe_file(path, source="Manual File")
            def _done() -> None:
                if finding is None:
                    self.lbl_scan_status.configure(text="Selected file is not a valid Windows PE binary.")
                    messagebox.showwarning("Invalid PE", "The selected file does not appear to be a valid Windows PE binary.")
                    return
                self.findings.insert(0, finding)
                self.lbl_scan_status.configure(text=f"Analyzed {finding.name} (Risk: {finding.risk_score} / {finding.severity})")
                self._render_findings()
            self.after(0, _done)

        threading.Thread(target=_worker, daemon=True).start()

    def _render_findings(self) -> None:
        for w in self.scanner_results.winfo_children():
            w.destroy()

        if not self.findings:
            ctk.CTkLabel(
                self.scanner_results,
                text="Clean! No suspicious binaries met the risk threshold.",
                text_color=ACCENT_GREEN,
                font=ctk.CTkFont(size=14, weight="bold"),
            ).pack(pady=40)
            return

        for f in self.findings:
            card = ctk.CTkFrame(
                self.scanner_results,
                fg_color=BG_CARD_ALT,
                corner_radius=10,
                border_width=1,
                border_color=BORDER_GLASS,
            )
            card.pack(fill="x", padx=8, pady=5)

            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=12, pady=(10, 4))

            sev_col = SEVERITY_COLORS.get(f.severity, TEXT_SECONDARY)
            ctk.CTkLabel(
                top,
                text=f" {f.severity} ({f.risk_score}) ",
                fg_color=sev_col,
                text_color="#090D16",
                corner_radius=6,
                font=ctk.CTkFont(size=11, weight="bold"),
            ).pack(side="left", padx=(0, 10))

            pid_txt = f" | PID {f.pid}" if f.pid else ""
            signed_txt = "Signed" if f.signed else "UNSIGNED"
            ctk.CTkLabel(
                top,
                text=f"{f.name}  [{f.source}{pid_txt} | {signed_txt} | Entropy {f.max_entropy}]",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=TEXT_PRIMARY,
            ).pack(side="left")

            # Action buttons
            ctk.CTkButton(
                top,
                text="Delete",
                width=68,
                height=28,
                fg_color="#7F1D1D",
                hover_color=ACCENT_RED,
                font=ctk.CTkFont(size=11, weight="bold"),
                command=lambda p=f.path: self._action_delete_finding(p),
            ).pack(side="right", padx=(6, 0))

            ctk.CTkButton(
                top,
                text="Quarantine",
                width=88,
                height=28,
                fg_color="#78350F",
                hover_color=ACCENT_AMBER,
                font=ctk.CTkFont(size=11, weight="bold"),
                command=lambda p=f.path: self._action_quarantine_finding(p),
            ).pack(side="right", padx=6)

            ctk.CTkButton(
                top,
                text="Deep Decompile & Patch",
                width=165,
                height=28,
                fg_color=ACCENT_PURPLE,
                hover_color="#7C3AED",
                font=ctk.CTkFont(size=11, weight="bold"),
                command=lambda p=f.path: self._open_in_patch_lab(p),
            ).pack(side="right", padx=6)

            ctk.CTkLabel(
                card,
                text=f.path + (f"   •   Persistence: {f.persistence_ref}" if f.persistence_ref else ""),
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=TEXT_SECONDARY,
                anchor="w",
            ).pack(fill="x", padx=12, pady=(0, 3))

            if f.indicators:
                ctk.CTkLabel(
                    card,
                    text="Indicators: " + "  |  ".join(f.indicators[:4]),
                    font=ctk.CTkFont(size=11),
                    text_color=TEXT_MUTED,
                    anchor="w",
                    wraplength=980,
                    justify="left",
                ).pack(fill="x", padx=12, pady=(0, 10))

    def _action_quarantine_finding(self, file_path: str) -> None:
        if not messagebox.askyesno("Confirm Quarantine", f"Quarantine and neutralize:\n{file_path}?"):
            return
        try:
            self.quarantine_mgr.quarantine_file(file_path, reason="Manual Quarantine from Scanner")
            self.findings = [x for x in self.findings if os.path.normpath(x.path).lower() != os.path.normpath(file_path).lower()]
            self._render_findings()
        except Exception as exc:
            messagebox.showerror("Quarantine Failed", str(exc))

    def _action_delete_finding(self, file_path: str) -> None:
        if not messagebox.askyesno(
            "Confirm Permanent Delete",
            f"PERMANENTLY delete this file from disk?\n{file_path}\n\nThis cannot be undone.",
        ):
            return
        try:
            self.quarantine_mgr.delete_file_permanently(file_path)
            self.findings = [x for x in self.findings if os.path.normpath(x.path).lower() != os.path.normpath(file_path).lower()]
            self._render_findings()
        except Exception as exc:
            messagebox.showerror("Delete Failed", str(exc))

    def _open_in_patch_lab(self, file_path: str) -> None:
        self.active_target_path = file_path
        self.lbl_patch_target.configure(text=file_path)
        self._show_view("patch_lab")

    # -----------------------------------------------------------------------
    # VIEW 2: AI Decompile & Patch Lab
    # -----------------------------------------------------------------------

    def _build_patch_lab_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Target & Controls Card
        ctrl = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=14, border_width=1, border_color=BORDER_GLASS)
        ctrl.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        row1 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=(14, 6))
        ctk.CTkLabel(
            row1,
            text="Iterative Ghidra Decompile & Local AI Patch Lab",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        self.btn_deploy_patch = ctk.CTkButton(
            row1,
            text="Deploy Patched Binary",
            fg_color=ACCENT_GREEN,
            hover_color="#059669",
            state="disabled",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._deploy_patched_binary,
        )
        self.btn_deploy_patch.pack(side="right", padx=(8, 0))

        self.btn_cancel_patch = ctk.CTkButton(
            row1,
            text="Stop",
            width=70,
            fg_color="#334155",
            hover_color="#475569",
            state="disabled",
            command=self._cancel_disinfection,
        )
        self.btn_cancel_patch.pack(side="right", padx=6)

        self.btn_start_patch = ctk.CTkButton(
            row1,
            text="Start Iterative Disinfection",
            fg_color=ACCENT_PURPLE,
            hover_color="#7C3AED",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._start_disinfection,
        )
        self.btn_start_patch.pack(side="right", padx=6)

        ctk.CTkButton(
            row1,
            text="Browse Binary...",
            width=120,
            fg_color=BG_CARD_ALT,
            hover_color=BORDER_GLASS,
            command=self._browse_patch_target,
        ).pack(side="right", padx=6)

        row2 = ctk.CTkFrame(ctrl, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=(0, 12))
        ctk.CTkLabel(row2, text="Target:", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT_SECONDARY).pack(
            side="left", padx=(0, 8)
        )
        self.lbl_patch_target = ctk.CTkLabel(
            row2,
            text="(No binary selected — choose from Scanner or Browse Binary)",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=BORDER_ACCENT,
        )
        self.lbl_patch_target.pack(side="left")

        self.lbl_patch_verdict = ctk.CTkLabel(
            row2, text="Idle", font=ctk.CTkFont(size=12, weight="bold"), text_color=TEXT_MUTED
        )
        self.lbl_patch_verdict.pack(side="right")

        # Split Workspace: Left = Pass-by-Pass AI Audit Viewer | Right = Binary Patch Diff Summary
        split = ctk.CTkFrame(frame, fg_color="transparent")
        split.grid(row=1, column=0, sticky="nsew")
        split.grid_columnconfigure(0, weight=3)
        split.grid_columnconfigure(1, weight=2)
        split.grid_rowconfigure(0, weight=1)

        # Left Panel: Pass-by-Pass AI Audit Viewer
        left_card = ctk.CTkFrame(split, fg_color=BG_CARD, corner_radius=14, border_width=1, border_color=BORDER_GLASS)
        left_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left_card.grid_columnconfigure(0, weight=1)
        left_card.grid_rowconfigure(1, weight=1)

        lhdr = ctk.CTkFrame(left_card, fg_color="transparent")
        lhdr.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 6))
        ctk.CTkLabel(
            lhdr,
            text="Pass-by-Pass Local AI Audit & Pseudo-C Viewer",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        self.pass_selector = ctk.CTkSegmentedButton(
            lhdr,
            values=["Pass 1"],
            command=self._on_select_pass_tab,
            selected_color=ACCENT_CYAN,
        )
        self.pass_selector.pack(side="right")

        self.audit_viewer = ctk.CTkTextbox(
            left_card,
            fg_color=BG_INPUT,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Consolas", size=11),
            corner_radius=10,
            wrap="word",
        )
        self.audit_viewer.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.audit_viewer.insert(
            "1.0",
            "Select a suspicious .exe or .dll and click 'Start Iterative Disinfection'.\n\n"
            "Pipeline per pass (max 5 passes):\n"
            "  1. Copy binary to isolated workspace & run Ghidra Headless (GhidraGuardExport.java)\n"
            "  2. Audit decompiled pseudo-C, imports, strings & XREFs directly with local CUDA + Flash Attention AI\n"
            "  3. Parse strict JSON patch plan & apply surgical .text patches (RET / NOP / Jcc flip)\n"
            "  4. Strip invalidated Authenticode signature & recalculate PE CheckSum\n"
            "  5. Re-decompile patched binary & re-verify until 0 malicious behaviors remain.\n",
        )
        self.audit_viewer.configure(state="disabled")

        # Right Panel: Binary Patch Diff Summary
        right_card = ctk.CTkFrame(split, fg_color=BG_CARD, corner_radius=14, border_width=1, border_color=BORDER_GLASS)
        right_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right_card.grid_columnconfigure(0, weight=1)
        right_card.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            right_card,
            text="Patched Offsets & Byte Diff Summary",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(12, 6))

        self.diff_box = ctk.CTkTextbox(
            right_card,
            fg_color=BG_INPUT,
            text_color="#A7F3D0",
            font=ctk.CTkFont(family="Consolas", size=11),
            corner_radius=10,
            wrap="word",
        )
        self.diff_box.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.diff_box.insert("1.0", "No byte patches applied yet.\n")
        self.diff_box.configure(state="disabled")

        return frame

    def _browse_patch_target(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Target PE Binary (.exe / .dll)",
            filetypes=[("Windows Binaries", "*.exe *.dll"), ("All Files", "*.*")],
        )
        if path:
            self.active_target_path = path
            self.lbl_patch_target.configure(text=path)

    def _start_disinfection(self) -> None:
        if self._patching:
            return
        if not self.active_target_path or not os.path.isfile(self.active_target_path):
            messagebox.showwarning("No Target", "Please select a valid .exe or .dll binary first.")
            return
        if not self.ghidra_engine.is_available():
            messagebox.showerror(
                "Ghidra Not Found",
                "Ghidra analyzeHeadless.bat was not found.\nGo to Settings to auto-detect or set its path manually.",
            )
            return

        self._patching = True
        self.pass_reports = []
        self.last_result = None
        self.btn_start_patch.configure(state="disabled")
        self.btn_cancel_patch.configure(state="normal")
        self.btn_deploy_patch.configure(state="disabled")
        self.lbl_patch_verdict.configure(text="Running Ghidra + Local AI...", text_color=BORDER_ACCENT)

        self._set_textbox(self.audit_viewer, "Starting Pass 1 headless decompilation...\n")
        self._set_textbox(self.diff_box, "Awaiting patches...\n")

        model_id = self.settings.data.get("llm_model", "") or DEFAULT_LOCAL_MODEL
        if self.direct_ai_client is None or self.direct_ai_client.model != model_id:
            self.direct_ai_client = DirectLocalAIClient(
                model=model_id,
                use_cuda=bool(self.settings.data.get("use_cuda", True)),
                flash_attention=bool(self.settings.data.get("flash_attention", True)),
                num_ctx=int(self.settings.data.get("num_ctx", 32768)),
                precision=str(self.settings.data.get("cuda_precision", "bf16")),
                log_callback=self.log,
            )
        llm_client = self.direct_ai_client
        self.active_pipeline = AIAuditorPipeline(
            ghidra=self.ghidra_engine,
            llm=llm_client,
            patcher=self.patcher,
            quarantine=self.quarantine_mgr,
            max_passes=int(self.settings.data.get("max_passes", 5)),
            log_callback=self.log,
        )

        target = self.active_target_path
        auto_quar = bool(self.settings.data.get("auto_quarantine", True))

        def _on_pass(report: PassAuditReport) -> None:
            self.pass_reports.append(report)
            self.after(0, lambda r=report: self._update_pass_ui(r))

        def _worker() -> None:
            try:
                assert self.active_pipeline is not None
                res = self.active_pipeline.run_disinfection_pipeline(
                    target_path=target,
                    auto_quarantine_on_failure=auto_quar,
                    on_pass_complete=_on_pass,
                )
                self.last_result = res
                self.after(0, lambda r=res: self._finish_disinfection_ui(r))
            except Exception as exc:
                self.log(f"[PIPELINE] ERROR: {exc}")
                self.after(
                    0,
                    lambda e=exc: (
                        self.lbl_patch_verdict.configure(text=f"Error: {e}", text_color=ACCENT_RED),
                        self.btn_start_patch.configure(state="normal"),
                        self.btn_cancel_patch.configure(state="disabled"),
                    ),
                )
                self._patching = False

        threading.Thread(target=_worker, daemon=True).start()

    def _cancel_disinfection(self) -> None:
        if self.active_pipeline:
            self.active_pipeline.cancel()
            self.btn_cancel_patch.configure(state="disabled")

    def _update_pass_ui(self, report: PassAuditReport) -> None:
        tabs = [f"Pass {r.pass_number}" for r in self.pass_reports]
        self.pass_selector.configure(values=tabs)
        self.pass_selector.set(f"Pass {report.pass_number}")
        self._render_pass_report(report)
        self._render_diff_summary()

    def _on_select_pass_tab(self, value: str) -> None:
        try:
            num = int(value.replace("Pass", "").strip())
            rep = next((r for r in self.pass_reports if r.pass_number == num), None)
            if rep:
                self._render_pass_report(rep)
        except ValueError:
            pass

    def _render_pass_report(self, report: PassAuditReport) -> None:
        lines = [
            f"=== PASS {report.pass_number} AUDIT REPORT [{report.status}] ===",
            f"Functions Analyzed: {report.functions_analyzed}",
            f"Clean Verdict: {report.is_clean}  |  Unpatchable/Packed: {report.unpatchable_or_packed}",
            f"Summary: {report.threat_summary}",
            "",
            f"--- Identified Malicious Functions ({len(report.malicious_findings)}) ---",
        ]
        for mf in report.malicious_findings:
            lines.append(
                f"  • {mf.get('function_name')} @ VA={mf.get('va')} Offset={mf.get('file_offset')}\n"
                f"    Category: {mf.get('category')} | Strategy: {mf.get('patch_strategy')}\n"
                f"    Reason: {mf.get('reason')}"
            )
        if not report.malicious_findings:
            lines.append("  (None — binary confirmed clean!)")

        lines.append("\n--- Ghidra Decompiled Pseudo-C Preview ---")
        lines.append(report.decompiled_preview or "(No pseudo-C available)")
        self._set_textbox(self.audit_viewer, "\n".join(lines))

    def _render_diff_summary(self) -> None:
        all_recs: List[PatchRecord] = []
        for r in self.pass_reports:
            all_recs.extend(r.applied_patches)

        if not all_recs:
            self._set_textbox(self.diff_box, "No surgical byte patches applied yet.\n")
            return

        lines: List[str] = [f"Total Patches Applied: {len(all_recs)}\n" + "=" * 46]
        for idx, p in enumerate(all_recs, 1):
            lines.append(
                f"\n#{idx} [Pass {p.pass_number}] {p.function_name} ({p.section_name})\n"
                f"   VA: {p.va}  |  File Offset: {p.file_offset}\n"
                f"   Strategy: {p.strategy} ({p.note})\n"
                f"   BEFORE: {p.before_hex}\n"
                f"   AFTER : {p.after_hex}\n"
                f"   Reason: {p.reason}"
            )
        self._set_textbox(self.diff_box, "\n".join(lines))

    def _finish_disinfection_ui(self, res: DisinfectionResult) -> None:
        self._patching = False
        self.btn_start_patch.configure(state="normal")
        self.btn_cancel_patch.configure(state="disabled")

        if res.final_status == "CLEAN":
            self.lbl_patch_verdict.configure(
                text=f"CLEAN ({res.passes_completed} pass(es), {len(res.all_patches)} patch(es))",
                text_color=ACCENT_GREEN,
            )
            if res.final_patched_path and os.path.isfile(res.final_patched_path):
                self.btn_deploy_patch.configure(state="normal")
        elif res.final_status.startswith("QUARANTINED"):
            self.lbl_patch_verdict.configure(text=res.final_status, text_color=ACCENT_AMBER)
        else:
            self.lbl_patch_verdict.configure(text=res.final_status, text_color=ACCENT_RED)

    def _deploy_patched_binary(self) -> None:
        if not self.last_result or not self.last_result.final_patched_path:
            return
        orig = self.last_result.target_path
        patched = self.last_result.final_patched_path
        if not messagebox.askyesno(
            "Deploy Patched Binary",
            f"Back up original binary and overwrite it with the disinfected binary?\n\nTarget: {orig}",
        ):
            return
        try:
            bak = self.quarantine_mgr.deploy_patched_binary(patched, orig)
            messagebox.showinfo("Deployed", f"Patched binary deployed successfully!\nBackup saved to:\n{bak}")
        except Exception as exc:
            messagebox.showerror("Deploy Failed", str(exc))

    # -----------------------------------------------------------------------
    # VIEW 3: Live Network Monitor
    # -----------------------------------------------------------------------

    def _build_network_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=14, border_width=1, border_color=BORDER_GLASS)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        top = ctk.CTkFrame(hdr, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=12)

        ctk.CTkLabel(
            top,
            text="Live Outbound TCP/UDP Network Monitor",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        ctk.CTkButton(
            top,
            text="Refresh Now",
            width=110,
            fg_color=ACCENT_CYAN,
            hover_color=ACCENT_CYAN_HOVER,
            command=self._refresh_network_connections,
        ).pack(side="right", padx=(8, 0))

        self.var_net_auto = tk.BooleanVar(value=False)
        ctk.CTkSwitch(
            top,
            text="Auto-Refresh (4s)",
            variable=self.var_net_auto,
            command=self._toggle_net_auto,
            font=ctk.CTkFont(size=12),
        ).pack(side="right", padx=12)

        self.net_list = ctk.CTkScrollableFrame(
            frame, fg_color=BG_CARD, corner_radius=14, border_width=1, border_color=BORDER_GLASS
        )
        self.net_list.grid(row=1, column=0, sticky="nsew")
        return frame

    def _toggle_net_auto(self) -> None:
        self.net_auto_refresh = bool(self.var_net_auto.get())
        if self.net_auto_refresh:
            self._schedule_net_refresh()
        elif self._net_timer_id:
            self.after_cancel(self._net_timer_id)
            self._net_timer_id = None

    def _schedule_net_refresh(self) -> None:
        if not self.net_auto_refresh:
            return
        self._refresh_network_connections()
        self._net_timer_id = self.after(4000, self._schedule_net_refresh)

    def _refresh_network_connections(self) -> None:
        if self._net_loading:
            return
        self._net_loading = True

        def _worker() -> None:
            try:
                conns = get_active_connections()
            finally:
                self._net_loading = False
            self.after(0, lambda c=conns: self._render_network_connections(c))

        threading.Thread(target=_worker, daemon=True).start()

    def _render_network_connections(self, conns: List[NetworkConnectionInfo]) -> None:
        for w in self.net_list.winfo_children():
            w.destroy()

        if not conns:
            ctk.CTkLabel(self.net_list, text="No active inet connections found.", text_color=TEXT_MUTED).pack(pady=30)
            return

        # Display top 80 connections for crisp UI responsiveness
        for c in conns[:80]:
            row = ctk.CTkFrame(
                self.net_list,
                fg_color=BG_CARD_ALT,
                corner_radius=8,
                border_width=1,
                border_color=ACCENT_AMBER if c.is_external else BORDER_GLASS,
            )
            row.pack(fill="x", padx=6, pady=3)

            badge_col = ACCENT_AMBER if c.is_external else "#334155"
            badge_txt = "EXT" if c.is_external else "LOC"
            ctk.CTkLabel(
                row,
                text=f" {badge_txt} ",
                fg_color=badge_col,
                text_color="#090D16" if c.is_external else TEXT_PRIMARY,
                corner_radius=5,
                font=ctk.CTkFont(size=10, weight="bold"),
            ).pack(side="left", padx=(8, 8), pady=6)

            info = (
                f"[{c.protocol}] PID {c.pid:<6}  {c.process_name:<22}  "
                f"{c.local_addr}  ->  {c.remote_addr}  ({c.status})"
            )
            ctk.CTkLabel(
                row,
                text=info,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=TEXT_PRIMARY,
                anchor="w",
            ).pack(side="left", fill="x", expand=True)

            if c.pid > 4:
                ctk.CTkButton(
                    row,
                    text="Kill PID",
                    width=64,
                    height=24,
                    fg_color="#7F1D1D",
                    hover_color=ACCENT_RED,
                    font=ctk.CTkFont(size=10, weight="bold"),
                    command=lambda pid=c.pid: self._kill_pid(pid),
                ).pack(side="right", padx=6, pady=4)

            if c.exe_path and os.path.isfile(c.exe_path):
                ctk.CTkButton(
                    row,
                    text="Audit Binary",
                    width=88,
                    height=24,
                    fg_color=ACCENT_PURPLE,
                    hover_color="#7C3AED",
                    font=ctk.CTkFont(size=10, weight="bold"),
                    command=lambda p=c.exe_path: self._open_in_patch_lab(p),
                ).pack(side="right", padx=4, pady=4)

    def _kill_pid(self, pid: int) -> None:
        if not messagebox.askyesno("Terminate Process", f"Terminate process PID {pid}?"):
            return
        try:
            psutil.Process(pid).terminate()
            self.log(f"[NET] Terminated PID {pid}.")
            self.after(600, self._refresh_network_connections)
        except Exception as exc:
            messagebox.showerror("Error", f"Could not terminate PID {pid}: {exc}")

    # -----------------------------------------------------------------------
    # VIEW 4: System Repair (SFC / DISM) & Quarantine Vault
    # -----------------------------------------------------------------------

    def _build_repair_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Windows System Repair Card
        rep = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=14, border_width=1, border_color=BORDER_GLASS)
        rep.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        ctk.CTkLabel(
            rep,
            text="Windows System Integrity Repair",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=16, pady=(14, 4))

        ctk.CTkLabel(
            rep,
            text="One-click Windows image & system file verification (requires Administrator privileges; live output streams to Terminal Log below).",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", padx=16, pady=(0, 10))

        btn_row = ctk.CTkFrame(rep, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 14))

        ctk.CTkButton(
            btn_row,
            text="Run SFC /scannow",
            fg_color=ACCENT_CYAN,
            hover_color=ACCENT_CYAN_HOVER,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=lambda: self._run_repair_cmd(["sfc", "/scannow"], "SFC /scannow"),
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_row,
            text="Run DISM /RestoreHealth",
            fg_color=ACCENT_PURPLE,
            hover_color="#7C3AED",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=lambda: self._run_repair_cmd(
                ["DISM", "/Online", "/Cleanup-Image", "/RestoreHealth"], "DISM RestoreHealth"
            ),
        ).pack(side="left", padx=(0, 10))

        # Quarantine Vault Card
        vault_card = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=14, border_width=1, border_color=BORDER_GLASS)
        vault_card.grid(row=1, column=0, sticky="nsew")
        vault_card.grid_columnconfigure(0, weight=1)
        vault_card.grid_rowconfigure(1, weight=1)

        vhdr = ctk.CTkFrame(vault_card, fg_color="transparent")
        vhdr.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 6))
        ctk.CTkLabel(
            vhdr,
            text="Quarantine Vault (XOR-Neutralized Samples)",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")
        ctk.CTkButton(
            vhdr, text="Refresh", width=80, fg_color=BG_CARD_ALT, command=self._refresh_quarantine_list
        ).pack(side="right")

        self.vault_list = ctk.CTkScrollableFrame(vault_card, fg_color=BG_INPUT, corner_radius=10)
        self.vault_list.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
        return frame

    def _run_repair_cmd(self, cmd: List[str], label: str) -> None:
        if not is_admin():
            messagebox.showwarning(
                "Administrator Required",
                f"{label} requires Administrator privileges. Relaunch GhidraGuard as Administrator.",
            )
            return

        self.log(f"[REPAIR] Launching: {' '.join(cmd)}")

        def _worker() -> None:
            try:
                creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    creationflags=creation_flags,
                )
                assert proc.stdout is not None
                for raw in proc.stdout:
                    # sfc often outputs UTF-16LE with null bytes on Windows
                    if b"\x00" in raw:
                        text = raw.decode("utf-16-le", errors="ignore").strip()
                    else:
                        text = raw.decode("utf-8", errors="ignore").strip()
                    if text:
                        self.log(f"[REPAIR] {text}")
                code = proc.wait()
                self.log(f"[REPAIR] {label} finished with exit code {code}.")
            except Exception as exc:
                self.log(f"[REPAIR] {label} error: {exc}")

        threading.Thread(target=_worker, daemon=True).start()

    def _refresh_quarantine_list(self) -> None:
        for w in self.vault_list.winfo_children():
            w.destroy()
        entries: List[QuarantineEntry] = self.quarantine_mgr.list_quarantined()
        if not entries:
            ctk.CTkLabel(self.vault_list, text="Quarantine Vault is empty.", text_color=TEXT_MUTED).pack(pady=30)
            return

        for e in entries:
            row = ctk.CTkFrame(self.vault_list, fg_color=BG_CARD_ALT, corner_radius=8)
            row.pack(fill="x", padx=6, pady=4)
            ctk.CTkLabel(
                row,
                text=f"{e.original_path}\nSHA256: {e.sha256[:24]}...  |  {e.timestamp}  |  {e.reason}",
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=TEXT_PRIMARY,
                justify="left",
                anchor="w",
            ).pack(side="left", padx=10, pady=8, fill="x", expand=True)

            ctk.CTkButton(
                row,
                text="Delete",
                width=70,
                height=26,
                fg_color="#7F1D1D",
                hover_color=ACCENT_RED,
                command=lambda eid=e.entry_id: self._vault_delete(eid),
            ).pack(side="right", padx=6)

            ctk.CTkButton(
                row,
                text="Restore",
                width=74,
                height=26,
                fg_color=ACCENT_GREEN,
                hover_color="#059669",
                command=lambda eid=e.entry_id: self._vault_restore(eid),
            ).pack(side="right", padx=4)

    def _vault_restore(self, entry_id: str) -> None:
        try:
            restored = self.quarantine_mgr.restore_quarantined(entry_id)
            messagebox.showinfo("Restored", f"Restored file to:\n{restored}")
            self._refresh_quarantine_list()
        except Exception as exc:
            messagebox.showerror("Restore Failed", str(exc))

    def _vault_delete(self, entry_id: str) -> None:
        if not messagebox.askyesno("Permanent Delete", "Permanently delete this quarantined sample?"):
            return
        self.quarantine_mgr.delete_quarantined(entry_id)
        self._refresh_quarantine_list()

    # -----------------------------------------------------------------------
    # VIEW 5: Settings & Engine Configuration
    # -----------------------------------------------------------------------

    def _build_settings_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkScrollableFrame(
            self.content_container, fg_color=BG_CARD, corner_radius=14, border_width=1, border_color=BORDER_GLASS
        )

        ctk.CTkLabel(
            frame,
            text="Local Engine Settings (100% Offline)",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w", padx=18, pady=(16, 12))

        # --- One-Click Automatic Setup Everything Card ---
        setup_card = ctk.CTkFrame(frame, fg_color=BG_CARD_ALT, corner_radius=12, border_width=1, border_color=BORDER_ACCENT)
        setup_card.pack(fill="x", padx=18, pady=8)

        ctk.CTkLabel(
            setup_card,
            text="Automatic Setup (JDK 21 + Official Ghidra + PyTorch CUDA Flash Attention)",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=BORDER_ACCENT,
        ).pack(anchor="w", padx=14, pady=(12, 4))

        env_st = check_environment()
        self.lbl_auto_setup_status = ctk.CTkLabel(
            setup_card,
            text=env_st.summary_line(),
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=ACCENT_GREEN if env_st.all_ready else ACCENT_AMBER,
            anchor="w",
        )
        self.lbl_auto_setup_status.pack(fill="x", padx=14, pady=(0, 8))

        s_row = ctk.CTkFrame(setup_card, fg_color="transparent")
        s_row.pack(fill="x", padx=14, pady=(0, 12))
        ctk.CTkButton(
            s_row,
            text="Auto-Setup Everything (JDK + Ghidra + CUDA AI)",
            fg_color=ACCENT_GREEN,
            hover_color="#059669",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._run_auto_setup_all_async,
        ).pack(side="left", padx=(0, 10))
        ctk.CTkButton(
            s_row,
            text="Auto-Install Ghidra Only",
            fg_color=ACCENT_CYAN,
            hover_color=ACCENT_CYAN_HOVER,
            command=self._run_auto_setup_ghidra_async,
        ).pack(side="left")

        # --- Ghidra Section ---
        g_card = ctk.CTkFrame(frame, fg_color=BG_CARD_ALT, corner_radius=12, border_width=1, border_color=BORDER_GLASS)
        g_card.pack(fill="x", padx=18, pady=8)

        ctk.CTkLabel(
            g_card, text="Ghidra Headless Integration", font=ctk.CTkFont(size=14, weight="bold"), text_color=BORDER_ACCENT
        ).pack(anchor="w", padx=14, pady=(12, 4))
        ctk.CTkLabel(
            g_card,
            text="Scans C:\\* two directory levels deep (C:\\<folder>\\<subfolder>\\support\\analyzeHeadless.bat) or use manual override:",
            font=ctk.CTkFont(size=11),
            text_color=TEXT_SECONDARY,
        ).pack(anchor="w", padx=14, pady=(0, 8))

        g_row = ctk.CTkFrame(g_card, fg_color="transparent")
        g_row.pack(fill="x", padx=14, pady=(0, 14))
        self.ent_ghidra = ctk.CTkEntry(g_row, fg_color=BG_INPUT, border_color=BORDER_GLASS)
        self.ent_ghidra.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.ent_ghidra.insert(0, self.settings.data.get("ghidra_headless_path", ""))

        ctk.CTkButton(g_row, text="Browse...", width=90, command=self._browse_ghidra).pack(side="left", padx=4)
        ctk.CTkButton(
            g_row,
            text="Auto-Detect C:\\",
            width=125,
            fg_color=ACCENT_CYAN,
            hover_color=ACCENT_CYAN_HOVER,
            command=self._auto_detect_ghidra,
        ).pack(side="left", padx=4)

        # --- Direct Local AI Model Section (Zero Ollama / Zero External Server) ---
        ai_card = ctk.CTkFrame(frame, fg_color=BG_CARD_ALT, corner_radius=12, border_width=1, border_color=BORDER_GLASS)
        ai_card.pack(fill="x", padx=18, pady=8)

        ctk.CTkLabel(
            ai_card,
            text="Direct Local AI Model (In-Process CUDA + Flash Attention — No Ollama Required)",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=BORDER_ACCENT,
        ).pack(anchor="w", padx=14, pady=(12, 8))

        m_row = ctk.CTkFrame(ai_card, fg_color="transparent")
        m_row.pack(fill="x", padx=14, pady=(2, 8))
        ctk.CTkLabel(m_row, text="Model ID / Path:", width=115, anchor="w").pack(side="left")
        cached_models = CUDAFlashAttentionEngine.list_local_models()
        cur_model = self.settings.data.get("llm_model", "") or DEFAULT_LOCAL_MODEL
        if cur_model not in cached_models:
            cached_models.insert(0, cur_model)
        self.opt_model = ctk.CTkOptionMenu(m_row, values=cached_models, width=320)
        self.opt_model.set(cur_model)
        self.opt_model.pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            m_row,
            text="Browse Local Folder...",
            width=145,
            fg_color=BG_CARD,
            hover_color=BORDER_GLASS,
            command=self._browse_local_model_dir,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            m_row,
            text="Scan Cache",
            width=100,
            fg_color=ACCENT_CYAN,
            hover_color=ACCENT_CYAN_HOVER,
            command=lambda: self._refresh_models_async(silent=False),
        ).pack(side="left")

        m_row2 = ctk.CTkFrame(ai_card, fg_color="transparent")
        m_row2.pack(fill="x", padx=14, pady=(0, 14))
        ctk.CTkButton(
            m_row2,
            text="Preload / Download Model to VRAM",
            fg_color=ACCENT_PURPLE,
            hover_color="#7C3AED",
            command=self._preload_model_async,
        ).pack(side="left", padx=(0, 10))
        ctk.CTkButton(
            m_row2,
            text="Unload VRAM",
            width=110,
            fg_color="#334155",
            hover_color="#475569",
            command=self._unload_model_vram,
        ).pack(side="left")

        # --- CUDA & Flash Attention Acceleration Card ---
        cuda_card = ctk.CTkFrame(frame, fg_color=BG_CARD_ALT, corner_radius=12, border_width=1, border_color=BORDER_GLASS)
        cuda_card.pack(fill="x", padx=18, pady=8)

        ctk.CTkLabel(
            cuda_card,
            text="CUDA GPU & Flash Attention Acceleration",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=BORDER_ACCENT,
        ).pack(anchor="w", padx=14, pady=(12, 4))

        hw = self.gpu_info
        hw_summary = (
            f"GPU: {hw.gpu_name} | VRAM: {hw.vram_total_gb} GB | CUDA: {hw.cuda_version or 'N/A'} | "
            f"PyTorch CUDA: {'Yes' if hw.torch_cuda_available else 'No'} | "
            f"FlashAttn-2: {'Yes' if hw.flash_attn_2_available else 'PyTorch SDPA'}"
        )
        self.lbl_cuda_hw_details = ctk.CTkLabel(
            cuda_card,
            text=hw_summary,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=ACCENT_GREEN if hw.cuda_available else TEXT_MUTED,
            anchor="w",
        )
        self.lbl_cuda_hw_details.pack(fill="x", padx=14, pady=(0, 8))

        c_row1 = ctk.CTkFrame(cuda_card, fg_color="transparent")
        c_row1.pack(fill="x", padx=14, pady=4)

        self.var_use_cuda = tk.BooleanVar(value=bool(self.settings.data.get("use_cuda", True)))
        ctk.CTkCheckBox(
            c_row1,
            text="Enable CUDA GPU Acceleration (device_map='cuda')",
            variable=self.var_use_cuda,
        ).pack(side="left", padx=(0, 18))

        self.var_flash_attn = tk.BooleanVar(value=bool(self.settings.data.get("flash_attention", True)))
        ctk.CTkCheckBox(
            c_row1,
            text="Enable Flash Attention (FlashAttention-2 / PyTorch SDPA)",
            variable=self.var_flash_attn,
        ).pack(side="left")

        c_row2 = ctk.CTkFrame(cuda_card, fg_color="transparent")
        c_row2.pack(fill="x", padx=14, pady=(6, 14))

        ctk.CTkLabel(c_row2, text="Precision:", width=75, anchor="w").pack(side="left")
        self.opt_precision = ctk.CTkOptionMenu(c_row2, values=["bf16", "fp16", "4bit-nf4"], width=110)
        self.opt_precision.set(str(self.settings.data.get("cuda_precision", "bf16")))
        self.opt_precision.pack(side="left", padx=(0, 16))

        ctk.CTkLabel(c_row2, text="Context Window:", width=110, anchor="w").pack(side="left")
        self.opt_num_ctx = ctk.CTkOptionMenu(c_row2, values=["16384", "32768", "65536"], width=100)
        self.opt_num_ctx.set(str(self.settings.data.get("num_ctx", 32768)))
        self.opt_num_ctx.pack(side="left", padx=(0, 16))

        ctk.CTkButton(
            c_row2,
            text="Run CUDA FlashAttn Self-Test",
            fg_color=ACCENT_CYAN,
            hover_color=ACCENT_CYAN_HOVER,
            command=self._run_cuda_self_test_async,
        ).pack(side="left")

        # --- Safety Loop Settings ---
        p_card = ctk.CTkFrame(frame, fg_color=BG_CARD_ALT, corner_radius=12, border_width=1, border_color=BORDER_GLASS)
        p_card.pack(fill="x", padx=18, pady=8)

        ctk.CTkLabel(
            p_card, text="Iterative Verification & Safety Controls", font=ctk.CTkFont(size=14, weight="bold"),
            text_color=BORDER_ACCENT,
        ).pack(anchor="w", padx=14, pady=(12, 8))

        p_row = ctk.CTkFrame(p_card, fg_color="transparent")
        p_row.pack(fill="x", padx=14, pady=(0, 14))
        ctk.CTkLabel(p_row, text="Max Re-Verify Passes (1-5):").pack(side="left", padx=(0, 8))
        self.var_max_passes = tk.IntVar(value=int(self.settings.data.get("max_passes", 5)))
        self.opt_passes = ctk.CTkOptionMenu(p_row, values=["1", "2", "3", "4", "5"], width=70)
        self.opt_passes.set(str(self.var_max_passes.get()))
        self.opt_passes.pack(side="left", padx=(0, 24))

        self.var_auto_quar = tk.BooleanVar(value=bool(self.settings.data.get("auto_quarantine", True)))
        ctk.CTkCheckBox(
            p_row,
            text="Auto-Quarantine if packed, unpatchable, or max passes exceeded",
            variable=self.var_auto_quar,
        ).pack(side="left")

        ctk.CTkButton(
            frame,
            text="Save Settings",
            height=38,
            width=180,
            fg_color=ACCENT_GREEN,
            hover_color="#059669",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._save_settings,
        ).pack(anchor="e", padx=18, pady=16)

        return frame

    def _browse_local_model_dir(self) -> None:
        folder = filedialog.askdirectory(title="Select Local HuggingFace / Safetensors Model Folder")
        if folder:
            vals = list(self.opt_model.cget("values"))
            if folder not in vals:
                vals.insert(0, folder)
                self.opt_model.configure(values=vals)
            self.opt_model.set(folder)
            self.log(f"[AI] Selected local model directory: {folder}")

    def _run_auto_setup_ghidra_async(self) -> None:
        self.lbl_auto_setup_status.configure(text="Auto-installing official Ghidra...", text_color=ACCENT_AMBER)

        def _worker() -> None:
            try:
                path = ensure_ghidra(self.log)
                st = check_environment()

                def _done() -> None:
                    self.ent_ghidra.delete(0, "end")
                    self.ent_ghidra.insert(0, path)
                    self._save_settings()
                    self.lbl_auto_setup_status.configure(
                        text=st.summary_line(),
                        text_color=ACCENT_GREEN if st.all_ready else ACCENT_AMBER,
                    )
                    messagebox.showinfo("Ghidra Ready", f"Ghidra Headless configured:\n{path}")

                self.after(0, _done)
            except Exception as exc:
                self.log(f"[SETUP] Ghidra auto-setup failed: {exc}")
                self.after(0, lambda e=exc: messagebox.showerror("Ghidra Auto-Setup Failed", str(e)))

        threading.Thread(target=_worker, daemon=True).start()

    def _run_auto_setup_all_async(self) -> None:
        self.lbl_auto_setup_status.configure(text="Running full auto-setup (JDK 21 + Ghidra + CUDA AI)...", text_color=ACCENT_AMBER)

        def _worker() -> None:
            try:
                res = run_full_auto_setup(
                    preload_model=False,
                    model_id=self.settings.data.get("llm_model", "") or DEFAULT_LOCAL_MODEL,
                    log_callback=self.log,
                )
                st = check_environment()
                self.gpu_info = detect_cuda_hardware()

                def _done() -> None:
                    if res.get("ghidra_headless_path"):
                        self.ent_ghidra.delete(0, "end")
                        self.ent_ghidra.insert(0, res["ghidra_headless_path"])
                    self._save_settings()
                    self.lbl_auto_setup_status.configure(
                        text=st.summary_line(),
                        text_color=ACCENT_GREEN if st.all_ready else ACCENT_AMBER,
                    )
                    self.lbl_cuda_status.configure(text=self.gpu_info.short_badge())
                    messagebox.showinfo(
                        "Auto-Setup Complete",
                        f"Environment verified and configured:\n{st.summary_line()}",
                    )

                self.after(0, _done)
            except Exception as exc:
                self.log(f"[SETUP] Full auto-setup failed: {exc}")
                self.after(0, lambda e=exc: messagebox.showerror("Auto-Setup Failed", str(e)))

        threading.Thread(target=_worker, daemon=True).start()

    def _run_cuda_self_test_async(self) -> None:
        self.log("[CUDA] Running direct CUDA & Flash Attention self-test...")

        def _worker() -> None:
            res = run_cuda_flash_benchmark()
            msg = res.get("message", "Self-test completed.")
            self.log(f"[CUDA] {msg}")
            self.after(0, lambda m=msg: messagebox.showinfo("CUDA & Flash Attention Self-Test", m))

        threading.Thread(target=_worker, daemon=True).start()

    def _preload_model_async(self) -> None:
        self._save_settings()
        model_id = self.settings.data.get("llm_model", "") or DEFAULT_LOCAL_MODEL
        self.lbl_ai_status.configure(text="Local AI: Loading...", text_color=ACCENT_AMBER)

        def _worker() -> None:
            try:
                client = DirectLocalAIClient(
                    model=model_id,
                    use_cuda=bool(self.settings.data.get("use_cuda", True)),
                    flash_attention=bool(self.settings.data.get("flash_attention", True)),
                    num_ctx=int(self.settings.data.get("num_ctx", 32768)),
                    precision=str(self.settings.data.get("cuda_precision", "bf16")),
                    log_callback=self.log,
                )
                client.ensure_model_ready()
                self.direct_ai_client = client
                short = Path(model_id).name[:20]
                self.after(0, lambda s=short: self.lbl_ai_status.configure(text=f"Local AI: {s}", text_color=ACCENT_GREEN))
            except Exception as exc:
                self.log(f"[AI] Model load failed: {exc}")
                self.after(0, lambda: self.lbl_ai_status.configure(text="Local AI: Load Failed", text_color=ACCENT_RED))
                self.after(0, lambda e=exc: messagebox.showerror("Direct Model Load Failed", str(e)))

        threading.Thread(target=_worker, daemon=True).start()

    def _unload_model_vram(self) -> None:
        if self.direct_ai_client is not None:
            self.direct_ai_client.unload()
            self.direct_ai_client = None
            self.log("[CUDA] Unloaded local AI model from VRAM.")
            self.lbl_ai_status.configure(text="Local AI: Standby", text_color=TEXT_SECONDARY)

    def _browse_ghidra(self) -> None:
        path = filedialog.askopenfilename(
            title="Locate Ghidra analyzeHeadless.bat",
            filetypes=[("Batch File", "analyzeHeadless.bat"), ("All Files", "*.*")],
        )
        if path:
            self.ent_ghidra.delete(0, "end")
            self.ent_ghidra.insert(0, path)

    def _auto_detect_ghidra(self) -> None:
        self.log("[GHIDRA] Scanning C:\\* (2 directory levels deep) for analyzeHeadless.bat...")
        found = discover_ghidra_headless("C:\\")
        if found:
            self.ent_ghidra.delete(0, "end")
            self.ent_ghidra.insert(0, found[0])
            self.log(f"[GHIDRA] Found {len(found)} installation(s). Selected: {found[0]}")
            self._save_settings()
        else:
            self.log("[GHIDRA] No analyzeHeadless.bat found within 2 levels of C:\\.")
            messagebox.showinfo(
                "Ghidra Not Found",
                "Could not find analyzeHeadless.bat within 2 levels of C:\\.\nPlease use Browse to select it manually.",
            )

    def _refresh_models_async(self, silent: bool = False) -> None:
        def _worker() -> None:
            models = CUDAFlashAttentionEngine.list_local_models()
            saved = self.settings.data.get("llm_model", "") or DEFAULT_LOCAL_MODEL
            if saved not in models:
                models.insert(0, saved)

            def _apply() -> None:
                self.opt_model.configure(values=models)
                self.opt_model.set(saved)
                short = Path(saved).name[:20]
                self.lbl_ai_status.configure(text=f"Local AI: {short}", text_color=ACCENT_GREEN)

            self.after(0, _apply)
            if not silent:
                self.log(f"[AI] Discovered {len(models)} direct local model(s) in cache.")

        threading.Thread(target=_worker, daemon=True).start()

    def _save_settings(self) -> None:
        ghidra_path = self.ent_ghidra.get().strip()
        model = self.opt_model.get().strip() or DEFAULT_LOCAL_MODEL

        self.settings.data.update(
            {
                "ghidra_headless_path": ghidra_path,
                "llm_model": model,
                "use_cuda": bool(self.var_use_cuda.get()),
                "flash_attention": bool(self.var_flash_attn.get()),
                "cuda_precision": self.opt_precision.get().strip(),
                "num_ctx": int(self.opt_num_ctx.get()),
                "max_passes": int(self.opt_passes.get()),
                "auto_quarantine": bool(self.var_auto_quar.get()),
            }
        )
        self.settings.save()
        self.ghidra_engine.set_headless_path(ghidra_path)

        ok = self.ghidra_engine.is_available()
        self.lbl_ghidra_status.configure(
            text=f"Ghidra: {'Ready' if ok else 'Not Found'}",
            text_color=ACCENT_GREEN if ok else ACCENT_RED,
        )
        short = Path(model).name[:20]
        self.lbl_ai_status.configure(text=f"Local AI: {short}", text_color=ACCENT_GREEN)
        self.log("[SETTINGS] Direct local AI & CUDA Flash Attention configuration saved.")

    @staticmethod
    def _set_textbox(widget: ctk.CTkTextbox, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")


def main() -> None:
    app = GhidraGuardApp()
    app.mainloop()


if __name__ == "__main__":
    main()
