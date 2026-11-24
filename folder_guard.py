"""
OpcodeShield - Real-Time Folder & Download Guard
Cross-platform background directory watcher (Windows, Linux, macOS) that monitors
Downloads, Temp, AppData, or custom game/app folders and automatically scans
newly dropped or modified .exe, .dll, .apk, .so, .elf, and .dylib binaries.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from apk_engine import analyze_apk_file
from binary_patcher import QuarantineManager
from scanner import PE_SCAN_EXTENSIONS, analyze_pe_file
from unix_binary_engine import analyze_unix_binary
from yara_engine import YaraRuleEngine

WATCH_EXTENSIONS: Tuple[str, ...] = PE_SCAN_EXTENSIONS + (".apk", ".so", ".elf", ".dylib", ".bin")


@dataclass
class GuardEvent:
    timestamp: str
    path: str
    binary_type: str
    risk_score: int
    severity: str
    yara_hits: List[str] = field(default_factory=list)
    quarantined: bool = False
    quarantine_id: str = ""
    summary: str = ""


class FolderGuard:
    """Real-time folder watcher with automatic static + YARA scanning and optional auto-quarantine."""

    def __init__(
        self,
        watch_dirs: List[str],
        auto_quarantine: bool = False,
        quarantine_threshold: int = 60,
        poll_interval: float = 1.0,
        on_event: Optional[Callable[[GuardEvent], None]] = None,
        log_callback: Optional[Callable[[str], None]] = None,
    ):
        self.watch_dirs = [Path(d) for d in watch_dirs if Path(d).is_dir()]
        self.auto_quarantine = auto_quarantine
        self.quarantine_threshold = quarantine_threshold
        self.poll_interval = max(0.25, poll_interval)
        self._on_event = on_event or (lambda ev: None)
        self._log = log_callback or (lambda msg: None)
        self._yara = YaraRuleEngine()
        self._quarantine = QuarantineManager(log_callback=self._log)
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen: Dict[str, Tuple[int, int]] = {}  # path -> (mtime_ns, size)
        self.events: List[GuardEvent] = []

    def _snapshot(self) -> Dict[str, Tuple[int, int]]:
        snap: Dict[str, Tuple[int, int]] = {}
        for root in self.watch_dirs:
            if not root.is_dir():
                continue
            try:
                for entry in root.iterdir():
                    if entry.is_file() and entry.name.lower().endswith(WATCH_EXTENSIONS):
                        try:
                            st = entry.stat()
                            snap[str(entry)] = (st.st_mtime_ns, st.st_size)
                        except OSError:
                            continue
            except OSError:
                continue
        return snap

    def inspect_file(self, fpath: str) -> GuardEvent:
        low = fpath.lower()
        score = 0
        sev = "LOW"
        btype = "unknown"
        summary = "Clean"

        if low.endswith(".apk"):
            res = analyze_apk_file(fpath)
            btype = "APK"
            if res:
                score, sev = res.risk_score, res.severity
                summary = "; ".join(res.indicators[:3]) or "Clean APK"
        elif low.endswith(PE_SCAN_EXTENSIONS):
            res = analyze_pe_file(fpath, source="Folder Guard")
            btype = "PE"
            if res:
                score, sev = res.risk_score, res.severity
                summary = "; ".join(res.indicators[:3]) or "Clean PE"
        else:
            res = analyze_unix_binary(fpath)
            if res:
                btype = res.binary_format
                score, sev = res.risk_score, res.severity
                summary = "; ".join(res.indicators[:3]) or f"Clean {btype}"

        ymatches = self._yara.scan_file(fpath)
        yhits = [m.rule_name for m in ymatches]
        if yhits:
            score = min(100, score + 30)
            sev = "CRITICAL" if score >= 75 else ("HIGH" if score >= 50 else "MEDIUM")
            summary = f"YARA={','.join(yhits[:3])}; {summary}"

        quarantined = False
        qid = ""
        if self.auto_quarantine and score >= self.quarantine_threshold and os.path.isfile(fpath):
            try:
                entry = self._quarantine.quarantine_file(fpath, reason=f"FolderGuard ({sev}, score={score}): {summary}")
                quarantined = True
                qid = entry.entry_id
            except Exception as exc:
                self._log(f"[GUARD] Quarantine failed for {fpath}: {exc}")

        ev = GuardEvent(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            path=fpath,
            binary_type=btype,
            risk_score=score,
            severity=sev,
            yara_hits=yhits,
            quarantined=quarantined,
            quarantine_id=qid,
            summary=summary,
        )
        self.events.append(ev)
        self._log(
            f"[GUARD] [{ev.severity}] score={ev.risk_score} {ev.binary_type} {os.path.basename(fpath)}"
            + (f" -> QUARANTINED ({qid})" if quarantined else "")
        )
        self._on_event(ev)
        return ev

    def poll_once(self) -> List[GuardEvent]:
        """Run one synchronous poll cycle (useful for CLI tests and deterministic loops)."""
        new_events: List[GuardEvent] = []
        current = self._snapshot()
        for fpath, sig in current.items():
            if self._seen.get(fpath) != sig:
                self._seen[fpath] = sig
                new_events.append(self.inspect_file(fpath))
        return new_events

    def start(self, scan_existing: bool = False) -> None:
        self._stop_evt.clear()
        self._seen = {} if scan_existing else self._snapshot()

        def _loop() -> None:
            self._log(f"[GUARD] Watching {len(self.watch_dirs)} folder(s): {', '.join(str(d) for d in self.watch_dirs)}")
            while not self._stop_evt.is_set():
                self.poll_once()
                self._stop_evt.wait(self.poll_interval)

        self._thread = threading.Thread(target=_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None
