"""
GhidraGuard - Automated Dynamic Sandbox Verification Runner
Safely runs an executable inside an isolated temporary directory with strict
timeout, clean environment, Windows Job Object (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
to prevent lingering child processes), and captures exit code, stdout/stderr,
created files, and crash status.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class SandboxResult:
    target_path: str
    completed: bool
    timed_out: bool
    crashed: bool
    exit_code: int
    elapsed_seconds: float
    stdout_preview: str = ""
    stderr_preview: str = ""
    created_files: List[str] = field(default_factory=list)
    verdict: str = ""


def _create_windows_kill_job():
    """Create a Windows Job Object that kills all child processes when closed."""
    if os.name != "nt":
        return None
    try:
        kernel32 = ctypes.windll.kernel32
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return None

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32),
            ]

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000 | ACTIVE_PROCESS = 0x8
        info.BasicLimitInformation.LimitFlags = 0x2000 | 0x8
        info.BasicLimitInformation.ActiveProcessLimit = 4
        kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))
        return job
    except Exception:
        return None


def run_in_sandbox(
    executable_path: str,
    args: Optional[List[str]] = None,
    timeout_seconds: float = 5.0,
) -> SandboxResult:
    """Execute a binary in an isolated temp directory under a strict process job/timeout."""
    src = Path(executable_path).resolve()
    if not src.is_file():
        return SandboxResult(
            target_path=str(src), completed=False, timed_out=False, crashed=True,
            exit_code=-1, elapsed_seconds=0.0, verdict="File not found",
        )

    work_dir = Path(tempfile.mkdtemp(prefix="gg_sandbox_"))
    t0 = time.time()
    job = _create_windows_kill_job()
    try:
        before_files = set(p.name for p in work_dir.iterdir())
        env = {"PATH": os.environ.get("PATH", ""), "TEMP": str(work_dir), "TMP": str(work_dir)}
        if os.name == "nt":
            env["SystemRoot"] = os.environ.get("SystemRoot", r"C:\Windows")

        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.Popen(
            [str(src)] + list(args or []),
            cwd=str(work_dir),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="ignore",
            creationflags=creation_flags,
        )
        if job and os.name == "nt":
            try:
                ctypes.windll.kernel32.AssignProcessToJobObject(job, int(proc._handle))
            except Exception:
                pass

        timed_out = False
        try:
            out, err = proc.communicate(timeout=timeout_seconds)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            out, err = proc.communicate(timeout=2)
            rc = -9

        elapsed = round(time.time() - t0, 2)
        after_files = set(p.name for p in work_dir.iterdir())
        created = sorted(after_files - before_files)
        crashed = (not timed_out) and (rc < 0 or rc >= 0x80000000)

        if crashed:
            verdict = f"CRASHED (exit={hex(rc & 0xFFFFFFFF)})"
        elif timed_out:
            verdict = f"TIMED_OUT_CLEANLY ({timeout_seconds}s cap)"
        elif created:
            verdict = f"OK_DROPPED_{len(created)}_FILES (exit={rc})"
        else:
            verdict = f"CLEAN_EXECUTION (exit={rc})"

        return SandboxResult(
            target_path=str(src),
            completed=not timed_out,
            timed_out=timed_out,
            crashed=crashed,
            exit_code=rc,
            elapsed_seconds=elapsed,
            stdout_preview=(out or "").strip()[:300],
            stderr_preview=(err or "").strip()[:300],
            created_files=created,
            verdict=verdict,
        )
    finally:
        if job and os.name == "nt":
            try:
                ctypes.windll.kernel32.CloseHandle(job)
            except Exception:
                pass
        shutil.rmtree(work_dir, ignore_errors=True)
