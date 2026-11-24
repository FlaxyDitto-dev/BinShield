"""
OpcodeShield - Automatic Environment & Dependency Bootstrapper
Automatically detects, downloads, and configures everything OpcodeShield needs:
  1. Java JDK 21+ (portable Eclipse Temurin JDK 21 if missing)
  2. NSA Ghidra (latest official GitHub release ZIP extracted to C:\\Ghidra or %LOCALAPPDATA%\\OpcodeShield\\tools)
  3. Direct PyTorch CUDA + Flash Attention + Transformers (torch cu128/cpu, transformers, accelerate, safetensors)
  4. Default local AI model preload (Qwen/Qwen2.5-Coder-3B-Instruct)

Can be invoked directly from the OpcodeShield GUI ("Auto-Setup Everything") or via CLI:
    python auto_setup.py
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from cuda_engine import DEFAULT_LOCAL_MODEL, detect_cuda_hardware
from ghidra_engine import discover_ghidra_headless


ADOPTIUM_JDK21_URL = (
    "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse"
)
GHIDRA_RELEASES_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"


@dataclass
class EnvironmentStatus:
    java_ok: bool = False
    java_version: str = ""
    java_home: str = ""
    ghidra_ok: bool = False
    ghidra_headless_path: str = ""
    torch_ok: bool = False
    torch_cuda_ok: bool = False
    transformers_ok: bool = False
    cuda_gpu_name: str = "CPU Only"

    @property
    def all_ready(self) -> bool:
        # Built-in ONNX Runtime + Capstone + SecNet-v3 are prebuilt — no external JDK/Ghidra/PyTorch required!
        try:
            import onnxruntime  # noqa: F401
            import capstone  # noqa: F401
            return True
        except Exception:
            return self.java_ok and self.ghidra_ok and self.torch_ok and self.transformers_ok

    def summary_line(self) -> str:
        ort_ok = False
        try:
            import onnxruntime  # noqa: F401
            ort_ok = True
        except Exception:
            pass
        parts = [
            f"Built-in AI (SecNet-v3 ONNX): {'Ready' if ort_ok else 'Missing'}",
            f"Disasm: {'Ghidra + Capstone' if self.ghidra_ok else 'Built-in Capstone'}",
            f"Optional CUDA PyTorch: {'CUDA' if self.torch_cuda_ok else ('CPU' if self.torch_ok else 'Not Needed')}",
        ]
        return " | ".join(parts)


def _tools_root() -> Path:
    """Prefer C:\\Ghidra if writable, else %LOCALAPPDATA%\\OpcodeShield\\tools."""
    preferred = Path("C:\\Ghidra")
    try:
        preferred.mkdir(parents=True, exist_ok=True)
        probe = preferred / ".gg_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return preferred
    except Exception:
        fallback = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "OpcodeShield" / "tools"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def _parse_java_major(version_output: str) -> int:
    m = re.search(r'version\s+"(\d+)(?:\.(\d+))?', version_output)
    if not m:
        return 0
    major = int(m.group(1))
    if major == 1 and m.group(2):
        return int(m.group(2))
    return major


def detect_java_21_plus() -> Tuple[bool, str, str]:
    """Check if Java 21+ is available in JAVA_HOME, PATH, or local tools folder."""
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    candidates: List[Tuple[str, str]] = []

    env_jh = os.environ.get("JAVA_HOME", "").strip()
    if env_jh:
        candidates.append((os.path.join(env_jh, "bin", "java.exe"), env_jh))

    # Check portable JDKs in C:\Ghidra and %LOCALAPPDATA%\OpcodeShield\tools
    for root in (
        Path("C:\\Ghidra"),
        Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "OpcodeShield" / "tools",
        Path("C:\\Program Files\\Java"),
    ):
        if root.is_dir():
            for child in sorted(root.iterdir(), reverse=True):
                java_exe = child / "bin" / "java.exe"
                if java_exe.is_file():
                    candidates.append((str(java_exe), str(child)))

    candidates.append(("java", ""))

    for exe, home in candidates:
        try:
            proc = subprocess.run(
                [exe, "-version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=6,
                creationflags=creation_flags,
            )
            out = proc.stdout or ""
            major = _parse_java_major(out)
            if major >= 21:
                first_line = out.splitlines()[0].strip() if out.splitlines() else f"JDK {major}"
                return True, first_line, home
        except Exception:
            continue
    return False, "", ""


def discover_all_ghidra_paths() -> List[str]:
    """Search C:\\ (2 levels) plus %LOCALAPPDATA%\\OpcodeShield\\tools for analyzeHeadless.bat."""
    found = discover_ghidra_headless("C:\\")
    tools_dir = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "OpcodeShield" / "tools"
    if tools_dir.is_dir():
        for child in sorted(tools_dir.iterdir(), reverse=True):
            cand = child / "support" / "analyzeHeadless.bat"
            if cand.is_file():
                norm = os.path.normpath(str(cand))
                if norm.lower() not in {x.lower() for x in found}:
                    found.append(norm)
    return found


def check_environment() -> EnvironmentStatus:
    """Inspect JDK 21+, Ghidra, PyTorch CUDA, and Transformers availability."""
    st = EnvironmentStatus()
    java_ok, java_ver, java_home = detect_java_21_plus()
    st.java_ok = java_ok
    st.java_version = java_ver
    st.java_home = java_home

    ghidras = discover_all_ghidra_paths()
    if ghidras:
        st.ghidra_ok = True
        st.ghidra_headless_path = ghidras[0]

    hw = detect_cuda_hardware()
    st.cuda_gpu_name = hw.gpu_name
    st.torch_ok = hw.torch_installed
    st.torch_cuda_ok = hw.torch_cuda_available

    try:
        import transformers  # type: ignore  # noqa: F401

        st.transformers_ok = True
    except ImportError:
        st.transformers_ok = False

    return st


def _download_file(
    url: str,
    dest: Path,
    log: Callable[[str], None],
    label: str,
) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "OpcodeShield-AutoSetup/0.2"})
    last_pct = -1
    with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as out:
        total = int(resp.headers.get("Content-Length", "0") or "0")
        done = 0
        chunk_size = 256 * 1024
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            out.write(chunk)
            done += len(chunk)
            if total > 0:
                pct = int((done * 100) / total)
                if pct >= last_pct + 10 or pct == 100:
                    last_pct = pct
                    log(f"[SETUP] Downloading {label}: {pct}% ({done // (1024 * 1024)}/{total // (1024 * 1024)} MB)")
    return dest


def ensure_java_21(log: Callable[[str], None]) -> str:
    ok, ver, home = detect_java_21_plus()
    if ok:
        if home:
            os.environ["JAVA_HOME"] = home
        log(f"[SETUP] Java 21+ already ready: {ver}")
        return home

    tools = _tools_root()
    zip_path = Path(tempfile.gettempdir()) / "temurin_jdk21_win64.zip"
    log("[SETUP] Java 21+ not found — downloading portable Eclipse Temurin JDK 21...")
    _download_file(ADOPTIUM_JDK21_URL, zip_path, log, "Eclipse Temurin JDK 21")

    log(f"[SETUP] Extracting JDK 21 into {tools}...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        top_dirs = {name.split("/")[0] for name in zf.namelist() if "/" in name}
        zf.extractall(tools)
    zip_path.unlink(missing_ok=True)

    for d in sorted(top_dirs, reverse=True):
        cand = tools / d
        if (cand / "bin" / "java.exe").is_file():
            os.environ["JAVA_HOME"] = str(cand)
            os.environ["PATH"] = str(cand / "bin") + os.pathsep + os.environ.get("PATH", "")
            log(f"[SETUP] Portable JDK 21 installed at: {cand}")
            return str(cand)

    raise RuntimeError("Downloaded JDK 21 archive did not contain bin/java.exe.")


def ensure_ghidra(log: Callable[[str], None]) -> str:
    existing = discover_all_ghidra_paths()
    if existing:
        log(f"[SETUP] Ghidra already installed: {existing[0]}")
        return existing[0]

    log("[SETUP] Querying official NSA Ghidra latest release from GitHub...")
    req = urllib.request.Request(
        GHIDRA_RELEASES_API,
        headers={"User-Agent": "OpcodeShield-AutoSetup/0.2", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        rel = json.loads(resp.read().decode("utf-8"))

    assets = rel.get("assets", [])
    zip_asset = next(
        (a for a in assets if str(a.get("name", "")).lower().endswith(".zip") and "ghidra_" in str(a.get("name", "")).lower()),
        None,
    )
    if not zip_asset:
        raise RuntimeError("Could not locate official Ghidra ZIP asset in latest GitHub release.")

    asset_name = str(zip_asset["name"])
    download_url = str(zip_asset["browser_download_url"])
    tools = _tools_root()
    zip_path = Path(tempfile.gettempdir()) / asset_name

    log(f"[SETUP] Downloading official {asset_name}...")
    _download_file(download_url, zip_path, log, asset_name)

    log(f"[SETUP] Extracting {asset_name} into {tools} (this takes ~20-40s)...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(tools)
    zip_path.unlink(missing_ok=True)

    discovered = discover_all_ghidra_paths()
    if not discovered:
        raise RuntimeError(f"Extracted {asset_name}, but analyzeHeadless.bat was not found under {tools}.")

    log(f"[SETUP] Ghidra installed and ready: {discovered[0]}")
    return discovered[0]


def ensure_cuda_ai_stack(log: Callable[[str], None]) -> bool:
    """Install PyTorch (CUDA if NVIDIA GPU detected, else CPU) + transformers + accelerate + safetensors."""
    if getattr(sys, "frozen", False):
        log("[SETUP] Running from frozen .exe — install PyTorch CUDA in Python source env for native CUDA AI.")
        return False

    st = check_environment()
    hw = detect_cuda_hardware()
    py = sys.executable
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

    def _run_pip(args: List[str], label: str) -> None:
        log(f"[SETUP] Running pip: {label}...")
        proc = subprocess.Popen(
            [py, "-m", "pip", "install", "--upgrade", *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="ignore",
            creationflags=creation_flags,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            clean = line.strip()
            if clean and any(k in clean for k in ("Downloading", "Installing", "Successfully", "ERROR", "Requirement")):
                log(f"[PIP] {clean[:150]}")
        code = proc.wait()
        if code != 0:
            raise RuntimeError(f"pip install ({label}) exited with code {code}")

    if not st.torch_ok or (hw.cuda_available and not st.torch_cuda_ok):
        if hw.cuda_available:
            _run_pip(["--index-url", "https://download.pytorch.org/whl/cu128", "torch"], "PyTorch CUDA (cu128)")
        else:
            _run_pip(["torch"], "PyTorch (CPU)")
    else:
        log(f"[SETUP] PyTorch already ready (CUDA={st.torch_cuda_ok}).")

    if not st.transformers_ok:
        _run_pip(["transformers>=4.48.0", "accelerate>=1.2.0", "safetensors>=0.4.5"], "transformers + accelerate + safetensors")
    else:
        log("[SETUP] Transformers + Accelerate already ready.")

    return True


def run_full_auto_setup(
    preload_model: bool = False,
    model_id: str = DEFAULT_LOCAL_MODEL,
    log_callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, str]:
    """
    One-click automatic setup for everything OpcodeShield needs:
      1. Portable Java JDK 21+ (if missing)
      2. Official NSA Ghidra (if missing)
      3. Direct PyTorch CUDA + Flash Attention + Transformers stack (if missing)
      4. Optional local AI model preload into cache/VRAM
    """
    log = log_callback or print
    log("[SETUP] === Starting OpcodeShield Automatic Full Setup ===")
    results: Dict[str, str] = {}

    java_home = ensure_java_21(log)
    results["java_home"] = java_home

    ghidra_path = ensure_ghidra(log)
    results["ghidra_headless_path"] = ghidra_path

    ensure_cuda_ai_stack(log)

    if preload_model:
        from cuda_engine import CUDAFlashAttentionEngine

        log(f"[SETUP] Preloading default local AI model '{model_id}'...")
        eng = CUDAFlashAttentionEngine(model_id=model_id, use_cuda=True, flash_attention=True, log_callback=log)
        eng.ensure_loaded()
        eng.unload()
        results["model_id"] = model_id

    log("[SETUP] === Automatic Full Setup Complete! ===")
    return results


if __name__ == "__main__":
    run_full_auto_setup(preload_model=False, log_callback=print)
