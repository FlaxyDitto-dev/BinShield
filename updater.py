"""
BinShield - Cross-Platform Auto-Updater (Windows, Linux, macOS, Google Colab)
Queries GitHub Releases API (Fastly Global CDN) for the latest SemVer release,
compares against APP_VERSION, and downloads the platform-matched binary/update.

Behavior by variant:
- Desktop GUI (Windows / Linux / macOS): checks automatically on startup in background.
- Google Colab: auto-updates repo & custom model on notebook run.
- Android: checks automatically via UpdateChecker.kt.
- CLI: NEVER auto-updates on normal commands; requires explicit `binshield update`.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Tuple

APP_VERSION = "3.0.0"
GITHUB_REPO = "FlaxyDitto-dev/BinShield"
RELEASES_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"


@dataclass
class UpdateCheckResult:
    current_version: str
    latest_version: str
    update_available: bool
    release_url: str = ""
    asset_name: str = ""
    asset_url: str = ""
    release_notes: str = ""
    error: str = ""


def parse_semver(version: str) -> Tuple[int, int, int]:
    """Parse 'v1.1.0' or '1.1.0-beta.1' into (major, minor, patch)."""
    clean = (version or "0.0.0").strip().lstrip("vV")
    base = clean.split("-", 1)[0]
    parts = base.split(".")
    nums = []
    for p in parts[:3]:
        try:
            nums.append(int(p))
        except ValueError:
            nums.append(0)
    while len(nums) < 3:
        nums.append(0)
    return nums[0], nums[1], nums[2]


def _pick_asset_for_platform(assets: list, variant: str = "gui") -> Tuple[str, str]:
    """Select the matching release asset name & download URL for current OS + variant."""
    sys_name = platform.system().lower()
    want_cli = variant.lower() == "cli"

    preferred: list[str] = []
    if sys_name == "windows":
        preferred = ["binshield-cli.exe"] if want_cli else ["binshield-gui.exe", "binshield.exe"]
    elif sys_name == "linux":
        preferred = ["binshield-cli-linux", "binshield-linux-cli"] if want_cli else ["binshield-gui-linux", "binshield-linux-gui"]
    elif sys_name == "darwin":
        preferred = ["binshield-cli-macos", "binshield-macos-cli"] if want_cli else ["binshield-gui-macos", "binshield-macos-gui"]

    for pref in preferred:
        for a in assets:
            name = str(a.get("name", ""))
            if name.lower() == pref:
                return name, str(a.get("browser_download_url", ""))

    # Fallback: partial match
    for a in assets:
        name = str(a.get("name", ""))
        low = name.lower()
        if want_cli and "cli" in low and (
            (sys_name == "windows" and low.endswith(".exe"))
            or (sys_name == "linux" and "linux" in low)
            or (sys_name == "darwin" and "macos" in low)
        ):
            return name, str(a.get("browser_download_url", ""))
        if not want_cli and "gui" in low and (
            (sys_name == "windows" and low.endswith(".exe"))
            or (sys_name == "linux" and "linux" in low)
            or (sys_name == "darwin" and "macos" in low)
        ):
            return name, str(a.get("browser_download_url", ""))

    return "", ""


def check_for_updates(variant: str = "gui", timeout: int = 10) -> UpdateCheckResult:
    """Query GitHub Releases API to check if a newer SemVer release is available."""
    try:
        req = urllib.request.Request(
            RELEASES_API_URL,
            headers={
                "User-Agent": f"BinShield/{APP_VERSION}",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))

        latest_tag = str(data.get("tag_name") or APP_VERSION)
        latest_clean = latest_tag.lstrip("vV")
        update_avail = parse_semver(latest_clean) > parse_semver(APP_VERSION)
        asset_name, asset_url = _pick_asset_for_platform(data.get("assets") or [], variant=variant)

        return UpdateCheckResult(
            current_version=APP_VERSION,
            latest_version=latest_clean,
            update_available=update_avail,
            release_url=str(data.get("html_url") or f"https://github.com/{GITHUB_REPO}/releases"),
            asset_name=asset_name,
            asset_url=asset_url,
            release_notes=str(data.get("body") or "")[:600],
        )
    except Exception as exc:
        return UpdateCheckResult(
            current_version=APP_VERSION,
            latest_version=APP_VERSION,
            update_available=False,
            error=str(exc),
        )


def download_update(
    result: UpdateCheckResult,
    dest_dir: Optional[Path] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> Path:
    """Download the matched release binary over GitHub's Fastly CDN."""
    log = log_callback or (lambda msg: None)
    if not result.asset_url or not result.asset_name:
        raise ValueError(
            f"No prebuilt binary asset found for {platform.system()} in v{result.latest_version}. "
            f"Download source from: {result.release_url}"
        )

    out_dir = dest_dir or (Path(tempfile.gettempdir()) / "BinShield_Updates")
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / result.asset_name
    tmp = dest.with_suffix(dest.suffix + ".part")

    log(f"[UPDATE] Downloading {result.asset_name} (v{result.latest_version})...")
    req = urllib.request.Request(result.asset_url, headers={"User-Agent": f"BinShield/{APP_VERSION}"})
    with urllib.request.urlopen(req, timeout=180) as resp, open(tmp, "wb") as out:
        while True:
            chunk = resp.read(256 * 1024)
            if not chunk:
                break
            out.write(chunk)
    tmp.replace(dest)

    if os.name != "nt":
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # If running as a frozen PyInstaller executable on Unix, offer atomic swap path
    log(f"[UPDATE] Downloaded v{result.latest_version} to: {dest}")
    return dest


def apply_self_update(
    downloaded_binary: Path,
    relaunch: bool = True,
    log_callback: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str]:
    """
    One-click self-replace updater for frozen executables (Windows .exe / Linux / macOS).
    - On Windows: writes a tiny self-deleting .bat helper that waits for the current PID to exit,
      atomically moves the new .exe into place, and optionally relaunches it.
    - On Linux/macOS: atomically replaces the running executable via os.replace().
    """
    import subprocess
    log = log_callback or (lambda msg: None)
    if not getattr(sys, "frozen", False):
        return False, f"Running from source; downloaded binary is ready at: {downloaded_binary}"

    current_exe = Path(sys.executable).resolve()
    if not downloaded_binary.is_file():
        return False, f"Downloaded update not found: {downloaded_binary}"

    if os.name == "nt":
        pid = os.getpid()
        bat = Path(tempfile.gettempdir()) / f"gg_self_update_{pid}.bat"
        relaunch_cmd = f'start "" "{current_exe}"' if relaunch else ""
        script = (
            "@echo off\r\n"
            f":wait\r\n"
            f'tasklist /FI "PID eq {pid}" 2>nul | find "{pid}" >nul\r\n'
            "if not errorlevel 1 (timeout /t 1 /nobreak >nul & goto wait)\r\n"
            f'move /Y "{downloaded_binary}" "{current_exe}" >nul\r\n'
            f"{relaunch_cmd}\r\n"
            'del "%~f0"\r\n'
        )
        bat.write_text(script, encoding="utf-8")
        subprocess.Popen(["cmd.exe", "/c", str(bat)], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        log(f"[UPDATE] Scheduled Windows self-replace swap for {current_exe.name}.")
        return True, f"Self-update scheduled; replacing {current_exe.name} on exit."

    os.replace(downloaded_binary, current_exe)
    current_exe.chmod(current_exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    log(f"[UPDATE] Replaced {current_exe} in-place.")
    if relaunch:
        os.execv(str(current_exe), [str(current_exe)])
    return True, f"Updated {current_exe} in-place."
