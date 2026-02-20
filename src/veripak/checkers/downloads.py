"""Download validation checker, ported from legacy-package-analysis."""

import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Optional

_USER_AGENT = "veripak/0.1"
_TIMEOUT = 15

PYTHON_ECOSYSTEMS = {"python"}
JS_ECOSYSTEMS = {"javascript"}
HEAD_ECOSYSTEMS = {
    "java", "go", "dotnet", "perl", "php",
    "c", "cpp", "system", "desktop-app", "driver",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _http_head(url: str, timeout: int = _TIMEOUT) -> tuple[bool, str]:
    """Return (reachable, status_or_error_string)."""
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", _USER_AGENT)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, str(resp.status)
    except urllib.error.HTTPError as e:
        if e.code < 400:
            return True, str(e.code)
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, str(e)


def _first_line(text: str, max_len: int = 120) -> Optional[str]:
    if not text:
        return None
    line = text.strip().splitlines()[0].strip()
    return line[:max_len] if line else None


# ---------------------------------------------------------------------------
# Per-ecosystem validators
# ---------------------------------------------------------------------------


def _validate_python(name: str, version: str) -> dict:
    tmpdir = tempfile.mkdtemp(prefix="veripak_")
    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "pip", "download",
                "--no-deps", "--dest", tmpdir,
                f"{name}=={version}",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        confirmed = result.returncode == 0
        notes = None if confirmed else _first_line(result.stderr or result.stdout)
        return {"method": "pip_download_no_deps", "confirmed": confirmed, "notes": notes}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _validate_javascript(name: str, version: str) -> dict:
    try:
        result = subprocess.run(
            ["npm", "pack", f"{name}@{version}", "--dry-run"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        confirmed = result.returncode == 0
        notes = None if confirmed else _first_line(result.stderr or result.stdout)
    except FileNotFoundError:
        confirmed = False
        notes = "npm not available"
    return {"method": "npm_pack_dry_run", "confirmed": confirmed, "notes": notes}


def _validate_http_head(download_url: str) -> dict:
    if not download_url:
        return {
            "method": "skipped",
            "confirmed": False,
            "notes": "No download_url available",
        }
    reachable, status = _http_head(download_url)
    notes = None if reachable else f"HTTP HEAD failed: {status}"
    return {"method": "http_head", "confirmed": reachable, "notes": notes}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_download(
    name: str,
    ecosystem: str,
    version: str,
    download_url: str = "",
) -> dict:
    """Confirm the package can be retrieved.

    Returns a dict with keys: confirmed (bool), method (str), notes (str|None).
    """
    if ecosystem in PYTHON_ECOSYSTEMS:
        if not version:
            return {"method": "skipped", "confirmed": False, "notes": "version unknown"}
        return _validate_python(name, version)

    if ecosystem in JS_ECOSYSTEMS:
        if not version:
            return {"method": "skipped", "confirmed": False, "notes": "version unknown"}
        return _validate_javascript(name, version)

    if ecosystem in HEAD_ECOSYSTEMS:
        return _validate_http_head(download_url)

    # Unknown ecosystem — attempt HTTP HEAD if we have a URL
    if download_url:
        return _validate_http_head(download_url)

    return {
        "method": "skipped",
        "confirmed": False,
        "notes": f"No download strategy for ecosystem '{ecosystem}'",
    }
