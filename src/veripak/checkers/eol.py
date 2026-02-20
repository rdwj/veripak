"""EOL status check via endoflife.date API."""

import datetime
import json
import re
import urllib.request
from typing import Optional

_BASE_URL = "https://endoflife.date/api"
_TIMEOUT = 10
_HEADERS = {"User-Agent": "veripak/0.1", "Accept": "application/json"}

# Known mappings where package name differs from endoflife.date slug
_SLUG_MAP: dict[str, str] = {
    "dotnet": "dotnet",
    "microsoft.netcore.app": "dotnet",
    "nodejs": "nodejs",
    "node": "nodejs",
}


def _fetch_cycles(product: str) -> tuple[Optional[list], Optional[str]]:
    """Fetch release cycle data from endoflife.date. Returns (cycles, slug) or (None, None)."""
    slug = _SLUG_MAP.get(product.lower(), product.lower())
    url = f"{_BASE_URL}/{slug}.json"
    try:
        req = urllib.request.Request(url, headers=_HEADERS)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode()), slug
    except Exception:
        pass
    # Try raw name if slug was remapped
    if slug != product.lower():
        url = f"{_BASE_URL}/{product.lower()}.json"
        try:
            req = urllib.request.Request(url, headers=_HEADERS)
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return json.loads(resp.read().decode()), product.lower()
        except Exception:
            pass
    return None, None


def _extract_branch(version: str) -> Optional[str]:
    """Extract major.minor from a version string, e.g. '6.0.1' → '6.0'."""
    m = re.match(r'^(\d+\.\d+)', version)
    if m:
        return m.group(1)
    m2 = re.match(r'^(\d+)', version)
    return m2.group(1) if m2 else None


def _is_eol(eol_value) -> Optional[bool]:
    """Interpret the eol field: bool or date string compared to today."""
    if isinstance(eol_value, bool):
        return eol_value
    if isinstance(eol_value, str):
        try:
            eol_date = datetime.date.fromisoformat(eol_value)
            return datetime.date.today() >= eol_date
        except ValueError:
            pass
    return None


def check_eol(name: str, versions_in_use: list[str]) -> dict:
    """Check EOL status for a package/version via endoflife.date.

    Returns a dict with keys:
      eol (bool|None), eol_date (str|None), cycle (str|None),
      latest_in_cycle (str|None), product (str|None)
    """
    empty: dict = {
        "eol": None,
        "eol_date": None,
        "cycle": None,
        "latest_in_cycle": None,
        "product": None,
    }

    result, slug = _fetch_cycles(name)
    if not result:
        return empty

    branch = _extract_branch(versions_in_use[0]) if versions_in_use else None

    # Find the matching cycle entry
    matched_cycle = None
    if branch:
        for entry in result:
            cycle = str(entry.get("cycle", ""))
            if cycle == branch or cycle.startswith(branch + "."):
                matched_cycle = entry
                break

    # Fall back to first entry if no version given or no match
    if matched_cycle is None and not versions_in_use and result:
        matched_cycle = result[0]

    if matched_cycle is None:
        return {**empty, "product": slug}

    eol_raw = matched_cycle.get("eol")
    eol_date_str = eol_raw if isinstance(eol_raw, str) else None

    return {
        "eol": _is_eol(eol_raw),
        "eol_date": eol_date_str,
        "cycle": str(matched_cycle.get("cycle", "")),
        "latest_in_cycle": matched_cycle.get("latest"),
        "product": slug,
    }
