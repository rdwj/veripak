"""Deterministic migration complexity and urgency computations."""

import datetime
import re


def _version_tuple(ver: str) -> tuple[int, ...]:
    """Extract numeric parts of a version string."""
    return tuple(int(p) for p in re.findall(r"\d+", ver))


# Known CalVer packages (supplementary signal)
_KNOWN_CALVER = {"automat", "pip", "setuptools", "certifi", "black", "isort", "twisted"}


def is_calver(version: str) -> bool:
    """Detect if a version string uses calendar versioning.

    Checks for:
    - YYYY.MM.patch format (major >= 2000 and <= current year + 1)
    - YY.MM.patch format (major 10-99, minor 1-12)
    - YYYY.MM.DD format
    """
    parts = _version_tuple(version)
    if not parts:
        return False

    current_year = datetime.date.today().year
    major = parts[0]

    # YYYY.MM.patch or YYYY.MM.DD — full year as major
    if 2000 <= major <= current_year + 1:
        if len(parts) >= 2 and 1 <= parts[1] <= 12:
            return True

    # YY.MM.patch — two-digit year as major
    if 10 <= major <= 99:
        short_year = current_year % 100
        if major <= short_year + 1 and len(parts) >= 2 and 1 <= parts[1] <= 12:
            return True

    return False


def compute_migration_complexity(
    version_in_use: str,
    latest_version: str,
    eol: bool | None = None,
) -> dict:
    """Compute migration complexity from version gap.

    Returns dict with: version_gap, major_gap, minor_gap,
    migration_complexity, breaking_change_likely
    """
    result = {
        "version_gap": None,
        "major_gap": 0,
        "minor_gap": 0,
        "migration_complexity": "unknown",
        "breaking_change_likely": None,
    }

    if not version_in_use or not latest_version:
        return result

    result["version_gap"] = f"{version_in_use} -> {latest_version}"

    try:
        in_parts = _version_tuple(version_in_use)
        latest_parts = _version_tuple(latest_version)
    except Exception:
        return result

    if not in_parts or not latest_parts:
        return result

    major_gap = (
        latest_parts[0] - in_parts[0]
        if len(latest_parts) > 0 and len(in_parts) > 0
        else 0
    )
    minor_gap = 0
    if major_gap == 0 and len(in_parts) > 1 and len(latest_parts) > 1:
        minor_gap = latest_parts[1] - in_parts[1]

    result["major_gap"] = max(0, major_gap)
    result["minor_gap"] = max(0, minor_gap)

    # CalVer detection: calendar-versioned packages use year-based major
    # numbers that don't indicate breaking API changes
    both_calver = is_calver(version_in_use) and is_calver(latest_version)
    if both_calver:
        # Compute time gap in years instead of version numbers
        year_gap = abs(latest_parts[0] - in_parts[0])
        # For two-digit years, the gap is the same
        if year_gap < 3:
            result["migration_complexity"] = "minor"
            result["breaking_change_likely"] = False
        else:
            result["migration_complexity"] = "major"
            result["breaking_change_likely"] = True  # API stability not guaranteed over long periods
        result["_calver"] = True
        return result

    if major_gap <= 0 and minor_gap <= 0:
        result["migration_complexity"] = "patch"
        result["breaking_change_likely"] = False
    elif major_gap <= 0:
        result["migration_complexity"] = "minor"
        result["breaking_change_likely"] = False
    elif major_gap >= 5:
        result["migration_complexity"] = "rewrite"
        result["breaking_change_likely"] = True
    else:
        result["migration_complexity"] = "major"
        result["breaking_change_likely"] = True

    # EOL override: a package at end-of-life requires migration regardless of version gap.
    # A "patch" result for an EOL package is misleading — the package must be replaced.
    if eol is True and result["migration_complexity"] == "patch":
        result["migration_complexity"] = "major"
        result["breaking_change_likely"] = True
        result["_eol_override"] = True

    result["_calver"] = False
    return result


# ---------------------------------------------------------------------------
# Urgency floor computation
# ---------------------------------------------------------------------------

_URGENCY_ORDER = {"low": 0, "medium": 1, "high": 2, "immediate": 3}


def compute_urgency_floor(
    eol: bool | None,
    high_critical_count: int,
    total_cves: int,
    migration_complexity: str,
    has_critical: bool = False,
) -> str:
    """Compute a minimum urgency score from raw audit data.

    The model may escalate beyond this floor but should not rate lower.

    Rules:
    - EOL + any HIGH/CRITICAL CVE -> "immediate"
    - EOL without CVEs -> "high"
    - Active support + any CRITICAL CVE -> "high"
    - Active support + HIGH CVEs or (EOL + major version gap) -> "medium"
    - Active support + only MEDIUM/LOW CVEs -> "low"
    """
    if eol and high_critical_count > 0:
        return "immediate"

    if eol:
        return "high"

    if has_critical:
        return "high"

    if high_critical_count > 0:
        return "medium"

    if total_cves > 0:
        return "low"

    if migration_complexity in ("major", "rewrite"):
        return "medium"

    return "low"


def urgency_at_least(current: str | None, floor: str) -> str:
    """Return the higher of current urgency and the floor."""
    if current is None:
        return floor
    current_rank = _URGENCY_ORDER.get(current.lower(), -1)
    floor_rank = _URGENCY_ORDER.get(floor.lower(), 0)
    if current_rank >= floor_rank:
        return current
    return floor
