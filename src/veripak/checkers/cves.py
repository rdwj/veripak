"""CVE lookup via OSV.dev (programmatic ecosystems) and NVD API v2 (non-programmatic)."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from packaging.version import Version, InvalidVersion

from .. import config
from .. import model_caller

_HEADERS = {"User-Agent": "veripak/0.1"}
_TIMEOUT = 15

# ---------------------------------------------------------------------------
# Ecosystem classification
# ---------------------------------------------------------------------------

OSV_ECOSYSTEMS = {"python", "javascript", "java", "go", "dotnet", "perl", "php"}
NVD_ECOSYSTEMS = {"c", "cpp", "system", "desktop-app", "driver"}

# Linux distro ecosystems to try via OSV before falling back to NVD keyword search
_OSV_LINUX_ECOSYSTEMS = ["Debian", "Alpine", "Ubuntu"]

OSV_ECOSYSTEM_MAP = {
    "python": "PyPI",
    "javascript": "npm",
    "java": "Maven",
    "go": "Go",
    "dotnet": "NuGet",
    "perl": "CPAN",
    "php": "Packagist",
}

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_STRINGS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def _cvss_score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def _extract_osv_severity(vuln: dict) -> str:
    db_sev = vuln.get("database_specific", {}).get("severity", "").upper()
    if db_sev in _SEVERITY_STRINGS:
        return db_sev

    for entry in vuln.get("severity", []):
        if entry.get("type") in ("CVSS_V3", "CVSS_V4"):
            try:
                return _cvss_score_to_severity(float(entry.get("score", "")))
            except (ValueError, TypeError):
                pass

    for affected in vuln.get("affected", []):
        for sev in affected.get("severity", []):
            try:
                return _cvss_score_to_severity(float(sev.get("score", "")))
            except (ValueError, TypeError):
                pass

    return "UNKNOWN"


def _extract_nvd_severity(cve_item: dict) -> str:
    metrics = cve_item.get("cve", {}).get("metrics", {})
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_key, [])
        if entries:
            cvss = entries[0].get("cvssData", {})
            base = cvss.get("baseSeverity", "")
            if base:
                return base.upper()
            score = cvss.get("baseScore")
            if score is not None:
                return _cvss_score_to_severity(float(score))
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _http_post_json(url: str, payload: dict) -> tuple[Optional[int], Optional[bytes]]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={**_HEADERS, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except Exception:
        return None, None


def _parse_body(body: Optional[bytes]) -> Optional[dict]:
    if not body:
        return None
    try:
        return json.loads(body.decode())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# OSV.dev
# ---------------------------------------------------------------------------

_OSV_URL = "https://api.osv.dev/v1/query"
_OSV_SLEEP = 0.1


def _osv_normalise(vulns: list) -> list[dict]:
    return [
        {
            "id": v.get("id", "UNKNOWN"),
            "severity": _extract_osv_severity(v),
            "summary": v.get("summary", ""),
        }
        for v in vulns
    ]


def _osv_query_version(name: str, ecosystem: str, version: str) -> list[dict]:
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    status, body = _http_post_json(_OSV_URL, payload)
    time.sleep(_OSV_SLEEP)
    if status != 200:
        return []
    return _osv_normalise((_parse_body(body) or {}).get("vulns", []))


def _osv_query_package(name: str, ecosystem: str) -> list[dict]:
    payload = {"package": {"name": name, "ecosystem": ecosystem}}
    status, body = _http_post_json(_OSV_URL, payload)
    time.sleep(_OSV_SLEEP)
    if status != 200:
        return []
    return _osv_normalise((_parse_body(body) or {}).get("vulns", []))


def _dedupe(cves: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result = []
    for c in cves:
        if c["id"] not in seen:
            seen.add(c["id"])
            result.append(c)
    return result


# ---------------------------------------------------------------------------
# NVD API v2
# ---------------------------------------------------------------------------

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_MAX_RETRIES = 3

# Module-level request-time ring for rate limiting
_nvd_request_times: list[float] = []


def _nvd_rate_limit(api_key: str) -> None:
    """Block until NVD rate limit allows another request."""
    max_req, window = (50, 30.0) if api_key else (5, 10.0)
    now = time.time()
    _nvd_request_times[:] = [t for t in _nvd_request_times if now - t < window]
    if len(_nvd_request_times) >= max_req:
        sleep_until = _nvd_request_times[0] + window
        wait = max(0.0, sleep_until - now) + 0.1
        time.sleep(wait)
        now = time.time()
        _nvd_request_times[:] = [t for t in _nvd_request_times if now - t < window]
    _nvd_request_times.append(time.time())


def _nvd_fetch(keyword: str, api_key: str) -> list[dict]:
    url = (
        f"{_NVD_BASE}?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=100"
    )
    extra = {"apiKey": api_key} if api_key else {}
    for attempt in range(_NVD_MAX_RETRIES):
        _nvd_rate_limit(api_key)
        req = urllib.request.Request(url, headers={**_HEADERS, **extra})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return (_parse_body(resp.read()) or {}).get("vulnerabilities", [])
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 503):
                time.sleep(2 ** (attempt + 1))
            else:
                break
        except Exception:
            break
    return []


# ---------------------------------------------------------------------------
# CPE version range filtering
# ---------------------------------------------------------------------------


def _version_in_cpe_range(version_str: str, cpe_match: dict) -> bool:
    """Return True if version_str falls within the CPE match's version range.

    Uses the four versionStart/End Inclusive/Excluding fields from NVD CPE data.
    On any parse failure, returns True (conservative: assume affected).
    """
    try:
        v = Version(version_str)
    except InvalidVersion:
        return True

    start_incl = cpe_match.get("versionStartIncluding", "")
    start_excl = cpe_match.get("versionStartExcluding", "")
    end_incl = cpe_match.get("versionEndIncluding", "")
    end_excl = cpe_match.get("versionEndExcluding", "")

    has_range = any([start_incl, start_excl, end_incl, end_excl])
    if not has_range:
        return bool(cpe_match.get("vulnerable", True))

    try:
        if start_incl and v < Version(start_incl):
            return False
        if start_excl and v <= Version(start_excl):
            return False
        if end_incl and v > Version(end_incl):
            return False
        if end_excl and v >= Version(end_excl):
            return False
    except InvalidVersion:
        return True

    return True


def _cve_affects_versions(cve_item: dict, versions: list[str]) -> bool:
    """Return True if the CVE affects any of the given versions.

    If the CVE has no CPE configuration data, returns True (conservative).
    """
    configurations = cve_item.get("cve", {}).get("configurations", [])
    if not configurations:
        return True

    for config_entry in configurations:
        for node in config_entry.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue
                for ver in versions:
                    if _version_in_cpe_range(ver, cpe_match):
                        return True

    return False


# ---------------------------------------------------------------------------
# NVD keyword helper
# ---------------------------------------------------------------------------


def _suggest_nvd_keyword(name: str, ecosystem: str) -> str:
    """Ask the model for a precise NVD search keyword. Falls back to name on any failure."""
    prompt = (
        f'What is the best NVD (National Vulnerability Database) keywordSearch term '
        f'for the package "{name}" (ecosystem: {ecosystem})? '
        f'Reply with just the search term string, nothing else. '
        f'Example: for "dotnet" in the "system" ecosystem, reply: microsoft .net core'
    )
    try:
        keyword = model_caller.call_model(prompt).strip().strip('"').strip("'").lower()
        if keyword and len(keyword) <= 100:
            return keyword
    except Exception:
        pass
    return name


# ---------------------------------------------------------------------------
# no_cpe_data model filter
# ---------------------------------------------------------------------------


def _filter_no_cpe_via_model(
    entries: list[dict], name: str, versions: list[str]
) -> list[dict]:
    """Use the model to filter no_cpe_data CVE entries by version relevance.

    NVD entries without CPE configuration data cannot be version-filtered
    structurally. This function sends all such entries in a single batch to
    the model, which checks each description for two disqualifying conditions:
      1. The stated affected version range clearly excludes the given version(s).
      2. The CVE is for a plugin/extension rather than the package itself.

    Falls back to returning all entries unchanged on any failure.
    """
    if not entries:
        return entries

    version_str = ", ".join(versions)
    lines = [
        f'{e["id"]}: {(e.get("summary") or "").replace(chr(10), " ")[:400]}'
        for e in entries
    ]

    prompt = (
        f'For each CVE below, does it affect {name} version {version_str}? '
        f'Answer false if the described affected version range clearly excludes '
        f'{version_str}, or if the CVE is for a plugin/extension rather than '
        f'{name} itself. If uncertain, answer true (conservative). '
        'Reply with ONLY a JSON array: [{"id":"CVE-...","affects":true},...]\n\n'
        + "\n".join(lines)
    )

    try:
        raw = model_caller.call_model(prompt).strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()
        decisions = json.loads(raw)
        if not isinstance(decisions, list):
            return entries
        exclude_ids = {str(d["id"]) for d in decisions if not d.get("affects", True)}
        return [e for e in entries if e["id"] not in exclude_ids]
    except Exception:
        return entries


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_cves(
    name: str,
    ecosystem: str,
    versions: list[str],
    latest_version: str = "",
    replacement_name: str = "",
) -> dict:
    """Query CVEs for a package.

    Returns a dict with keys:
      method, versions_cves, latest_cves, replacement_cves,
      total_count, high_critical_count
    """
    if ecosystem in OSV_ECOSYSTEMS:
        osv_eco = OSV_ECOSYSTEM_MAP[ecosystem]

        versions_cves_raw: list[dict] = []
        for ver in versions:
            versions_cves_raw.extend(_osv_query_version(name, osv_eco, ver))

        latest_cves_raw: list[dict] = []
        if latest_version:
            latest_cves_raw = _osv_query_version(name, osv_eco, latest_version)

        replacement_cves_raw: list[dict] = []
        if replacement_name and replacement_name.lower() != name.lower():
            replacement_cves_raw = _osv_query_package(replacement_name, osv_eco)

        versions_cves = _dedupe(versions_cves_raw)
        latest_cves = _dedupe(latest_cves_raw)
        replacement_cves = _dedupe(replacement_cves_raw)
        method = "osv_dev"

    elif ecosystem in NVD_ECOSYSTEMS:
        api_key = config.get("nvd_api_key") or ""

        # 1. Try OSV.dev for common Linux ecosystems first.
        # Skip when versions_in_use is provided: distro package versioning (e.g. "9.2.10+dfsg-1")
        # cannot be compared against upstream versions (e.g. "6.7.4"), causing false positives.
        osv_cves_by_id: dict[str, dict] = {}
        if not versions:
            for linux_eco in _OSV_LINUX_ECOSYSTEMS:
                for entry in _osv_query_package(name, linux_eco):
                    cve_id = entry["id"]
                    if cve_id not in osv_cves_by_id:
                        osv_cves_by_id[cve_id] = entry

        # 2. NVD keyword search with CPE version filtering
        nvd_keyword = _suggest_nvd_keyword(name, ecosystem)
        raw_items = _nvd_fetch(nvd_keyword, api_key)
        name_lower = name.lower()
        # When the model suggested a specific keyword (different from the raw package name),
        # trust NVD's search results directly — applying a text filter would drop real CVEs
        # whose descriptions don't repeat the keyword verbatim (e.g. ".NET and Visual Studio"
        # doesn't contain "microsoft .net core"). Only filter when using the raw name, where
        # NVD results can include unrelated products with similar names.
        apply_text_filter = nvd_keyword == name
        nvd_cves_by_id: dict[str, dict] = {}
        for item in raw_items:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id", "UNKNOWN")
            descriptions = cve_obj.get("descriptions", [])
            summary = descriptions[0].get("value", "") if descriptions else ""
            if cve_id in nvd_cves_by_id:
                continue
            if apply_text_filter and name_lower not in summary.lower():
                continue

            entry: dict = {
                "id": cve_id,
                "severity": _extract_nvd_severity(item),
                "summary": summary,
            }

            configurations = item.get("cve", {}).get("configurations", [])
            if not configurations:
                entry["version_filter"] = "no_cpe_data"
                nvd_cves_by_id[cve_id] = entry
            elif versions and not _cve_affects_versions(item, versions):
                # Filtered out by version range — silently drop
                pass
            else:
                entry["version_filter"] = "matched" if versions else "unfiltered"
                nvd_cves_by_id[cve_id] = entry

        # 2.5. Filter no_cpe_data entries via the model when specific versions are known.
        # Structural CPE version filtering cannot apply to these entries, so we ask the
        # model to exclude CVEs whose descriptions clearly target a different version range
        # or a third-party plugin/extension rather than the package itself.
        if versions:
            no_cpe = [
                e for e in nvd_cves_by_id.values()
                if e.get("version_filter") == "no_cpe_data"
            ]
            if no_cpe:
                kept = _filter_no_cpe_via_model(no_cpe, name, versions)
                kept_ids = {e["id"] for e in kept}
                nvd_cves_by_id = {
                    cve_id: e
                    for cve_id, e in nvd_cves_by_id.items()
                    if e.get("version_filter") != "no_cpe_data" or cve_id in kept_ids
                }

        # 3. Merge: OSV takes precedence on duplicate IDs
        merged: dict[str, dict] = {**nvd_cves_by_id, **osv_cves_by_id}
        versions_cves = list(merged.values())

        latest_cves = []
        replacement_cves = []

        if osv_cves_by_id and nvd_cves_by_id:
            method = "osv_dev+nvd_api"
        elif osv_cves_by_id:
            method = "osv_dev"
        else:
            method = "nvd_api"

    else:
        return {
            "method": "skipped",
            "versions_cves": [],
            "latest_cves": [],
            "replacement_cves": [],
            "total_count": 0,
            "high_critical_count": 0,
        }

    all_ids: set[str] = set()
    high_critical = 0
    for entry in versions_cves + latest_cves + replacement_cves:
        all_ids.add(entry["id"])
        if entry.get("severity") in ("HIGH", "CRITICAL"):
            high_critical += 1

    return {
        "method": method,
        "versions_cves": versions_cves,
        "latest_cves": latest_cves,
        "replacement_cves": replacement_cves,
        "total_count": len(all_ids),
        "high_critical_count": high_critical,
    }
