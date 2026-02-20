"""CVE lookup via OSV.dev (programmatic ecosystems) and NVD API v2 (non-programmatic)."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from .. import config

_HEADERS = {"User-Agent": "veripak/0.1"}
_TIMEOUT = 15

# ---------------------------------------------------------------------------
# Ecosystem classification
# ---------------------------------------------------------------------------

OSV_ECOSYSTEMS = {"python", "javascript", "java", "go", "dotnet", "perl", "php"}
NVD_ECOSYSTEMS = {"c", "cpp", "system", "desktop-app", "driver"}

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
        f"{_NVD_BASE}?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=20"
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
        raw_items = _nvd_fetch(name, api_key)
        name_lower = name.lower()
        seen: set[str] = set()
        versions_cves = []
        for item in raw_items:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id", "UNKNOWN")
            descriptions = cve_obj.get("descriptions", [])
            summary = descriptions[0].get("value", "") if descriptions else ""
            if name_lower not in summary.lower() or cve_id in seen:
                continue
            seen.add(cve_id)
            versions_cves.append({
                "id": cve_id,
                "severity": _extract_nvd_severity(item),
                "summary": summary,
                "note": "NVD keyword search; not filtered by version",
            })
        latest_cves = []
        replacement_cves = []
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
