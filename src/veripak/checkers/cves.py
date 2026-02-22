"""CVE lookup via OSV.dev (programmatic ecosystems) and NVD API v2 (non-programmatic)."""

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from packaging.version import InvalidVersion, Version

from .. import config, model_caller
from .. import tavily as tavily_client

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

# Maps human-readable Java package names to their OSV/Maven groupId:artifactId identifiers.
# OSV indexes Java packages by Maven coordinates, not display names, so "Apache Tomcat"
# returns 0 results whereas "org.apache.tomcat:tomcat-catalina" returns 20+.
_JAVA_OSV_NAMES: dict[str, str] = {
    "apache tomcat": "org.apache.tomcat:tomcat-catalina",
    "apache poi": "org.apache.poi:poi",
    "apache struts": "org.apache.struts:struts2-core",
    "apache activemq": "org.apache.activemq:activemq-broker",
    "activemq": "org.apache.activemq:activemq-broker",
    "spring boot": "org.springframework.boot:spring-boot",
    "spring framework": "org.springframework:spring-core",
    "log4j": "org.apache.logging.log4j:log4j-core",
    "jackson": "com.fasterxml.jackson.core:jackson-databind",
    "hibernate": "org.hibernate:hibernate-core",
    "apache commons-text": "org.apache.commons:commons-text",
    "apache commons-collections": "org.apache.commons:commons-collections4",
    "guava": "com.google.guava:guava",
    "gson": "com.google.code.gson:gson",
    "netty": "io.netty:netty-handler",
}

# OSV indexes JavaScript packages by their npm package name. Map common display
# names (which may include ".js" suffixes or spaces) to their npm identifiers.
_JS_OSV_NAMES: dict[str, str] = {
    "angularjs": "angular",
    "angular.js": "angular",
    "lodash.js": "lodash",
    "vue.js": "vue",
    "react.js": "react",
    "jquery ui": "jquery-ui",
    "moment.js": "moment",
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


def _http_post_json(url: str, payload: dict) -> tuple[int | None, bytes | None]:
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


def _parse_body(body: bytes | None) -> dict | None:
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
            "aliases": v.get("aliases", []),
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


def _dedupe_cross_source(cves: list[dict]) -> list[dict]:
    """Deduplicate CVEs across sources using alias relationships.

    Groups CVEs that share any ID or alias into clusters, then keeps
    the best entry from each cluster (preferring CVE-prefixed IDs over
    GHSA, and entries with severity data).
    """
    if not cves:
        return cves

    # Build union-find structure based on ID + aliases
    # Map every known identifier to the list index
    id_to_indices: dict[str, list[int]] = {}
    for i, entry in enumerate(cves):
        entry_id = entry.get("id", "")
        all_ids = [entry_id] + entry.get("aliases", [])
        for aid in all_ids:
            if aid:
                id_to_indices.setdefault(aid, []).append(i)

    # Group indices that share any identifier
    visited: set[int] = set()
    clusters: list[list[int]] = []

    for i in range(len(cves)):
        if i in visited:
            continue
        # BFS to find all connected indices
        cluster: list[int] = []
        queue = [i]
        while queue:
            idx = queue.pop()
            if idx in visited:
                continue
            visited.add(idx)
            cluster.append(idx)
            # Find all IDs for this entry
            entry = cves[idx]
            all_ids = [entry.get("id", "")] + entry.get("aliases", [])
            for aid in all_ids:
                if aid:
                    for linked_idx in id_to_indices.get(aid, []):
                        if linked_idx not in visited:
                            queue.append(linked_idx)
        clusters.append(cluster)

    # Pick the best entry from each cluster
    result: list[dict] = []
    for cluster in clusters:
        entries = [cves[i] for i in cluster]
        # Prefer CVE-prefixed IDs over GHSA
        best = entries[0]
        for entry in entries:
            entry_id = entry.get("id", "")
            best_id = best.get("id", "")
            # Prefer CVE- prefix
            if entry_id.startswith("CVE-") and not best_id.startswith("CVE-"):
                best = entry
            # Prefer entries with known severity
            elif entry.get("severity", "UNKNOWN") != "UNKNOWN" and best.get("severity", "UNKNOWN") == "UNKNOWN":
                best = entry

        # Collect all aliases from the cluster
        all_aliases: set[str] = set()
        for entry in entries:
            all_aliases.add(entry.get("id", ""))
            all_aliases.update(entry.get("aliases", []))
        all_aliases.discard(best.get("id", ""))
        all_aliases.discard("")

        merged = dict(best)
        merged["aliases"] = sorted(all_aliases)
        result.append(merged)

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


def _nvd_fetch_by_cpe_name(cpe_name: str, api_key: str) -> list[dict]:
    """Query NVD for CVEs matching a specific CPE name (version-aware).

    Unlike keyword search, cpeName queries return only CVEs where the specified
    product version falls within the CVE's declared vulnerable range. NVD
    applies its own version matching server-side, so results are authoritative
    and pagination is manageable (tens of CVEs per version, not hundreds).
    """
    url = f"{_NVD_BASE}?cpeName={urllib.parse.quote(cpe_name)}&resultsPerPage=500"
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


def _cpe_matches_package(cve_item: dict, name: str, ecosystem: str) -> bool:
    """Check if any CPE product in the CVE matches the target package.

    Returns True if the CVE has no CPE data (conservative) or if any CPE
    product string matches the target package name.
    """
    configurations = cve_item.get("cve", {}).get("configurations", [])
    if not configurations:
        return True  # No CPE data — can't filter, keep it

    name_lower = name.lower().replace("-", "_").replace(" ", "_")
    name_variants = {name_lower, name.lower(), name.lower().replace("_", "-")}

    for config_entry in configurations:
        for node in config_entry.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                # CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
                parts = criteria.split(":")
                if len(parts) >= 5:
                    product = parts[4].lower()
                    # Check product match (allow for underscores/hyphens)
                    product_variants = {product, product.replace("_", "-"), product.replace("-", "_")}
                    if name_variants & product_variants:
                        return True
                    # Also check if name is a substring of vendor:product
                    if name_lower in product or product in name_lower:
                        return True

    return False


# ---------------------------------------------------------------------------
# NVD model helpers
# ---------------------------------------------------------------------------


def _suggest_nvd_keyword(name: str, ecosystem: str) -> str:
    """Ask the model for a precise NVD search keyword. Falls back to name on any failure."""
    eco_label = {
        "c": "C library",
        "cpp": "C++ library",
        "system": "Linux system package",
        "desktop-app": "desktop application",
        "driver": "hardware driver",
    }.get(ecosystem, ecosystem)

    prompt = (
        f'What is the best NVD (National Vulnerability Database) keywordSearch term '
        f'for the package "{name}" (a {eco_label})? '
        f'Reply with just the search term string, nothing else. '
        f'Use the name of the {eco_label}, not wrappers in other languages. '
        f'Example: for "dotnet" in the "system" ecosystem, reply: microsoft .net core'
    )
    try:
        keyword = model_caller.call_model(prompt).strip().strip('"').strip("'").lower()
        if keyword and len(keyword) <= 100:
            return keyword
    except Exception:
        pass
    return name


# Hardcoded CPE overrides for packages where the model reliably suggests the wrong string.
# Values are a list because some packages span multiple NVD CPE product entries.
# The first entry in the list is used for the primary CPE query; additional entries
# are queried in sequence and their results merged.
_CPE_OVERRIDES: dict[str, list[str]] = {
    # .NET 5+ dropped the "Core" branding in CPE; runtime CVEs are under "microsoft:.net",
    # ASP.NET Core CVEs are under "microsoft:asp.net_core".
    "dotnet": ["microsoft:.net", "microsoft:asp.net_core"],
    "microsoft.netcore.app": ["microsoft:.net", "microsoft:asp.net_core"],
    "tomcat": ["apache:tomcat"],
    "apache tomcat": ["apache:tomcat"],
    "boost": ["boost:boost"],
    "openssl": ["openssl:openssl"],
    "curl": ["haxx:curl", "haxx:libcurl"],
    "libcurl": ["haxx:curl", "haxx:libcurl"],
}

# Map veripak ecosystems to CPE target_sw values that would be contradictory.
# If a CVE's CPE entries specify one of these target_sw values and it contradicts
# the package's ecosystem, the CVE is likely for a different package.
_ECOSYSTEM_CPE_EXCLUSIONS: dict[str, set[str]] = {
    "c": {"python", "node.js", "ruby", "php", "java", "cran_r"},
    "cpp": {"python", "node.js", "ruby", "php", "java", "cran_r"},
    "system": {"python", "node.js", "ruby", "php"},
    "desktop-app": {"python", "node.js", "ruby", "php"},
    "driver": {"python", "node.js", "ruby", "php", "java"},
}


def _ecosystem_compatible(cve_item: dict, ecosystem: str) -> bool:
    """Check if a CVE's CPE target_sw is compatible with the package ecosystem.

    Returns True if compatible or if can't determine (conservative).
    """
    exclusions = _ECOSYSTEM_CPE_EXCLUSIONS.get(ecosystem)
    if not exclusions:
        return True

    configurations = cve_item.get("cve", {}).get("configurations", [])
    if not configurations:
        return True

    for config_entry in configurations:
        for node in config_entry.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                parts = criteria.split(":")
                # CPE 2.3: cpe:2.3:a:vendor:product:ver:update:edition:lang:sw_edition:target_sw:target_hw:other
                if len(parts) >= 11:
                    target_sw = parts[10].lower()
                    if target_sw != "*" and target_sw in exclusions:
                        return False

    return True


def _suggest_nvd_cpe(name: str, ecosystem: str) -> list[str]:
    """Return NVD CPE 2.3 vendor:product strings for the given package.

    Returns a list (usually one entry) of strings like "grafana:grafana".
    Checks _CPE_OVERRIDES first; falls back to asking the model.
    Returns an empty list on any failure or unrecognised format.
    """
    override = _CPE_OVERRIDES.get(name.lower())
    if override:
        return override

    eco_label = {
        "c": "C library",
        "cpp": "C++ library",
        "system": "Linux system package",
        "desktop-app": "desktop application",
        "driver": "hardware driver",
    }.get(ecosystem, ecosystem)

    prompt = (
        f'What is the NVD CPE 2.3 vendor:product identifier for the package "{name}" '
        f'(a {eco_label})? Reply with just "vendor:product", nothing else. '
        f'Return the CPE for the {eco_label} version, not wrappers or bindings in other languages. '
        f'Examples: "grafana:grafana", "microsoft:.net", "openssl:openssl", '
        f'"linux:linux_kernel"'
    )
    try:
        cpe = model_caller.call_model(prompt).strip().strip('"').strip("'").lower()
        if cpe and re.match(r'^[a-z0-9_\-]+:[a-z0-9_.\-]+$', cpe):
            return [cpe]
    except Exception:
        pass
    return []


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
# Security advisory page discovery
# ---------------------------------------------------------------------------

_ADVISORY_URL_KEYWORDS = {"security", "advisory", "advisories", "cve", "vulnerability", "vulnerabilities"}


def _discover_security_advisory_cves(name: str, versions: list[str]) -> list[dict]:
    try:
        results = tavily_client.search(f"{name} security advisory CVE list", max_results=5)
    except Exception:
        return []

    candidates = [
        r for r in results
        if any(kw in (r.get("url", "") + " " + r.get("title", "")).lower() for kw in _ADVISORY_URL_KEYWORDS)
    ]
    if not candidates:
        return []

    snippets = []
    for c in candidates[:2]:
        title = c.get("title", "")
        content = c.get("content", "")
        url = c.get("url", "")
        snippets.append(f"Source: {url}\nTitle: {title}\n{content}")

    combined = "\n\n---\n\n".join(snippets)
    version_str = ", ".join(versions)

    prompt = (
        f"Below are excerpts from security advisory pages for {name}. "
        f"Extract all CVE IDs (format: CVE-YYYY-NNNNN) that affect any of: {version_str}. "
        f"Include a CVE if the page says it affects any of those versions or a range that includes them. "
        f"Exclude CVEs that clearly only affect versions outside that set. "
        f"If uncertain whether a CVE affects the version, include it. "
        f"Return ONLY a JSON array of CVE ID strings, e.g. [\"CVE-2023-12345\"]. "
        f"If no CVEs apply, return [].\n\n{combined}"
    )

    try:
        raw = model_caller.call_model(prompt).strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()
        cve_ids = json.loads(raw)
        if not isinstance(cve_ids, list):
            return []
    except Exception:
        return []

    cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$")
    return [
        {
            "id": cve_id,
            "severity": "UNKNOWN",
            "summary": f"Found on {name} security advisory page",
            "version_filter": "advisory_page",
        }
        for cve_id in cve_ids
        if isinstance(cve_id, str) and cve_pattern.match(cve_id)
    ]


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

        # Normalize the package name for OSV before querying:
        # - Java: OSV indexes by Maven groupId:artifactId, not display names.
        # - JavaScript: OSV indexes by npm package name; strip ".js" suffixes and
        #   spaces that appear in display names but not in the npm registry.
        osv_name = name
        if ecosystem == "java":
            mapped = _JAVA_OSV_NAMES.get(name.lower())
            if mapped:
                osv_name = mapped
        elif ecosystem == "javascript":
            mapped = _JS_OSV_NAMES.get(name.lower())
            if mapped:
                osv_name = mapped

        versions_cves_raw: list[dict] = []
        for ver in versions:
            versions_cves_raw.extend(_osv_query_version(osv_name, osv_eco, ver))

        latest_cves_raw: list[dict] = []
        if latest_version:
            latest_cves_raw = _osv_query_version(osv_name, osv_eco, latest_version)

        # Package-level fallback: only when we had NO versions to query at all.
        # When version-specific queries ran but returned 0 CVEs, that means
        # the version genuinely has no known vulnerabilities — don't override
        # that correct result with a noisy package-level dump.
        if (not versions_cves_raw and not latest_cves_raw
                and not versions and not latest_version):
            versions_cves_raw = _osv_query_package(osv_name, osv_eco)

        replacement_cves_raw: list[dict] = []
        if replacement_name and replacement_name.lower() != name.lower():
            replacement_cves_raw = _osv_query_package(replacement_name, osv_eco)

        versions_cves = _dedupe_cross_source(versions_cves_raw)
        latest_cves = _dedupe_cross_source(latest_cves_raw)
        replacement_cves = _dedupe_cross_source(replacement_cves_raw)
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

        # 2. NVD CVE lookup — CPE-based when versions are known, keyword fallback otherwise.
        nvd_cves_by_id: dict[str, dict] = {}

        if versions:
            # 2a. CPE-based query: ask the model for the NVD CPE vendor:product string,
            # then query NVD by cpeName for each version in use. NVD performs its own
            # version range matching server-side, so all returned CVEs are confirmed to
            # affect the queried version. This avoids the keyword-search ordering problem
            # where popular packages have hundreds of CVEs and the relevant version-specific
            # ones are buried beyond the first page.
            cpe_prefixes = _suggest_nvd_cpe(name, ecosystem)
            for cpe_prefix in cpe_prefixes:
                for ver in versions:
                    cpe_name = f"cpe:2.3:a:{cpe_prefix}:{ver}:*:*:*:*:*:*:*"
                    for item in _nvd_fetch_by_cpe_name(cpe_name, api_key):
                        cve_obj = item.get("cve", {})
                        cve_id = cve_obj.get("id", "UNKNOWN")
                        if cve_id in nvd_cves_by_id:
                            continue
                        descriptions = cve_obj.get("descriptions", [])
                        summary = descriptions[0].get("value", "") if descriptions else ""
                        nvd_cves_by_id[cve_id] = {
                            "id": cve_id,
                            "severity": _extract_nvd_severity(item),
                            "summary": summary,
                            "version_filter": "cpe_matched",
                        }

        if not nvd_cves_by_id:
            # 2b. Keyword search fallback: used when no specific versions are provided
            # (package-level query), when the model couldn't produce a CPE string, or
            # when the CPE query returned no results (unindexed product, wrong CPE).
            nvd_keyword = _suggest_nvd_keyword(name, ecosystem)
            raw_items = _nvd_fetch(nvd_keyword, api_key)
            name_lower = name.lower()
            # When the model suggested a specific keyword (different from the raw package
            # name), trust NVD's search results — applying a text filter would drop real
            # CVEs whose descriptions don't repeat the keyword verbatim. Only filter when
            # using the raw name, where unrelated products with similar names can appear.
            apply_text_filter = nvd_keyword == name
            for item in raw_items:
                cve_obj = item.get("cve", {})
                cve_id = cve_obj.get("id", "UNKNOWN")
                descriptions = cve_obj.get("descriptions", [])
                summary = descriptions[0].get("value", "") if descriptions else ""
                if cve_id in nvd_cves_by_id:
                    continue
                if apply_text_filter:
                    if len(name_lower) < 5:
                        # Short names need word-boundary matching to avoid false positives
                        # e.g., "b64" should not match "base64", "blt" should not match "built"
                        if not re.search(r'\b' + re.escape(name_lower) + r'\b', summary.lower()):
                            continue
                    else:
                        if name_lower not in summary.lower():
                            continue
                # CPE product identity validation
                if not _cpe_matches_package(item, name, ecosystem):
                    continue
                # Ecosystem compatibility check
                if not _ecosystem_compatible(item, ecosystem):
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

            # Filter no_cpe_data entries via the model when specific versions are known.
            # Structural CPE version filtering cannot apply, so the model checks the
            # description text for version range exclusions and plugin/extension indicators.
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

    # Advisory page discovery: only when primary sources returned few results,
    # since OSV is authoritative for programmatic ecosystems.
    if versions and len(versions_cves) < 3:
        advisory_cves = _discover_security_advisory_cves(name, versions)
        if advisory_cves:
            versions_cves = _dedupe_cross_source(versions_cves + advisory_cves)

    # Deduplicate across all three lists using alias-cluster identity.
    # We track every seen identifier (CVE ID + aliases) to skip duplicates, but
    # count unique CVEs — not unique identifiers — so a CVE with 3 aliases is
    # counted once, not four times.
    seen_ids: set[str] = set()
    unique_cve_count = 0
    high_critical = 0
    for entry in versions_cves + latest_cves + replacement_cves:
        entry_id = entry["id"]
        if entry_id in seen_ids:
            continue
        # New unique CVE: mark its ID and all aliases as seen
        seen_ids.add(entry_id)
        for alias in entry.get("aliases", []):
            seen_ids.add(alias)
        unique_cve_count += 1
        if entry.get("severity") in ("HIGH", "CRITICAL"):
            high_critical += 1

    return {
        "method": method,
        "versions_cves": versions_cves,
        "latest_cves": latest_cves,
        "replacement_cves": replacement_cves,
        "total_count": unique_cve_count,
        "high_critical_count": high_critical,
    }
