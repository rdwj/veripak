"""CVE Agent: Agentic loop for CVE discovery with OSV, NVD, and advisory page tools.

Replaces the fixed code path in cves.py with an agent that can reason about
coverage gaps, iterate on incomplete results, and cross-reference advisory pages.
"""

import logging
import re
import urllib.error
import urllib.parse
import urllib.request

from .. import config
from ..checkers.cves import (
    _CPE_OVERRIDES,
    _JAVA_OSV_NAMES,
    _JS_OSV_NAMES,
    NVD_ECOSYSTEMS,
    OSV_ECOSYSTEM_MAP,
    OSV_ECOSYSTEMS,
    _extract_nvd_severity,
    _nvd_fetch,
    _nvd_fetch_by_cpe_name,
    _osv_query_package,
    _osv_query_version,
)
from .base import AgentResult, ToolDef, run_agent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _tool_osv_query(
    package: str,
    ecosystem: str,
    version: str | None = None,
) -> dict:
    """Query OSV.dev for vulnerabilities affecting a package/version."""
    osv_eco = OSV_ECOSYSTEM_MAP.get(ecosystem)
    if not osv_eco:
        return {"error": f"No OSV ecosystem mapping for {ecosystem}", "cves": []}

    # Normalize package name for OSV
    osv_name = package
    if ecosystem == "java":
        mapped = _JAVA_OSV_NAMES.get(package.lower())
        if mapped:
            osv_name = mapped
    elif ecosystem == "javascript":
        mapped = _JS_OSV_NAMES.get(package.lower())
        if mapped:
            osv_name = mapped

    if version:
        cves = _osv_query_version(osv_name, osv_eco, version)
    else:
        cves = _osv_query_package(osv_name, osv_eco)

    return {
        "source": "osv.dev",
        "query_package": osv_name,
        "query_ecosystem": osv_eco,
        "query_version": version,
        "count": len(cves),
        "cves": cves[:50],  # Truncate for context window
    }


def _tool_nvd_search(
    keyword: str,
    results_per_page: int = 100,
    cpe_name: str | None = None,
) -> dict:
    """Search NVD for CVEs by keyword or CPE name."""
    api_key = config.get("nvd_api_key") or ""

    if cpe_name:
        items = _nvd_fetch_by_cpe_name(cpe_name, api_key)
    else:
        items = _nvd_fetch(keyword, api_key)

    cves = []
    for item in items[:50]:  # Truncate for context window
        cve_obj = item.get("cve", {})
        cve_id = cve_obj.get("id", "UNKNOWN")
        descriptions = cve_obj.get("descriptions", [])
        summary = descriptions[0].get("value", "") if descriptions else ""
        cves.append({
            "id": cve_id,
            "severity": _extract_nvd_severity(item),
            "summary": summary[:200],
        })

    return {
        "source": "nvd",
        "query": cpe_name or keyword,
        "count": len(cves),
        "cves": cves,
    }


def _tool_web_search(query: str) -> dict:
    """Search the web for security advisory pages and CVE lists."""
    try:
        from .. import tavily as tavily_client
        results = tavily_client.search(query, max_results=5)
        return {
            "results": [
                {
                    "title": r.get("title", ""),
                    "url": r.get("url", ""),
                    "snippet": (r.get("content") or "")[:400],
                }
                for r in results
            ]
        }
    except Exception as exc:
        return {"error": str(exc)}


def _tool_fetch_advisory_page(url: str) -> dict:
    """Fetch a security advisory page and extract CVE IDs from it."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "veripak/0.1"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read(100_000).decode("utf-8", errors="replace")
    except Exception as exc:
        return {"error": f"Failed to fetch {url}: {exc}", "url": url, "cve_ids": []}

    # Strip HTML tags
    text = re.sub(r"<[^>]+>", " ", raw)

    # Extract all CVE IDs
    cve_ids = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", text)))

    return {
        "url": url,
        "cve_ids": cve_ids,
        "cve_count": len(cve_ids),
        "content_preview": re.sub(r"\s+", " ", text).strip()[:1500],
    }


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

_TOOLS = [
    ToolDef(
        name="osv_query",
        description=(
            "Query OSV.dev for vulnerabilities. For programmatic ecosystems "
            "(Python/PyPI, JavaScript/npm, Java/Maven, Go, .NET/NuGet, Perl/CPAN, PHP/Packagist), "
            "this is the most authoritative source with precise version-specific data. "
            "Provide a version for version-specific results, or omit for all known CVEs."
        ),
        parameters={
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "Package name"},
                "ecosystem": {"type": "string", "description": "Ecosystem (python, javascript, java, etc.)"},
                "version": {"type": "string", "description": "Specific version to check (optional)"},
            },
            "required": ["package", "ecosystem"],
        },
        fn=_tool_osv_query,
    ),
    ToolDef(
        name="nvd_search",
        description=(
            "Search NVD (National Vulnerability Database) for CVEs. Better for "
            "system/C/C++ packages that aren't in OSV. Use cpe_name for precise "
            "version-matched results (e.g. 'cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*'), "
            "or keyword for broad search."
        ),
        parameters={
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "NVD keyword search term"},
                "cpe_name": {
                    "type": "string",
                    "description": "Full CPE 2.3 name for precise version matching (optional)",
                },
            },
            "required": ["keyword"],
        },
        fn=_tool_nvd_search,
    ),
    ToolDef(
        name="web_search",
        description="Search the web for security advisory pages, CVE databases, and vulnerability reports.",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
            },
            "required": ["query"],
        },
        fn=_tool_web_search,
    ),
    ToolDef(
        name="fetch_advisory_page",
        description=(
            "Fetch a security advisory URL and extract CVE IDs from the page content. "
            "Returns a list of CVE IDs found on the page plus a content preview."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL of the security advisory page"},
            },
            "required": ["url"],
        },
        fn=_tool_fetch_advisory_page,
    ),
]


# ---------------------------------------------------------------------------
# System prompt template
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_TEMPLATE = """\
You are finding all known CVEs that affect **{package}** version **{version}** \
({ecosystem}).

STRATEGY:
1. Start with the most authoritative source for this ecosystem:
   - For programmatic ecosystems (Python, JavaScript, Java, Go, .NET, Perl, PHP): \
use osv_query with the specific version. OSV.dev has precise version-specific data.
   - For system/C/C++ packages: try osv_query first (it covers Debian, Alpine, Ubuntu \
advisories), then supplement with nvd_search.

2. If the primary source returns fewer CVEs than expected for a widely-used package, \
search for the project's official security advisory page:
   - web_search for "{package} security advisory"
   - fetch_advisory_page on promising URLs
   - Cross-reference any additional CVE IDs found

3. For NVD searches on system packages, construct a CPE name if you know the vendor \
and product: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*

4. Deduplicate results: OSV uses GHSA IDs with CVE aliases, NVD uses CVE IDs directly. \
A GHSA entry with alias CVE-2024-XXXXX is the same as the NVD CVE-2024-XXXXX entry.

{extra_context}

Return a deduplicated list as JSON:
{{
  "cves": [
    {{"id": "CVE-...", "severity": "CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN", "summary": "brief"}}
  ],
  "sources_consulted": ["osv.dev", "nvd", "advisory_page"],
  "total_count": N,
  "high_critical_count": N,
  "notes": "any coverage gaps or concerns"
}}
"""


def check_cves(
    package: str,
    version: str,
    ecosystem: str,
    versions: list[str] | None = None,
    latest_version: str = "",
    replacement_name: str = "",
) -> AgentResult:
    """Run the CVE agent for a package.

    Returns an AgentResult whose `answer` dict contains:
      cves, sources_consulted, total_count, high_critical_count, notes
    """
    extra_lines = []
    if ecosystem in OSV_ECOSYSTEMS:
        osv_eco = OSV_ECOSYSTEM_MAP.get(ecosystem, ecosystem)
        extra_lines.append(f"OSV ecosystem: {osv_eco}")
        # Include Java/JS name mappings if applicable
        if ecosystem == "java":
            mapped = _JAVA_OSV_NAMES.get(package.lower())
            if mapped:
                extra_lines.append(f"OSV Maven name: {mapped}")
        elif ecosystem == "javascript":
            mapped = _JS_OSV_NAMES.get(package.lower())
            if mapped:
                extra_lines.append(f"OSV npm name: {mapped}")

    if ecosystem in NVD_ECOSYSTEMS:
        cpe_override = _CPE_OVERRIDES.get(package.lower())
        if cpe_override:
            extra_lines.append(f"Known CPE prefixes: {', '.join(cpe_override)}")

    if versions and len(versions) > 1:
        extra_lines.append(f"Additional versions in use: {', '.join(versions)}")

    extra_context = "\n".join(extra_lines) if extra_lines else ""

    system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(
        package=package,
        version=version,
        ecosystem=ecosystem,
        extra_context=extra_context,
    )

    user_prompt = (
        f"Find all known CVEs affecting {package} version {version} ({ecosystem})."
    )

    result = run_agent(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        tools=_TOOLS,
        agent_name="cve_agent",
        max_turns=8,
        max_tool_calls=25,
    )

    return result
