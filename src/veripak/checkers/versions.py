"""Per-ecosystem version lookup, ported from legacy-package-analysis."""

import json
import re
import urllib.request
from typing import Optional

from .. import tavily
from .. import model_caller

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ECO_LABELS = {
    "c": "C library",
    "cpp": "C++ library",
    "system": "Linux system package",
    "desktop-app": "desktop application",
    "driver": "hardware driver",
}

PROGRAMMATIC = {"python", "javascript", "java", "go", "dotnet", "perl", "php"}
MODEL_BASED = {"c", "cpp", "system", "desktop-app", "driver"}

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def strip_v(version: str) -> str:
    """Strip a leading 'v' from a version string for comparison."""
    return version.lstrip("v") if version else version


def is_stable(version: str) -> bool:
    """Return True if the version string looks like a stable release."""
    lower = version.lower()
    return not any(
        tag in lower for tag in ("a", "b", "rc", "dev", "post", "alpha", "beta")
    )


def _parse_json_response(text: str) -> dict:
    """Extract a JSON object from model response text.

    Tries three strategies in order:
    1. Direct JSON parse of the full text.
    2. Unwrap ```json ... ``` or ``` ... ``` markdown fences.
    3. Regex search for a bare {...} block containing a "version" key.

    Returns {} on total failure.
    """
    text = text.strip()

    # 1. Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Markdown fence
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except json.JSONDecodeError:
            pass

    # 3. Bare {...} containing "version"
    brace_match = re.search(r'(\{[^{}]*"version"[^{}]*\})', text)
    if brace_match:
        try:
            return json.loads(brace_match.group(1))
        except json.JSONDecodeError:
            pass

    return {}


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


def _http_get_json(url: str, timeout: int = 15) -> Optional[dict]:
    """Fetch URL and return parsed JSON, or None on error."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "veripak/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Per-ecosystem version checkers
# ---------------------------------------------------------------------------


def check_pypi(name: str) -> tuple[Optional[str], str]:
    """Return (version, source_url) for a PyPI package."""
    url = f"https://pypi.org/pypi/{name}/json"
    data = _http_get_json(url)
    if not data:
        return None, url

    releases = data.get("releases", {})
    stable = [v for v in releases if is_stable(v) and not v.lower().startswith("post")]
    if not stable:
        return None, url

    def release_time(ver: str) -> str:
        files = releases[ver]
        if not files:
            return ""
        return max(f.get("upload_time", "") for f in files)

    latest = max(stable, key=release_time)
    return latest, url


def check_npm(name: str) -> tuple[Optional[str], str]:
    """Return (version, source_url) for an npm package."""
    encoded = name.replace("/", "%2F")
    url = f"https://registry.npmjs.org/{encoded}"
    data = _http_get_json(url)
    if not data:
        return None, url
    version = data.get("dist-tags", {}).get("latest")
    return version, url


def check_maven(name: str) -> tuple[Optional[str], str]:
    """Return (version, source_url) for a Maven artifact."""
    url = f"https://search.maven.org/solrsearch/select?q=a:{name}&rows=1&wt=json"
    data = _http_get_json(url)
    version = None
    if data:
        docs = data.get("response", {}).get("docs", [])
        if docs:
            version = docs[0].get("latestVersion")

    if not version:
        url = f"https://search.maven.org/solrsearch/select?q={name}&rows=1&wt=json"
        data = _http_get_json(url)
        if data:
            docs = data.get("response", {}).get("docs", [])
            if docs:
                version = docs[0].get("latestVersion")

    return version, url


def check_go(module: str) -> tuple[Optional[str], str]:
    """Return (version, source_url) for a Go module via the Go proxy."""
    encoded = module.replace("/", "%2F")
    url = f"https://proxy.golang.org/{encoded}/@latest"
    data = _http_get_json(url)
    if not data:
        return None, url
    version = strip_v(data.get("Version", ""))
    return version or None, url


def check_nuget(name: str) -> tuple[Optional[str], str]:
    """Return (version, source_url) for a NuGet package."""
    url = f"https://api.nuget.org/v3-flatcontainer/{name.lower()}/index.json"
    data = _http_get_json(url)
    if not data:
        return None, url
    versions = data.get("versions", [])
    stable = [v for v in versions if "-" not in v]
    if not stable:
        stable = versions
    return stable[-1] if stable else None, url


def check_cpan(name: str) -> tuple[Optional[str], str]:
    """Return (version, source_url) for a CPAN/Perl module."""
    url = f"https://fastapi.metacpan.org/v1/module/{name}"
    data = _http_get_json(url)
    if not data:
        return None, url
    version = data.get("version")
    return str(version) if version is not None else None, url


def check_packagist(name: str) -> tuple[Optional[str], str]:
    """Return (version, source_url) for a PHP Packagist package."""
    pkg = name.lower()
    url = f"https://packagist.org/packages/{pkg}.json"
    data = _http_get_json(url)
    if not data:
        search_url = f"https://packagist.org/search.json?q={name}&per_page=1"
        search_data = _http_get_json(search_url)
        if search_data and search_data.get("results"):
            pkg = search_data["results"][0]["name"]
            url = f"https://packagist.org/packages/{pkg}.json"
            data = _http_get_json(url)

    if not data:
        return None, url

    package = data.get("package", {})
    versions = package.get("versions", {})
    stable = [
        v
        for v in versions
        if not re.search(r"(alpha|beta|rc|dev|-)", v, re.I) and v != "dev-master"
    ]
    if not stable:
        return None, url

    def ver_tuple(v: str) -> tuple:
        parts = re.findall(r"\d+", v)
        return tuple(int(p) for p in parts)

    try:
        latest = max(stable, key=ver_tuple)
        return latest.lstrip("v"), url
    except Exception:
        return stable[-1].lstrip("v"), url


# ---------------------------------------------------------------------------
# Tavily + model fallback
# ---------------------------------------------------------------------------


def check_via_model(
    name: str, ecosystem: str, versions_in_use: Optional[list[str]] = None,
    skip_branch_scope: bool = False,
) -> tuple[Optional[str], str, Optional[str], Optional[str]]:
    """Return (version, source_url, proof, notes) using Tavily + model.

    Queries Tavily for two searches ("latest version" + "release notes"),
    then asks the configured LLM to extract the stable version.
    When versions_in_use is provided (and skip_branch_scope is False),
    searches are scoped to that branch (e.g. "6.0") so the model returns
    the latest patch in that line.  When skip_branch_scope is True the
    branch constraint is ignored and the overall latest version is sought
    — useful for EOL packages where the branch-scoped latest is irrelevant.
    """
    label = ECO_LABELS.get(ecosystem, ecosystem)

    # Detect branch constraint from versions_in_use (e.g. "6.0" → branch "6.0")
    branch: Optional[str] = None
    if versions_in_use and not skip_branch_scope:
        m = re.match(r'^(\d+\.\d+)', versions_in_use[0])
        if m:
            branch = m.group(1)

    version_query = f"{name} {branch} latest version" if branch else f"{name} latest version"
    notes_query = f"{name} {branch} release notes" if branch else f"{name} release notes"
    try:
        r1 = tavily.search(version_query, max_results=3)
    except RuntimeError:
        r1 = []
    try:
        r2 = tavily.search(notes_query, max_results=3)
    except RuntimeError:
        r2 = []

    snippets = []
    for result_set in (r1, r2):
        for r in result_set:
            url = r.get("url", "")
            title = r.get("title", "")
            content = r.get("content", "")[:200]
            snippets.append(f"URL: {url}\nTitle: {title}\nContent: {content}")

    if not snippets:
        return None, "", None, "Tavily returned no results"

    search_text = "\n\n---\n\n".join(snippets)
    if branch:
        question = f'What is the latest stable patch release of "{name}" in the {branch}.x branch?'
    else:
        question = f'What is the latest stable release version of "{name}"?'
    prompt = (
        f"{question}\n\n"
        f"{search_text}\n\n"
        "Reply with JSON only:\n"
        '{"version": "X.Y.Z", "source_url": "URL where you found it", "proof": "exact quote"}'
    )

    try:
        raw = model_caller.call_model(prompt)
    except Exception as exc:
        return None, "", None, str(exc)

    parsed = _parse_json_response(raw)
    version = parsed.get("version") or None
    source_url = parsed.get("source_url") or ""
    proof = parsed.get("proof") or None

    return version, source_url, proof, None


# ---------------------------------------------------------------------------
# Top-level dispatcher
# ---------------------------------------------------------------------------


def get_latest_version(name: str, ecosystem: str, versions_in_use: Optional[list[str]] = None, skip_branch_scope: bool = False) -> dict:
    """Look up the latest version for a package.

    Returns a dict with keys:
      version (str|None), source_url (str), method (str),
      proof (str|None), notes (str|None)
    """
    version: Optional[str] = None
    source_url: str = ""
    method: str = "registry_api"
    proof: Optional[str] = None
    notes: Optional[str] = None

    if ecosystem == "python":
        version, source_url = check_pypi(name)
    elif ecosystem == "javascript":
        version, source_url = check_npm(name)
    elif ecosystem == "java":
        version, source_url = check_maven(name)
        if version is None:
            notes = "Maven coordinates unknown"
    elif ecosystem == "go":
        version, source_url = check_go(name)
    elif ecosystem == "dotnet":
        version, source_url = check_nuget(name)
    elif ecosystem == "perl":
        version, source_url = check_cpan(name)
    elif ecosystem == "php":
        version, source_url = check_packagist(name)
    elif ecosystem in MODEL_BASED:
        method = "tavily_model"
        version, source_url, proof, notes = check_via_model(name, ecosystem, versions_in_use, skip_branch_scope=skip_branch_scope)
    else:
        method = "skipped"
        notes = f"Unknown ecosystem: {ecosystem}"

    return {
        "version": strip_v(version) if version else None,
        "source_url": source_url,
        "method": method,
        "proof": proof,
        "notes": notes,
    }
