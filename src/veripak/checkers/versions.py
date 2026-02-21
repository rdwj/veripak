"""Per-ecosystem version lookup, ported from legacy-package-analysis."""

import json
import re
import urllib.parse
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

# Disambiguation data for packages with short or ambiguous names.
# Used to improve Tavily queries and model extraction accuracy.
_DISAMBIGUATION: dict[str, dict] = {
    "b64": {"ecosystem": "c", "full_name": "b64 C base64 encoding library", "not": ["R", "CRAN", "Python"]},
    "blt": {"ecosystem": "c", "full_name": "BLT Tcl/Tk extension toolkit", "not": ["Windows", "RDP", "BPF", "Linux kernel"]},
    "argon2": {"ecosystem": "c", "full_name": "argon2 C reference implementation (password hashing)", "not": ["npm", "node", "Python", "pip"]},
    "lz4": {"ecosystem": "c", "full_name": "LZ4 C compression library", "not": ["Python", "Java", "npm"]},
    "zstd": {"ecosystem": "c", "full_name": "Zstandard C compression library by Facebook", "not": ["Python", "npm"]},
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


# Matches Maven milestones (-M3), alpha/beta/rc/preview/snapshot/dev suffixes,
# and dot-separated pre-release qualifiers (e.g. "1.0.alpha1").
_PRERELEASE_RE = re.compile(
    r'(?:[-.](?:alpha|beta|rc|dev|preview|snapshot|M\d+))',
    re.IGNORECASE,
)


def is_prerelease(version: str) -> bool:
    """Return True if the version string looks like a pre-release.

    Detects common patterns such as:
      -alpha, -beta, -rc, -RC, -M3 (Maven milestone), -SNAPSHOT,
      -preview, -dev, .alpha1, .beta2
    """
    return bool(_PRERELEASE_RE.search(version))


def _version_tuple(ver: str) -> tuple[int, ...]:
    """Extract numeric parts of a version string for semantic comparison.

    Examples: "4.2.28" -> (4, 2, 28), "v6.0.2" -> (6, 0, 2)
    """
    return tuple(int(p) for p in re.findall(r"\d+", ver))


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


def strip_distro_suffix(version: str) -> str:
    """Remove common Linux distribution packaging suffixes from a version string.

    Handles:
    - Epoch prefix: "1:3.7.0" -> "3.7.0"
    - Debian DFSG: "9.2.10+dfsg-1" -> "9.2.10"
    - Fedora/RHEL: "3.7.0-1.fc39" or "3.7.0-1.el9" -> "3.7.0"
    - Debian/Ubuntu revision: "3.7.0-4" or "3.7.0-4.1" -> "3.7.0"

    Preserves legitimate version components like pre-release tags.
    """
    if not version:
        return version

    # Strip epoch prefix (e.g., "1:3.7.0" -> "3.7.0")
    if re.match(r'^\d+:', version):
        version = version.split(':', 1)[1]

    # Strip +dfsg suffix and everything after
    version = re.sub(r'\+dfsg.*$', '', version)

    # Strip Fedora/RHEL suffixes: -N.fcNN or -N.elN
    version = re.sub(r'-\d+\.(fc|el)\d+.*$', '', version)

    # Strip Debian/Ubuntu revision: -N or -N.N at end
    # But only if the part before the dash looks like a complete version
    # Don't strip things like "2.0.0-beta1" or "1.0.0-rc1"
    m = re.match(r'^(.+\.\d+)-(\d+)(\.\d+)*$', version)
    if m:
        base = m.group(1)
        # Verify the base looks like a real version (has at least one dot with digits)
        if re.match(r'^\d+(\.\d+)+$', base):
            version = base

    return version


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

    latest = max(stable, key=_version_tuple)
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


def _maven_branch_latest(
    group_id: str, artifact_id: str, target_major: int,
) -> Optional[str]:
    """Find the latest stable version in a specific major version line.

    Uses the Maven Central ``core=gav`` endpoint which returns individual
    version records rather than the grouped artifact summary, allowing
    filtering by major version.
    """
    url = (
        f"https://search.maven.org/solrsearch/select"
        f"?q=g:{group_id}+AND+a:{artifact_id}&rows=200&wt=json&core=gav"
    )
    data = _http_get_json(url)
    if not data:
        return None
    docs = data.get("response", {}).get("docs", [])
    candidates = []
    for doc in docs:
        v = doc.get("v", "")
        parts = _version_tuple(v)
        if parts and parts[0] == target_major and not is_prerelease(v):
            candidates.append(v)
    if not candidates:
        return None
    return max(candidates, key=_version_tuple)


def check_maven(name: str, versions_in_use: Optional[list[str]] = None) -> tuple[Optional[str], str, Optional[str]]:
    """Return (version, source_url, notes) for a Maven artifact.

    If Maven Central returns a pre-release (e.g. a milestone like "4.0-M3"),
    the version is returned as-is with a notes string — there may be no stable
    release yet.

    When versions_in_use is provided and the latest version is in a different
    major version line, queries for the latest version in the user's branch.
    """
    from .cves import _JAVA_OSV_NAMES

    # Try precise groupId:artifactId lookup from the coordinate mapping first
    mapped = _JAVA_OSV_NAMES.get(name.lower())
    if mapped and ":" in mapped:
        g, a = mapped.split(":", 1)
        url = f"https://search.maven.org/solrsearch/select?q=g:{g}+AND+a:{a}&rows=1&wt=json"
        data = _http_get_json(url)
        if data:
            docs = data.get("response", {}).get("docs", [])
            if docs:
                version = docs[0].get("latestVersion")
                if version:
                    # Branch-scope: if user is on a different major line,
                    # find the latest version in their branch instead.
                    if versions_in_use:
                        user_parts = _version_tuple(versions_in_use[0])
                        result_parts = _version_tuple(version)
                        if (user_parts and result_parts
                                and user_parts[0] != result_parts[0]):
                            branch_ver = _maven_branch_latest(g, a, user_parts[0])
                            if branch_ver:
                                version = branch_ver
                    notes = "pre-release version" if is_prerelease(version) else None
                    return version, url, notes

    # Fall back to artifact-name search
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

    notes = "pre-release version" if version and is_prerelease(version) else None
    return version, url, notes


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

    try:
        latest = max(stable, key=_version_tuple)
        return latest.lstrip("v"), url
    except Exception:
        return stable[-1].lstrip("v"), url


# ---------------------------------------------------------------------------
# Structured source lookups (for non-programmatic ecosystems)
# ---------------------------------------------------------------------------


def check_github_releases(repo_url: str) -> tuple[Optional[str], str]:
    """Query GitHub API for the latest release version.

    Returns (version, source_url) or (None, source_url) on failure.
    """
    if not repo_url:
        return None, ""

    # Extract owner/repo from URL
    m = re.match(r'https?://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$', repo_url)
    if not m:
        return None, repo_url

    owner_repo = m.group(1)
    api_url = f"https://api.github.com/repos/{owner_repo}/releases/latest"
    data = _http_get_json(api_url)
    if not data:
        # Try tags endpoint as fallback
        tags_url = f"https://api.github.com/repos/{owner_repo}/tags?per_page=1"
        tags = _http_get_json(tags_url)
        if tags and isinstance(tags, list) and tags:
            tag_name = tags[0].get("name", "")
            return strip_v(tag_name) or None, f"https://github.com/{owner_repo}/tags"
        return None, api_url

    tag = data.get("tag_name", "")
    version = strip_v(tag)
    html_url = data.get("html_url", api_url)
    return version or None, html_url


def check_release_monitoring(name: str) -> tuple[Optional[str], str, Optional[str]]:
    """Query release-monitoring.org (Anitya) for the latest upstream version.

    Returns (version, source_url, notes) or (None, source_url, None) on failure.

    Prefers stable_version from the Anitya record.  If the best available
    version is still a pre-release, returns it with a notes string.
    """
    encoded = urllib.parse.quote(name, safe='')
    url = f"https://release-monitoring.org/api/v2/projects/?name={encoded}"
    data = _http_get_json(url)
    if not data:
        return None, url, None

    projects = data.get("items", [])
    # Find exact name match (case-insensitive)
    for project in projects:
        if project.get("name", "").lower() == name.lower():
            project_url = f"https://release-monitoring.org/project/{project.get('id', '')}/"

            # Prefer stable_version; fall back to version
            stable = project.get("stable_version")
            latest = project.get("version")

            if stable and not is_prerelease(stable):
                return stable, project_url, None

            # stable_version is absent or itself a pre-release — try to find
            # a non-prerelease in versions_list if the API provides it.
            versions_list = project.get("versions", [])
            stable_candidates = [v for v in versions_list if not is_prerelease(v)]
            if stable_candidates:
                # versions_list is newest-first from Anitya
                return stable_candidates[0], project_url, None

            # Last resort: return whatever version we have with a note
            best = stable or latest
            if best:
                notes = "pre-release version" if is_prerelease(best) else None
                return best, project_url, notes

            return None, project_url, None

    return None, url, None


def check_repology(name: str) -> tuple[Optional[str], str, Optional[str]]:
    """Query Repology for the newest upstream version.

    Returns (version, source_url, notes) or (None, source_url, None) on failure.
    Filters for entries with status=="newest" to get upstream latest.
    If only a pre-release is available, returns it with a notes string.
    """
    encoded = name.lower().replace(" ", "-")
    url = f"https://repology.org/api/v1/project/{encoded}"

    # Repology requires a more specific User-Agent
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "veripak/0.1 (package auditor)"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None, url, None

    if not isinstance(data, list):
        return None, url, None

    # Filter for "newest" status entries (upstream latest)
    newest = [entry for entry in data if entry.get("status") == "newest"]
    if newest:
        version = newest[0].get("version")
        if version:
            clean = strip_distro_suffix(version)
            repology_url = f"https://repology.org/project/{encoded}/versions"
            notes = "pre-release version" if is_prerelease(clean) else None
            return clean, repology_url, notes

    return None, url, None


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

    # Disambiguation for packages with short or ambiguous names
    disambig = _DISAMBIGUATION.get(name.lower())
    if disambig:
        label = disambig.get("full_name", label)
        negative_terms = disambig.get("not", [])
    else:
        negative_terms = []

    # Detect branch constraint from versions_in_use (e.g. "6.0" → branch "6.0")
    branch: Optional[str] = None
    if versions_in_use and not skip_branch_scope:
        m = re.match(r'^(\d+\.\d+)', versions_in_use[0])
        if m:
            branch = m.group(1)

    version_query = f"{name} {label} {branch} latest version" if branch else f"{name} {label} latest version"
    notes_query = f"{name} {label} {branch} release notes" if branch else f"{name} {label} release notes"
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

    # Add ecosystem context to help the model ignore wrong-ecosystem results
    ecosystem_hint = f"\nThe package is a {ECO_LABELS.get(ecosystem, ecosystem)}."
    if negative_terms:
        ecosystem_hint += f" Ignore results for: {', '.join(negative_terms)} packages."
    prompt += ecosystem_hint

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


def get_latest_version(name: str, ecosystem: str, versions_in_use: Optional[list[str]] = None, skip_branch_scope: bool = False, repository_url: Optional[str] = None) -> dict:
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
        version, source_url, notes = check_maven(name, versions_in_use=versions_in_use)
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
        # Try structured sources first, then fall back to Tavily+model
        # 1. GitHub Releases (if repository_url known)
        if repository_url:
            gh_version, gh_url = check_github_releases(repository_url)
            if gh_version:
                version, source_url = gh_version, gh_url
                method = "github_releases"
                if is_prerelease(gh_version):
                    notes = "pre-release version"

        # 2. release-monitoring.org
        if version is None:
            rm_version, rm_url, rm_notes = check_release_monitoring(name)
            if rm_version:
                version, source_url, notes = rm_version, rm_url, rm_notes
                method = "release_monitoring"

        # 3. Repology
        if version is None:
            rep_version, rep_url, rep_notes = check_repology(name)
            if rep_version:
                version, source_url, notes = rep_version, rep_url, rep_notes
                method = "repology"

        # 4. Tavily + model (existing fallback)
        if version is None:
            method = "tavily_model"
            version, source_url, proof, notes = check_via_model(
                name, ecosystem, versions_in_use, skip_branch_scope=skip_branch_scope,
            )
    else:
        method = "skipped"
        notes = f"Unknown ecosystem: {ecosystem}"

    # Clean version: strip 'v' prefix and distro packaging suffixes
    clean_version = strip_distro_suffix(strip_v(version)) if version else None

    return {
        "version": clean_version,
        "source_url": source_url,
        "method": method,
        "proof": proof,
        "notes": notes,
    }
