"""
N2: Discover a download URL using multiple strategies.

Strategies (first call):
  1. existing_url already set -> return it unchanged
  2. release_notes_url -> fetch page -> find link matching version -> fetch that page -> extract tarball
  3. repository_url is GitHub -> GitHub releases API for that version tag

Strategies (retry=True, added):
  4. GitHub releases/latest as fallback
  5. Tavily search: "{name} {version} download source tarball"
"""

import re
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

_USER_AGENT = "veripak/0.1"
_TIMEOUT = 15
_TARBALL_EXTENSIONS = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip")
_TARBALL_RE = re.compile(
    r'https?://\S+\.(?:tar\.gz|tar\.bz2|tar\.xz|tgz|zip)(?=["\s>]|$)',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _fetch_text(url: str, timeout: int = _TIMEOUT) -> str | None:
    """GET url and return decoded text, or None on error."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def _fetch_json(url: str, timeout: int = _TIMEOUT) -> dict | None:
    """GET url with JSON Accept header and return parsed dict, or None on error."""
    import json
    req = urllib.request.Request(
        url,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# HTML link extraction
# ---------------------------------------------------------------------------


class _LinkExtractor(HTMLParser):
    """Collects all href values from anchor tags."""

    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.hrefs.append(value)


def _extract_tarballs_from_html(html: str) -> list[str]:
    """Return deduplicated list of tarball URLs from anchor hrefs and raw text."""
    found: list[str] = []
    seen: set[str] = set()

    # From anchor hrefs
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    for href in parser.hrefs:
        if _is_tarball(href) and href not in seen:
            seen.add(href)
            found.append(href)

    # From raw text via regex
    for match in _TARBALL_RE.finditer(html):
        url = match.group(0)
        if url not in seen:
            seen.add(url)
            found.append(url)

    return found


def _is_tarball(url: str) -> bool:
    """Return True if url ends with a tarball extension (case-insensitive)."""
    lower = url.lower().split("?")[0]  # strip query string before checking
    return any(lower.endswith(ext) for ext in _TARBALL_EXTENSIONS)


# ---------------------------------------------------------------------------
# Individual strategies
# ---------------------------------------------------------------------------


def _strategy_release_notes(
    release_notes_url: str, version: str, name: str
) -> str | None:
    """Strategy 2: fetch release notes index, follow links, extract tarball."""
    html = _fetch_text(release_notes_url)
    if not html:
        return None

    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass

    version_dashed = version.replace(".", "-")
    candidates = []
    for href in parser.hrefs:
        if version in href or version_dashed in href:
            resolved = urllib.parse.urljoin(release_notes_url, href)
            candidates.append(resolved)

    for candidate_url in candidates[:3]:
        if _is_tarball(candidate_url):
            return candidate_url
        page_html = _fetch_text(candidate_url)
        if not page_html:
            continue
        tarballs = _extract_tarballs_from_html(page_html)
        name_lower = name.lower()
        # Prefer a URL containing both the package name and the version
        for tb in tarballs:
            tb_lower = tb.lower()
            if name_lower in tb_lower and version in tb_lower:
                return tb
        # Fall back to first tarball found
        if tarballs:
            return tarballs[0]

    return None


def _extract_github_owner_repo(repository_url: str) -> tuple[str, str] | None:
    """Extract (owner, repo) from a GitHub URL, or None if not a GitHub URL."""
    match = re.search(
        r"github\.com[/:]([^/]+)/([^/\s.]+?)(?:\.git)?$",
        repository_url,
        re.IGNORECASE,
    )
    if match:
        return match.group(1), match.group(2)
    return None


def _extract_asset_tarball(release: dict) -> str | None:
    """From a GitHub release dict, return a tarball asset URL or tarball_url."""
    for asset in release.get("assets", []):
        url = asset.get("browser_download_url", "")
        if _is_tarball(url):
            return url
    # Fall back to the auto-generated source tarball
    return release.get("tarball_url") or None


def _strategy_github_releases(repository_url: str, version: str) -> str | None:
    """Strategy 3: try GitHub releases API for specific version tags."""
    parsed = _extract_github_owner_repo(repository_url)
    if not parsed:
        return None
    owner, repo = parsed

    tags_to_try = [version, f"v{version}", f"{repo}-{version}"]
    for tag in tags_to_try:
        url = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
        release = _fetch_json(url)
        if release and isinstance(release, dict) and "id" in release:
            result = _extract_asset_tarball(release)
            if result:
                return result

    return None


def _strategy_github_latest(repository_url: str) -> str | None:
    """Strategy 4: fall back to the latest GitHub release."""
    parsed = _extract_github_owner_repo(repository_url)
    if not parsed:
        return None
    owner, repo = parsed

    url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    release = _fetch_json(url)
    if release and isinstance(release, dict) and "id" in release:
        return _extract_asset_tarball(release)

    return None


def _strategy_tavily(name: str, version: str) -> str | None:
    """Strategy 5: Tavily search for the tarball URL."""
    from .. import tavily as tavily_mod

    query = f"{name} {version} download source tarball"
    try:
        results = tavily_mod.search(query, max_results=3)
    except RuntimeError:
        return None

    for r in results:
        content = r.get("content", "")
        result_url = r.get("url", "")
        # Check the result URL itself
        if _is_tarball(result_url) and version in result_url:
            return result_url
        # Scan content for tarball URLs containing the version
        for match in _TARBALL_RE.finditer(content):
            candidate = match.group(0)
            if version in candidate:
                return candidate
        # Scan result URL area even if not a tarball itself
        for match in _TARBALL_RE.finditer(result_url):
            candidate = match.group(0)
            if version in candidate:
                return candidate

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def discover(
    name: str,
    ecosystem: str,
    version: str | None,
    release_notes_url: str | None = None,
    repository_url: str | None = None,
    homepage: str | None = None,
    existing_url: str | None = None,
    retry: bool = False,
) -> str | None:
    """Discover a download URL for the given package using multiple strategies.

    On first call (retry=False): try strategies 1-3 in order.
    On retry: skip strategy 1, run strategies 2-5.
    Returns None if version is None/empty (version-specific search impossible).
    """
    if not version:
        return None

    # Strategy 1: existing URL (skip on retry to force re-validation)
    if not retry and existing_url:
        return existing_url

    # Strategy 2: release notes page chain
    if release_notes_url:
        result = _strategy_release_notes(release_notes_url, version, name)
        if result:
            return result

    # Strategy 3: GitHub releases API for specific version tag
    if repository_url and "github.com" in repository_url.lower():
        result = _strategy_github_releases(repository_url, version)
        if result:
            return result

    if not retry:
        return None

    # Retry-only strategies below

    # Strategy 4: GitHub latest release as fallback
    if repository_url and "github.com" in repository_url.lower():
        result = _strategy_github_latest(repository_url)
        if result:
            return result

    # Strategy 5: Tavily search
    result = _strategy_tavily(name, version)
    if result:
        return result

    return None
