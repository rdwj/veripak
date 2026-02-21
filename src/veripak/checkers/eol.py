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
    # .NET
    "dotnet": "dotnet",
    "microsoft.netcore.app": "dotnet",
    ".net core": "dotnet",
    ".net": "dotnet",
    # Node
    "nodejs": "nodejs",
    "node": "nodejs",
    "node.js": "nodejs",
    # Databases
    "postgres": "postgresql",
    "microsoft sql server": "mssqlserver",
    "sql server": "mssqlserver",
    # Java
    "apache tomcat": "tomcat",
    "spring boot": "spring-boot",
    "spring framework": "spring-framework",
}

# Vendor prefixes commonly prepended to product names that the
# endoflife.date slug may omit.
_VENDOR_PREFIXES = (
    "apache-", "microsoft-", "red-hat-", "ibm-",
    "oracle-", "google-", "hashicorp-",
)

# Module-level cache for the full product list from endoflife.date.
_product_list_cache: Optional[set[str]] = None


# ------------------------------------------------------------------
# Candidate generation
# ------------------------------------------------------------------

def _normalize_candidates(name: str) -> list[str]:
    """Generate candidate endoflife.date slugs from a package name.

    Returns an ordered list of unique slugs to try, most-likely first.
    """
    lower = name.lower().strip()

    # 1. Direct alias lookup (case-insensitive)
    if lower in _SLUG_MAP:
        return [_SLUG_MAP[lower]]

    candidates: list[str] = []

    # 2. Basic: lowercase, spaces → hyphens
    basic = lower.replace(" ", "-")
    candidates.append(basic)

    # 3. Strip vendor prefixes
    for prefix in _VENDOR_PREFIXES:
        if basic.startswith(prefix):
            stripped = basic[len(prefix):]
            if stripped:
                candidates.append(stripped)

    # 4. Dots removed (e.g. "node.js" → "nodejs")
    no_dots = basic.replace(".", "")
    if no_dots != basic:
        candidates.append(no_dots)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


# ------------------------------------------------------------------
# Product list fetching + fuzzy matching
# ------------------------------------------------------------------

def _fetch_product_list() -> set[str]:
    """Fetch the full list of products from endoflife.date/api/all.json.

    Caches the result in a module-level variable so repeated calls are free.
    Returns an empty set on any failure.
    """
    global _product_list_cache
    if _product_list_cache is not None:
        return _product_list_cache

    url = f"{_BASE_URL}/all.json"
    try:
        req = urllib.request.Request(url, headers=_HEADERS)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
            _product_list_cache = set(data) if isinstance(data, list) else set()
    except Exception:
        _product_list_cache = set()
    return _product_list_cache


# Words that carry little distinguishing value when fuzzy-matching.
_NOISE_WORDS = frozenset({
    "apache", "microsoft", "red", "hat", "ibm", "oracle",
    "google", "hashicorp", "server", "the", "project",
})


def _content_words(text: str) -> set[str]:
    """Split *text* on spaces/hyphens, lowercase, and drop noise words."""
    parts = re.split(r"[\s\-]+", text.lower())
    return {w for w in parts if w and w not in _NOISE_WORDS}


def _fuzzy_match(name: str, products: set[str]) -> Optional[str]:
    """Try to find a matching product slug via content-word overlap.

    Returns the best matching product slug, or None.
    """
    if not products:
        return None

    input_words = _content_words(name)
    if not input_words:
        return None

    best: Optional[str] = None
    best_score = -1

    for product in products:
        prod_words = _content_words(product)
        if not prod_words:
            continue

        # Check subset relationship in either direction
        if not (input_words <= prod_words or prod_words <= input_words):
            continue

        # Prefer exact word-count match, then larger overlap
        overlap = len(input_words & prod_words)
        exact_bonus = 10 if len(input_words) == len(prod_words) else 0
        score = overlap + exact_bonus

        if score > best_score:
            best_score = score
            best = product

    return best


# ------------------------------------------------------------------
# HTTP helpers
# ------------------------------------------------------------------

def _try_fetch(slug: str) -> Optional[list]:
    """Attempt to fetch cycle data for a single slug. Returns None on failure."""
    url = f"{_BASE_URL}/{slug}.json"
    try:
        req = urllib.request.Request(url, headers=_HEADERS)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
            return data if isinstance(data, list) else None
    except Exception:
        return None


def _fetch_cycles(product: str) -> tuple[Optional[list], Optional[str]]:
    """Fetch release cycle data from endoflife.date. Returns (cycles, slug) or (None, None)."""
    # Try each normalized candidate
    for slug in _normalize_candidates(product):
        data = _try_fetch(slug)
        if data is not None:
            return data, slug

    # Fallback: fuzzy match against full product list
    products = _fetch_product_list()
    match = _fuzzy_match(product, products)
    if match:
        data = _try_fetch(match)
        if data is not None:
            return data, match

    return None, None


# ------------------------------------------------------------------
# Unchanged helpers
# ------------------------------------------------------------------

def _extract_branch(version: str) -> Optional[str]:
    """Extract major.minor from a version string, e.g. '6.0.1' -> '6.0'."""
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

    # Find the matching cycle entry.
    # endoflife.date uses mixed cycle formats: "6.7" for newer products and "6" (major-only)
    # for older ones (e.g. Grafana 6.x, .NET 6). Try exact match first, then major-only.
    matched_cycle = None
    if branch:
        major = branch.split(".")[0]
        for entry in result:
            cycle = str(entry.get("cycle", ""))
            if cycle == branch or cycle == major or cycle.startswith(branch + "."):
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


# ------------------------------------------------------------------
# Maintenance signal heuristics (beyond endoflife.date)
# ------------------------------------------------------------------

def check_maintenance_signals(
    name: str,
    ecosystem: str,
    repository_url: Optional[str] = None,
    latest_version_date: Optional[str] = None,
    version_in_use: Optional[str] = None,
    latest_version: Optional[str] = None,
) -> dict:
    """Check maintenance signals beyond endoflife.date.

    Returns a dict with the same shape as check_eol() output, or an empty
    result dict if no signal was detected.
    """
    empty: dict = {
        "eol": None,
        "eol_date": None,
        "cycle": None,
        "latest_in_cycle": None,
        "product": None,
    }

    # 1. Check GitHub repository status
    if repository_url:
        gh_result = _check_github_status(repository_url)
        if gh_result and gh_result.get("eol") is True:
            return gh_result

    # 2. Check version gap — de facto EOL if many major versions behind
    if version_in_use and latest_version:
        gap_result = _check_version_gap_eol(version_in_use, latest_version)
        if gap_result and gap_result.get("eol") is True:
            return gap_result

    # 3. Tavily search for EOL announcements
    tavily_result = _check_tavily_eol(name, ecosystem)
    if tavily_result and tavily_result.get("eol") is True:
        return tavily_result

    return empty


def _check_github_status(repository_url: str) -> Optional[dict]:
    """Check GitHub API for archived/abandoned status."""
    m = re.match(r'https?://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$', repository_url)
    if not m:
        return None

    owner_repo = m.group(1)
    url = f"https://api.github.com/repos/{owner_repo}"
    try:
        req = urllib.request.Request(url, headers={**_HEADERS, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return None

    # Check if archived
    if data.get("archived", False):
        return {
            "eol": True,
            "eol_date": None,
            "cycle": None,
            "latest_in_cycle": None,
            "product": None,
            "_evidence": f"GitHub repository {owner_repo} is archived",
        }

    # Check last push date — if no commits in 3+ years, likely abandoned
    pushed_at = data.get("pushed_at", "")
    if pushed_at:
        try:
            last_push = datetime.datetime.fromisoformat(pushed_at.rstrip("Z"))
            years_since = (datetime.datetime.utcnow() - last_push).days / 365.25
            if years_since >= 3:
                return {
                    "eol": True,
                    "eol_date": None,
                    "cycle": None,
                    "latest_in_cycle": None,
                    "product": None,
                    "_evidence": f"No commits in {years_since:.1f} years (last push: {pushed_at[:10]})",
                }
        except Exception:
            pass

    # Check description for deprecation keywords
    description = (data.get("description") or "").lower()
    deprecation_keywords = [
        "deprecated", "unmaintained", "archived",
        "no longer maintained", "end of life", "eol", "abandoned",
    ]
    for keyword in deprecation_keywords:
        if keyword in description:
            return {
                "eol": True,
                "eol_date": None,
                "cycle": None,
                "latest_in_cycle": None,
                "product": None,
                "_evidence": f"GitHub description contains '{keyword}'",
            }

    return None


def _check_version_gap_eol(version_in_use: str, latest_version: str) -> Optional[dict]:
    """Infer de facto EOL when version is many major versions behind."""
    try:
        in_parts = [int(p) for p in re.findall(r"\d+", version_in_use)]
        latest_parts = [int(p) for p in re.findall(r"\d+", latest_version)]
    except Exception:
        return None

    if not in_parts or not latest_parts:
        return None

    major_gap = latest_parts[0] - in_parts[0]
    # If 5+ major versions behind, the branch is de facto unsupported
    if major_gap >= 5:
        return {
            "eol": True,
            "eol_date": None,
            "cycle": None,
            "latest_in_cycle": None,
            "product": None,
            "_evidence": f"Version {version_in_use} is {major_gap} major versions behind {latest_version}",
        }

    return None


def _check_tavily_eol(name: str, ecosystem: str) -> Optional[dict]:
    """Search Tavily for EOL/deprecation announcements."""
    try:
        from .. import tavily as tavily_client
        from .. import model_caller
    except ImportError:
        return None

    query = f'"{name}" ("end of life" OR "deprecated" OR "unmaintained" OR "no longer maintained")'
    try:
        results = tavily_client.search(query, max_results=3)
    except Exception:
        return None

    if not results:
        return None

    # Ask the model to extract structured EOL info from search results
    snippets = []
    for r in results[:3]:
        title = r.get("title", "")
        content = r.get("content", "")[:300]
        snippets.append(f"Title: {title}\nContent: {content}")

    search_text = "\n\n---\n\n".join(snippets)
    prompt = (
        f'Based on these search results, is the package "{name}" ({ecosystem}) '
        f'end-of-life, deprecated, or unmaintained?\n\n'
        f'{search_text}\n\n'
        f'Reply with JSON only: {{"eol": true/false, "eol_date": "YYYY-MM-DD or null", "evidence": "brief explanation"}}'
    )

    try:
        raw = model_caller.call_model(prompt)
        # Parse JSON response
        raw = raw.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw).strip()
        data = json.loads(raw)
        if data.get("eol") is True:
            return {
                "eol": True,
                "eol_date": data.get("eol_date"),
                "cycle": None,
                "latest_in_cycle": None,
                "product": None,
                "_evidence": data.get("evidence", "Tavily search found EOL evidence"),
            }
    except Exception:
        pass

    return None
