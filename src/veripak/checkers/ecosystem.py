"""Ecosystem inference: registry probing with Tavily+model fallback."""

import urllib.request
import urllib.error
from typing import Optional

from .. import tavily as tavily_client
from .. import model_caller

# Ordered list of (ecosystem, probe_fn) — first hit wins.
# Each probe_fn takes a package name and returns True if found.

_TIMEOUT = 5

_VALID_ECOSYSTEMS = {
    "python", "javascript", "java", "go", "dotnet",
    "perl", "php", "c", "cpp", "system", "desktop-app", "driver",
}

_MODEL_ECOSYSTEM_LIST = "\n".join(f"- {e}" for e in sorted(_VALID_ECOSYSTEMS))


def _head_ok(url: str) -> bool:
    """Return True if a HEAD (or GET) request to url returns 2xx."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "veripak/0.1"},
            method="HEAD",
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status < 300
    except Exception:
        return False


def _get_ok(url: str) -> bool:
    """Return True if a GET request returns 2xx (for APIs that reject HEAD)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "veripak/0.1"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status < 300
    except Exception:
        return False


def _probe_pypi(name: str, version: Optional[str] = None) -> bool:
    if version:
        return _head_ok(f"https://pypi.org/pypi/{name}/{version}/json")
    return _head_ok(f"https://pypi.org/pypi/{name}/json")


def _probe_npm(name: str, version: Optional[str] = None) -> bool:
    encoded = name.replace("/", "%2F")
    if version:
        return _head_ok(f"https://registry.npmjs.org/{encoded}/{version}")
    return _head_ok(f"https://registry.npmjs.org/{encoded}")


def _probe_nuget(name: str, version: Optional[str] = None) -> bool:
    lower = name.lower()
    if version:
        # Flat container has a specific version directory if it exists
        return _get_ok(
            f"https://api.nuget.org/v3-flatcontainer/{lower}/{version.lower()}/{lower}.{version.lower()}.nupkg"
        )
    return _get_ok(f"https://api.nuget.org/v3-flatcontainer/{lower}/index.json")


def _probe_go(name: str, version: Optional[str] = None) -> bool:
    encoded = name.replace("/", "%2F")
    if version:
        v = version if version.startswith("v") else f"v{version}"
        return _get_ok(f"https://proxy.golang.org/{encoded}/@v/{v}.info")
    return _get_ok(f"https://proxy.golang.org/{encoded}/@latest")


def _probe_maven(name: str, version: Optional[str] = None) -> bool:
    """Maven search always returns 200; check numFound > 0 in the JSON body."""
    import json as _json

    query = f"a:{name}+AND+v:{version}" if version else f"a:{name}"
    url = f"https://search.maven.org/solrsearch/select?q={query}&rows=1&wt=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "veripak/0.1"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            body = _json.loads(resp.read())
            return body.get("response", {}).get("numFound", 0) > 0
    except Exception:
        return False


def _probe_cpan(name: str, version: Optional[str] = None) -> bool:
    return _get_ok(f"https://fastapi.metacpan.org/v1/module/{name}")


def _probe_packagist(name: str, version: Optional[str] = None) -> bool:
    # Packagist requires vendor/package format. Names without "/" are not PHP packages.
    if "/" not in name:
        return False
    return _get_ok(f"https://packagist.org/packages/{name.lower()}.json")


_REGISTRY_PROBES: list[tuple[str, object]] = [
    ("python",     _probe_pypi),
    ("javascript", _probe_npm),
    ("dotnet",     _probe_nuget),
    ("go",         _probe_go),
    ("java",       _probe_maven),
    ("perl",       _probe_cpan),
    ("php",        _probe_packagist),
]


def _infer_via_model(name: str, version: Optional[str] = None) -> Optional[str]:
    """Use Tavily search + model to classify a package's ecosystem."""
    query = f"{name} {version} software package" if version else f"{name} software package"
    try:
        results = tavily_client.search(query, max_results=5)
    except Exception:
        results = []

    snippets = []
    for r in results:
        title = r.get("title", "")
        content = (r.get("content") or "")[:300]
        snippets.append(f"{title}: {content}")

    search_text = "\n\n".join(snippets) if snippets else "(no search results)"

    prompt = (
        f'What ecosystem does the software package "{name}" belong to?\n\n'
        f"Search results:\n{search_text}\n\n"
        f"Reply with exactly one of these ecosystem names, nothing else:\n"
        f"{_MODEL_ECOSYSTEM_LIST}"
    )

    try:
        raw = model_caller.call_model(prompt).strip().lower().strip('"').strip("'")
        if raw in _VALID_ECOSYSTEMS:
            return raw
    except Exception:
        pass
    return None


def infer_ecosystem(name: str, version: Optional[str] = None) -> Optional[str]:
    """Infer the ecosystem for a package.

    Stage 1: probe programmatic registries (PyPI, npm, NuGet, Go, Maven,
    CPAN, Packagist) — first 2xx response wins.
    Stage 2: Tavily search + model for anything not found on a registry.

    Returns None if inference fails (caller should prompt user to supply
    --ecosystem manually).
    """
    for ecosystem, probe_fn in _REGISTRY_PROBES:
        if probe_fn(name, version):
            return ecosystem

    return _infer_via_model(name, version)
