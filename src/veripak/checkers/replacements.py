"""Replacement package validation, ported from legacy-package-analysis."""

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from .. import tavily
from .. import model_caller

_HEADERS = {"User-Agent": "veripak/0.1"}
_TIMEOUT = 12

REGISTRY_API_ECOSYSTEMS = {"python", "javascript", "go", "dotnet", "perl"}
TAVILY_ECOSYSTEMS = {"c", "cpp", "system", "desktop-app", "driver"}
ECOSYSTEM_LABELS = {
    "c": "C library",
    "cpp": "C++ library",
    "system": "Linux system package",
    "desktop-app": "desktop application",
    "driver": "hardware driver",
}

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _request(url: str, method: str = "GET") -> tuple[Optional[int], Optional[bytes]]:
    try:
        req = urllib.request.Request(url, headers=_HEADERS, method=method)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            body = resp.read() if method == "GET" else None
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return None, None


def _get_json(url: str) -> Optional[dict]:
    status, body = _request(url, "GET")
    if status == 200 and body:
        try:
            return json.loads(body.decode())
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# Per-ecosystem registry checks
# ---------------------------------------------------------------------------


def _check_pypi(repl_name: str) -> tuple[Optional[bool], Optional[str]]:
    candidates = [repl_name]
    if " " in repl_name:
        candidates += [repl_name.replace(" ", "-"), repl_name.replace(" ", "_")]
    for candidate in candidates:
        norm = re.sub(r"[^a-zA-Z0-9._-]", "-", candidate)
        data = _get_json(f"https://pypi.org/pypi/{urllib.parse.quote(norm)}/json")
        if data:
            latest = data.get("info", {}).get("version", "?")
            suffix = f"; queried as '{norm}'" if norm != repl_name else ""
            return True, f"Found on PyPI as '{norm}' (latest {latest}){suffix}"
    return False, f"Not found on PyPI (tried: {', '.join(candidates)})"


def _check_npm(repl_name: str) -> tuple[Optional[bool], Optional[str]]:
    norm = repl_name.lower().replace(" ", "-")
    data = _get_json(f"https://registry.npmjs.org/{urllib.parse.quote(norm, safe='@/')}")
    if data:
        latest = data.get("dist-tags", {}).get("latest", "?")
        return True, f"Found on npm (latest {latest})"
    return False, f"Not found on npm (queried: {norm})"


def _check_go(repl_name: str) -> tuple[Optional[bool], Optional[str]]:
    candidate = repl_name.strip().lower().replace(" ", "")
    if "." not in candidate:
        return None, "Go replacement name is not a resolvable module path; manual check required"
    status, _ = _request(
        f"https://proxy.golang.org/{urllib.parse.quote(candidate, safe='/')}/@v/list"
    )
    if status == 200:
        return True, f"Module found at Go proxy ({candidate})"
    return False, f"Module not found at Go proxy (tried: {candidate})"


def _check_nuget(repl_name: str) -> tuple[Optional[bool], Optional[str]]:
    norm = re.sub(r"[^a-zA-Z0-9._-]", ".", repl_name).lower()
    status, _ = _request(f"https://api.nuget.org/v3-flatcontainer/{norm}/index.json")
    if status == 200:
        return True, f"Found on NuGet (id: {norm})"
    return False, f"Not found on NuGet (tried id: {norm})"


def _check_maven(repl_name: str) -> tuple[Optional[bool], Optional[str]]:
    artifact = re.sub(r"[^a-zA-Z0-9._-]", "-", repl_name).lower()
    data = _get_json(
        f"https://search.maven.org/solrsearch/select"
        f"?q=a:{urllib.parse.quote(artifact)}&rows=1&wt=json"
    )
    if data and data.get("response", {}).get("numFound", 0) > 0:
        docs = data["response"].get("docs", [])
        coord = f"{docs[0].get('g', '?')}:{docs[0].get('a', '?')}" if docs else artifact
        return True, f"Found on Maven Central as '{coord}'"
    return False, f"Not found on Maven Central by artifact name '{artifact}'"


def _check_cpan(repl_name: str) -> tuple[Optional[bool], Optional[str]]:
    dist = repl_name.replace("::", "-").replace(" ", "-")
    data = _get_json(
        f"https://fastapi.metacpan.org/v1/distribution/{urllib.parse.quote(dist)}"
    )
    if data and "name" in data:
        return True, f"Found on MetaCPAN: {data['name']}"
    return False, f"Not found on MetaCPAN (tried: {dist})"


# ---------------------------------------------------------------------------
# Tavily + model validation
# ---------------------------------------------------------------------------


def _parse_json_response(text: str) -> dict:
    """Extract a JSON object from model response text.

    Tries three strategies in order:
    1. Direct JSON parse of the full text.
    2. Unwrap ```json ... ``` or ``` ... ``` markdown fences.
    3. Regex search for a bare {...} block containing a "confirmed" key.

    Returns {} on total failure.
    """
    text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except json.JSONDecodeError:
            pass

    brace_match = re.search(r'(\{[^{}]*"confirmed"[^{}]*\})', text)
    if brace_match:
        try:
            return json.loads(brace_match.group(1))
        except json.JSONDecodeError:
            pass

    return {}


def _validate_via_model(
    repl_name: str, label: str
) -> tuple[Optional[bool], str, Optional[str]]:
    """Validate a replacement using Tavily + model.

    Returns (confirmed, notes, proof).
    """
    query = f"{repl_name} {label} official homepage package"
    try:
        results = tavily.search(query)
    except RuntimeError as exc:
        return None, str(exc), None

    if not results:
        return None, f"Tavily search returned no results for '{repl_name}'", None

    snippets = []
    for r in results:
        url = r.get("url", "")
        title = r.get("title", "")
        content = r.get("content", "")[:400]
        snippets.append(f"URL: {url}\nTitle: {title}\nContent: {content}")

    search_text = "\n\n---\n\n".join(snippets)
    prompt = (
        f'Based on the following search results, determine whether "{repl_name}" '
        f"appears to be a real, actively maintained {label}.\n\n"
        f"{search_text}\n\n"
        "Return ONLY a JSON object with no markdown fences or other text: "
        '{"confirmed": true, "source_url": "https://...", '
        '"proof": "verbatim text confirming this"}. '
        'Set "confirmed" to false if the package does not appear to exist or is abandoned.'
    )

    try:
        raw = model_caller.call_model(prompt)
    except Exception as exc:
        return None, f"model_caller error: {exc}", None

    parsed = _parse_json_response(raw)
    confirmed = parsed.get("confirmed")
    source_url = parsed.get("source_url") or ""
    proof = parsed.get("proof") or None

    if confirmed is None:
        return None, f"model did not return a clear confirmed value; raw: {raw[:200]}", None

    notes = f"{source_url}: {proof}" if (source_url or proof) else f"model response: {raw[:200]}"
    return bool(confirmed), notes, proof


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_replacement(replacement_name: str, ecosystem: str) -> dict:
    """Validate that a replacement package exists.

    Returns a dict with keys: confirmed (bool|None), method (str),
    notes (str|None), proof (str|None).
    """
    if not replacement_name:
        return {"confirmed": None, "method": "not_applicable", "notes": None, "proof": None}

    confirmed: Optional[bool] = None
    notes: Optional[str] = None
    proof: Optional[str] = None
    method: str = "registry_api"

    if ecosystem in REGISTRY_API_ECOSYSTEMS:
        fn = {
            "python": _check_pypi,
            "javascript": _check_npm,
            "go": _check_go,
            "dotnet": _check_nuget,
            "perl": _check_cpan,
        }.get(ecosystem)
        if fn:
            confirmed, notes = fn(replacement_name)
        else:
            confirmed, notes = None, f"Unhandled ecosystem: {ecosystem}"

    elif ecosystem == "java":
        confirmed, notes = _check_maven(replacement_name)
        method = "name_only"
        notes = (notes or "") + "; groupId unknown — validated by artifact name only"

    elif ecosystem == "php":
        confirmed, notes = _check_pypi(replacement_name)

    elif ecosystem in TAVILY_ECOSYSTEMS:
        method = "tavily_model"
        label = ECOSYSTEM_LABELS.get(ecosystem, ecosystem)
        confirmed, notes, proof = _validate_via_model(replacement_name, label)

    else:
        confirmed, notes = None, f"No validation strategy for ecosystem '{ecosystem}'"

    return {
        "confirmed": confirmed,
        "method": method,
        "notes": notes,
        "proof": proof,
    }
