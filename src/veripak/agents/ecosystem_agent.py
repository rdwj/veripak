"""Ecosystem Agent (E0): LLM-first ecosystem inference with registry validation.

Instead of probing every registry sequentially, we ask the model "what ecosystem
is this?" — which it usually knows instantly — then validate by probing the
candidate registry. Falls back to Tavily search if the probe fails.
"""

import logging
from typing import Optional

from .base import AgentResult, ToolDef, run_agent
from ..checkers.ecosystem import (
    _ECOSYSTEM_OVERRIDES,
    _REGISTRY_PROBES,
    _VALID_ECOSYSTEMS,
)

logger = logging.getLogger(__name__)

# Map ecosystem names to their probe functions for targeted validation
_PROBE_MAP = {eco: fn for eco, fn in _REGISTRY_PROBES}

_SYSTEM_PROMPT = """\
You are determining the software ecosystem for a package. The ecosystem tells us
where users obtain and install the package.

Valid ecosystems:
- python: installed via pip/PyPI
- javascript: installed via npm
- java: installed via Maven Central
- go: installed via `go get` (Go modules)
- dotnet: installed via NuGet
- perl: installed via CPAN
- php: installed via Packagist (vendor/package format)
- c: C library, typically compiled from source or installed via system package manager
- cpp: C++ library, typically compiled from source or installed via system package manager
- system: system utility/daemon distributed via OS package managers (yum, apt)
- desktop-app: standalone binary application (Grafana, Prometheus, etc.)
- driver: hardware driver

Key distinctions:
- A Go tool installed via `go get` is "go", but a Go binary downloaded from
  GitHub releases is "desktop-app"
- The language a package is WRITTEN in is not always its ecosystem — a C library
  wrapped for Python and distributed on PyPI is "python"
- "system" is for OS-level utilities (389-ds, systemd), not libraries

First, tell me what ecosystem this package belongs to. Then I will ask you to
validate your answer by probing the registry. Reply with JSON:
{"ecosystem": "<name>", "confidence": "high"|"medium"|"low", "reasoning": "<brief>"}
"""


def _tool_probe_registry(package: str, ecosystem: str) -> dict:
    """Probe a specific ecosystem's registry to verify the package exists there."""
    if ecosystem not in _VALID_ECOSYSTEMS:
        return {"found": False, "error": f"Unknown ecosystem: {ecosystem}"}

    probe_fn = _PROBE_MAP.get(ecosystem)
    if not probe_fn:
        # Non-programmatic ecosystems (c, cpp, system, desktop-app, driver)
        # don't have registries to probe
        return {"found": None, "note": f"No registry for {ecosystem}"}

    try:
        found = probe_fn(package)
    except Exception as exc:
        return {"found": None, "error": str(exc)}

    return {"found": found, "ecosystem": ecosystem}


def _tool_web_search(query: str) -> dict:
    """Search the web via Tavily to determine a package's ecosystem."""
    try:
        from .. import tavily as tavily_client
        results = tavily_client.search(query, max_results=3)
        return {
            "results": [
                {"title": r.get("title", ""), "snippet": (r.get("content") or "")[:300]}
                for r in results
            ]
        }
    except Exception as exc:
        return {"error": str(exc)}


_TOOLS = [
    ToolDef(
        name="probe_registry",
        description=(
            "Check if a package exists in a specific ecosystem's registry. "
            "For programmatic ecosystems (python, javascript, java, go, dotnet, perl, php), "
            "this probes the actual registry API. Returns {found: true/false}."
        ),
        parameters={
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "Package name"},
                "ecosystem": {"type": "string", "description": "Ecosystem to check"},
            },
            "required": ["package", "ecosystem"],
        },
        fn=_tool_probe_registry,
    ),
    ToolDef(
        name="web_search",
        description="Search the web for information about a package's ecosystem.",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
            },
            "required": ["query"],
        },
        fn=_tool_web_search,
    ),
]


def infer_ecosystem(name: str, version: Optional[str] = None) -> Optional[str]:
    """Infer the ecosystem for a package using the Ecosystem Agent.

    Checks hard-coded overrides first, then runs the LLM agent which can
    probe registries and search the web to validate its answer.

    Returns None if inference fails.
    """
    # Fast path: hard-coded overrides
    override = _ECOSYSTEM_OVERRIDES.get(name.lower())
    if override:
        return override

    version_hint = f" version {version}" if version else ""
    user_prompt = (
        f'What ecosystem does the package "{name}"{version_hint} belong to?\n\n'
        f"Use the probe_registry tool to validate your answer. If the probe "
        f"returns found=false, reconsider and try other ecosystems or use "
        f"web_search to find out more."
    )

    result = run_agent(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        tools=_TOOLS,
        agent_name="ecosystem_agent",
        max_turns=6,
        max_tool_calls=8,
    )

    if result.error:
        logger.warning("Ecosystem agent failed for %s: %s", name, result.error)
        return _fallback_probe_all(name, version)

    ecosystem = result.answer.get("ecosystem", "").strip().lower()
    if ecosystem in _VALID_ECOSYSTEMS:
        return ecosystem

    logger.warning("Ecosystem agent returned invalid ecosystem %r for %s", ecosystem, name)
    return _fallback_probe_all(name, version)


def _fallback_probe_all(name: str, version: Optional[str] = None) -> Optional[str]:
    """Deterministic fallback: probe all registries sequentially."""
    for eco, probe_fn in _REGISTRY_PROBES:
        try:
            if probe_fn(name, version):
                return eco
        except Exception:
            continue
    return None
