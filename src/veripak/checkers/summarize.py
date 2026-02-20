"""Multi-turn security summary agent with two-stage schema filling."""

import json
import re
from pathlib import Path
from typing import Optional

from .. import model_caller
from .. import tavily as tavily_client

# ---------------------------------------------------------------------------
# Agent-level instructions loaded from prompts/summary_rules.md
# ---------------------------------------------------------------------------

# Walk up to the repo root (src/veripak/checkers/ → src/veripak/ → src/ → repo root)
# then into prompts/. The try/except in _load_rules() handles installed-wheel scenarios
# where this path won't resolve.
_RULES_PATH = Path(__file__).parent.parent.parent.parent / "prompts" / "summary_rules.md"


def _load_rules() -> str:
    """Load summary_rules.md from the repo prompts/ directory.

    Returns empty string silently if the file is unavailable (e.g. installed as a wheel).
    The agent still functions without the rules — they are enhancement, not required.
    """
    try:
        return _RULES_PATH.read_text()
    except Exception:
        return ""


_SYSTEM_ANALYST = """You are a security analyst reviewing software package audit data for an operations team.

{rules}

You have access to a tavily_search tool. Use it when the provided data is insufficient — for example to understand a CVE's real-world impact, find the migration guide for a major version upgrade, or confirm the current latest version of the package."""

_TAVILY_TOOL = {
    "type": "function",
    "function": {
        "name": "tavily_search",
        "description": "Search the web for current information about a CVE, package, or upgrade path.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The search query"}
            },
            "required": ["query"],
        },
    },
}

_ANALYSIS_REQUEST = """Based on the audit data and any searches above, write a free-form security analysis. Cover:

1. CVE risk — count, severity breakdown, most critical CVEs and what they allow
2. EOL implications — is the package still receiving security patches?
3. Version gap — how far behind is the version in use, and what migration complexity does that imply (patch/minor/major)?
4. Breaking change assessment — if a major version upgrade is needed, say so explicitly and name the ecosystem-specific concerns
5. Upgrade path — what does the ops team actually need to do, and how urgent is it?

Be specific. Use version numbers. Do not soften the recommendation if the situation is critical."""

_SYSTEM_SCHEMA = """You are a data extraction assistant. Your job is to read a security analysis and extract structured data from it into a JSON schema. Fill in only fields you can determine with confidence from the analysis. Set any field to null if the analysis does not clearly support a value."""

# The schema the second thread maps to
SUMMARY_SCHEMA = {
    "total_distinct_cves": None,
    "high_or_critical_count": None,
    "eol": None,
    "eol_date": None,
    "version_in_use": None,
    "latest_version": None,
    "version_gap": None,
    "migration_complexity": None,   # "patch" | "minor" | "major" | "unknown"
    "breaking_change_likely": None,
    "upgrade_path": None,
    "recommendation": None,
    "urgency": None,                # "immediate" | "high" | "medium" | "low"
}

_SCHEMA_REQUEST = """Here is a security analysis:

{analysis}

Extract values into this JSON schema. Fill only what the analysis clearly states. Set uncertain fields to null. Reply with ONLY valid JSON, no fences, no explanation.

{schema}"""

_MAX_TOOL_ROUNDS = 3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_context(
    pkg: str,
    ecosystem: str,
    versions_in_use: list[str],
    result: dict,
) -> str:
    eol_data = result.get("eol") or {}
    version_data = result.get("version") or {}
    cve_data = result.get("cves") or {}

    ver_in_use = versions_in_use[0] if versions_in_use else "unknown"
    latest = version_data.get("version") or "unknown"
    latest_in_cycle = eol_data.get("latest_in_cycle")
    cycle = eol_data.get("cycle")
    eol_flag = eol_data.get("eol")
    eol_date = eol_data.get("eol_date")

    lines = [
        f"Package: {pkg}  |  Ecosystem: {ecosystem}",
        f"Version in use: {ver_in_use}",
        f"Latest available: {latest}",
    ]
    if latest_in_cycle:
        lines.append(f"Latest in current branch (cycle {cycle}): {latest_in_cycle}")
    if eol_flag is True:
        lines.append(f"End of life: YES — EOL date: {eol_date or 'unknown'}")
    elif eol_flag is False:
        lines.append("End of life: No (currently supported)")
    else:
        lines.append("End of life: unknown")

    # Structural breaking-change hint
    try:
        in_major = int(ver_in_use.split(".")[0])
        latest_major = int(latest.split(".")[0])
        if latest_major > in_major:
            lines.append(
                f"\nNote: version gap spans major versions "
                f"({in_major}.x → {latest_major}.x). "
                f"Major version upgrades typically involve breaking changes."
            )
    except Exception:
        pass

    total = cve_data.get("total_count", 0)
    hc = cve_data.get("high_critical_count", 0)
    lines.append(f"\nCVEs affecting {ver_in_use}: {total} total, {hc} HIGH or CRITICAL")

    cve_list = cve_data.get("versions_cves", [])
    if cve_list:
        lines.append("")
        for cve in cve_list[:25]:
            cid = cve.get("id", "")
            sev = cve.get("severity", "UNKNOWN")
            summary = (cve.get("summary") or "")[:250].replace("\n", " ")
            lines.append(f"{cid} ({sev}): {summary}")

    return "\n".join(lines)


def _execute_tool(name: str, args: dict) -> str:
    if name == "tavily_search":
        try:
            results = tavily_client.search(args.get("query", ""), max_results=3)
            parts = [f"[{r['title']}]\n{r['content'][:400]}" for r in results]
            return "\n\n".join(parts) or "No results found."
        except Exception as exc:
            return f"Search failed: {exc}"
    return f"Unknown tool: {name}"


def _msg_to_dict(msg) -> dict:
    d: dict = {"role": msg.role}
    if msg.content is not None:
        d["content"] = msg.content
    tool_calls = getattr(msg, "tool_calls", None)
    if tool_calls:
        d["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.function.name, "arguments": tc.function.arguments},
            }
            for tc in tool_calls
        ]
    return d


def _strip_fences(raw: str) -> str:
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw).strip()
    return raw


# ---------------------------------------------------------------------------
# Stage 1: free-form analyst thread
# ---------------------------------------------------------------------------

def _run_analysis(context: str) -> Optional[str]:
    """Run the analyst thread and return free-form prose analysis."""
    rules = _load_rules()
    system = _SYSTEM_ANALYST.format(rules=rules).strip()

    messages: list[dict] = [
        {"role": "system", "content": system},
        {"role": "user", "content": context},
    ]
    tools = [_TAVILY_TOOL]

    for _ in range(_MAX_TOOL_ROUNDS):
        msg = model_caller.call_model_chat(messages, tools=tools)
        messages.append(_msg_to_dict(msg))

        tool_calls = getattr(msg, "tool_calls", None) or []
        if not tool_calls:
            break
        for tc in tool_calls:
            try:
                fn_args = json.loads(tc.function.arguments)
            except Exception:
                fn_args = {}
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": _execute_tool(tc.function.name, fn_args),
            })

    messages.append({"role": "user", "content": _ANALYSIS_REQUEST})
    final = model_caller.call_model_chat(messages, tools=None)
    return final.content or None


# ---------------------------------------------------------------------------
# Stage 2: schema mapping thread
# ---------------------------------------------------------------------------

def _run_schema_mapping(analysis: str) -> dict:
    """Map free-form analysis to the summary schema in a fresh conversation."""
    schema_json = json.dumps(SUMMARY_SCHEMA, indent=2)
    prompt = _SCHEMA_REQUEST.format(analysis=analysis, schema=schema_json)

    messages = [
        {"role": "system", "content": _SYSTEM_SCHEMA},
        {"role": "user", "content": prompt},
    ]
    msg = model_caller.call_model_chat(messages, tools=None)
    raw = _strip_fences((msg.content or "").strip())

    try:
        result = json.loads(raw)
    except Exception:
        result = dict(SUMMARY_SCHEMA)

    # Normalise: only keep known schema keys, coerce types where possible
    out: dict = {}
    for key in SUMMARY_SCHEMA:
        out[key] = result.get(key)

    # Collect null fields as _gaps
    gaps = [k for k, v in out.items() if v is None]
    if gaps:
        out["_gaps"] = gaps

    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_summary(
    result: dict,
    versions_in_use: Optional[list[str]] = None,
) -> Optional[dict]:
    """Run the two-stage summary agent and return a summary dict.

    Stage 1: free-form analyst thread (with Tavily tool access).
    Stage 2: schema mapping in a fresh conversation (no tools).

    Returns None if both stages fail. Null schema fields are listed in _gaps.
    """
    pkg = result.get("package", "")
    ecosystem = result.get("ecosystem", "")
    versions_in_use = versions_in_use or []

    context = _format_context(pkg, ecosystem, versions_in_use, result)

    try:
        analysis = _run_analysis(context)
        if not analysis:
            return None
        return _run_schema_mapping(analysis)
    except Exception:
        return None
