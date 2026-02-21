"""Multi-turn security summary agent with two-stage schema filling."""

import json
import logging
import re
from pathlib import Path
from typing import Optional

from .. import model_caller
from .. import tavily as tavily_client
from .migration import compute_migration_complexity, is_calver, compute_urgency_floor, urgency_at_least

log = logging.getLogger(__name__)

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
    "migration_complexity": None,   # "patch" | "minor" | "major" | "rewrite" | "unknown"
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

    # Pre-computed migration complexity
    if ver_in_use != "unknown" and latest != "unknown":
        complexity = compute_migration_complexity(ver_in_use, latest, eol_flag)
        lines.append(
            f"\nPre-computed migration assessment: complexity={complexity['migration_complexity']}, "
            f"breaking_change_likely={complexity['breaking_change_likely']}, "
            f"version_gap={complexity['version_gap']}"
        )
        if complexity.get("_calver"):
            lines.append(
                f"Note: This package uses calendar versioning (CalVer). "
                f"Version {ver_in_use} -> {latest} represents a time gap, "
                f"not a breaking API change."
            )

    total = cve_data.get("total_count", 0)
    hc = cve_data.get("high_critical_count", 0)

    # Pre-computed urgency floor
    if ver_in_use != "unknown":
        cve_list_inner = cve_data.get("versions_cves", [])
        has_critical = any(
            (c.get("severity") or "").upper() == "CRITICAL" for c in cve_list_inner
        )
        urgency_floor = compute_urgency_floor(
            eol=eol_flag,
            high_critical_count=hc,
            total_cves=total,
            migration_complexity=complexity["migration_complexity"] if ver_in_use != "unknown" and latest != "unknown" else "unknown",
            has_critical=has_critical,
        )
        lines.append(
            f"Minimum urgency based on data: {urgency_floor}. "
            f"You may escalate this but do not rate urgency lower than this floor."
        )
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
    content = final.content or ""

    # Quality gate: reject empty or trivially short responses
    if not content.strip() or len(content.strip()) < 100:
        log.warning("Analysis response too short (%d chars), rejecting", len(content.strip()))
        return None

    return content


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

    _ENUM_FIELDS = {
        "migration_complexity": {"patch", "minor", "major", "rewrite", "unknown"},
        "urgency": {"immediate", "high", "medium", "low"},
    }

    # Normalise: only keep known schema keys, coerce types where possible
    out: dict = {}
    for key in SUMMARY_SCHEMA:
        val = result.get(key)
        if isinstance(val, str) and key in _ENUM_FIELDS:
            val = val.lower()
            if val not in _ENUM_FIELDS[key]:
                val = None
        out[key] = val

    # Collect null fields as _gaps
    gaps = [k for k, v in out.items() if v is None]
    if gaps:
        out["_gaps"] = gaps

    # Check critical field completeness; retry schema mapping if too many nulls
    _CRITICAL_FIELDS = [
        "urgency", "migration_complexity", "breaking_change_likely",
        "upgrade_path", "recommendation",
    ]
    null_critical = [f for f in _CRITICAL_FIELDS if out.get(f) is None]
    if len(null_critical) > 3:
        log.info(
            "Schema mapping left %d/5 critical fields null (%s), retrying with explicit prompt",
            len(null_critical), ", ".join(null_critical),
        )
        retry_prompt = (
            f"The following fields are still null and MUST be filled from the analysis: "
            f"{', '.join(null_critical)}.\n\n"
            f"Re-read the analysis carefully and extract values for these fields. "
            f"If the analysis doesn't state them explicitly, infer them from the data "
            f"(e.g., a major version gap implies migration_complexity='major').\n\n"
            f"Analysis:\n{analysis}\n\n"
            f"Reply with ONLY valid JSON matching this schema:\n{schema_json}"
        )
        retry_messages = [
            {"role": "system", "content": _SYSTEM_SCHEMA},
            {"role": "user", "content": retry_prompt},
        ]
        retry_msg = model_caller.call_model_chat(retry_messages, tools=None)
        retry_raw = _strip_fences((retry_msg.content or "").strip())
        try:
            retry_result = json.loads(retry_raw)
            # Merge: only fill in fields that were null
            for f in null_critical:
                val = retry_result.get(f)
                if val is not None:
                    if isinstance(val, str) and f in _ENUM_FIELDS:
                        val = val.lower()
                        if val not in _ENUM_FIELDS[f]:
                            continue
                    out[f] = val
            # Recompute gaps
            gaps = [k for k, v in out.items() if k != "_gaps" and v is None]
            if gaps:
                out["_gaps"] = gaps
            elif "_gaps" in out:
                del out["_gaps"]
        except Exception:
            pass  # Retry parse failed; keep original results

    return out


# ---------------------------------------------------------------------------
# Rule-based fallback (no model needed)
# ---------------------------------------------------------------------------

def _rule_based_fallback(result: dict, versions_in_use: list[str]) -> dict:
    """Generate a minimal summary from raw audit data when the model fails.

    Produces a dict with the same shape as SUMMARY_SCHEMA plus _gaps and
    a _method indicator so callers know this was not model-generated.
    """
    eol_data = result.get("eol") or {}
    version_data = result.get("version") or {}
    cve_data = result.get("cves") or {}

    ver_in_use = versions_in_use[0] if versions_in_use else None
    latest = version_data.get("version")
    is_eol = eol_data.get("eol")
    eol_date = eol_data.get("eol_date")

    total_cves = cve_data.get("total_count", 0)
    high_critical = cve_data.get("high_critical_count", 0)

    # Compute version gap via the deterministic module
    gaps = compute_migration_complexity(
        version_in_use=ver_in_use or "",
        latest_version=latest or "",
        eol=is_eol,
    )

    migration_complexity = gaps["migration_complexity"]

    # Determine urgency floor from raw data
    has_critical = any(
        (c.get("severity") or "").upper() == "CRITICAL"
        for c in cve_data.get("versions_cves", [])
    )
    urgency = compute_urgency_floor(
        eol=is_eol,
        high_critical_count=high_critical,
        total_cves=total_cves,
        migration_complexity=migration_complexity,
        has_critical=has_critical,
    )
    breaking = gaps["breaking_change_likely"]

    # Build upgrade_path and recommendation from available data
    upgrade_path = None
    recommendation = None
    if latest and ver_in_use:
        if migration_complexity in ("patch", "minor"):
            upgrade_path = f"Update from {ver_in_use} to {latest}"
            recommendation = (
                f"Update to {latest} to remediate {total_cves} CVEs."
                if total_cves > 0
                else f"Update to {latest} to stay current."
            )
        elif migration_complexity in ("major", "rewrite"):
            upgrade_path = f"Migrate from {ver_in_use} to {latest}"
            recommendation = (
                f"Initiate a migration project to {latest}. "
                f"This is a breaking change — allocate engineering time for "
                f"code changes, testing, and validation."
            )
            if total_cves > 0:
                recommendation += f" {total_cves} CVEs affect the current version."

    out = {
        "total_distinct_cves": total_cves,
        "high_or_critical_count": high_critical,
        "eol": is_eol,
        "eol_date": eol_date,
        "version_in_use": ver_in_use,
        "latest_version": latest,
        "version_gap": gaps["version_gap"],
        "migration_complexity": migration_complexity,
        "breaking_change_likely": breaking,
        "upgrade_path": upgrade_path,
        "recommendation": recommendation,
        "urgency": urgency,
        "_method": "rule_based",
    }

    null_fields = [k for k in SUMMARY_SCHEMA if out.get(k) is None]
    if null_fields:
        out["_gaps"] = null_fields

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

    Falls back to rule-based summary if the model pipeline fails.
    Returns None only if both the model and fallback fail.
    Null schema fields are listed in _gaps.
    """
    pkg = result.get("package", "")
    ecosystem = result.get("ecosystem", "")
    versions_in_use = versions_in_use or []

    context = _format_context(pkg, ecosystem, versions_in_use, result)

    try:
        analysis = _run_analysis(context)
        if not analysis:
            log.warning("Analysis returned no content for %s, falling back to rules", pkg)
            return _rule_based_fallback(result, versions_in_use)
        summary = _run_schema_mapping(analysis)

        # Fill null migration fields from pre-computed deterministic values
        ver_in_use = versions_in_use[0] if versions_in_use else ""
        latest = (result.get("version") or {}).get("version") or ""
        eol_flag = (result.get("eol") or {}).get("eol")
        if ver_in_use and latest and ver_in_use != "unknown" and latest != "unknown":
            precomputed = compute_migration_complexity(ver_in_use, latest, eol_flag)
            if summary.get("migration_complexity") is None:
                summary["migration_complexity"] = precomputed["migration_complexity"]
            if summary.get("breaking_change_likely") is None:
                summary["breaking_change_likely"] = precomputed["breaking_change_likely"]
            if summary.get("version_gap") is None:
                summary["version_gap"] = precomputed["version_gap"]
            # Remove now-filled fields from _gaps
            if "_gaps" in summary:
                summary["_gaps"] = [g for g in summary["_gaps"] if summary.get(g) is None]
                if not summary["_gaps"]:
                    del summary["_gaps"]

        # Enforce urgency floor
        if ver_in_use:
            cve_data = result.get("cves") or {}
            has_crit = any(
                (c.get("severity") or "").upper() == "CRITICAL"
                for c in cve_data.get("versions_cves", [])
            )
            floor = compute_urgency_floor(
                eol=eol_flag,
                high_critical_count=cve_data.get("high_critical_count", 0),
                total_cves=cve_data.get("total_count", 0),
                migration_complexity=summary.get("migration_complexity") or "unknown",
                has_critical=has_crit,
            )
            summary["urgency"] = urgency_at_least(summary.get("urgency"), floor)
            # Update gaps if urgency was filled
            if "_gaps" in summary:
                summary["_gaps"] = [g for g in summary["_gaps"] if g != "urgency"]
                if not summary["_gaps"]:
                    del summary["_gaps"]

        # Enforce complexity floor: if the LLM ignored EOL and rated complexity as
        # "patch", override to "major" — an EOL package always requires migration.
        if eol_flag is True and summary.get("migration_complexity") == "patch":
            summary["migration_complexity"] = "major"
            summary["breaking_change_likely"] = True

        return summary
    except Exception as exc:
        log.warning("Model pipeline failed for %s (%s), falling back to rules", pkg, exc)
        try:
            return _rule_based_fallback(result, versions_in_use)
        except Exception as fb_exc:
            return {
                "_error": f"model: {type(exc).__name__}: {exc}; fallback: {fb_exc}",
                "_gaps": list(SUMMARY_SCHEMA.keys()),
            }
