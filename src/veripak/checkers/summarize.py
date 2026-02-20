"""Multi-turn security summary agent with Tavily tool access."""

import json
import re
from typing import Optional

from .. import model_caller
from .. import tavily as tavily_client

_SYSTEM = """You are a security analyst reviewing software package audit data for an operations team.

You will receive structured data about a package: version in use, latest available version, end-of-life status, and a list of CVEs.

Use the tavily_search tool if you need additional context — for example, to understand a specific CVE's real-world impact, confirm the upgrade path, or check what the latest version offers security-wise. Use it sparingly (only when the provided data is insufficient).

Be direct and specific. Quantify risk. Give actionable recommendations with urgency appropriate to the findings."""

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

_SUMMARY_REQUEST = """Based on all of the above, produce a JSON security summary. Reply with ONLY valid JSON, no markdown fences, no explanation.

{
  "total_distinct_cves": <integer>,
  "high_or_critical_count": <integer>,
  "eol": <true or false or null>,
  "eol_date": "<human-readable EOL status, e.g. 'Grafana 6.x reached end of life on 2021-06-08'>",
  "version_gap": "<describe how far behind the version in use is from current, e.g. '6.7.4 is 6 major versions behind 12.3.3'>",
  "recommendation": "<single actionable recommendation for the ops team, specific about urgency>"
}"""

_MAX_TOOL_ROUNDS = 3


def _format_context(
    pkg: str,
    ecosystem: str,
    versions_in_use: list[str],
    result: dict,
) -> str:
    """Format the assembled audit result as a readable first user message."""
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
            parts = []
            for r in results:
                parts.append(f"[{r['title']}]\n{r['content'][:400]}")
            return "\n\n".join(parts) or "No results found."
        except Exception as exc:
            return f"Search failed: {exc}"
    return f"Unknown tool: {name}"


def _msg_to_dict(msg) -> dict:
    """Convert a liteLLM message object to a plain dict for the messages list."""
    d: dict = {"role": msg.role}
    if msg.content is not None:
        d["content"] = msg.content
    tool_calls = getattr(msg, "tool_calls", None)
    if tool_calls:
        d["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                },
            }
            for tc in tool_calls
        ]
    return d


def generate_summary(
    result: dict,
    versions_in_use: Optional[list[str]] = None,
) -> Optional[dict]:
    """Run the multi-turn summary agent and return a summary dict.

    Returns None if the model loop fails entirely (caller decides whether to
    include a partial fallback or omit the summary key).
    """
    pkg = result.get("package", "")
    ecosystem = result.get("ecosystem", "")
    versions_in_use = versions_in_use or []

    context = _format_context(pkg, ecosystem, versions_in_use, result)

    messages: list[dict] = [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": context},
    ]
    tools = [_TAVILY_TOOL]

    # Agentic loop: model can call tavily_search up to _MAX_TOOL_ROUNDS times.
    try:
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
                tool_result = _execute_tool(tc.function.name, fn_args)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": tool_result,
                })

        # Final turn: ask for structured JSON.
        messages.append({"role": "user", "content": _SUMMARY_REQUEST})
        final_msg = model_caller.call_model_chat(messages, tools=None)
        raw = (final_msg.content or "").strip()

        # Strip markdown fences if present.
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw).strip()

        return json.loads(raw)

    except Exception:
        return None
