"""EOL Agent: Multi-signal end-of-life determination with HITL flags.

Three phases:
  Phase 1 — Is this version EOL? (needs 2+ corroborating signals)
  Phase 2 — Is the project dead? (only if Phase 1 says EOL)
  Phase 3 — What's the replacement? (upgrade path or successor package)
"""

import logging
from typing import Optional

from .base import AgentResult, ToolDef, run_agent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _tool_web_search(query: str) -> dict:
    """Search the web via Tavily."""
    try:
        from .. import tavily as tavily_client
        results = tavily_client.search(query, max_results=5)
        return {
            "results": [
                {
                    "title": r.get("title", ""),
                    "url": r.get("url", ""),
                    "snippet": (r.get("content") or "")[:400],
                }
                for r in results
            ]
        }
    except Exception as exc:
        return {"error": str(exc)}


def _tool_check_endoflife_date(product: str, version: Optional[str] = None) -> dict:
    """Query the endoflife.date API for lifecycle data."""
    from ..checkers.eol import check_eol
    versions = [version] if version else []
    return check_eol(product, versions)


def _tool_check_registry(package: str, ecosystem: str) -> dict:
    """Check a package registry for version info and release dates."""
    from ..checkers.versions import get_latest_version
    try:
        result = get_latest_version(package, ecosystem, [])
        return {
            "latest_version": result.get("version"),
            "method": result.get("method"),
            "notes": result.get("notes"),
        }
    except Exception as exc:
        return {"error": str(exc)}


def _tool_check_github(repo_url: str) -> dict:
    """Check a GitHub repository for activity and status."""
    import datetime
    import json
    import re
    import urllib.request

    m = re.match(r'https?://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$', repo_url)
    if not m:
        return {"error": f"Not a GitHub URL: {repo_url}"}

    owner_repo = m.group(1)
    headers = {"User-Agent": "veripak/0.1", "Accept": "application/json"}

    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{owner_repo}",
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        return {"error": f"GitHub API: {exc}"}

    result = {
        "archived": data.get("archived", False),
        "description": data.get("description", ""),
        "pushed_at": data.get("pushed_at", ""),
        "default_branch": data.get("default_branch", ""),
        "open_issues_count": data.get("open_issues_count", 0),
        "stargazers_count": data.get("stargazers_count", 0),
    }

    # Calculate days since last push
    pushed_at = data.get("pushed_at", "")
    if pushed_at:
        try:
            last_push = datetime.datetime.fromisoformat(pushed_at.rstrip("Z"))
            days_since = (datetime.datetime.utcnow() - last_push).days
            result["days_since_last_push"] = days_since
        except Exception:
            pass

    return result


def _tool_fetch_page(url: str) -> dict:
    """Fetch a URL and return its text content (truncated to 2000 chars)."""
    import urllib.request

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "veripak/0.1"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "html" in content_type or "text" in content_type:
                raw = resp.read(50_000).decode("utf-8", errors="replace")
                # Strip HTML tags for readability
                import re
                text = re.sub(r"<[^>]+>", " ", raw)
                text = re.sub(r"\s+", " ", text).strip()
                return {"content": text[:2000], "url": url}
            return {"error": "Non-text content type", "content_type": content_type}
    except Exception as exc:
        return {"error": f"Failed to fetch {url}: {exc}", "url": url}


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

_TOOLS = [
    ToolDef(
        name="web_search",
        description=(
            "Search the web for EOL announcements, lifecycle pages, and "
            "deprecation notices. Returns titles, URLs, and snippets."
        ),
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
            },
            "required": ["query"],
        },
        fn=_tool_web_search,
    ),
    ToolDef(
        name="check_endoflife_date",
        description=(
            "Query endoflife.date API for structured lifecycle data. "
            "Returns EOL status, dates, and cycle info. Note: this is "
            "crowdsourced data — treat as supporting evidence, not authoritative."
        ),
        parameters={
            "type": "object",
            "properties": {
                "product": {"type": "string", "description": "Product name"},
                "version": {"type": "string", "description": "Version to check"},
            },
            "required": ["product"],
        },
        fn=_tool_check_endoflife_date,
    ),
    ToolDef(
        name="check_registry",
        description=(
            "Check a package registry for the latest version and release info. "
            "Useful for determining if a specific branch is still receiving updates."
        ),
        parameters={
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "Package name"},
                "ecosystem": {"type": "string", "description": "Ecosystem (python, javascript, java, etc.)"},
            },
            "required": ["package", "ecosystem"],
        },
        fn=_tool_check_registry,
    ),
    ToolDef(
        name="check_github",
        description=(
            "Check a GitHub repository for activity: archived status, last push "
            "date, open issues. Indicates whether the project is actively maintained."
        ),
        parameters={
            "type": "object",
            "properties": {
                "repo_url": {
                    "type": "string",
                    "description": "GitHub repository URL (e.g. https://github.com/owner/repo)",
                },
            },
            "required": ["repo_url"],
        },
        fn=_tool_check_github,
    ),
    ToolDef(
        name="fetch_page",
        description=(
            "Fetch a web page and return its text content (up to 2000 chars). "
            "Use this to read lifecycle pages, release notes, or announcements. "
            "If the page is blocked (403, AI blocker), use flag_hitl instead."
        ),
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to fetch"},
            },
            "required": ["url"],
        },
        fn=_tool_fetch_page,
    ),
]


# ---------------------------------------------------------------------------
# System prompt template
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_TEMPLATE = """\
You are determining whether **version {version}** of **{package}** ({ecosystem}) \
is end-of-life.

"End of life" means this specific version/branch no longer receives security \
patches from the maintainer.

IMPORTANT DISTINCTIONS:
- A newer version existing does NOT mean the old version is EOL. Many projects \
maintain multiple branches simultaneously (e.g., Node 18 LTS + Node 22 LTS + \
Node 25 Current).
- "EOL" is about the VERSION/BRANCH, not the project. Node 16 is EOL, but Node \
the project is very much alive.
- A large version gap alone is NOT sufficient evidence of EOL.

EVIDENCE REQUIREMENTS — you need at least 2 corroborating signals:
  Strong signals (1 strong + 1 any = sufficient):
    - Vendor lifecycle page explicitly says this version is EOL
    - No releases on this branch in 12+ months while newer branches get updates
    - Vendor deprecation announcement
    - Registry deprecated flag (npm deprecated, PyPI Inactive classifier)

  Supporting signals (need 3 supporting if no strong signal):
    - endoflife.date says EOL (crowdsourced — use as supporting, not primary)
    - Version gap of 5+ major versions
    - GitHub repo archived

If the version IS EOL, also determine:
1. Is the project itself dead (no branch receives updates)?
2. What should the user upgrade to?
   - If project alive: recommend the current/LTS version of the SAME package
   - If project dead: search for a successor/replacement package

If you cannot access a key data source (website blocked, API down), use the \
flag_hitl tool to request human review rather than guessing.

{extra_context}

Reply with JSON:
{{
  "eol": true | false | null,
  "eol_date": "YYYY-MM-DD or null",
  "confidence": "high" | "medium" | "low",
  "project_status": "active" | "dead" | "archived" | "unknown",
  "signals": [
    {{"source": "url or description", "type": "signal type", "says": "what it says"}}
  ],
  "current_version": "latest version of this package or null",
  "recommended_version": "version to upgrade to or null",
  "replacement_package": "different package name if project is dead, else null"
}}
"""


def check_eol(
    package: str,
    version: str,
    ecosystem: str,
    repository_url: Optional[str] = None,
    homepage: Optional[str] = None,
) -> AgentResult:
    """Run the EOL agent for a package version.

    Returns an AgentResult whose `answer` dict contains:
      eol, eol_date, confidence, project_status, signals,
      current_version, recommended_version, replacement_package
    """
    extra_lines = []
    if repository_url:
        extra_lines.append(f"Repository URL: {repository_url}")
    if homepage:
        extra_lines.append(f"Homepage: {homepage}")
    extra_context = "\n".join(extra_lines) if extra_lines else ""

    system_prompt = _SYSTEM_PROMPT_TEMPLATE.format(
        package=package,
        version=version,
        ecosystem=ecosystem,
        extra_context=extra_context,
    )

    user_prompt = (
        f"Determine the EOL status of {package} version {version}.\n\n"
        f"Start by searching for lifecycle information and checking the "
        f"endoflife.date API. Then validate with additional sources."
    )

    result = run_agent(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        tools=_TOOLS,
        agent_name="eol_agent",
        max_turns=10,
        max_tool_calls=25,
    )

    return result
