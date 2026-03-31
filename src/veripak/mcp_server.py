"""veripak MCP server — expose package auditing over MCP (stdio)."""

from __future__ import annotations

import time
from typing import Annotated

from fastmcp import FastMCP
from fastmcp.tools.tool import ToolResult

from . import __version__
from .agent import PackageCheckAgent


def _collect_data_gaps(result: dict) -> list[str]:
    """Identify missing or incomplete data and explain why."""
    from . import config

    gaps = []

    # Check for missing API keys that limit coverage
    if not config.get("tavily_api_key"):
        gaps.append(
            "No Tavily API key configured — web search disabled. "
            "EOL and CVE checks for non-registry ecosystems (c, cpp, system) will be limited."
        )
    if not config.get("nvd_api_key"):
        gaps.append(
            "No NVD API key configured — NVD rate limit is 5 requests per 30 seconds. "
            "CVE lookups for non-registry ecosystems may be incomplete."
        )

    # Check for null/missing results and surface reasons
    eol = result.get("eol") or {}
    if eol.get("eol") is None:
        product = eol.get("product")
        if product is None:
            gaps.append(
                "EOL status unknown — package not found on endoflife.date and "
                "no other EOL signal available."
            )
        else:
            gaps.append(f"EOL status could not be determined for '{product}'.")

    cves = result.get("cves")
    if cves is None:
        gaps.append("CVE check was skipped.")
    elif cves.get("method") == "error":
        gaps.append("CVE lookup failed — see pipeline_errors in metadata for details.")
    elif cves.get("total_count", 0) == 0:
        gaps.append(
            "No CVEs found — this may mean the package is clean, or that "
            "the vulnerability database does not track this package."
        )

    version = result.get("version") or {}
    if version.get("version") is None:
        gaps.append("Could not determine latest version from registry API.")

    download = result.get("download")
    if download is None:
        gaps.append("Download validation was skipped.")
    elif download.get("method") == "error":
        gaps.append(f"Download validation failed: {download.get('notes', 'unknown error')}")

    return gaps


def create_server() -> FastMCP:
    """Create and return a configured FastMCP server."""
    mcp = FastMCP(
        name="veripak",
        version=__version__,
    )

    @mcp.tool(
        name="veripak_check_package",
        description=(
            "Audit an open-source package for security and maintenance health. "
            "Returns latest version, end-of-life status, known CVEs (with severity) "
            "against specified versions in use, and download availability. "
            "All data comes from authoritative sources (PyPI, npm, Maven, OSV.dev, "
            "NVD, endoflife.date) — no LLM processing is applied to the results. "
            "Use this to evaluate whether a dependency is safe, current, and "
            "actively maintained."
        ),
        annotations={
            "title": "Check Package Health",
            "readOnlyHint": True,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        timeout=120.0,
    )
    def check_package(
        package: Annotated[str, "Package name (e.g. 'requests', 'lodash', 'log4j')"],
        ecosystem: Annotated[
            str | None,
            "Package ecosystem (python, javascript, java, go, dotnet, perl, php, c, cpp). "
            "Inferred automatically if omitted.",
        ] = None,
        versions_in_use: Annotated[
            list[str] | None,
            "Versions currently deployed, for CVE matching (e.g. ['2.28.0', '2.31.0'])",
        ] = None,
        replacement: Annotated[
            str | None, "Name of a replacement package to validate"
        ] = None,
        skip_cves: Annotated[bool, "Skip the CVE vulnerability check"] = False,
        skip_download: Annotated[bool, "Skip download URL validation"] = False,
    ) -> ToolResult:
        """Run the veripak audit pipeline for a single package."""
        start = time.monotonic()

        agent = PackageCheckAgent()
        result = agent.run(
            package=package,
            ecosystem=ecosystem,
            versions_in_use=versions_in_use or [],
            replacement_name=replacement,
            skip_cves=skip_cves,
            skip_download=skip_download,
            deterministic_only=True,
        )

        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Separate operational metadata from the audit payload
        usage = result.pop("_usage", None)
        agent_meta = result.pop("_agent", {})

        # Build a concise text summary for the content block
        lines = [f"veripak audit: {package}"]
        eco = result.get("ecosystem") or ecosystem or "unknown"
        lines.append(f"  Ecosystem:  {eco}")

        ver = result.get("version", {})
        lines.append(f"  Version:    {ver.get('version', 'unknown')}")

        eol = result.get("eol", {})
        if eol.get("eol") is True:
            lines.append(f"  EOL:        WARNING — end of life {eol.get('eol_date', 'unknown')}")
        elif eol.get("eol") is False:
            lines.append("  EOL:        supported")

        cves = result.get("cves")
        if cves is not None:
            total = cves.get("total_count", 0)
            hc = cves.get("high_critical_count", 0)
            lines.append(f"  CVEs:       {total} total ({hc} high/critical)")

        gaps = _collect_data_gaps(result)
        if gaps:
            lines.append("")
            lines.append("  Data gaps:")
            for gap in gaps:
                lines.append(f"    - {gap}")

        if gaps:
            result["data_gaps"] = gaps

        meta = {"execution_time_ms": elapsed_ms}
        if usage:
            meta["token_usage"] = usage
        if agent_meta.get("errors"):
            meta["pipeline_errors"] = agent_meta["errors"]

        return ToolResult(
            content="\n".join(lines),
            structured_content=result,
            meta=meta,
        )

    return mcp
