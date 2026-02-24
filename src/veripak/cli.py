"""veripak CLI entry point."""

import json

import click

from . import __version__, config
from .agent import PackageCheckAgent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _echo_check(label: str, value: str) -> None:
    click.echo(f"  {label:<12}{value}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@click.group()
def main() -> None:
    """veripak — open-source package auditor."""


@main.command("version")
def cmd_version() -> None:
    """Print the veripak version."""
    click.echo(f"veripak {__version__}")


@main.command("config")
def cmd_config() -> None:
    """Interactive setup wizard."""
    cfg = config.load_config()

    backend = click.prompt(
        "LLM backend [ollama/anthropic/openai/vllm]",
        default=cfg.get("llm_backend", "ollama"),
    )
    model = click.prompt(
        "Model name",
        default=cfg.get("llm_model", "gpt-oss:20b"),
    )
    base_url = click.prompt(
        "Base URL (for ollama/vllm)",
        default=cfg.get("llm_base_url", "http://localhost:11434"),
    )
    tavily_key = click.prompt(
        "Tavily API key",
        default=cfg.get("tavily_api_key", ""),
        hide_input=True,
    )
    nvd_key = click.prompt(
        "NVD API key (optional, press enter to skip)",
        default=cfg.get("nvd_api_key", ""),
        hide_input=True,
    )
    anthropic_key = click.prompt(
        "Anthropic API key (optional fallback, press enter to skip)",
        default=cfg.get("anthropic_api_key", ""),
        hide_input=True,
    )

    new_cfg: dict = {
        "llm_backend": backend,
        "llm_model": model,
        "llm_base_url": base_url,
        "tavily_api_key": tavily_key,
    }
    if nvd_key:
        new_cfg["nvd_api_key"] = nvd_key
    if anthropic_key:
        new_cfg["anthropic_api_key"] = anthropic_key

    config.save_config(new_cfg)
    click.echo(f"Config saved to {config.config_path()}")


@main.command("check")
@click.argument("package")
@click.option("--ecosystem", "-e", default=None, help="Package ecosystem (python, java, c, …). Inferred automatically if omitted.")
@click.option(
    "--versions", "version_list",
    default="",
    help="Comma-separated versions in use for CVE matching (e.g. 2.14.0,2.15.0)",
)
@click.option("--replacement", "-r", default="", help="Name of the replacement package to validate")
@click.option("--release-notes-url", default="", help="URL of the release notes page")
@click.option("--repository-url", default="", help="Source repository URL")
@click.option("--homepage", default="", help="Project homepage URL")
@click.option("--download-url", default="", help="Known download URL")
@click.option("--json", "output_json", is_flag=True, help="Output machine-readable JSON")
@click.option("--no-cves", is_flag=True, help="Skip CVE check")
@click.option("--no-download", is_flag=True, help="Skip download validation")
@click.option("--no-summary", is_flag=True, help="Skip AI security summary")
def cmd_check(
    package: str,
    ecosystem: str,
    version_list: str,
    replacement: str,
    release_notes_url: str,
    repository_url: str,
    homepage: str,
    download_url: str,
    output_json: bool,
    no_cves: bool,
    no_download: bool,
    no_summary: bool,
) -> None:
    """Audit PACKAGE in ECOSYSTEM."""
    if not ecosystem:
        from .checkers.ecosystem import infer_ecosystem
        inferred = infer_ecosystem(
            package,
            version=version_list.split(",")[0].strip() if version_list.strip() else None,
        )
        if not inferred:
            raise click.UsageError(
                f"Could not infer ecosystem for '{package}'. "
                "Please specify it with --ecosystem."
            )
        ecosystem = inferred
        inferred_note = "  (inferred)"
    else:
        inferred_note = ""

    agent = PackageCheckAgent()
    result = agent.run(
        package=package,
        ecosystem=ecosystem,
        versions_in_use=[v.strip() for v in version_list.split(",") if v.strip()],
        replacement_name=replacement or None,
        homepage=homepage or None,
        release_notes_url=release_notes_url or None,
        repository_url=repository_url or None,
        download_url=download_url or None,
        skip_cves=no_cves,
        skip_download=no_download,
        skip_summary=no_summary,
    )

    if output_json:
        click.echo(json.dumps(result, indent=2))
        return

    # Human-readable output
    version_result = result.get("version") or {}
    download_result = result.get("download")
    cve_result = result.get("cves")
    replacement_result = result.get("replacement")
    agent_meta = result.get("_agent", {})

    latest_stable = version_result.get("version")

    click.echo()
    click.echo(f"  Package:     {package}  ({ecosystem}{inferred_note})")

    eol_result = result.get("eol") or {}
    if eol_result.get("eol") is True:
        eol_date = eol_result.get("eol_date") or "unknown date"
        eol_cycle = eol_result.get("cycle", "")
        eol_latest = eol_result.get("latest_in_cycle", "")
        eol_suffix = f"  (cycle {eol_cycle}, latest patch: {eol_latest})" if eol_cycle else ""
        click.echo(f"  EOL:         WARNING — end of life {eol_date}{eol_suffix}")
    elif eol_result.get("eol") is False:
        eol_cycle = eol_result.get("cycle", "")
        eol_latest = eol_result.get("latest_in_cycle", "")
        eol_suffix = f"  (cycle {eol_cycle}, latest patch: {eol_latest})" if eol_cycle else ""
        click.echo(f"  EOL:         supported{eol_suffix}")

    version_str = latest_stable or "(not found)"
    method_tag = version_result.get("method", "")
    notes_tag = f"  NOTE: {version_result.get('notes')}" if version_result.get("notes") else ""
    click.echo(f"  Version:     {version_str}  [{method_tag}]{notes_tag}")

    if download_result is not None:
        dl_confirmed = download_result.get("confirmed")
        dl_method = download_result.get("method", "")
        if dl_method == "skipped":
            dl_notes = download_result.get("notes") or "skipped"
            dl_str = f"skipped: {dl_notes}"
        elif dl_confirmed is True:
            dl_str = f"confirmed  [{dl_method}]"
        elif dl_confirmed is False:
            dl_notes = download_result.get("notes") or "failed"
            dl_str = f"FAILED: {dl_notes}  [{dl_method}]"
        else:
            dl_str = f"unknown  [{dl_method}]"
        click.echo(f"  Download:    {dl_str}")

    if cve_result is not None:
        total = cve_result.get("total_count", 0)
        hc = cve_result.get("high_critical_count", 0)
        cve_str = f"{total} total  ({hc} HIGH/CRITICAL)  [{cve_result.get('method')}]"
        click.echo(f"  CVEs:        {cve_str}")

    summary = result.get("summary")
    if summary:
        click.echo()
        click.echo("  Summary:")
        if summary.get("version_gap"):
            click.echo(f"    Version gap:    {summary['version_gap']}")
        migration = summary.get("migration_complexity")
        breaking = summary.get("breaking_change_likely")
        if migration:
            breaking_tag = "  (breaking change likely)" if breaking else ""
            click.echo(f"    Migration:      {migration}{breaking_tag}")
        if summary.get("eol_date"):
            click.echo(f"    EOL:            {summary['eol_date']}")
        urgency = summary.get("urgency")
        if urgency:
            click.echo(f"    Urgency:        {urgency.upper()}")
        if summary.get("recommendation"):
            click.echo(f"    Recommend:      {summary['recommendation']}")
        gaps = summary.get("_gaps", [])
        if gaps:
            click.echo(f"    (undetermined:  {', '.join(gaps)})")

    if replacement_result is not None:
        r_confirmed = replacement_result.get("confirmed")
        r_method = replacement_result.get("method", "")
        r_notes = replacement_result.get("notes") or ""
        if r_confirmed is True:
            r_str = f"confirmed  [{r_method}]"
        elif r_confirmed is False:
            r_str = f"NOT FOUND  [{r_method}]"
        else:
            r_str = f"unknown  [{r_method}]"
        if r_notes:
            r_str += f"  ({r_notes[:80]})"
        click.echo(f"  Replacement: {replacement}  {r_str}")
    else:
        click.echo("  Replacement: n/a")

    agent_errors = agent_meta.get("errors", [])
    if agent_errors:
        click.echo("  Errors:")
        for err in agent_errors:
            click.echo(f"    {err}")

    usage = result.get("_usage")
    if usage and usage.get("total_tokens"):
        prompt_t = usage["prompt_tokens"]
        comp_t = usage["completion_tokens"]
        total_t = usage["total_tokens"]
        cost = usage["estimated_cost_usd"]
        click.echo(f"  Tokens:      {prompt_t:,} prompt + {comp_t:,} completion = {total_t:,} total (${cost:.4f})")

    click.echo()
