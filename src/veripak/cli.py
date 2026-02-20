"""veripak CLI entry point."""

import datetime
import json
import sys
from typing import Optional

import click

from . import __version__, config
from .checkers import cves, downloads, replacements, versions


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
        hide_input=False,
    )
    nvd_key = click.prompt(
        "NVD API key (optional, press enter to skip)",
        default=cfg.get("nvd_api_key", ""),
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
@click.option("--ecosystem", "-e", required=True, help="Package ecosystem (python, java, c, …)")
@click.option(
    "--versions", "version_list",
    default="",
    help="Comma-separated versions in use for CVE matching (e.g. 2.14.0,2.15.0)",
)
@click.option("--replacement", "-r", default="", help="Name of the replacement package to validate")
@click.option("--json", "output_json", is_flag=True, help="Output machine-readable JSON")
@click.option("--no-cves", is_flag=True, help="Skip CVE check")
@click.option("--no-download", is_flag=True, help="Skip download validation")
def cmd_check(
    package: str,
    ecosystem: str,
    version_list: str,
    replacement: str,
    output_json: bool,
    no_cves: bool,
    no_download: bool,
) -> None:
    """Audit PACKAGE in ECOSYSTEM."""
    checked_at = datetime.datetime.utcnow().isoformat() + "Z"
    parsed_versions = [v.strip() for v in version_list.split(",") if v.strip()]

    # --- Version ---
    version_result = versions.get_latest_version(package, ecosystem)
    latest_stable = version_result.get("version")

    # --- Download ---
    download_result: Optional[dict] = None
    if not no_download:
        download_url = ""  # CLI doesn't accept download_url; rely on ecosystem logic
        download_result = downloads.check_download(
            name=package,
            ecosystem=ecosystem,
            version=latest_stable or (parsed_versions[0] if parsed_versions else ""),
            download_url=download_url,
        )

    # --- CVEs ---
    cve_result: Optional[dict] = None
    if not no_cves:
        cve_result = cves.check_cves(
            name=package,
            ecosystem=ecosystem,
            versions=parsed_versions,
            latest_version=latest_stable or "",
            replacement_name=replacement,
        )

    # --- Replacement ---
    replacement_result: Optional[dict] = None
    if replacement:
        replacement_result = replacements.check_replacement(
            replacement_name=replacement,
            ecosystem=ecosystem,
        )

    # --- Output ---
    result = {
        "package": package,
        "ecosystem": ecosystem,
        "checked_at": checked_at,
        "version": {
            "latest_stable": latest_stable,
            "method": version_result.get("method"),
            "source_url": version_result.get("source_url"),
            "proof": version_result.get("proof"),
            "notes": version_result.get("notes"),
        },
        "download": download_result,
        "cves": cve_result,
        "replacement": replacement_result,
    }

    if output_json:
        click.echo(json.dumps(result, indent=2))
        return

    # Human-readable output
    click.echo()
    click.echo(f"  Package:     {package}  ({ecosystem})")

    version_str = latest_stable or "(not found)"
    method_tag = version_result.get("method", "")
    notes_tag = f"  NOTE: {version_result.get('notes')}" if version_result.get("notes") else ""
    click.echo(f"  Version:     {version_str}  [{method_tag}]{notes_tag}")

    if download_result is not None:
        dl_confirmed = download_result.get("confirmed")
        dl_method = download_result.get("method", "")
        if dl_confirmed is True:
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

    click.echo()
