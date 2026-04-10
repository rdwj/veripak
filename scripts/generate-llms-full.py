#!/usr/bin/env python3
"""Generate llms-full.txt by concatenating a curated list of Markdown files.

Run:
    python scripts/generate-llms-full.py > llms-full.txt

Regenerate whenever a constituent file meaningfully changes.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_NAME = "veripak"

INTRO = """\
veripak is a CLI tool and MCP server for auditing open-source package health:
version staleness, EOL status, CVE exposure, download validation, and
replacement checking. It uses a parallel agent-based pipeline where LLM agents
handle non-deterministic lookups and deterministic checkers query package
registries directly.

This bundle contains the curated set of reference documents most useful for an
LLM agent helping users with this project. It complements `llms.txt` (the
navigation index at the repo root) by inlining content rather than linking to
it, so an LLM agent can understand the project in a single fetch.
"""

FILES: list[str] = [
    "README.md",
    "CLAUDE.md",
    "docs/README.md",
    "docs/PUBLISHING.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "prompts/summary_rules.md",
    "planning/PLAN.md",
    "research/research-litellm-security.md",
]

REPO_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    output: list[str] = []
    output.append(f"# {PROJECT_NAME} — Full Documentation Bundle")
    output.append("")
    output.append(INTRO.strip())
    output.append("")
    output.append("---")
    output.append("")

    missing: list[str] = []
    for rel_path in FILES:
        path = REPO_ROOT / rel_path
        if not path.is_file():
            missing.append(rel_path)
            continue
        content = path.read_text().rstrip()
        output.append(f"## `{rel_path}`")
        output.append("")
        output.append(content)
        output.append("")
        output.append("---")
        output.append("")

    if missing:
        for m in missing:
            print(f"WARNING: {m} not found, skipping", file=sys.stderr)

    sys.stdout.write("\n".join(output))
    sys.stdout.write("\n")
    return 0 if not missing else 1


if __name__ == "__main__":
    sys.exit(main())
