#!/usr/bin/env python3
"""Check relative Markdown links across the repo.

Walks all .md files (excluding .venv, node_modules, .git, .pytest_cache,
__pycache__), parses [text](target) patterns while skipping fenced code
blocks, and resolves each relative path from the file's directory. Reports
any that don't exist.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

SKIP_DIRS = {".venv", "node_modules", ".git", ".pytest_cache", "__pycache__", "dist", "htmlcov"}
LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
FENCE_RE = re.compile(r"^(`{3,}|~{3,})")

REPO_ROOT = Path(__file__).resolve().parent.parent


def find_md_files(root: Path) -> list[Path]:
    results = []
    for p in root.rglob("*.md"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        results.append(p)
    return sorted(results)


def check_file(md_path: Path) -> list[tuple[int, str, str]]:
    """Return list of (line_number, link_text, target) for broken links."""
    broken = []
    in_fence = False
    fence_marker = ""

    for lineno, line in enumerate(md_path.read_text().splitlines(), 1):
        fence_match = FENCE_RE.match(line.strip())
        if fence_match:
            marker = fence_match.group(1)[0]  # ` or ~
            if not in_fence:
                in_fence = True
                fence_marker = marker
            elif line.strip().startswith(marker * 3) and marker == fence_marker:
                in_fence = False
                fence_marker = ""
            continue
        if in_fence:
            continue

        for text, target in LINK_RE.findall(line):
            # Skip external URLs, anchors, and mailto
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue

            # Strip anchor from target
            target_path = target.split("#")[0]
            if not target_path:
                continue

            resolved = (md_path.parent / target_path).resolve()
            if not resolved.exists():
                broken.append((lineno, text, target))

    return broken


def main() -> int:
    md_files = find_md_files(REPO_ROOT)
    total_broken = 0

    for md_path in md_files:
        broken = check_file(md_path)
        if broken:
            rel = md_path.relative_to(REPO_ROOT)
            for lineno, text, target in broken:
                print(f"  {rel}:{lineno}: [{text}]({target})")
                total_broken += 1

    if total_broken:
        print(f"\n{total_broken} broken link(s) found.")
        return 1
    else:
        print("All links OK.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
