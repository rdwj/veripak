# Retrospective: Agent Feedback Improvements

**Date:** 2026-04-09
**Effort:** Address 6 issues surfaced by an agent that used veripak 0.3.1 in production
**Issues:** #3, #4, #5, #6, #7, #8
**Commits:** cfb5df5..755da49 (6 commits)

## What We Set Out To Do

An external agent audited veripak and reported 6 concrete issues across correctness,
usability, and integration. Three were correctness bugs (CVE hallucination, Maven stale
version, ecosystem misclassification) and three were quality-of-life improvements (EOL
heuristic, non-interactive config, verbose flag). We committed to fixing all six.

## What Changed

| Change | Type | Rationale |
|--------|------|-----------|
| CVE validation drops unverified IDs instead of flagging as low-confidence | Good pivot | A false CVE in output is worse than a missing one; the HITL flag makes omissions visible |
| Ecosystem ambiguity is an error, not a warning | Good pivot | Warnings in CLI output are easy to miss, especially for programmatic callers |
| EOL heuristic covers 4 ecosystems instead of all 7 | Scope deferral | Focused on PyPI, npm, Maven, Go — the most common. NuGet, CPAN, Packagist deferred |

## What Went Well

- Parallel agent decomposition: launching 3-4 implementation workers simultaneously cut
  wall-clock time significantly vs sequential execution
- Code review caught 5 real issues before commit: inconsistent eol/project_status in
  heuristic merge, redundant sleep, missing NVD-only test, wrong type annotation,
  undocumented limitation
- Clean commit separation despite 6 features touching shared files (cli.py, agent.py,
  test_checkers.py)
- 35 new tests with good edge case coverage; 163 total tests passing

## Gaps Identified

| Gap | Severity | Resolution |
|-----|----------|------------|
| No integration test with live APIs | Accept | Unit tests mock all HTTP/LLM; live tests are expensive and flaky for CI |
| Ecosystem ambiguity probes 7 registries sequentially | Accept | Could parallelize later if latency becomes a UX problem |
| EOL heuristic missing NuGet, CPAN, Packagist | Follow-up | Track as enhancement when those ecosystems see more use |
| `validate_cve_ids` not exposed in MCP server | Accept | MCP uses deterministic pipeline which doesn't need validation |

## Patterns

**Continue:** Using agent feedback as a structured source of improvement items — the
6-issue batch from one agent trial produced higher-quality issues than speculative
feature planning.

**Continue:** Parallel worker decomposition with a review pass — catches real bugs
without slowing down implementation.

**Start:** Running veripak against itself (or a known package set) as a smoke test
after major changes, before release.
