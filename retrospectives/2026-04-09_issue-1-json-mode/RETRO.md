# Retrospective: JSON Response Format Enforcement + v0.6.0 Release

**Date:** 2026-04-09
**Effort:** Implement issue #1, research issue #2, release v0.6.0
**Issues:** #1 (closed), #2 (researched, deferred), #23 (follow-up created)
**Commits:** fc44f58, 8c07361, 611988b, 618bd5d, 7f103b0 (tag: v0.6.0)

## What We Set Out To Do

Two items from the backlog:
- **Issue #1**: Add API-level JSON enforcement to LLM calls via `response_format`
  (OpenAI-compatible) and assistant prefill (Anthropic), keeping existing defensive
  parsing as a safety net.
- **Issue #2**: Assess feasibility and impact of batch processing for multiple packages
  before starting implementation.

## What Changed

| Change | Type | Rationale |
|--------|------|-----------|
| Skipped `json_mode` for `_extract_on_budget()` | Good pivot | Tool-use + json_mode interaction is complex with marginal benefit; prompt already asks for JSON |
| Issue #2 deferred after research | Scope deferral | Impact analysis revealed two concurrency bugs and significant test gaps; not ready to implement safely |

## What Went Well

- Plan-first approach correctly identified which call sites should (and shouldn't) get `json_mode`. No rework needed during implementation.
- All 181 tests passed after implementation with zero regressions.
- Batch processing research caught two real bugs before they could cause production issues: `_nvd_request_times` rate limiter has no thread lock, and `_usage_records` gets wiped mid-flight by concurrent runs.
- Smoke test against live Anthropic backend confirmed the feature works end-to-end.
- Release v0.6.0 went cleanly: all pre-flight checks passed, CI green first try, PyPI publish succeeded.
- `llms-full.txt` regeneration automatically picked up CLAUDE.md and README changes.

## Gaps Identified

| Gap | Severity | Resolution |
|-----|----------|------------|
| Missing test: `call_model` Anthropic fallback with `json_mode` | Low | Follow-up issue #23 |
| Anthropic prefill behavior not verified against live API before smoke test | Low | Verified during smoke test; works correctly |
| Research doc link in issue #2 comment uses `main` branch URL | Low | Accept; will stay valid unless file moves |

## Action Items

- [ ] rdwj/veripak#23 — Add missing `call_model` Anthropic fallback json_mode test
- [ ] Fix `_nvd_request_times` thread safety before starting batch work (documented in research/batch-processing-impact.md)

## Patterns

**Continue:** Plan mode before non-trivial features. The plan caught the `_extract_on_budget()` edge case and correctly scoped the call site changes.

**Continue:** Research-first for large features. The batch processing analysis saved us from shipping concurrency bugs.

**Start:** Run a live smoke test as part of the implementation workflow, not just unit tests with mocks. The `/create-release` workflow runs unit tests but not live integration — smoke tests are the only gate for API-level issues.
