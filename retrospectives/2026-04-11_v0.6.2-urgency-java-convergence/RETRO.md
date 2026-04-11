# Retrospective: v0.6.2 — Urgency Ceiling, Java Version Convergence

**Date:** 2026-04-11
**Effort:** Three feedback-driven fixes from downstream skill integration
**Issues:** #23 (closed)
**Commits:** 1d8b7bf (release), follow-up tests + release script fix

## What We Set Out To Do

Three fixes prioritized by downstream impact:
1. Cap urgency at "medium" when total CVEs are 0 and EOL is not confirmed
2. Make bare Java artifact names converge on the same version as coordinate format
3. Document which summary fields are legitimately nullable

## What Changed

| Change | Type | Rationale |
|--------|------|-----------|
| None | — | All three fixes shipped as planned, no scope changes |

## What Went Well

- Feedback-driven prioritization: user arrived with specific integration pain points, we triaged veripak-actionable vs external, and executed in priority order.
- Parallel sub-agent pattern for implementation + review worked cleanly; both fixes landed without rework.
- Live smoke test confirmed both fixes end-to-end: `python-dateutil` urgency dropped from `high` to `low`, and `jsoup`/`org.jsoup:jsoup` now both return `1.22.1` from `maven-metadata.xml`.
- Issue #23 (test gap from v0.6.0 retro) was closed — the missing `call_model` Anthropic fallback json_mode test now exists.
- Release script hardened to handle pre-bumped versions and prevent tag overwrites.

## Gaps Identified

| Gap | Severity | Resolution |
|-----|----------|------------|
| No new tests shipped with the release commit | Medium | Fixed post-release: 18 new tests added (199 total) |
| Release script failed when version already bumped | Low | Fixed: script now skips commit when tree is clean |
| No live smoke test before release | Medium | Run post-release; confirmed both fixes work. Should be pre-release |
| EOL agent hallucinated signals for `jsoup` (dates inconsistent with reality) | Low | Accept; EOL agent accuracy is a broader issue, not specific to this release |

## Action Items

- [x] rdwj/veripak#23 — `call_model` Anthropic fallback json_mode test (closed)
- [ ] Add urgency ceiling and Java convergence tests to the pre-release checklist (done this cycle, formalize)
- [ ] Move live smoke test before `/create-release` in the workflow, not after

## Patterns

From reviewing the v0.6.0 retro:

**Continue:** Plan-first approach before implementation. This session discussed the plan, got approval, then executed.

**Continue:** Parallel sub-agents for independent implementation tasks. Two fixes landed concurrently without conflicts.

**Start:** Ship tests with the release commit, not as a follow-up. Both v0.6.0 and v0.6.2 had test gaps caught in the retro. The pattern is: implement -> release -> realize tests are missing -> add tests after. Should be: implement -> test -> release.

**Start:** Run live smoke test as a pre-release gate. The `/create-release` skill has no smoke test phase. Both retros flagged this.

**Stop:** Committing version bumps with code changes. The release script expects to own the version bump. Pre-bumping causes the script to fail. Either always let the script bump, or fix the script (done).
