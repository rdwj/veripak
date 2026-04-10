# Batch Processing Impact Analysis (Issue #2)

**Date**: 2026-04-09  
**Scope**: Codebase impact analysis for adding batch package auditing to veripak  
**Issue**: https://github.com/rdwj/veripak/issues/2

---

## Context

Issue #2 proposes adding batch processing so users can audit multiple packages in a single
invocation (e.g., `veripak check --from requirements.txt`). The design describes three
components: a shared batch engine, CLI batch mode, and async MCP job tools. A real-world
use case of 400 packages drives the design.

This document captures findings from a codebase impact analysis performed before
implementation begins.

---

## Current Pipeline Architecture

The single-package flow is:

```
CLI: cmd_check("requests", ecosystem="python")
  → detect_ecosystem_ambiguity() (registry probes)
  → PackageCheckAgent().run(package, ecosystem, ...)
      → model_caller.reset_usage()  ← clears GLOBAL usage list
      → Fork 1 (ThreadPoolExecutor, 2 workers):
          Track A: versions → download_discovery → download_validation
          Track B: eol_agent (LLM + endoflife.date)
      → Join 1, cross-pollinate version data
      → Fork 2 (ThreadPoolExecutor, 2 workers):
          Track C: replacement validation (if EOL found replacement)
          Track D: cve_agent (LLM + OSV/NVD) → validate_cve_ids
      → Join 2
      → _to_result(state) → result dict
      → summarize.generate_summary(result) (LLM)
      → model_caller.get_usage_summary() ← reads GLOBAL usage list
  → format and print result
```

Key architectural properties relevant to batch work:

`PackageCheckAgent` is stateless — no instance state. `AgentState` is a per-run dataclass with no cross-run sharing. SDK clients (`_clients` dict in `model_caller.py`) are shared but thread-safe: they are lazy-initialized under a lock, with connection pooling handled by the SDKs themselves. The internal `ThreadPoolExecutor` pools are created and torn down per run.

The MCP server (`mcp_server.py`) exposes one tool (`veripak_check_package`) with
`deterministic_only=True` hardcoded — it skips all LLM agents and runs only deterministic
checkers. This means the global usage tracking problem described below does not currently
affect the MCP path.

---

## Concurrency Blockers

Three pieces of global mutable state would cause problems when package checks run
concurrently. These must be fixed before or alongside the batch engine.

### 1. `model_caller._usage_records` — HIGH severity

This module-level list accumulates LLM token usage across calls. `agent.run()` calls
`reset_usage()` at the start (clearing the list entirely) and `get_usage_summary()` at the
end. With concurrent runs, one run's `reset_usage()` wipes another's mid-flight records,
making per-package `_usage` attribution incorrect and non-deterministic.

The fix is to scope usage tracking per-run rather than globally. The cleanest options are
passing a collector object into `agent.run()`, returning usage directly from individual
calls, or using a `contextvars.ContextVar`-based approach that isolates state per thread.

### 2. `cves._nvd_request_times` — HIGH severity

The NVD sliding-window rate limiter reads and mutates a module-level list with no lock:

```python
_nvd_request_times[:] = [t for t in _nvd_request_times if now - t < window]
if len(_nvd_request_times) >= max_req:
    ...
_nvd_request_times.append(time.time())
```

Two threads can both pass the length check simultaneously, both append, and both send
requests — defeating the rate limit entirely. NVD has the tightest limits in veripak's
dependency set (5 req/10s without a key), making this the most dangerous race condition.

The fix is to wrap the rate limiter body in a `threading.Lock`. The `time.sleep()` call must
remain outside the lock to avoid blocking the entire pool while waiting.

### 3. `eol._product_list_cache` — LOW severity

Lazy initialization has a benign race: two threads can both see `None`, both fetch the
product list from endoflife.date, and both write to the global. The result is correct (both
fetches return the same data) but causes a duplicate HTTP request on startup. The simplest
fix is to warm the cache once before spawning batch threads. Adding a lock is also
straightforward.

`config._cache` has the same lazy-init pattern but is safe in practice since all concurrent
reads produce identical results.

---

## External API Rate Limits

The table below covers every external API hit by veripak, its known rate limit, and whether
veripak currently enforces anything.

| API | Rate Limit | Current Enforcement |
|---|---|---|
| PyPI | ~1,000 req/min | None |
| npm registry | ~100 req/min | None |
| Maven Central (metadata XML) | ~100 req/min | None |
| Maven Central (Solr search) | ~20 req/min | None |
| Go proxy | ~300 req/min | None |
| NuGet | ~100 req/min | None |
| MetaCPAN | ~100 req/min | None |
| Packagist | ~60 req/min | None |
| GitHub API | 60 req/hr (unauth), 5,000/hr (auth) | None |
| release-monitoring.org (Anitya) | Unknown, relatively low | None |
| Repology | ~1 req/sec (strict) | None |
| endoflife.date | Unknown, moderate | None |
| OSV.dev | ~100 req/min | `time.sleep(0.1)` between calls |
| NVD | 5 req/10s (no key), 50 req/30s (with key) | Sliding-window enforcer (no lock — see above) |
| Tavily | Varies by plan (~1–5 req/sec) | Exponential backoff on HTTP 429 (up to 6 retries) |
| Anthropic / OpenAI / Ollama / vLLM | Tier-dependent | None — SDKs handle retries internally |

At 400 packages, the tightest bottlenecks are NVD (roughly 13 minutes at 5 req/10s),
GitHub unauthenticated (exhausted after ~60 packages), and Repology (7 minutes at 1
req/sec). The issue's proposed concurrency defaults — 10 for registry APIs, 3 for LLM
calls, 1 for NVD — are reasonable given these limits. A shared per-host semaphore or
token-bucket approach would enforce them cleanly without embedding limits in every caller.

---

## Test Coverage Gaps

The following areas have no test coverage and would need tests before or alongside batch
work:

- `agent.py` (PackageCheckAgent orchestrator) — the entire pipeline, cross-pollination
  logic, HITL flag propagation, and CVE cross-validation
- `agents/` directory — ecosystem_agent, eol_agent, cve_agent, and `_extract_on_budget()`
- `cli.py` `check` command — no integration tests at all
- `checkers/summarize.py`, `checkers/replacements.py`, `checkers/migration.py`,
  `checkers/downloads.py`

There is no `conftest.py` and no multi-package fixtures. The existing test suite uses
`unittest.mock.patch` with data-driven `@pytest.mark.parametrize` tables — a solid pattern
to extend for batch scenarios.

New test categories needed specifically for batch:

- Input parsing (requirements.txt, package.json, pyproject.toml, etc.)
- Concurrency isolation (one package failure does not abort the batch)
- Partial failure handling (mixed success and error results in output)
- Progress and output formatting (no garbled interleaved output under concurrency)
- Job persistence (write results to disk, resume interrupted batches, skip completed)
- Deduplication (duplicate package names in input → single run)
- Rate limit enforcement (bounded concurrency, per-host semaphore behavior)

---

## Recommended Implementation Approach

The work decomposes naturally into three sequential PRs, each independently mergeable.

**PR 1 — Prep (concurrency fixes).** Scope `_usage_records` per-run, add a lock to the NVD
rate limiter, and warm `_product_list_cache` before spawning threads. These are standalone
correctness improvements that change no observable behavior and carry low review risk.

**PR 2 — Batch engine and CLI.** Add the `--from` flag, parallel execution with configurable
concurrency, progress output, and partial failure handling. No MCP changes in this PR. This
is the core user-facing feature and should include the new test categories listed above.

**PR 3 — MCP async jobs.** Job persistence layer (`~/.veripak/jobs/`), and three new MCP
tools: `veripak_batch_start`, `veripak_batch_status`, and `veripak_batch_cancel`. This PR
builds directly on the batch engine introduced in PR 2.

---

## Open Questions

These questions should be resolved before PR 2 begins:

1. **LLM agents in batch mode.** Should batch mode support the full agent pipeline or be
   restricted to `deterministic_only=True`? At 400 packages with LLM agents, token cost is
   significant and would likely require per-batch budget controls.

2. **Dependency file parsing.** Should veripak parse requirements.txt, package.json, and
   similar formats natively, or delegate to external tools (e.g., `pip freeze`, `npm ls`)
   and accept a simpler package-per-line format?

3. **Output format.** One JSON array written at completion? NDJSON (one object per line as
   packages finish)? A human-readable summary report? The choice affects the MCP job design
   in PR 3.

4. **CLI resume support.** Should `--resume` for interrupted batch runs be part of PR 2, or
   deferred to PR 3 alongside the MCP job persistence layer?
