# veripak v2: Agent-Based Architecture

## Overview

Replace the current serial deterministic pipeline with a parallel agent-based
architecture. Three specialized agents (Ecosystem, EOL, CVE) replace fixed code
paths, enabling reasoning about gaps and iterating on incomplete results.

## Architecture Diagram

```
                        +-------------------------+
                        |      PACKAGE INPUT      |
                        |  name, versions_in_use, |
                        |  urls, replacement_name |
                        +-----------+-------------+
                                    |
                        +-----------v-------------+
                        |   E0: ECOSYSTEM AGENT   |
                        |                         |
                        |  1. LLM: "What is this?"|
                        |     -> "java" (instant)  |
                        |                         |
                        |  2. Validate: probe     |
                        |     Maven/PyPI/npm/etc  |
                        |     -> confirmed        |
                        |                         |
                        |  3. If no hit: Tavily   |
                        |     search to confirm   |
                        +-----------+-------------+
                                    |
                  +-----------------+-----------------+
                  |            FORK (parallel)        |
                  |                                   |
         +--------v--------+             +------------v-----------+
         |  TRACK A        |             |  TRACK B               |
         |                 |             |                        |
         |  N1: VERSION    |             |  EOL AGENT             |
         |  (registry API) |             |  (see detail below)    |
         |       |         |             |                        |
         |       v         |             |  Phase 1: Is version   |
         |  N2: DOWNLOAD   |             |    EOL?                |
         |   discovery     |             |  Phase 2: Is project   |
         |       |         |             |    dead?               |
         |       v         |             |  Phase 3: What's the   |
         |  N3: DOWNLOAD   |             |    replacement?        |
         |   validation    |             |                        |
         +--------+--------+             +------------+-----------+
                  |                                   |
                  +-----------------+-----------------+
                                    |
                              JOIN  |
                                    |
                  +-----------------+-----------------+
                  |            FORK (parallel)        |
                  |                                   |
         +--------v--------+             +------------v-----------+
         |  TRACK C        |             |  TRACK D               |
         |                 |             |                        |
         |  N5: REPLACEMENT|             |  CVE AGENT             |
         |  VALIDATION     |             |  (agentic loop)        |
         |  (only if EOL   |             |                        |
         |   agent found   |             |  Uses: version from    |
         |   a replacement |             |  Track A, EOL status   |
         |   to validate)  |             |  from Track B          |
         +--------+--------+             +------------+-----------+
                  |                                   |
                  +-----------------+-----------------+
                                    |
                              JOIN  |
                                    |
                        +-----------v-------------+
                        |  N6: SUMMARY AGENT      |
                        |                         |
                        |  All raw results +      |
                        |  deterministic guards + |
                        |  HITL flags propagated  |
                        +-----------+-------------+
                                    |
                        +-----------v-------------+
                        |    FINAL RESULT JSON    |
                        +-------------------------+
```

## Implementation Plan

### Phase 1: EOL Agent

Replace the current `eol.py` (577 lines of deterministic heuristics) with an
LLM agent that has tools.

**New file:** `src/veripak/agents/eol_agent.py`

**Tools the agent gets:**
- `web_search(query)` — Tavily search
- `check_registry(package, ecosystem)` — get versions, release dates
- `check_github(repo_url)` — branches, last commit, archived status
- `fetch_page(url)` — read a URL (may fail on AI blockers)
- `flag_hitl(field, reason)` — mark field for human review

**Agent phases:**

Phase 1 — Is this version EOL?
1. `web_search("{name} {version} end of life")` and
   `web_search("{name} lifecycle support policy")`
2. If a lifecycle page URL is found, `fetch_page(url)` to read it.
   If fetch fails (AI blocker), `flag_hitl("eol", "Cannot access {url}")`.
3. `check_registry(name, ecosystem)` — last release on this branch?
4. Evaluate signals. Need 2+ to assert EOL:
   - Signal A: Lifecycle page says EOL (strong)
   - Signal B: No branch releases in 12 months (strong)
   - Signal C: endoflife.date says EOL (supporting)
   - Signal D: Vendor announcement (strong)
   - Signal E: Registry deprecated flag (strong)
   - Signal F: Version gap alone (supporting, never sufficient alone)
   - Rule: need >=1 strong + >=1 any, OR >=3 supporting

Phase 2 — Is the project dead? (only if Phase 1 says EOL)
1. `check_github(repo)` — last commit on ANY branch
2. `check_registry` — any version released in past year?
3. `web_search("{name} deprecated replacement alternative")`
4. Outcomes: project alive (version EOL), project dead, project archived

Phase 3 — What's the replacement?
- If project alive: `check_registry` for current/LTS version
- If project dead: use search results from Phase 2 for successor package
- If can't determine: `flag_hitl("replacement", "...")`

**Returns:**
```json
{
  "eol": true,
  "eol_date": "2025-04-01",
  "confidence": "high",
  "project_status": "active",
  "signals": [
    {"source": "https://nodejs.org/...", "type": "lifecycle_page",
     "says": "Node 18 EOL April 2025"},
    {"source": "npm registry", "type": "branch_activity",
     "says": "Last 18.x release: 18.20.8 (March 2025)"}
  ],
  "current_version": "25.6.1",
  "recommended_version": "22.15.0",
  "replacement_package": null,
  "hitl_flags": []
}
```

**What to keep from current eol.py:**
- `check_eol()` (endoflife.date API) becomes the `check_endoflife_date` tool
- `_check_github_status()` becomes part of `check_github` tool
- `_check_npm_deprecated()` and `_check_pypi_inactive()` become part of
  `check_registry` tool
- Everything else (version gap heuristic, Tavily+LLM jury-rig) is replaced
  by the agent's own reasoning

**System prompt for EOL agent:**
> You are determining whether **version {version}** of **{package}** is
> end-of-life. "End of life" means this specific version/branch no longer
> receives security patches.
>
> A newer version existing does NOT mean the old version is EOL — many
> projects maintain multiple branches simultaneously (e.g., Node 18 LTS +
> Node 22 LTS + Node 25 Current).
>
> If the version IS EOL, identify what the customer should upgrade to —
> this is usually a newer version of the SAME package, not a different
> package.
>
> You need at least 2 corroborating signals before asserting eol=true.
> If you cannot access a key data source (website blocked, API down), use
> flag_hitl to request human review rather than guessing.

### Phase 2: Ecosystem Agent

Replace the current `ecosystem.py` probe-first approach with LLM-first,
probe-to-validate.

**New file:** `src/veripak/agents/ecosystem_agent.py`

**Tools:**
- `probe_registry(package, ecosystem)` — HEAD/GET check against the
  ecosystem's registry (PyPI, npm, Maven, etc.)
- `web_search(query)` — Tavily fallback

**Flow:**
1. LLM call: "What ecosystem is {package}?" → candidate (instant, one call)
2. `probe_registry(package, candidate)` → confirmed? done.
3. If probe fails, `web_search("{package} package ecosystem")` → confirm
4. If still uncertain, LLM retry with search context
5. If can't determine → raise error asking user for `--ecosystem`

**What to keep from current ecosystem.py:**
- `_ECOSYSTEM_OVERRIDES` map (stays as a fast pre-check before calling the
  agent at all)
- Registry probe functions (`_probe_pypi`, `_probe_npm`, etc.) become the
  `probe_registry` tool implementation
- `_infer_via_model` is replaced by the agent's native reasoning

### Phase 3: CVE Agent

Replace the fixed OSV/NVD code path in `cves.py` (919 lines) with an agent
that can reason about coverage gaps and iterate.

**New file:** `src/veripak/agents/cve_agent.py`

**Tools:**
- `osv_query(package, version, ecosystem)` — OSV.dev API
- `nvd_search(keyword, results_per_page)` — NVD API v2
- `web_search(query)` — Tavily search for advisory pages
- `fetch_advisory_page(url)` — read a security advisory URL, extract CVE IDs
- `flag_hitl(field, reason)` — mark for human review

**Agent loop (max 8 turns, max 5 tool calls):**
1. `osv_query(pkg, ver, eco)` → N CVEs
2. If N seems low for a major package, `web_search("{pkg} security advisory")`
3. `fetch_advisory_page(url)` → extract additional CVE IDs
4. Optionally `nvd_search` to get severity scores for new CVEs
5. Deduplicate and return scored list

**What to keep from current cves.py:**
- `_osv_query_version()`, `_osv_query_package()` → `osv_query` tool
- `_nvd_query()` → `nvd_search` tool
- `_dedupe_cross_source()` → used by agent to merge results
- `_discover_security_advisory_cves()` → replaced by agent's own reasoning +
  `fetch_advisory_page` tool
- Rate limiting logic for NVD stays in the tool implementation

**System prompt for CVE agent:**
> You are finding all known CVEs that affect **{package}** version
> **{version}** ({ecosystem}).
>
> Start with the most authoritative source for this ecosystem. For
> programmatic ecosystems (Python, JavaScript, Java, Go, .NET, Perl, PHP),
> OSV.dev has precise version-specific data. For system/C/C++ packages, try
> OSV first then supplement with NVD.
>
> If the primary source returns fewer CVEs than expected for a widely-used
> package, search for the project's official security advisory page and
> cross-reference.
>
> Return a deduplicated list with CVE ID, severity, and summary for each.

### Phase 4: Parallel Orchestration

Rewrite `agent.py` to run agents in parallel where possible.

**Changes to `agent.py`:**
- E0 (ecosystem) runs first, blocking (needed by everything else)
- Fork 1: Track A (N1 version → N2/N3 download) || Track B (EOL agent)
- Join 1: wait for both
- Fork 2: Track C (N5 replacement validation) || Track D (CVE agent)
- Join 2: wait for both
- N6 summary agent runs last with all results

**Parallelism approach:** Use `concurrent.futures.ThreadPoolExecutor` with
`max_workers=2`. Each track is a callable submitted to the executor. This
avoids async complexity while still getting wall-clock speedup.

**HITL flag propagation:** Each agent may return `hitl_flags`. The orchestrator
collects these from all agents and includes them in the final result JSON.

### Phase 5: Agent Infrastructure

Before implementing the agents, we need a lightweight agent runner.

**New file:** `src/veripak/agents/base.py`

Provides:
- Tool registration and dispatch (tool name → callable mapping)
- Multi-turn conversation loop with model_caller
- Turn budget enforcement (max_turns, max_tool_calls)
- HITL flag collection

This is NOT a framework — it's a thin loop:
```python
def run_agent(system_prompt, tools, max_turns=8):
    messages = [{"role": "system", "content": system_prompt}]
    hitl_flags = []
    for turn in range(max_turns):
        response = model_caller.call_model_chat(messages, tools=tool_schemas)
        if no tool calls in response:
            return parse_final_answer(response), hitl_flags
        for tool_call in response.tool_calls:
            result = dispatch(tool_call, tool_registry)
            messages.append(tool_call_result)
    return timeout_result, hitl_flags
```

### Phase 6: Summary Agent Updates

Update `summarize.py` to:
- Accept HITL flags from upstream agents and propagate them
- Remove the feedback loop from `agent.py` (agents now produce complete data)
- Use the EOL agent's structured output (signals, confidence) instead of
  re-deriving EOL status

### Phase 7: Validation and Testing

1. Add unit tests for each agent's tool functions (deterministic, mockable)
2. Add integration tests that run each agent on the 5 validation packages
3. Re-run the 5-package validation suite and compare scores to baseline:
   - apache_poi: 0.786
   - apache_tomcat: 0.929
   - axios: 1.000
   - botan2: 0.786
   - bottles: 0.821
   - mean: 0.864
4. Target: mean >= 0.900

## Implementation Order

```
Phase 5 (agent infrastructure)   <-- build the runner first
    |
    +---> Phase 2 (ecosystem agent)   <-- smallest, validates infra
    |
    +---> Phase 1 (EOL agent)         <-- biggest impact
    |
    +---> Phase 3 (CVE agent)         <-- most complex
    |
Phase 4 (parallel orchestration) <-- wire agents into pipeline
    |
Phase 6 (summary updates)
    |
Phase 7 (validation)
```

Phase 5 is the prerequisite. Then Phases 1-3 can be done in any order (each
is an independent agent). Phase 2 (ecosystem) is the simplest and serves as
the proof-of-concept for the agent infrastructure. Phase 4 wires everything
together. Phases 6-7 finalize and validate.

## HITL Flags

Any agent can call `flag_hitl(field, reason)` when:
- A key URL is blocked (AI blocker, 403, paywall)
- Signals are contradictory
- Confidence is low and the data matters
- Registry data is ambiguous

HITL flags propagate to the final JSON and can drive a dashboard
"needs human review" queue:

```json
{
  "hitl_flags": [
    {
      "field": "eol",
      "agent": "eol_agent",
      "reason": "Cannot access redhat.com/lifecycle (HTTP 403). Need human to verify RHEL 6 EOL date.",
      "blocked_url": "https://access.redhat.com/..."
    }
  ]
}
```

## Scraping Policy

If `fetch_page` fails due to AI blockers and we determine we consistently
need data from a specific site, we can build a targeted scraper with a
browser user-agent string. Rules:
- Extract structured insight only (dates, version numbers, CVE IDs)
- Drop the raw HTML immediately — never persist scraped content
- Only for sites where Tavily snippets are insufficient

## File Layout (after implementation)

```
src/veripak/
    agents/
        __init__.py
        base.py              # agent runner infrastructure
        ecosystem_agent.py   # E0: ecosystem inference
        eol_agent.py         # EOL determination (3-phase)
        cve_agent.py         # CVE discovery (agentic loop)
    checkers/
        cves.py              # tool implementations (OSV, NVD queries)
        downloads.py         # N2/N3 download discovery/validation
        download_discovery.py
        ecosystem.py         # registry probe functions (used as tools)
        eol.py               # endoflife.date API (used as a tool)
        migration.py         # complexity/breaking-change logic
        replacements.py      # N5 replacement validation
        summarize.py         # N6 summary (updated for HITL)
        versions.py          # N1 version lookup
    agent.py                 # orchestrator (parallel fork/join)
    cli.py
    config.py
    model_caller.py
    tavily.py
```

The `checkers/` directory retains the deterministic functions but they become
tool implementations callable by agents rather than pipeline stages called
directly by the orchestrator.
