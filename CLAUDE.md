# veripak — CLAUDE.md

## Project Overview

veripak is a CLI tool for auditing open-source package health: latest version, EOL status,
CVE exposure, download validation, and replacement package confirmation. It uses a parallel
agent-based pipeline where LLM agents handle non-deterministic lookups (EOL, CVEs, ecosystem
inference) and deterministic checkers handle registry APIs. Published to PyPI as `veripak`;
both `veripak` and `vpk` are registered as CLI entry points.

GitHub: https://github.com/rdwj/veripak

## Architecture

```
E0: Ecosystem agent (blocking)
    |
  FORK 1 (parallel)
    Track A: N1 version (registry API) → N2 download discovery → N3 download validation
    Track B: EOL agent (LLM agentic loop)
  JOIN 1
    |
  FORK 2 (parallel)
    Track C: N5 replacement validation (deterministic, only if EOL agent found a replacement)
    Track D: CVE agent (LLM agentic loop)
  JOIN 2
    |
  N6: Summary agent
```

Tracks A+B and C+D use `ThreadPoolExecutor` for parallelism — no async complexity.

### Source layout

```
src/veripak/
  agent.py             # PackageCheckAgent orchestrator
  cli.py               # Click entry point (veripak / vpk)
  config.py            # Config file load/save (~/.config/veripak/config.json)
  model_caller.py      # LLM backend abstraction (openai + anthropic SDKs); tracks token usage
  tavily.py            # Tavily search helper
  version.py           # __version__ constant (must stay in sync with pyproject.toml)
  agents/
    base.py            # BaseAgent, HITLFlag, _extract_on_budget()
    ecosystem_agent.py # E0: ecosystem inference
    eol_agent.py       # Track B: EOL + replacement discovery
    cve_agent.py       # Track D: CVE lookup
  checkers/
    versions.py        # N1: deterministic version lookup (PyPI, npm, Maven, etc.)
    download_discovery.py  # N2: URL construction/discovery
    downloads.py       # N3: HTTP HEAD validation
    replacements.py    # N5: replacement package confirmation
    summarize.py       # N6: summary agent (via model_caller)
    cves.py            # Deterministic CVE fallback (OSV.dev, NVD) + CVE ID validation
    eol.py             # Deterministic EOL fallback (endoflife.date) + release-date heuristic
    ecosystem.py       # Deterministic ecosystem inference + ambiguity detection
    migration.py       # Migration complexity helpers

prompts/               # YAML prompt templates for agents
tests/
  test_checkers.py
  test_cli_config.py
```

## Development

Requirements: Python >= 3.10

```bash
# Install for development
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage report
pytest --cov=veripak --cov-report=term-missing

# Lint
ruff check src tests

# Build distribution
python -m build
```

Line length limit: 100 (ruff). Ruff rule sets: E, W, F, I, B, C4, UP.

## Version Management

Version is tracked in **two files that must always be in sync**:

- `src/veripak/version.py` — `__version__ = "0.2.0"`
- `pyproject.toml` — `version = "0.2.0"`

Never edit just one. Use the release script or update both together.

## Releasing

Preferred — use the `/create-release` slash command if available.

Manual:

```bash
./scripts/release.sh <version> "<commit message>"
# Example: ./scripts/release.sh 0.3.0 "feat: Add perl ecosystem support"
```

The script: bumps both version files, commits, pushes to main, tags `v<version>`, pushes
the tag. GitHub Actions then runs tests, creates a GitHub Release, builds dist packages, and
publishes to PyPI via trusted OIDC (no API token needed).

Always run tests and linting before releasing. You cannot re-publish the same version to PyPI.

Monitor: https://github.com/rdwj/veripak/actions

## API Keys

| Key | Required | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes (agent pipeline) | LLM calls via anthropic SDK |
| `OPENAI_API_KEY` | Only if openai backend | LLM calls via openai SDK |
| `TAVILY_API_KEY` | Yes | Web search for non-programmatic ecosystems (c, cpp, system, etc.) |
| `NVD_API_KEY` | Optional | Raises CVE rate limit from 5 req/10s to 50 req/30s |

Keys are read from: environment variables first, then `.env` in project root, then `~/.zshrc`.
The `.env` file is gitignored.

LLM backend and model are configured via `veripak config` (interactive) or
`veripak config set <key> <value>` (programmatic) and stored in
`~/.config/veripak/config.json`. Supported backends: Ollama (default), Anthropic,
OpenAI, vLLM.

## Ecosystem Coverage

| Ecosystem | Version source | CVE source |
|---|---|---|
| python | PyPI API | OSV.dev |
| javascript | npm registry | OSV.dev |
| java | Maven Central | OSV.dev |
| go | Go proxy | OSV.dev |
| dotnet | NuGet API | OSV.dev |
| perl | MetaCPAN | OSV.dev |
| php | Packagist | OSV.dev |
| c, cpp, system, desktop-app, driver | Tavily + LLM | NVD API |

## Key Design Decisions

**Agent budget exhaustion** — `_extract_on_budget()` in `agents/base.py` gives the model one
final synthesis turn when the tool-call budget runs out. This turn MUST include `tool_schemas`
in the API call because Anthropic rejects requests that have tool calls in history but no
`tools` parameter.

**NVD keyword search is unreliable** for popular packages (ordering problems). Prefer OSV.dev
product-level queries. For .NET, check `github.com/dotnet/core/release-notes/{version}/cve.md`
directly.

**Deterministic checkers are fallbacks.** The agents (EOL, CVE) are the primary pipeline.
Checkers in `checkers/` exist for when agents are skipped or fail, and as sub-tools that
agents can call.

**Cross-pollination between tracks** — after Join 1, `agent.py` reconciles version results:
if the version checker returned the user's own in-use version (stale data) but the EOL agent
found the real current version, the EOL agent's value wins.

**HITL flags** — agents emit `HITLFlag` objects when a field needs human review (data source
inaccessible, signals contradictory, etc.). These propagate through `AgentState.hitl_flags`
and appear in the result JSON as `hitl_flags`.

**CVE cross-validation** — after the CVE agent returns, `agent.py` calls
`checkers.cves.validate_cve_ids()` to verify each CVE ID against OSV.dev/NVD. Unverified
CVEs are dropped (not downgraded) and a HITL flag is emitted. This prevents hallucinated
CVE IDs from smaller models from reaching the output.

**Maven metadata XML** — `checkers/versions.py` prefers `maven-metadata.xml` from the
Maven Central repository over the Solr search endpoint for coordinate-format lookups
(`groupId:artifactId`). The search endpoint can return stale `latestVersion` data.

**Ecosystem ambiguity** — `checkers/ecosystem.py` has `detect_ecosystem_ambiguity()` that
probes all registries. The CLI refuses to proceed when a package exists in 2+ ecosystems
without an explicit `--ecosystem` flag.

**EOL release-date heuristic** — `checkers/eol.py` has `check_eol_heuristic()` as a
fallback when endoflife.date has no data. Uses last release date from PyPI/npm/Maven/Go
with thresholds: <1y active, 1-3y maintenance, >3y possibly_eol.

**JSON response format enforcement** — `model_caller.py` accepts a `json_mode` parameter on
`call_model()` and `call_model_chat()`. For OpenAI-compatible backends this passes
`response_format={"type": "json_object"}`; for Anthropic it uses assistant prefill with `{`.
Only non-tool-use calls that expect JSON output set `json_mode=True`. Tool-use loops
(agent main loops, summarize analysis) do NOT use json_mode because the model needs to choose
between tool calls and text responses. The existing defensive JSON parsing (fence stripping,
regex extraction, fallback dicts) remains as a safety net. If a backend rejects
`response_format`, the call retries without it.

**Summary deterministic merge** — after the LLM summary returns, `summarize.py` runs a
deterministic merge pass that fills null fields from raw audit data: CVE counts, EOL
status/date, version numbers, and urgency (via `compute_urgency_floor()`). LLM values
always win; deterministic values only fill holes. The `_gaps` list is recomputed after all
fills and should only contain fields where data was genuinely unavailable. Consumers of
veripak output (e.g. a `discover` skill) can expect all 13 summary schema fields to be
populated for successful audits. Defensive null-checks are still recommended but should
rarely fire.

**Verbose flag** — debug fields (`_agent`, `_usage`) are filtered at the CLI layer, not
in the pipeline. The MCP server has its own filtering. The pipeline always computes them.
