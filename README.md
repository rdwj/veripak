# veripak

CLI tool for auditing open-source packages.

## Install

```bash
pip install veripak
```

## Setup

`vpk` is available as a shorthand alias for `veripak` in all commands below.

```bash
veripak config
```

Configures your LLM backend (Ollama, Anthropic, OpenAI, or vLLM self-hosted), Tavily API key, and optional NVD API key.

## Usage

```bash
# Check a single package
veripak check django --ecosystem python

# Include versions in use for CVE matching
veripak check log4j --ecosystem java --versions 2.14.0,2.15.0

# Machine-readable JSON
veripak check openssl --ecosystem c --json

# Skip CVE check (faster)
veripak check requests --ecosystem python --no-cves
```

Additional flags not shown above: `--replacement` (known replacement package name), `--release-notes-url`, `--repository-url`, `--homepage`, `--download-url` (supply known URLs to skip discovery), `--no-download` (skip download validation), and `--no-summary` (skip AI security summary). Run `veripak check --help` for the full list.

## How It Works

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
                  +-------------+-------------+
                  |       FORK (parallel)     |
                  |                           |
         +--------v--------+     +------------v-----------+
         |  TRACK A        |     |  TRACK B               |
         |                 |     |                        |
         |  N1: VERSION    |     |  EOL AGENT             |
         |  (registry API) |     |  (single agentic loop) |
         |       |         |     |                        |
         |       v         |     |  - Is version EOL?     |
         |  N2: DOWNLOAD   |     |  - Is project dead?    |
         |   discovery     |     |  - What's the          |
         |       |         |     |    replacement?        |
         |       v         |     |                        |
         |  N3: DOWNLOAD   |     |                        |
         |   validation    |     +------------+-----------+
         +--------+--------+                  |
                  +-------------+-------------+
                                |
                          JOIN  |
                                |
                  +-------------+-------------+
                  |       FORK (parallel)     |
                  |                           |
         +--------v--------+     +------------v-----------+
         |  TRACK C        |     |  TRACK D               |
         |                 |     |                        |
         |  N5: REPLACEMENT|     |  CVE AGENT             |
         |  VALIDATION     |     |  (agentic loop)        |
         |  (only if EOL   |     |                        |
         |   agent found   |     |  Uses: version from    |
         |   a replacement |     |  Track A, EOL status   |
         |   to validate)  |     |  from Track B          |
         +--------+--------+     +------------+-----------+
                  |                            |
                  +-------------+--------------+
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

Four specialized LLM agents (Ecosystem, EOL, CVE, Summary) replace fixed code paths, enabling reasoning about gaps and iterating on incomplete results. The agents use tools (registry probes, web search, GitHub API, advisory page fetching) and can flag fields for human review when data sources are inaccessible or signals are contradictory. Tracks A+B and C+D run in parallel via `ThreadPoolExecutor` for wall-clock speedup without async complexity.

## Supported ecosystems

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

## LLM backends

veripak uses a local or hosted LLM to extract version information from web search results for non-programmatic ecosystems (C, C++, system packages, etc.).

Supported backends: Ollama (default), Anthropic, OpenAI, vLLM (self-hosted).

## Changelog

### 0.2.0

- Parallel agent-based pipeline (v2) replacing serial checker pipeline
- Token usage tracking and cost estimation
- Agent budget exhaustion handling
- EOL cross-pollination from EOL agent to version track
- Summary prompt refinements for accuracy
- Project automation: CLAUDE.md, `/create-release` slash command, `.claude/` configuration

### 0.1.0

- Initial release with hybrid agent/checker architecture
- CLI with `veripak check` and `veripak config` commands
- Support for Ollama, Anthropic, OpenAI, and vLLM backends
- CI/CD pipeline with GitHub Actions and PyPI trusted publishing
