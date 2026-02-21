# veripak

CLI tool for auditing open-source packages.

## Install

```bash
pip install veripak
```

## Setup

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
         |  (registry API) |     |                        |
         |       |         |     |  Phase 1: Is version   |
         |       v         |     |    EOL?                |
         |  N2: DOWNLOAD   |     |  Phase 2: Is project   |
         |   discovery     |     |    dead?               |
         |       |         |     |  Phase 3: What's the   |
         |       v         |     |    replacement?        |
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

Three specialized LLM agents (Ecosystem, EOL, CVE) replace fixed code paths, enabling reasoning about gaps and iterating on incomplete results. The agents use tools (registry probes, web search, GitHub API, advisory page fetching) and can flag fields for human review when data sources are inaccessible or signals are contradictory. Tracks A+B and C+D run in parallel via `ThreadPoolExecutor` for wall-clock speedup without async complexity.

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
