# veripak

Audit open-source package health: version staleness, EOL status, CVE exposure, download validation, and replacement checking.

## Install

```bash
pip install veripak

# With MCP server support (for AI coding assistants)
pip install veripak[mcp]
```

Requires Python 3.10+.

## Using with AI agents

veripak integrates with AI coding assistants and agents through two paths: an MCP server for tool-calling agents, and JSON CLI output for agents with shell access.

### MCP server

`veripak serve` runs veripak as an MCP server over stdio transport. It operates in **deterministic-only mode** -- querying authoritative sources directly (PyPI, npm, Maven Central, OSV.dev, NVD, endoflife.date) without making any LLM calls. The calling agent's own LLM reasons over the raw data. This is faster and avoids redundant LLM costs.

The server exposes a single tool, `veripak_check_package`, with these parameters:

| Parameter | Required | Description |
|---|---|---|
| `package` | Yes | Package name (e.g. `requests`, `lodash`, `log4j`) |
| `ecosystem` | No | Package ecosystem -- inferred automatically if omitted |
| `versions_in_use` | No | List of deployed versions for CVE matching |
| `replacement` | No | Replacement package name to validate |
| `skip_cves` | No | Skip the CVE vulnerability check |
| `skip_download` | No | Skip download URL validation |

The response includes a `data_gaps` field that tells the calling agent what couldn't be verified and why (missing API keys, package not found in a database, rate limits hit, etc.). This lets the agent adjust its reasoning rather than treating missing data as a clean bill of health.

### CLI with `--json`

Any agent with shell access can call veripak directly -- no MCP setup needed. This works with Pi, Aider, or any tool that can invoke a command and parse JSON output:

```bash
veripak check requests --ecosystem python --versions 2.28.0 --json
```

The `--json` path runs the full agent pipeline (including LLM calls), so it requires a configured LLM backend (`veripak config`). In exchange, you get richer analysis: the pipeline reasons about ambiguous signals, writes a security summary, and flags items for human review. The MCP server path gives raw structured data only — faster, cheaper, no LLM backend required.

## MCP setup guides

### Claude Code

Add via CLI:

```bash
claude mcp add veripak -e TAVILY_API_KEY=tvly-xxx -e NVD_API_KEY=xxx -- veripak serve
```

Or in your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "veripak": {
      "command": "veripak",
      "args": ["serve"],
      "env": {
        "TAVILY_API_KEY": "your-key-here",
        "NVD_API_KEY": "your-key-here"
      }
    }
  }
}
```

### Claude Desktop

In Settings > Developer > Edit Config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "veripak": {
      "command": "veripak",
      "args": ["serve"],
      "env": {
        "TAVILY_API_KEY": "your-key-here",
        "NVD_API_KEY": "your-key-here"
      }
    }
  }
}
```

### Codex (OpenAI)

In `~/.codex/config.toml`:

```toml
[mcp_servers.veripak]
command = "veripak"
args = ["serve"]

[mcp_servers.veripak.env]
TAVILY_API_KEY = "your-key-here"
NVD_API_KEY = "your-key-here"
```

### Continue (VS Code / JetBrains)

In `.continue/config.yaml`:

```yaml
mcpServers:
  - name: veripak
    command: veripak
    args:
      - serve
    env:
      TAVILY_API_KEY: your-key-here
      NVD_API_KEY: your-key-here
```

MCP tools are only available in Continue's Agent mode.

### OpenCode

In `opencode.json`:

```json
{
  "mcp": {
    "veripak": {
      "type": "local",
      "command": ["veripak", "serve"],
      "environment": {
        "TAVILY_API_KEY": "your-key-here",
        "NVD_API_KEY": "your-key-here"
      }
    }
  }
}
```

### Pi

[Pi](https://github.com/badlogic/pi-mono) does not support MCP by design — its author argues that MCP tool manifests consume too much context. Pi uses "Skills" (CLI tools with README docs) instead. Since veripak is already a CLI tool, Pi can invoke it directly via its bash tool:

```bash
veripak check requests --ecosystem python --versions 2.28.0 --json
```

No additional configuration needed. Pi will discover veripak's capabilities from its `--help` output.

The community fork [oh-my-pi](https://github.com/can1357/oh-my-pi) does add native MCP support. If you're using that fork, configure it the same way as Claude Desktop (JSON with `mcpServers` key).

Both `TAVILY_API_KEY` and `NVD_API_KEY` are included in the examples above. See [API keys](#api-keys) for details on obtaining them.

## CLI usage

Both `veripak` and `vpk` work as entry points. Check the installed version with `veripak --version`.

Configure your LLM backend and API keys:

```bash
veripak config
```

Run an audit:

```bash
$ veripak check django --ecosystem python --versions 4.2.0

  Package:     django  (python)
  EOL:         supported  (cycle 4.2, latest patch: 4.2.16)
  Version:     5.1.6  [pypi]
  Download:    confirmed  [pypi]
  CVEs:        3 total  (1 HIGH/CRITICAL)  [osv]

  Summary:
    Version gap:    4 minor versions behind
    Migration:      moderate  (breaking change likely)
    Urgency:        MEDIUM
    Recommend:      Update to 5.1.x; review breaking changes in 5.0 release notes
```

```bash
# Basic check (ecosystem inferred automatically)
veripak check requests

# Specify ecosystem and versions in use
veripak check log4j --ecosystem java --versions 2.14.0,2.15.0

# Machine-readable JSON output
veripak check openssl --ecosystem c --json

# Skip CVE check (faster)
vpk check requests --no-cves

# Skip download validation
vpk check lodash --ecosystem javascript --no-download

# Check a replacement package
veripak check nose --ecosystem python --replacement pytest
```

Additional flags: `--release-notes-url`, `--repository-url`, `--homepage`, `--download-url` (supply known URLs to skip discovery), and `--no-summary` (skip AI security summary). Run `veripak check --help` for the full list.

## API keys

| Key | Required | Purpose |
|---|---|---|
| `TAVILY_API_KEY` | Recommended | Web search for non-registry ecosystems (c, cpp, system). Not strictly required for registry-based ecosystems. [Get a key](https://app.tavily.com/home) (free tier: 1,000 requests/month). |
| `NVD_API_KEY` | Recommended | CVE lookups via the National Vulnerability Database. Without a key, rate limits are 5 requests per 30 seconds; with one, 50 per 30 seconds. [Request a key](https://nvd.nist.gov/developers/request-an-api-key) (free, instant via email). |
| `ANTHROPIC_API_KEY` | CLI only | LLM calls via litellm for the agent pipeline. Not needed when using the MCP server. |

Keys are resolved in this order: environment variables (highest priority), then `~/.config/veripak/config.json`, then `.env` in the project root.

Run `veripak config` to set keys and LLM backend interactively. The config wizard stores values in `~/.config/veripak/config.json`. For MCP server deployments, environment variables are usually more convenient since you pass them directly in the server configuration.

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

## veripak vs OSV-Scanner

Google's [OSV-Scanner](https://github.com/google/osv-scanner) is a purpose-built vulnerability scanner designed for CI pipelines. It scans lockfiles and dependency manifests, checks them against the OSV database, and exits with a non-zero code if vulnerabilities are found. It's fast, lightweight, and the right tool for CI gates.

veripak is a holistic dependency health auditor. Beyond CVE exposure, it checks version staleness, end-of-life status, download availability, and replacement package viability. The CLI runs LLM agents that reason about ambiguous signals and flag items for human review. The MCP server gives AI coding assistants structured access to the same data sources so they can make informed dependency decisions.

Use OSV-Scanner in your CI pipeline. Use veripak (especially via MCP) when an AI agent or a human needs to evaluate whether a dependency is healthy, not just whether it has known vulnerabilities.

## How it works

This section describes the internal architecture -- useful for contributors and anyone curious about what happens under the hood.

The CLI runs a parallel agent-based pipeline where LLM agents handle non-deterministic lookups (EOL reasoning, CVE triage, ecosystem inference) and deterministic checkers handle registry APIs:

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

Four specialized LLM agents (Ecosystem, EOL, CVE, Summary) enable reasoning about gaps and iterating on incomplete results. The agents use tools (registry probes, web search, GitHub API, advisory page fetching) and can flag fields for human review when data sources are inaccessible or signals are contradictory. Tracks A+B and C+D run in parallel via `ThreadPoolExecutor`.

**MCP server path:** When running as an MCP server (`veripak serve`), the LLM agents are bypassed entirely. The pipeline uses deterministic checkers only -- direct API calls to package registries, OSV.dev, NVD, and endoflife.date. The calling agent's LLM handles interpretation of the raw results.

## Development

```bash
# Clone and install for development (includes MCP dependencies)
git clone https://github.com/rdwj/veripak.git
cd veripak
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=veripak --cov-report=term-missing

# Lint
ruff check src tests

# Build distribution
python -m build
```

Line length limit: 100 (ruff). Rule sets: E, W, F, I, B, C4, UP.

## Changelog

### 0.3.0

- MCP server support (`veripak serve`) with FastMCP v3
- `veripak --version` flag
- Deterministic-only pipeline mode for MCP integration
- Environment variable support for API key configuration
- Data gap reporting in MCP responses

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
