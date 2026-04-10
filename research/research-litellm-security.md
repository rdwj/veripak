# LiteLLM Security Assessment & Replacement Analysis

**Date**: 2026-03-30
**Context**: veripak depends on `litellm>=1.0` for multi-provider LLM routing

## Summary

LiteLLM was **supply-chain compromised on March 24, 2026** (6 days ago). Versions 1.82.7 and 1.82.8 were published to PyPI with a multi-stage credential stealer by the TeamPCP threat group, who gained access by compromising Aqua Security's Trivy scanner upstream. The malicious versions were live for ~5.5 hours before PyPI quarantined the package. Combined with 13+ pre-existing CVEs (including unpatched RCE and SSRF), litellm represents unacceptable supply chain risk.

**Recommendation**: Replace litellm with **direct provider SDKs** (`openai` + `anthropic`). The migration surface in veripak is small (~186 lines in `model_caller.py`), and both Ollama and vLLM expose OpenAI-compatible APIs, so two SDKs cover all four backends.

## The Supply Chain Attack

### What Happened

1. **TeamPCP** (also known as PCPcat/ShellForce) first compromised **Aqua Security's Trivy** (a security scanner)
2. LiteLLM's CI/CD ran Trivy **without version pinning** -- the poisoned Trivy binary dumped CI runner memory and scraped credentials
3. The attacker stole litellm's PyPI publishing token and published malicious versions directly to PyPI

### Affected Versions

- `litellm==1.82.7` -- payload in `proxy_server.py` (executes on module import)
- `litellm==1.82.8` -- added `litellm_init.pth` that executes on **any Python interpreter startup** (no import required)

### Malware Behavior

**Stage 1 (Credential Harvesting)**: SSH keys, `.env` files, AWS/GCP/Azure credentials, Kubernetes configs, database passwords, crypto wallets, Git credentials, shell history, CI/CD secrets, Terraform/Helm configs, Docker configs, SSL keys.

**Stage 2 (Kubernetes Lateral Movement)**: Read all cluster secrets across all namespaces; attempted to create privileged pods on every node in `kube-system` mounting the host filesystem.

**Stage 3 (Persistence)**: Installed systemd service polling `checkmarx[.]zone/raw` every 50 minutes for follow-on payloads. Exfiltrated data encrypted with AES-256-CBC + RSA-4096, sent to `models.litellm[.]cloud`.

### Timeline

| Date | Event |
|---|---|
| March 1 | Aqua Security (Trivy maintainer) suffers initial breach |
| March 19 | Poisoned Trivy v0.69.4 published |
| March 23 | Attacker registers `litellm.cloud` for exfiltration |
| March 24 ~08:30 UTC | Malicious litellm 1.82.7 and 1.82.8 published to PyPI |
| March 24 ~13:48 UTC | BerriAI discloses the compromise |
| March 24 ~16:00 UTC | PyPI quarantines the package (~5.5h exposure) |
| March 27 | SHA-256 checksums published for verified safe versions |

### veripak Impact

veripak's installed version (1.81.13) is clean, but the `>=1.0` pin meant anyone doing a fresh install during the 5.5-hour window could have pulled a compromised version.

## Pre-Existing CVE History

Even before the supply chain attack, litellm had 13+ known vulnerabilities:

| Advisory | Severity | Description | Fixed? |
|---|---|---|---|
| GHSA-gppg-gqw8-wh9g | 9.8 CRITICAL | RCE via unsafe `eval()` | Yes |
| GHSA-46cm-pfwv-cgf8 | CRITICAL | SSTI in `/completions` | Yes |
| GHSA-53gh-p8jc-7rg8 | 8.8 HIGH | Remote Code Execution | Yes |
| GHSA-7ggm-4rjg-594w | 7.2 HIGH | Unsafe eval | **No** |
| GHSA-8j42-pcfm-3467 | MEDIUM | SQL injection | **No** |
| GHSA-g26j-5385-hhw3 | 8.7 HIGH | SSRF | Yes |
| GHSA-fjcf-3j3r-78rp | 8.1 HIGH | Improper Authorization | Yes |
| GHSA-879v-fggm-vxw2 | 7.5 HIGH | Langfuse API key leak | Yes |
| GHSA-g5pg-73fc-hjwq | 7.5 HIGH | API key in logs | Yes |
| GHSA-fh2c-86xm-pm2x | 7.5 HIGH | DoS via crafted request | Yes |
| GHSA-gw2q-qw9j-rgv7 | 7.5 HIGH | DoS | Yes |
| GHSA-3xr8-qfvj-9p9j | 7.0 HIGH | Arbitrary file deletion | Yes |
| GHSA-qqcv-vg9f-5rr3 | 5.3 MEDIUM | Improper access control | Yes |

Most CVEs target the proxy server component (not used by veripak), but the pattern of `eval()` usage and SQL injection indicates systemic code quality issues.

## Alternatives Evaluated

| Criterion | litellm | aisuite | LangChain | Direct SDKs |
|---|---|---|---|---|
| **Dependencies** | 12 direct | ~2 core | 7+ core | ~9 unique |
| **Anthropic** | Yes | Yes | Yes | Yes (native) |
| **OpenAI** | Yes | Yes | Yes | Yes (native) |
| **Ollama** | Yes | Yes | Yes | Yes (via openai SDK) |
| **vLLM** | Yes | Workaround | Workaround | Yes (via openai SDK) |
| **Tool calling** | Yes | Yes | Yes | Yes (native) |
| **Cost tracking** | Built-in | No | No | DIY |
| **Supply chain risk** | **HIGH** | Low | Medium | **Lowest** |
| **Migration effort** | N/A | Medium | High | Low-Medium |
| **Maturity** | Compromised | v0.1.x, stalled | High | High (first-party) |

### Why Direct SDKs Win

1. **First-party trust**: `openai` and `anthropic` SDKs are maintained by the model providers themselves
2. **Ollama and vLLM are OpenAI-compatible**: Both expose `/v1/chat/completions`, so the `openai` SDK works with `base_url` override -- two SDKs cover all four backends
3. **Small migration surface**: veripak uses only `litellm.completion()` and `litellm.completion_cost()` in a single 186-line file (`model_caller.py`)
4. **Fewer dependencies**: Drops litellm's heavy transitive deps (tiktoken, tokenizers, jinja2, etc.)
5. **Cost tracking is replaceable**: A small lookup table for per-token pricing replaces `litellm.completion_cost()`

### aisuite (Honorable Mention)

Andrew Ng's [aisuite](https://github.com/andrewyng/aisuite) has the right philosophy (minimal, provider-prefixed model names), but the last PyPI release was November 2025 and vLLM support is missing. Worth watching if development resumes.

## Migration Path

The entire litellm surface in veripak is in `model_caller.py`:
- `litellm.completion(**kwargs)` -- replace with `openai.chat.completions.create()` or `anthropic.messages.create()`
- `litellm.completion_cost()` -- replace with a token-count pricing table
- Response format: both SDKs return `choices[0].message` with `.content` and `.tool_calls`

For Ollama/vLLM backends, instantiate the OpenAI client with a custom `base_url`:
```python
client = openai.OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
```

The Anthropic SDK uses a different request/response format, so the fallback path needs its own normalization -- but it's straightforward since veripak already branches on backend type in `_resolve_model()`.

## Sources

- [LiteLLM Official Security Update](https://docs.litellm.ai/blog/security-update-march-2026)
- [Datadog Security Labs: TeamPCP Campaign](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/)
- [Sonatype: Compromised litellm](https://www.sonatype.com/blog/compromised-litellm-pypi-package-delivers-multi-stage-credential-stealer)
- [Snyk: Poisoned Security Scanner Backdooring LiteLLM](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/)
- [Kaspersky: Trojanization of Trivy, Checkmarx, and LiteLLM](https://www.kaspersky.com/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/55510/)
- [BleepingComputer: Popular LiteLLM PyPI Package Backdoored](https://www.bleepingcomputer.com/news/security/popular-litellm-pypi-package-compromised-in-teampcp-supply-chain-attack/)
- [GitHub Issue #24518: Full Timeline](https://github.com/BerriAI/litellm/issues/24518)
- [OSV.dev: LiteLLM Vulnerabilities](https://osv.dev/list?q=litellm&ecosystem=PyPI)
- [Wiz: TeamPCP Trojanizes LiteLLM](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign)
