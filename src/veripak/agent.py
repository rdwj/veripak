"""PackageCheckAgent — orchestrates the 5-node audit pipeline with retry logic."""

import datetime
from dataclasses import dataclass, field
from typing import Optional

from .checkers import cves, downloads, eol, replacements, versions
from .checkers import download_discovery
from .checkers.ecosystem import infer_ecosystem


@dataclass
class AgentState:
    # Inputs
    package: str
    ecosystem: str
    versions_in_use: list[str] = field(default_factory=list)
    replacement_name: Optional[str] = None

    # URLs (passed in or discovered during run)
    homepage: Optional[str] = None
    release_notes_url: Optional[str] = None
    repository_url: Optional[str] = None
    download_url: Optional[str] = None

    # Node outputs (None = not yet run)
    eol_result: Optional[dict] = None
    version_result: Optional[dict] = None
    download_result: Optional[dict] = None
    cve_result: Optional[dict] = None
    replacement_result: Optional[dict] = None

    # Control
    attempts: dict = field(default_factory=dict)   # node_id -> int
    errors: list[str] = field(default_factory=list)
    max_attempts: int = 2


class PackageCheckAgent:
    """Orchestrates the veripak audit pipeline with retry loops and link-following."""

    def run(
        self,
        package: str,
        ecosystem: Optional[str] = None,
        versions_in_use: Optional[list[str]] = None,
        replacement_name: Optional[str] = None,
        homepage: Optional[str] = None,
        release_notes_url: Optional[str] = None,
        repository_url: Optional[str] = None,
        download_url: Optional[str] = None,
        skip_cves: bool = False,
        skip_download: bool = False,
        skip_summary: bool = False,
    ) -> dict:
        """Run the full audit pipeline and return a consolidated result dict."""
        if not ecosystem:
            version_hint = (versions_in_use[0] if versions_in_use else None)
            ecosystem = infer_ecosystem(package, version=version_hint)
            if not ecosystem:
                raise ValueError(
                    f"Could not infer ecosystem for '{package}'. "
                    "Please supply the ecosystem explicitly."
                )

        state = AgentState(
            package=package,
            ecosystem=ecosystem,
            versions_in_use=versions_in_use or [],
            replacement_name=replacement_name,
            homepage=homepage,
            release_notes_url=release_notes_url,
            repository_url=repository_url,
            download_url=download_url,
        )

        # N0: EOL check (fast, no model call)
        self._n0_eol(state)

        # N1: version lookup
        self._n1_version(state)

        # Version fallback: use EOL cycle data when registry lookup fails
        if (state.version_result or {}).get("version") is None:
            eol_latest = (state.eol_result or {}).get("latest_in_cycle")
            if eol_latest:
                if state.version_result is None:
                    state.version_result = {}
                state.version_result["version"] = eol_latest
                state.version_result["method"] = "eol_cycle_fallback"
                state.version_result["notes"] = "Fell back to endoflife.date latest_in_cycle"

        # N0b: EOL enrichment (runs after N1 when endoflife.date had no data)
        if (state.eol_result or {}).get("eol") is None:
            self._n0b_eol_enrichment(state)

        # N2+N3: download discovery and validation with loop-back.
        # N2 tries to find a URL (useful for non-programmatic ecosystems).
        # N3 validates the download; for programmatic ecosystems (python, js)
        # check_download works without a URL (pip/npm), so we always call N3.
        if not skip_download:
            self._n2_discover_download(state)
            self._n3_validate_download(state)
            # Loop-back: if validation failed and we have URL discovery to retry
            if (
                state.download_result is not None
                and not state.download_result.get("confirmed", False)
                and state.download_result.get("method") != "skipped"
                and self._bump(state, "n2") <= state.max_attempts
            ):
                self._n2_discover_download(state)
                self._n3_validate_download(state)

        # N4: CVE lookup
        if not skip_cves:
            self._n4_cves(state)

        # N5: replacement validation
        if state.replacement_name:
            self._n5_replacement(state)

        result = self._to_result(state)

        # N6: security summary (multi-turn model agent)
        if not skip_summary:
            self._n6_summary(result, state.versions_in_use)

        # Feed summary discoveries back to raw blocks when they found
        # values that the deterministic checkers missed.
        summary = result.get("summary") or {}

        # Latest version: summary may have found it via Tavily tool use
        # even when the N1 version checker failed
        version_block = result.get("version") or {}
        if not version_block.get("version") and summary.get("latest_version"):
            version_block["version"] = summary["latest_version"]
            version_block["notes"] = (version_block.get("notes") or "") + " (backfilled from summary)"
            version_block["notes"] = version_block["notes"].strip()
            result["version"] = version_block

        # EOL: only backfill eol=False from summary, not eol=True.
        # When deterministic checkers return null, that means "can't determine"
        # — if the summary asserts True, it overrides the guard's deliberate
        # uncertainty. But False ("not EOL") is a safe low-risk backfill.
        eol_block = result.get("eol") or {}
        if eol_block.get("eol") is None and summary.get("eol") is False:
            eol_block["eol"] = False
            if summary.get("eol_date") and not eol_block.get("eol_date"):
                eol_block["eol_date"] = summary["eol_date"]
            result["eol"] = eol_block

        return result

    # ------------------------------------------------------------------
    # Node implementations
    # ------------------------------------------------------------------

    def _n0_eol(self, state: AgentState) -> None:
        """N0: check EOL status via endoflife.date."""
        try:
            state.eol_result = eol.check_eol(state.package, state.versions_in_use)
        except Exception as exc:
            state.errors.append(f"n0: {exc}")
            state.eol_result = {
                "eol": None,
                "eol_date": None,
                "cycle": None,
                "latest_in_cycle": None,
                "product": None,
            }

    def _n0b_eol_enrichment(self, state: AgentState) -> None:
        """N0b: enrich EOL data using maintenance signal heuristics.

        Only runs when endoflife.date returned eol=None (product not found
        or no matching cycle). Uses GitHub status, version gap analysis,
        and Tavily search as supplementary signals.
        """
        latest_version = (state.version_result or {}).get("version")
        version_in_use = state.versions_in_use[0] if state.versions_in_use else None

        try:
            enriched = eol.check_maintenance_signals(
                name=state.package,
                ecosystem=state.ecosystem,
                repository_url=state.repository_url,
                version_in_use=version_in_use,
                latest_version=latest_version,
            )
            if enriched.get("eol") is not None:
                # Merge enriched data, preserving any product slug from N0
                state.eol_result = {
                    **state.eol_result,
                    "eol": enriched["eol"],
                    "eol_date": enriched.get("eol_date") or state.eol_result.get("eol_date"),
                    "_evidence": enriched.get("_evidence"),
                }
        except Exception as exc:
            state.errors.append(f"n0b: {exc}")

    def _n1_version(self, state: AgentState) -> None:
        """N1: look up the latest version with retry.

        When the package is EOL, skip branch scoping so we find the overall
        latest version rather than the latest patch in the (dead) branch.
        """
        node_id = "n1"
        last_result: Optional[dict] = None
        skip_branch_scope = bool((state.eol_result or {}).get("eol"))

        while self._bump(state, node_id) <= state.max_attempts:
            try:
                result = versions.get_latest_version(
                    state.package, state.ecosystem, state.versions_in_use,
                    skip_branch_scope=skip_branch_scope,
                    repository_url=state.repository_url,
                )
            except Exception as exc:
                state.errors.append(f"n1 attempt {state.attempts[node_id]}: {exc}")
                continue

            last_result = result
            if result.get("version") is not None:
                state.version_result = result
                return
            else:
                state.errors.append(
                    f"n1 attempt {state.attempts[node_id]}: version=None"
                    + (f", notes={result.get('notes')}" if result.get("notes") else "")
                )

        # Store whatever we got, even if version is None
        state.version_result = last_result

    def _n2_discover_download(self, state: AgentState) -> None:
        """N2: discover a download URL using multiple strategies."""
        node_id = "n2"
        attempt_count = state.attempts.get(node_id, 0)
        is_retry = attempt_count > 0

        version = (
            (state.version_result or {}).get("version")
            or (state.versions_in_use[0] if state.versions_in_use else None)
        )

        try:
            url = download_discovery.discover(
                name=state.package,
                ecosystem=state.ecosystem,
                version=version,
                release_notes_url=state.release_notes_url,
                repository_url=state.repository_url,
                homepage=state.homepage,
                existing_url=state.download_url,
                retry=is_retry,
            )
        except Exception as exc:
            state.errors.append(f"n2: {exc}")
            url = None

        if url:
            state.download_url = url

    def _n3_validate_download(self, state: AgentState) -> None:
        """N3: validate the download URL."""
        version = (
            (state.version_result or {}).get("version")
            or (state.versions_in_use[0] if state.versions_in_use else "")
        )

        try:
            result = downloads.check_download(
                name=state.package,
                ecosystem=state.ecosystem,
                version=version or "",
                download_url=state.download_url or "",
            )
        except Exception as exc:
            state.errors.append(f"n3: {exc}")
            result = {"method": "error", "confirmed": False, "notes": str(exc)}

        state.download_result = result

    def _n4_cves(self, state: AgentState) -> None:
        """N4: CVE lookup. One attempt; failures return empty result."""
        latest_version = (state.version_result or {}).get("version") or ""

        try:
            result = cves.check_cves(
                name=state.package,
                ecosystem=state.ecosystem,
                versions=state.versions_in_use,
                latest_version=latest_version,
                replacement_name=state.replacement_name or "",
            )
        except Exception as exc:
            state.errors.append(f"n4: {exc}")
            result = {
                "method": "error",
                "versions_cves": [],
                "latest_cves": [],
                "replacement_cves": [],
                "total_count": 0,
                "high_critical_count": 0,
            }

        state.cve_result = result

    def _n5_replacement(self, state: AgentState) -> None:
        """N5: validate the replacement package."""
        try:
            result = replacements.check_replacement(
                replacement_name=state.replacement_name or "",
                ecosystem=state.ecosystem,
            )
        except Exception as exc:
            state.errors.append(f"n5: {exc}")
            result = {
                "confirmed": None,
                "method": "error",
                "notes": str(exc),
                "proof": None,
            }

        state.replacement_result = result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _bump(self, state: AgentState, node_id: str) -> int:
        """Increment and return the attempt count for a node."""
        state.attempts[node_id] = state.attempts.get(node_id, 0) + 1
        return state.attempts[node_id]

    def _n6_summary(self, result: dict, versions_in_use: list[str]) -> None:
        """N6: generate a security summary via multi-turn model agent.

        Retries up to 3 times with exponential backoff (3s, 6s, 12s),
        since summary model calls can fail under concurrent load
        (e.g. multiple veripak runs sharing an Ollama instance).
        """
        import time
        from .checkers import summarize

        summary = None
        for attempt in range(3):
            summary = summarize.generate_summary(result, versions_in_use=versions_in_use)
            if summary is not None and "_error" not in summary:
                result["summary"] = summary
                return
            error_msg = summary.get("_error", "unknown") if summary else "returned None"
            result.setdefault("_agent", {}).setdefault("errors", []).append(
                f"n6 attempt {attempt + 1}: {error_msg}"
            )
            if attempt < 2:
                delay = 3 * (2 ** attempt)  # 3, 6, 12
                time.sleep(delay)

        # Store whatever we got, even if it has an _error
        if summary is not None:
            result["summary"] = summary

    def _to_result(self, state: AgentState) -> dict:
        """Assemble the final result dict from agent state."""
        return {
            "package": state.package,
            "ecosystem": state.ecosystem,
            "versions_in_use": state.versions_in_use,
            "checked_at": datetime.datetime.utcnow().isoformat() + "Z",
            "eol": state.eol_result,
            "version": state.version_result,
            "download": state.download_result,
            "cves": state.cve_result,
            "replacement": state.replacement_result,
            "_agent": {
                "attempts": state.attempts,
                "errors": state.errors,
            },
        }
