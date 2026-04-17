"""PackageCheckAgent — parallel agent-based orchestration.

Architecture:
  E0: Ecosystem agent (blocking)
  Fork 1: Track A (N1 version → N2/N3 download) || Track B (EOL agent)
  Join 1
  Fork 2: Track C (N5 replacement validation) || Track D (CVE agent)
  Join 2
  N6: Summary agent
"""

import datetime
import logging
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field

from .agents.base import HITLFlag
from .checkers import download_discovery, downloads, replacements, versions
from .version import __version__

logger = logging.getLogger(__name__)


@dataclass
class AgentState:
    # Inputs
    package: str
    ecosystem: str
    versions_in_use: list[str] = field(default_factory=list)
    replacement_name: str | None = None

    # URLs (passed in or discovered during run)
    homepage: str | None = None
    release_notes_url: str | None = None
    repository_url: str | None = None
    download_url: str | None = None

    # Node outputs (None = not yet run)
    eol_result: dict | None = None
    version_result: dict | None = None
    download_result: dict | None = None
    cve_result: dict | None = None
    replacement_result: dict | None = None

    # Agent outputs
    hitl_flags: list[HITLFlag] = field(default_factory=list)

    # Control
    attempts: dict = field(default_factory=dict)   # node_id -> int
    errors: list[str] = field(default_factory=list)
    max_attempts: int = 2


class PackageCheckAgent:
    """Orchestrates the veripak audit pipeline with parallel agent-based tracks."""

    def run(
        self,
        package: str,
        ecosystem: str | None = None,
        versions_in_use: list[str] | None = None,
        replacement_name: str | None = None,
        homepage: str | None = None,
        release_notes_url: str | None = None,
        repository_url: str | None = None,
        download_url: str | None = None,
        skip_cves: bool = False,
        skip_download: bool = False,
        skip_summary: bool = False,
        deterministic_only: bool = False,
    ) -> dict:
        """Run the full audit pipeline and return a consolidated result dict."""

        if deterministic_only:
            skip_summary = True

        if not deterministic_only:
            from . import model_caller
            model_caller.reset_usage()

        # --- E0: Ecosystem agent (blocking) ---
        if not ecosystem:
            if deterministic_only:
                from .checkers.ecosystem import _ECOSYSTEM_OVERRIDES, _REGISTRY_PROBES
                version_hint = (versions_in_use[0] if versions_in_use else None)
                override = _ECOSYSTEM_OVERRIDES.get(package.lower())
                if override:
                    ecosystem = override
                else:
                    for eco, probe_fn in _REGISTRY_PROBES:
                        if probe_fn(package, version_hint):
                            ecosystem = eco
                            break
                if not ecosystem:
                    raise ValueError(
                        f"Could not infer ecosystem for '{package}' from registry probes. "
                        "Please supply the ecosystem explicitly."
                    )
            else:
                from .agents.ecosystem_agent import infer_ecosystem
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

        # --- Fork 1: Track A (version + download) || Track B (EOL agent) ---
        with ThreadPoolExecutor(max_workers=2) as pool:
            track_a = pool.submit(self._track_a_version_download, state, skip_download)
            track_b = pool.submit(
                self._track_b_eol_deterministic if deterministic_only else self._track_b_eol,
                state,
            )

            # Join 1: wait for both; collect exceptions from each independently
            for label, future in [("track_a", track_a), ("track_b", track_b)]:
                try:
                    future.result()
                except Exception as exc:
                    state.errors.append(f"{label}: unhandled {type(exc).__name__}: {exc}")

        # Cross-pollinate: if version lookup failed but EOL agent found a version
        if (state.version_result or {}).get("version") is None:
            eol_result = state.eol_result or {}
            # Try current_version from EOL agent
            eol_version = eol_result.get("current_version") or eol_result.get("latest_in_cycle")
            if eol_version:
                if state.version_result is None:
                    state.version_result = {}
                state.version_result["version"] = eol_version
                state.version_result["method"] = "eol_agent_fallback"

        # Cross-pollinate: if version checker echoed the user's own version
        # for an EOL package, prefer the EOL agent's current_version
        eol_result = state.eol_result or {}
        version_result = state.version_result or {}
        if (
            eol_result.get("eol") is True
            and version_result.get("version") is not None
            and state.versions_in_use
            and version_result["version"] == state.versions_in_use[0]
            and eol_result.get("current_version")
            and eol_result["current_version"] != state.versions_in_use[0]
        ):
            version_result["version"] = eol_result["current_version"]
            version_result["method"] = (
                (version_result.get("method") or "") + "+eol_agent_override"
            )
            state.version_result = version_result

        # --- Fork 2: Track C (replacement) || Track D (CVE agent) ---
        # Determine if we need replacement validation
        eol_answer = state.eol_result or {}
        replacement_pkg = eol_answer.get("replacement_package")
        needs_replacement = bool(
            replacement_pkg
            or state.replacement_name
        )

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures: list[Future] = []

            if needs_replacement:
                repl_name = replacement_pkg or state.replacement_name
                futures.append(pool.submit(self._track_c_replacement, state, repl_name))

            if not skip_cves:
                futures.append(pool.submit(
                    self._track_d_cves_deterministic if deterministic_only else self._track_d_cves,
                    state,
                ))

            # Join 2: wait for all; collect exceptions independently
            for f in futures:
                try:
                    f.result()
                except Exception as exc:
                    state.errors.append(f"fork2: unhandled {type(exc).__name__}: {exc}")

        result = self._to_result(state)

        # --- N6: Summary agent ---
        if not skip_summary:
            self._n6_summary(result, state.versions_in_use)

        # Feed summary discoveries back to raw blocks
        self._backfill_from_summary(result)

        if deterministic_only:
            result["_usage"] = None
        else:
            from . import model_caller
            result["_usage"] = model_caller.get_usage_summary()

        return result

    # ------------------------------------------------------------------
    # Track A: Version + Download (deterministic)
    # ------------------------------------------------------------------

    def _track_a_version_download(self, state: AgentState, skip_download: bool) -> None:
        """Track A: N1 (version) → N2 (download discovery) → N3 (download validation)."""
        self._n1_version(state)

        if not skip_download:
            self._n2_discover_download(state)
            self._n3_validate_download(state)
            # Loop-back: retry if validation failed
            if (
                state.download_result is not None
                and not state.download_result.get("confirmed", False)
                and state.download_result.get("method") != "skipped"
                and self._bump(state, "n2") <= state.max_attempts
            ):
                self._n2_discover_download(state)
                self._n3_validate_download(state)

    # ------------------------------------------------------------------
    # Track B: EOL Agent
    # ------------------------------------------------------------------

    def _track_b_eol(self, state: AgentState) -> None:
        """Track B: Run the EOL agent for multi-signal EOL determination."""
        from .agents import eol_agent

        version = state.versions_in_use[0] if state.versions_in_use else "unknown"

        try:
            agent_result = eol_agent.check_eol(
                package=state.package,
                version=version,
                ecosystem=state.ecosystem,
                repository_url=state.repository_url,
                homepage=state.homepage,
            )
        except Exception as exc:
            state.errors.append(f"eol_agent: {exc}")
            state.eol_result = {
                "eol": None, "eol_date": None, "cycle": None,
                "latest_in_cycle": None, "product": None,
                "confidence": None, "project_status": None,
                "signals": [], "current_version": None,
                "replacement_package": None,
            }
            return

        # Collect HITL flags
        state.hitl_flags.extend(agent_result.hitl_flags)

        # Map agent answer to the expected eol_result format
        answer = agent_result.answer
        state.eol_result = {
            "eol": answer.get("eol"),
            "eol_date": answer.get("eol_date"),
            "cycle": None,
            "latest_in_cycle": answer.get("recommended_version"),
            "product": None,
            "confidence": answer.get("confidence"),
            "project_status": answer.get("project_status"),
            "signals": answer.get("signals", []),
            "current_version": answer.get("current_version"),
            "replacement_package": answer.get("replacement_package"),
        }

        # Enrich with release-date heuristic when agent returned
        # low confidence with unknown status
        if (
            answer.get("confidence") == "low"
            and answer.get("project_status") == "unknown"
        ):
            try:
                from .checkers.eol import check_eol_heuristic
                heuristic = check_eol_heuristic(
                    state.package, state.ecosystem,
                    version=(
                        state.versions_in_use[0]
                        if state.versions_in_use else None
                    ),
                )
                if heuristic.get("last_release_date") is not None:
                    # Merge heuristic fields without overwriting
                    # agent-provided values
                    state.eol_result.setdefault(
                        "project_status", None,
                    )
                    if state.eol_result["project_status"] in (
                        None, "unknown",
                    ):
                        state.eol_result["project_status"] = (
                            heuristic["project_status"]
                        )
                    state.eol_result["last_release_date"] = (
                        heuristic["last_release_date"]
                    )
                    state.eol_result["last_release_age_days"] = (
                        heuristic["last_release_age_days"]
                    )
                    state.eol_result["method"] = (
                        "eol_agent+release_date_heuristic"
                    )
                    # Upgrade confidence if heuristic is stronger
                    if (
                        heuristic.get("confidence") == "medium"
                        and state.eol_result.get("confidence")
                        == "low"
                    ):
                        state.eol_result["confidence"] = "medium"
                    # Sync eol field with heuristic project_status
                    if state.eol_result.get("eol") is None:
                        h_status = heuristic.get("project_status")
                        if h_status == "active":
                            state.eol_result["eol"] = False
                        elif h_status == "possibly_eol":
                            state.eol_result["eol"] = True
            except Exception as exc:
                state.errors.append(f"eol_heuristic: {exc}")

        if agent_result.error:
            state.errors.append(f"eol_agent: {agent_result.error}")

    def _track_b_eol_deterministic(self, state: AgentState) -> None:
        """Track B (deterministic): EOL check via endoflife.date API,
        with release-date heuristic fallback."""
        from .checkers import eol

        try:
            result = eol.check_eol(state.package, state.versions_in_use)
        except Exception as exc:
            state.errors.append(f"eol_checker: {exc}")
            result = {
                "eol": None, "eol_date": None, "cycle": None,
                "latest_in_cycle": None, "product": None,
            }

        # Fallback: if endoflife.date had no data, try the heuristic
        if result.get("eol") is None and result.get("product") is None:
            try:
                version = (
                    state.versions_in_use[0]
                    if state.versions_in_use else None
                )
                heuristic = eol.check_eol_heuristic(
                    state.package, state.ecosystem, version=version,
                )
                if heuristic.get("last_release_date") is not None:
                    result = heuristic
            except Exception as exc:
                state.errors.append(
                    f"eol_heuristic: {exc}"
                )

        state.eol_result = result

    # ------------------------------------------------------------------
    # Track C: Replacement validation (deterministic)
    # ------------------------------------------------------------------

    def _track_c_replacement(self, state: AgentState, replacement_name: str) -> None:
        """Track C: N5 replacement validation."""
        try:
            result = replacements.check_replacement(
                replacement_name=replacement_name,
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
    # Track D: CVE Agent
    # ------------------------------------------------------------------

    def _track_d_cves(self, state: AgentState) -> None:
        """Track D: Run the CVE agent for vulnerability discovery."""
        from .agents import cve_agent

        version = state.versions_in_use[0] if state.versions_in_use else ""
        latest_version = (state.version_result or {}).get("version") or ""

        try:
            agent_result = cve_agent.check_cves(
                package=state.package,
                version=version or latest_version or "unknown",
                ecosystem=state.ecosystem,
                versions=state.versions_in_use,
                latest_version=latest_version,
                replacement_name=state.replacement_name or "",
            )
        except Exception as exc:
            state.errors.append(f"cve_agent: {exc}")
            state.cve_result = {
                "method": "error",
                "versions_cves": [],
                "latest_cves": [],
                "replacement_cves": [],
                "total_count": 0,
                "high_critical_count": 0,
            }
            return

        # Collect HITL flags
        state.hitl_flags.extend(agent_result.hitl_flags)

        # Map agent answer to the expected cve_result format
        answer = agent_result.answer
        cves_list = answer.get("cves", [])

        # Count severities
        high_critical = sum(
            1 for c in cves_list
            if c.get("severity", "").upper() in ("HIGH", "CRITICAL")
        )

        state.cve_result = {
            "method": "cve_agent",
            "versions_cves": cves_list,
            "latest_cves": [],
            "replacement_cves": [],
            "total_count": answer.get("total_count", len(cves_list)),
            "high_critical_count": answer.get("high_critical_count", high_critical),
            "sources_consulted": answer.get("sources_consulted", []),
            "notes": answer.get("notes"),
        }

        if agent_result.error:
            state.errors.append(f"cve_agent: {agent_result.error}")

        # Cross-validate agent-sourced CVE IDs against OSV.dev/NVD.
        # NOTE: Only validates versions_cves (the agent's primary list).
        # latest_cves and replacement_cves are always empty from the agent;
        # if that changes, extend validation to cover those lists too.
        from .checkers.cves import validate_cve_ids

        cve_ids = [
            c.get("id", "") for c in cves_list if c.get("id")
        ]
        if cve_ids:
            validation = validate_cve_ids(
                cve_ids, state.package, state.ecosystem,
            )
            validated_cves = []
            dropped_cves = []
            for cve in cves_list:
                cve_id = cve.get("id", "")
                if validation.get(cve_id, True):
                    cve["validated"] = True
                    validated_cves.append(cve)
                else:
                    cve["validated"] = False
                    dropped_cves.append(cve)

            if dropped_cves:
                dropped_ids = [c["id"] for c in dropped_cves]
                state.hitl_flags.append(HITLFlag(
                    field_name="cves",
                    agent="cve_agent",
                    reason=(
                        f"Dropped {len(dropped_cves)} unverified "
                        f"CVE(s): {', '.join(dropped_ids)}. "
                        f"These CVE IDs could not be confirmed "
                        f"against OSV.dev/NVD for package "
                        f"'{state.package}'."
                    ),
                    blocked_url=None,
                ))
                state.errors.append(
                    f"cve_agent: dropped "
                    f"{len(dropped_cves)} unverified CVE(s): "
                    f"{', '.join(dropped_ids)}"
                )

            state.cve_result["versions_cves"] = validated_cves
            high_critical = sum(
                1 for c in validated_cves
                if c.get("severity", "").upper()
                in ("HIGH", "CRITICAL")
            )
            state.cve_result["total_count"] = len(
                validated_cves
            )
            state.cve_result["high_critical_count"] = (
                high_critical
            )

    def _track_d_cves_deterministic(self, state: AgentState) -> None:
        """Track D (deterministic): CVE check via OSV.dev/NVD only."""
        from .checkers import cves

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
            state.errors.append(f"cve_checker: {exc}")
            result = {
                "method": "error",
                "versions_cves": [],
                "latest_cves": [],
                "replacement_cves": [],
                "total_count": 0,
                "high_critical_count": 0,
            }
        state.cve_result = result

    # ------------------------------------------------------------------
    # Deterministic node implementations (kept from v1)
    # ------------------------------------------------------------------

    def _n1_version(self, state: AgentState) -> None:
        """N1: look up the latest version with retry.

        When the EOL agent hasn't run yet (parallel), we can't know
        branch-scope. Default to no scoping; the EOL agent provides
        the recommended version separately.
        """
        node_id = "n1"
        last_result: dict | None = None

        while self._bump(state, node_id) <= state.max_attempts:
            try:
                result = versions.get_latest_version(
                    state.package, state.ecosystem, state.versions_in_use,
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

        state.version_result = last_result

    def _n2_discover_download(self, state: AgentState) -> None:
        """N2: discover a download URL."""
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

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _bump(self, state: AgentState, node_id: str) -> int:
        """Increment and return the attempt count for a node."""
        state.attempts[node_id] = state.attempts.get(node_id, 0) + 1
        return state.attempts[node_id]

    def _n6_summary(self, result: dict, versions_in_use: list[str]) -> None:
        """N6: generate a security summary via multi-turn model agent."""
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
                delay = 3 * (2 ** attempt)
                time.sleep(delay)

        if summary is not None:
            result["summary"] = summary

    def _backfill_from_summary(self, result: dict) -> None:
        """Feed summary discoveries back to raw blocks."""
        summary = result.get("summary") or {}

        # Latest version: summary may have found it via Tavily
        version_block = result.get("version") or {}
        if not version_block.get("version") and summary.get("latest_version"):
            version_block["version"] = summary["latest_version"]
            version_block["notes"] = (
                (version_block.get("notes") or "") + " (backfilled from summary)"
            ).strip()
            result["version"] = version_block

        # EOL: only backfill eol=False from summary, not eol=True
        eol_block = result.get("eol") or {}
        if eol_block.get("eol") is None and summary.get("eol") is False:
            eol_block["eol"] = False
            if summary.get("eol_date") and not eol_block.get("eol_date"):
                eol_block["eol_date"] = summary["eol_date"]
            result["eol"] = eol_block

    def _to_result(self, state: AgentState) -> dict:
        """Assemble the final result dict from agent state."""
        result = {
            "veripak_version": __version__,
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

        # Attach HITL flags if any agents raised them
        if state.hitl_flags:
            result["hitl_flags"] = [
                {
                    "field": f.field_name,
                    "agent": f.agent,
                    "reason": f.reason,
                    "blocked_url": f.blocked_url,
                }
                for f in state.hitl_flags
            ]

        return result
