"""Structural unit tests for checker utilities — no network calls."""

import json as _json
from unittest.mock import MagicMock, patch

import pytest

from veripak.checkers.cves import (
    _filter_no_cpe_via_model,
    _nvd_fetch_by_cpe_name,
    _suggest_nvd_cpe,
    _version_in_cpe_range,
    validate_cve_ids,
)
from veripak.checkers.download_discovery import (
    _extract_tarballs_from_html,
    _is_tarball,
)
from veripak.checkers.ecosystem import detect_ecosystem_ambiguity, infer_ecosystem
from veripak.checkers.eol import (
    _extract_branch,
    _is_eol,
    _normalize_candidates,
    check_eol,
    check_eol_heuristic,
)
from veripak.checkers.migration import _URGENCY_ORDER, compute_urgency_floor
from veripak.checkers.versions import (
    _maven_metadata_version,
    _parse_json_response,
    _version_tuple,
    check_maven,
    check_pypi,
    is_prerelease,
    is_stable,
    strip_v,
)

# ---------------------------------------------------------------------------
# strip_v
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version, expected", [
    ("v1.2.3", "1.2.3"),
    ("1.2.3", "1.2.3"),
    ("v0.0.1", "0.0.1"),
    ("V1.0", "V1.0"),   # only strips lowercase 'v'
    ("", ""),
    ("vvv2.0", "2.0"),  # lstrip("v") strips ALL leading v chars
])
def test_strip_v(version, expected):
    assert strip_v(version) == expected, f"strip_v({version!r}) should be {expected!r}"


# ---------------------------------------------------------------------------
# is_stable
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version, expected", [
    ("1.0.0", True),
    ("2.1.3", True),
    ("1.0.0rc1", False),
    ("1.0.0RC1", False),
    ("3.0.0a1", False),
    ("3.0.0A1", False),    # case-insensitive: 'a' in lower is in forbidden list
    ("1.0b2", False),
    ("1.0.0dev0", False),
    ("1.0.0.post1", False),
    ("1.0.0alpha1", False),
    ("1.0.0beta2", False),
    ("1.0.0-beta", False),
    # Version strings that contain 'b' but are not pre-releases
    # Note: 'b' alone triggers the filter — matches legacy behaviour
    ("3.1b2", False),
])
def test_is_stable(version, expected):
    assert is_stable(version) == expected, (
        f"is_stable({version!r}) should be {expected}"
    )


# ---------------------------------------------------------------------------
# is_prerelease
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version, expected", [
    # Stable versions — must return False
    ("1.0.0",           False),
    ("2.1.3",           False),
    ("6.7.4",           False),
    ("5.15.2",          False),
    # Maven milestones
    ("4.0-M3",          True),
    ("5.0-M1",          True),
    # Alpha/beta/rc suffixes
    ("1.0.0-alpha",     True),
    ("1.0.0-alpha1",    True),
    ("2.0-beta",        True),
    ("3.0.0-rc1",       True),
    ("3.0.0-RC2",       True),   # case-insensitive
    # SNAPSHOT and preview
    ("1.0.0-SNAPSHOT",  True),
    ("2.0.0-snapshot",  True),
    ("1.0.0-preview",   True),
    ("1.0.0-dev",       True),
    # Dot-separated qualifiers
    ("5.5.0-alpha",     True),   # bctoolbox-style
    # Edge: short stable versions should not be confused
    ("10.0",            False),
    ("3",               False),
])
def test_is_prerelease(version, expected):
    assert is_prerelease(version) == expected, (
        f"is_prerelease({version!r}) should be {expected}"
    )


# ---------------------------------------------------------------------------
# _parse_json_response
# ---------------------------------------------------------------------------

def test_parse_json_response_direct():
    raw = '{"version": "1.2.3", "source_url": "https://example.com"}'
    result = _parse_json_response(raw)
    assert result["version"] == "1.2.3"
    assert result["source_url"] == "https://example.com"


def test_parse_json_response_fenced_json():
    raw = '```json\n{"version": "2.0.0", "source_url": "https://foo.bar"}\n```'
    result = _parse_json_response(raw)
    assert result["version"] == "2.0.0"


def test_parse_json_response_fenced_no_lang():
    raw = '```\n{"version": "3.1.4"}\n```'
    result = _parse_json_response(raw)
    assert result["version"] == "3.1.4"


def test_parse_json_response_bare_brace():
    raw = 'Here is the answer: {"version": "5.0.1", "source_url": "https://x.io"} done.'
    result = _parse_json_response(raw)
    assert result["version"] == "5.0.1"


def test_parse_json_response_junk_returns_empty():
    raw = "I could not find any version information for this package."
    result = _parse_json_response(raw)
    assert result == {}


def test_parse_json_response_null_version():
    raw = '{"version": null, "source_url": ""}'
    result = _parse_json_response(raw)
    assert result["version"] is None


def test_parse_json_response_proof_field():
    raw = '{"version": "4.2.0", "source_url": "https://s.io", "proof": "Release 4.2.0"}'
    result = _parse_json_response(raw)
    assert result["proof"] == "Release 4.2.0"


# ---------------------------------------------------------------------------
# _version_tuple
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ver, expected", [
    ("4.2.28", (4, 2, 28)),
    ("6.0.2", (6, 0, 2)),
    ("v1.3.0", (1, 3, 0)),
    ("10", (10,)),
    ("", ()),
])
def test_version_tuple(ver, expected):
    assert _version_tuple(ver) == expected, f"_version_tuple({ver!r}) should be {expected}"


# ---------------------------------------------------------------------------
# check_pypi — semantic version sorting (not upload time)
# ---------------------------------------------------------------------------


def test_check_pypi_prefers_highest_semver_over_recent_upload():
    """An older LTS branch with a more recent upload must not beat the
    highest semantic version.  Reproduces the Django-style scenario where
    a 4.2.28 security patch is uploaded *after* 6.0.2."""
    fake_pypi = {
        "releases": {
            # LTS branch — uploaded MORE RECENTLY
            "4.2.28": [{"upload_time": "2026-02-19T12:00:00"}],
            # Main branch — the true latest, uploaded earlier
            "6.0.2":  [{"upload_time": "2026-02-10T08:00:00"}],
            # Another LTS
            "5.2.1":  [{"upload_time": "2026-01-15T10:00:00"}],
            # Pre-release (should be excluded)
            "7.0a1":  [{"upload_time": "2026-02-20T00:00:00"}],
        }
    }

    with patch("veripak.checkers.versions._http_get_json", return_value=fake_pypi):
        version, url = check_pypi("Django")

    assert version == "6.0.2", (
        f"Expected highest semantic version '6.0.2', got {version!r}. "
        "check_pypi should sort by version number, not upload timestamp."
    )


# ---------------------------------------------------------------------------
# _version_in_cpe_range
# ---------------------------------------------------------------------------



@pytest.mark.parametrize("version_str, cpe_match, expected, description", [
    (
        "2.5.0",
        {"vulnerable": True, "versionStartIncluding": "2.0.0", "versionEndIncluding": "3.0.0"},
        True,
        "version within start/end inclusive range",
    ),
    (
        "1.9.9",
        {"vulnerable": True, "versionStartIncluding": "2.0.0", "versionEndIncluding": "3.0.0"},
        False,
        "version below start inclusive",
    ),
    (
        "3.0.1",
        {"vulnerable": True, "versionStartIncluding": "2.0.0", "versionEndIncluding": "3.0.0"},
        False,
        "version above end inclusive",
    ),
    (
        "2.0.0",
        {"vulnerable": True, "versionStartExcluding": "2.0.0", "versionEndExcluding": "3.0.0"},
        False,
        "version at exclusive start boundary",
    ),
    (
        "2.0.1",
        {"vulnerable": True, "versionStartExcluding": "2.0.0", "versionEndExcluding": "3.0.0"},
        True,
        "version just above exclusive start",
    ),
    (
        "3.0.0",
        {"vulnerable": True, "versionStartExcluding": "2.0.0", "versionEndExcluding": "3.0.0"},
        False,
        "version at exclusive end boundary",
    ),
    (
        "1.2.3",
        {"vulnerable": True},
        True,
        "no range fields and vulnerable=True returns True",
    ),
    (
        "1.2.3",
        {"vulnerable": False},
        False,
        "no range fields and vulnerable=False returns False",
    ),
    (
        "not-a-version",
        {"vulnerable": True, "versionStartIncluding": "1.0.0"},
        True,
        "unparseable version string returns True (conservative)",
    ),
    (
        "2.5.0",
        {"vulnerable": True, "versionStartIncluding": "bad-range"},
        True,
        "unparseable range boundary returns True (conservative)",
    ),
])
def test_version_in_cpe_range(version_str, cpe_match, expected, description):
    result = _version_in_cpe_range(version_str, cpe_match)
    assert result == expected, (
        f"{description}: _version_in_cpe_range({version_str!r}, {cpe_match}) "
        f"expected {expected}, got {result}"
    )


# ---------------------------------------------------------------------------
# download_discovery._is_tarball
# ---------------------------------------------------------------------------



@pytest.mark.parametrize("url, expected", [
    ("https://example.com/pkg-1.2.3.tar.gz", True),
    ("https://example.com/pkg-1.2.3.tar.bz2", True),
    ("https://example.com/pkg-1.2.3.tar.xz", True),
    ("https://example.com/pkg-1.2.3.tgz", True),
    ("https://example.com/pkg-1.2.3.zip", True),
    ("https://example.com/pkg-1.2.3.TAR.GZ", True),   # case-insensitive
    ("https://example.com/pkg-1.2.3.tar.gz?foo=bar", True),  # query string stripped
    ("https://example.com/index.html", False),
    ("https://example.com/pkg-1.2.3.whl", False),
    ("https://example.com/pkg-1.2.3.deb", False),
    ("", False),
])
def test_is_tarball(url, expected):
    assert _is_tarball(url) == expected, f"_is_tarball({url!r}) should be {expected}"


# ---------------------------------------------------------------------------
# download_discovery._extract_tarballs_from_html
# ---------------------------------------------------------------------------



def test_extract_tarballs_from_html_anchor_hrefs():
    html = """
    <html><body>
      <a href="https://files.example.com/mylib-1.2.3.tar.gz">Download</a>
      <a href="https://files.example.com/mylib-1.2.3.tar.bz2">Alt download</a>
      <a href="https://example.com/index.html">Home</a>
    </body></html>
    """
    result = _extract_tarballs_from_html(html)
    assert "https://files.example.com/mylib-1.2.3.tar.gz" in result
    assert "https://files.example.com/mylib-1.2.3.tar.bz2" in result
    assert "https://example.com/index.html" not in result


def test_extract_tarballs_from_html_raw_text():
    html = """
    <p>Download the source from
    https://releases.example.com/proj-2.0.0.tar.xz here.</p>
    """
    result = _extract_tarballs_from_html(html)
    assert "https://releases.example.com/proj-2.0.0.tar.xz" in result


def test_extract_tarballs_from_html_deduplication():
    url = "https://files.example.com/pkg-3.0.tgz"
    html = f'<a href="{url}">link</a> also see {url} in text'
    result = _extract_tarballs_from_html(html)
    assert result.count(url) == 1, "Duplicate URLs should be deduplicated"


def test_extract_tarballs_from_html_empty():
    result = _extract_tarballs_from_html("<html><body>No tarballs here.</body></html>")
    assert result == []


# ---------------------------------------------------------------------------
# eol._extract_branch
# ---------------------------------------------------------------------------



@pytest.mark.parametrize("version, expected", [
    ("6.0.1",  "6.0"),
    ("10.2.3", "10.2"),
    ("6.0",    "6.0"),
    ("3",      "3"),
    ("",       None),
    ("abc",    None),
])
def test_extract_branch(version, expected):
    assert _extract_branch(version) == expected, (
        f"_extract_branch({version!r}) should be {expected!r}"
    )


# ---------------------------------------------------------------------------
# eol._is_eol
# ---------------------------------------------------------------------------



@pytest.mark.parametrize("eol_value, expected", [
    (True,   True),
    (False,  False),
    ("2000-01-01", True),   # far in the past → EOL
    ("2099-12-31", False),  # far in the future → supported
    (None,   None),
    (42,     None),         # unexpected type → None
])
def test_is_eol(eol_value, expected):
    assert _is_eol(eol_value) == expected, (
        f"_is_eol({eol_value!r}) should be {expected!r}"
    )


# ---------------------------------------------------------------------------
# eol.check_eol (mocked network)
# ---------------------------------------------------------------------------



def _make_urlopen_mock(payload: list):
    """Return a context-manager mock that yields a fake HTTP response."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = _json.dumps(payload).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


_FAKE_CYCLES = [
    {"cycle": "6.0", "eol": "2024-11-12", "latest": "6.0.35"},
    {"cycle": "8.0", "eol": "2026-11-10", "latest": "8.0.14"},
    {"cycle": "10.0", "eol": False, "latest": "10.0.3"},
]


def test_check_eol_matched_cycle_eol():
    """6.0 branch should be flagged as EOL with the correct date."""
    with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(_FAKE_CYCLES)):
        result = check_eol("dotnet", ["6.0.15"])
    assert result["eol"] is True, f"Expected eol=True, got {result}"
    assert result["eol_date"] == "2024-11-12"
    assert result["cycle"] == "6.0"
    assert result["latest_in_cycle"] == "6.0.35"


def test_check_eol_matched_cycle_supported():
    """8.0 branch should be active (eol date in future → supported)."""
    with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(_FAKE_CYCLES)):
        result = check_eol("dotnet", ["8.0.1"])
    assert result["eol"] is False, f"Expected eol=False, got {result}"
    assert result["cycle"] == "8.0"


def test_check_eol_no_versions_returns_first_cycle():
    """With no versions supplied, return the first (most recent) cycle."""
    with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(_FAKE_CYCLES)):
        result = check_eol("dotnet", [])
    # First entry is 6.0 which is EOL
    assert result["cycle"] == "6.0"


def test_check_eol_unknown_product():
    """Unindexed product returns all-None dict."""
    with patch("urllib.request.urlopen", side_effect=Exception("404")):
        result = check_eol("obscure-package-xyz", ["1.0.0"])
    assert result["eol"] is None
    assert result["product"] is None


def test_check_eol_no_matching_cycle():
    """Version with no matching cycle returns product slug but None eol."""
    with patch("urllib.request.urlopen", return_value=_make_urlopen_mock(_FAKE_CYCLES)):
        result = check_eol("dotnet", ["99.0.0"])
    assert result["eol"] is None
    assert result["product"] == "dotnet"


# ---------------------------------------------------------------------------
# eol._normalize_candidates
# ---------------------------------------------------------------------------


def test_normalize_candidates_apache_tomcat():
    """'Apache Tomcat' has a slug-map entry, so it resolves directly to ['tomcat']."""
    candidates = _normalize_candidates("Apache Tomcat")
    assert "tomcat" in candidates, (
        f"Expected 'tomcat' in candidates for 'Apache Tomcat', got {candidates}"
    )


def test_normalize_candidates_direct_alias():
    """'.NET Core' should resolve to ['dotnet'] via the slug map."""
    candidates = _normalize_candidates(".NET Core")
    assert candidates == ["dotnet"], (
        f"Expected ['dotnet'] for '.NET Core', got {candidates}"
    )


def test_normalize_candidates_vendor_prefix_stripping():
    """'Apache Kafka' (not in slug map) generates both full and stripped slugs."""
    candidates = _normalize_candidates("Apache Kafka")
    assert "apache-kafka" in candidates, (
        f"Expected 'apache-kafka' in candidates, got {candidates}"
    )
    assert "kafka" in candidates, (
        f"Expected 'kafka' in candidates, got {candidates}"
    )


def test_normalize_candidates_simple_name():
    """A simple lowercase name like 'django' should return just itself."""
    candidates = _normalize_candidates("django")
    assert candidates == ["django"], (
        f"Expected ['django'] for 'django', got {candidates}"
    )


def test_check_eol_apache_tomcat_resolves():
    """'Apache Tomcat' resolves to 'tomcat' when 'apache-tomcat' 404s."""
    tomcat_cycles = [
        {"cycle": "9.0", "eol": "2027-10-31", "latest": "9.0.97"},
        {"cycle": "10.1", "eol": False, "latest": "10.1.40"},
    ]

    def fake_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "/tomcat.json" in url:
            return _make_urlopen_mock(tomcat_cycles)
        raise Exception("404 Not Found")

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        result = check_eol("Apache Tomcat", ["9.0.69"])

    assert result["product"] == "tomcat", (
        f"Expected product='tomcat', got {result['product']!r}"
    )
    assert result["cycle"] == "9.0"
    assert result["eol"] is not None


# ---------------------------------------------------------------------------
# cves._filter_no_cpe_via_model
# ---------------------------------------------------------------------------


_NO_CPE_ENTRIES = [
    {"id": "CVE-2024-1313", "severity": "MEDIUM", "summary": "This issue affects Grafana: from 9.5.0 before 9.5.18.", "version_filter": "no_cpe_data"},
    {"id": "CVE-2025-8341", "severity": "MEDIUM", "summary": "The Infinity datasource plugin for Grafana. Fixed in version 3.4.1.", "version_filter": "no_cpe_data"},
    {"id": "CVE-2021-27358", "severity": "HIGH",   "summary": "Grafana snapshot API DoS affecting 6.7.3 through 7.4.1.", "version_filter": "no_cpe_data"},
]


def test_filter_no_cpe_drops_excluded_ids():
    """Model returns affects=false for two entries — both are dropped."""
    model_response = '[{"id":"CVE-2024-1313","affects":false},{"id":"CVE-2025-8341","affects":false},{"id":"CVE-2021-27358","affects":true}]'
    with patch("veripak.checkers.cves.model_caller.call_model", return_value=model_response):
        result = _filter_no_cpe_via_model(_NO_CPE_ENTRIES, "grafana", ["6.7.4"])
    ids = [e["id"] for e in result]
    assert ids == ["CVE-2021-27358"], f"Expected only CVE-2021-27358, got {ids}"


def test_filter_no_cpe_keeps_all_when_all_affect():
    """Model returns affects=true for all entries — nothing dropped."""
    model_response = '[{"id":"CVE-2024-1313","affects":true},{"id":"CVE-2025-8341","affects":true},{"id":"CVE-2021-27358","affects":true}]'
    with patch("veripak.checkers.cves.model_caller.call_model", return_value=model_response):
        result = _filter_no_cpe_via_model(_NO_CPE_ENTRIES, "grafana", ["6.7.4"])
    assert len(result) == 3


def test_filter_no_cpe_fallback_on_model_error():
    """Model raises an exception — all entries are returned unchanged."""
    with patch("veripak.checkers.cves.model_caller.call_model", side_effect=RuntimeError("timeout")):
        result = _filter_no_cpe_via_model(_NO_CPE_ENTRIES, "grafana", ["6.7.4"])
    assert len(result) == 3, "Fallback should return all entries on error"


def test_filter_no_cpe_fallback_on_malformed_json():
    """Model returns non-JSON — all entries are returned unchanged."""
    with patch("veripak.checkers.cves.model_caller.call_model", return_value="I cannot determine this."):
        result = _filter_no_cpe_via_model(_NO_CPE_ENTRIES, "grafana", ["6.7.4"])
    assert len(result) == 3, "Fallback should return all entries on malformed JSON"


def test_filter_no_cpe_strips_code_fence():
    """Model wraps response in markdown code fence — still parsed correctly."""
    model_response = '```json\n[{"id":"CVE-2024-1313","affects":false},{"id":"CVE-2025-8341","affects":true},{"id":"CVE-2021-27358","affects":true}]\n```'
    with patch("veripak.checkers.cves.model_caller.call_model", return_value=model_response):
        result = _filter_no_cpe_via_model(_NO_CPE_ENTRIES, "grafana", ["6.7.4"])
    ids = [e["id"] for e in result]
    assert "CVE-2024-1313" not in ids
    assert "CVE-2025-8341" in ids


def test_filter_no_cpe_empty_entries():
    """Empty input returns empty without calling the model."""
    with patch("veripak.checkers.cves.model_caller.call_model") as mock_model:
        result = _filter_no_cpe_via_model([], "grafana", ["6.7.4"])
    assert result == []
    mock_model.assert_not_called()


# ---------------------------------------------------------------------------
# cves._suggest_nvd_cpe
# ---------------------------------------------------------------------------



def test_suggest_nvd_cpe_valid_response():
    """Model returns a well-formed vendor:product string — wrapped in a list."""
    with patch("veripak.checkers.cves.model_caller.call_model", return_value="grafana:grafana"):
        result = _suggest_nvd_cpe("grafana", "desktop-app")
    assert result == ["grafana:grafana"]


def test_suggest_nvd_cpe_override_map():
    """Known package uses hardcoded override without calling the model."""
    with patch("veripak.checkers.cves.model_caller.call_model") as mock_model:
        result = _suggest_nvd_cpe("dotnet", "system")
    mock_model.assert_not_called()
    assert "microsoft:.net" in result
    assert "microsoft:asp.net_core" in result


def test_suggest_nvd_cpe_strips_quotes():
    """Model wraps the answer in quotes — they are stripped."""
    with patch("veripak.checkers.cves.model_caller.call_model", return_value='"openssl:openssl"'):
        result = _suggest_nvd_cpe("openssl", "system")
    assert result == ["openssl:openssl"]


def test_suggest_nvd_cpe_rejects_invalid_format():
    """Model returns something that doesn't match vendor:product pattern."""
    with patch("veripak.checkers.cves.model_caller.call_model", return_value="not a valid cpe string here"):
        result = _suggest_nvd_cpe("somepackage", "desktop-app")
    assert result == [], f"Should return empty list, got {result!r}"


def test_suggest_nvd_cpe_rejects_uppercase():
    """Uppercase letters in model response are lowercased; if still valid, returned in list."""
    with patch("veripak.checkers.cves.model_caller.call_model", return_value="GRAFANA:GRAFANA"):
        result = _suggest_nvd_cpe("grafana", "desktop-app")
    assert result == ["grafana:grafana"]


def test_suggest_nvd_cpe_fallback_on_error():
    """Model raises exception — returns empty list."""
    with patch("veripak.checkers.cves.model_caller.call_model", side_effect=RuntimeError("down")):
        result = _suggest_nvd_cpe("grafana", "desktop-app")
    assert result == []


# ---------------------------------------------------------------------------
# cves._nvd_fetch_by_cpe_name
# ---------------------------------------------------------------------------



def _make_cpe_response(vulns: list) -> MagicMock:
    """Return a mock urlopen context manager that yields a JSON NVD response."""
    body = _json.dumps({"vulnerabilities": vulns}).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def test_nvd_fetch_by_cpe_name_returns_vulns():
    """Normal 200 response: all vulnerabilities are returned."""
    fake_vulns = [{"cve": {"id": "CVE-2021-27358"}}, {"cve": {"id": "CVE-2021-39226"}}]
    with patch("veripak.checkers.cves.urllib.request.urlopen", return_value=_make_cpe_response(fake_vulns)):
        result = _nvd_fetch_by_cpe_name("cpe:2.3:a:grafana:grafana:6.7.4:*:*:*:*:*:*:*", "")
    assert len(result) == 2
    ids = [item.get("cve", {}).get("id") for item in result]
    assert "CVE-2021-27358" in ids
    assert "CVE-2021-39226" in ids


def test_nvd_fetch_by_cpe_name_empty_on_exception():
    """Network exception returns empty list."""
    with patch("veripak.checkers.cves.urllib.request.urlopen", side_effect=OSError("connection refused")):
        result = _nvd_fetch_by_cpe_name("cpe:2.3:a:grafana:grafana:6.7.4:*:*:*:*:*:*:*", "")
    assert result == []


def test_nvd_fetch_by_cpe_name_empty_on_http_error():
    """Non-retryable HTTP error returns empty list after one attempt."""
    import urllib.error
    with patch("veripak.checkers.cves.urllib.request.urlopen",
               side_effect=urllib.error.HTTPError(None, 404, "Not Found", {}, None)):
        result = _nvd_fetch_by_cpe_name("cpe:2.3:a:grafana:grafana:6.7.4:*:*:*:*:*:*:*", "")
    assert result == []


# ---------------------------------------------------------------------------
# ecosystem.infer_ecosystem
# ---------------------------------------------------------------------------



def test_infer_ecosystem_override():
    """Well-known binary apps are returned from the override map without probing."""
    result = infer_ecosystem("grafana", version="6.7.4")
    assert result == "desktop-app", f"Expected 'desktop-app', got {result!r}"


def test_infer_ecosystem_hits_first_registry():
    """First registry hit returns that ecosystem without calling later probes."""
    calls = []

    def fake_probe_false(name, version=None):
        calls.append(name)
        return False

    def fake_probe_true(name, version=None):
        calls.append(name)
        return True

    with patch("veripak.checkers.ecosystem._REGISTRY_PROBES", [
        ("python", fake_probe_false),
        ("javascript", fake_probe_true),
        ("dotnet", fake_probe_true),   # should not be reached
    ]):
        result = infer_ecosystem("somepackage")

    assert result == "javascript", f"Expected 'javascript', got {result!r}"
    assert len(calls) == 2, f"Expected 2 probe calls (stopped after hit), got {len(calls)}"


def test_infer_ecosystem_falls_through_to_model():
    """All registry probes miss → model is called."""
    all_false = lambda name, version=None: False  # noqa: E731

    with patch("veripak.checkers.ecosystem._REGISTRY_PROBES", [
        ("python", all_false),
    ]):
        with patch("veripak.checkers.ecosystem._infer_via_model", return_value="desktop-app") as mock_model:
            result = infer_ecosystem("someunknownapp", version="1.2.3")

    mock_model.assert_called_once_with("someunknownapp", "1.2.3")
    assert result == "desktop-app", f"Expected 'desktop-app', got {result!r}"


def test_infer_ecosystem_returns_none_on_total_failure():
    """All probes miss and model returns None → infer_ecosystem returns None."""
    with patch("veripak.checkers.ecosystem._REGISTRY_PROBES", []):
        with patch("veripak.checkers.ecosystem._infer_via_model", return_value=None):
            result = infer_ecosystem("unknownpkg")
    assert result is None, f"Expected None, got {result!r}"


def test_infer_via_model_rejects_invalid_ecosystem():
    """Model returns something not in _VALID_ECOSYSTEMS → returns None."""
    from veripak.checkers.ecosystem import _infer_via_model
    with patch("veripak.checkers.ecosystem.tavily_client.search", return_value=[]):
        with patch("veripak.checkers.ecosystem.model_caller.call_model", return_value="ruby"):
            result = _infer_via_model("rails")
    assert result is None, f"Expected None for invalid ecosystem 'ruby', got {result!r}"


# ---------------------------------------------------------------------------
# detect_ecosystem_ambiguity
# ---------------------------------------------------------------------------


def test_detect_ecosystem_ambiguity_multiple():
    """Package found in two registries returns both ecosystems."""
    with patch("veripak.checkers.ecosystem._REGISTRY_PROBES", [
        ("python", lambda n, v=None: True),
        ("java", lambda n, v=None: True),
        ("javascript", lambda n, v=None: False),
    ]):
        result = detect_ecosystem_ambiguity("jsoup")
    assert result == ["python", "java"], (
        f"Expected ['python', 'java'], got {result}"
    )


def test_detect_ecosystem_ambiguity_single():
    """Package found in exactly one registry returns a single-item list."""
    with patch("veripak.checkers.ecosystem._REGISTRY_PROBES", [
        ("python", lambda n, v=None: False),
        ("java", lambda n, v=None: True),
    ]):
        result = detect_ecosystem_ambiguity("jsoup")
    assert result == ["java"], f"Expected ['java'], got {result}"


def test_detect_ecosystem_ambiguity_none():
    """No registry matches returns an empty list."""
    with patch("veripak.checkers.ecosystem._REGISTRY_PROBES", [
        ("python", lambda n, v=None: False),
        ("java", lambda n, v=None: False),
    ]):
        result = detect_ecosystem_ambiguity("unknownpkg")
    assert result == [], f"Expected [], got {result}"


def test_detect_ecosystem_ambiguity_exception_tolerant():
    """A failing probe is skipped; remaining probes still run."""
    def raise_error(n, v=None):
        raise RuntimeError("network failure")

    with patch("veripak.checkers.ecosystem._REGISTRY_PROBES", [
        ("python", raise_error),
        ("java", lambda n, v=None: True),
        ("javascript", lambda n, v=None: True),
    ]):
        result = detect_ecosystem_ambiguity("somepkg")
    assert result == ["java", "javascript"], (
        f"Expected ['java', 'javascript'] (python probe error skipped),"
        f" got {result}"
    )


def test_detect_ecosystem_ambiguity_skips_overrides():
    """Packages in the override map return empty — no probing needed."""
    result = detect_ecosystem_ambiguity("grafana")
    assert result == [], (
        f"Expected [] for overridden package, got {result}"
    )


# ---------------------------------------------------------------------------
# _maven_metadata_version
# ---------------------------------------------------------------------------

_JSOUP_METADATA_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>org.jsoup</groupId>
  <artifactId>jsoup</artifactId>
  <versioning>
    <latest>1.21.1</latest>
    <release>1.21.1</release>
    <versions>
      <version>1.15.4</version>
      <version>1.21.1</version>
    </versions>
    <lastUpdated>20250101000000</lastUpdated>
  </versioning>
</metadata>
"""

_METADATA_XML_LATEST_ONLY = """\
<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>example</artifactId>
  <versioning>
    <latest>2.0.0</latest>
    <versions>
      <version>2.0.0</version>
    </versions>
  </versioning>
</metadata>
"""

_METADATA_XML_NO_VERSIONING = """\
<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>example</artifactId>
</metadata>
"""


def test_maven_metadata_version_release_tag():
    """Extracts version from the <release> tag."""
    with patch(
        "veripak.checkers.versions._http_get_text",
        return_value=_JSOUP_METADATA_XML,
    ):
        result = _maven_metadata_version("org.jsoup", "jsoup")
    assert result == "1.21.1", (
        f"Expected '1.21.1' from <release> tag, got {result!r}"
    )


def test_maven_metadata_version_latest_fallback():
    """Falls back to <latest> when <release> is absent."""
    with patch(
        "veripak.checkers.versions._http_get_text",
        return_value=_METADATA_XML_LATEST_ONLY,
    ):
        result = _maven_metadata_version("com.example", "example")
    assert result == "2.0.0", (
        f"Expected '2.0.0' from <latest> tag, got {result!r}"
    )


def test_maven_metadata_version_http_failure():
    """Returns None when the HTTP fetch fails."""
    with patch(
        "veripak.checkers.versions._http_get_text",
        return_value=None,
    ):
        result = _maven_metadata_version("org.jsoup", "jsoup")
    assert result is None, f"Expected None on HTTP failure, got {result!r}"


def test_maven_metadata_version_bad_xml():
    """Returns None when the XML is malformed."""
    with patch(
        "veripak.checkers.versions._http_get_text",
        return_value="this is not xml",
    ):
        result = _maven_metadata_version("org.jsoup", "jsoup")
    assert result is None, f"Expected None on bad XML, got {result!r}"


def test_maven_metadata_version_no_versioning_element():
    """Returns None when <versioning> element is missing."""
    with patch(
        "veripak.checkers.versions._http_get_text",
        return_value=_METADATA_XML_NO_VERSIONING,
    ):
        result = _maven_metadata_version("com.example", "example")
    assert result is None, (
        f"Expected None when <versioning> is missing, got {result!r}"
    )


# ---------------------------------------------------------------------------
# check_maven — coordinate format and metadata fallback
# ---------------------------------------------------------------------------


def test_check_maven_coordinate_format_uses_metadata():
    """Input 'org.jsoup:jsoup' should parse coordinates and hit metadata."""
    with patch(
        "veripak.checkers.versions._maven_metadata_version",
        return_value="1.21.1",
    ) as mock_meta:
        version, url, notes = check_maven("org.jsoup:jsoup")
    mock_meta.assert_called_once_with("org.jsoup", "jsoup")
    assert version == "1.21.1", (
        f"Expected '1.21.1' for coordinate input, got {version!r}"
    )
    assert "maven-metadata.xml" in url, (
        f"Expected metadata URL, got {url!r}"
    )
    assert notes is None


def test_check_maven_coordinate_format_falls_back_to_solr():
    """When metadata XML fails, Solr search is used as fallback."""
    solr_response = {
        "response": {
            "docs": [{"latestVersion": "1.15.4"}],
        },
    }
    with patch(
        "veripak.checkers.versions._maven_metadata_version",
        return_value=None,
    ):
        with patch(
            "veripak.checkers.versions._http_get_json",
            return_value=solr_response,
        ):
            version, url, notes = check_maven("org.jsoup:jsoup")
    assert version == "1.15.4", (
        f"Expected Solr fallback version '1.15.4', got {version!r}"
    )
    assert "solrsearch" in url, (
        f"Expected Solr URL on fallback, got {url!r}"
    )


def test_check_maven_osv_mapping_uses_metadata():
    """Bare name with an OSV mapping should also try metadata first."""
    with patch(
        "veripak.checkers.versions._maven_metadata_version",
        return_value="5.0.0",
    ) as mock_meta:
        version, url, notes = check_maven("log4j")
    mock_meta.assert_called_once_with(
        "org.apache.logging.log4j", "log4j-core",
    )
    assert version == "5.0.0"


def test_check_maven_coordinate_branch_scoping():
    """Branch-scoping still works with coordinate input."""
    with patch(
        "veripak.checkers.versions._maven_metadata_version",
        return_value="2.0.0",
    ):
        with patch(
            "veripak.checkers.versions._maven_branch_latest",
            return_value="1.17.2",
        ) as mock_branch:
            version, _, _ = check_maven(
                "org.jsoup:jsoup",
                versions_in_use=["1.15.4"],
            )
    mock_branch.assert_called_once_with("org.jsoup", "jsoup", 1)
    assert version == "1.17.2", (
        f"Expected branch-scoped '1.17.2', got {version!r}"
    )


def test_check_maven_bare_name_no_mapping_uses_solr():
    """Bare name without OSV mapping falls through to artifact search."""
    solr_response = {
        "response": {
            "docs": [{"latestVersion": "3.2.1"}],
        },
    }
    with patch(
        "veripak.checkers.versions._http_get_json",
        return_value=solr_response,
    ):
        version, url, notes = check_maven("some-unknown-artifact")
    assert version == "3.2.1"
    assert "solrsearch" in url


def test_check_maven_prerelease_noted():
    """Pre-release version from metadata gets a notes string."""
    with patch(
        "veripak.checkers.versions._maven_metadata_version",
        return_value="4.0-M3",
    ):
        version, _, notes = check_maven("org.example:lib")
    assert version == "4.0-M3"
    assert notes == "pre-release version"


def test_check_maven_bare_name_resolves_via_metadata():
    """Bare artifact name should re-query maven-metadata.xml using coordinates from Solr."""
    solr_response = {
        "response": {
            "docs": [{"g": "org.jsoup", "a": "jsoup", "latestVersion": "1.21.1"}],
        },
    }

    def mock_http_get_json(url):
        if "solrsearch" in url:
            return solr_response
        return None

    with patch("veripak.checkers.versions._http_get_json", side_effect=mock_http_get_json), \
         patch("veripak.checkers.versions._maven_metadata_version", return_value="1.22.1") as mock_meta:
        version, url, notes = check_maven("jsoup")

    # Should have called _maven_metadata_version with resolved coordinates
    mock_meta.assert_called_once_with("org.jsoup", "jsoup")
    # Should return the canonical version from metadata, not Solr's stale one
    assert version == "1.22.1", f"Expected canonical '1.22.1', got {version!r}"
    # URL should point to maven-metadata.xml, not Solr
    assert "maven-metadata.xml" in url, (
        f"Expected metadata URL after coordinate resolution, got {url!r}"
    )


def test_check_maven_bare_name_falls_back_to_solr_when_metadata_fails():
    """When metadata.xml returns None for resolved coordinates, keep the Solr version."""
    solr_response = {
        "response": {
            "docs": [{"g": "org.jsoup", "a": "jsoup", "latestVersion": "1.21.1"}],
        },
    }

    def mock_http_get_json(url):
        if "solrsearch" in url:
            return solr_response
        return None

    with patch("veripak.checkers.versions._http_get_json", side_effect=mock_http_get_json), \
         patch("veripak.checkers.versions._maven_metadata_version", return_value=None):
        version, url, notes = check_maven("jsoup")

    assert version == "1.21.1", f"Expected Solr fallback '1.21.1', got {version!r}"
    assert "solrsearch" in url, (
        f"Expected Solr URL when metadata returns None, got {url!r}"
    )


# ---------------------------------------------------------------------------
# validate_cve_ids
# ---------------------------------------------------------------------------


def test_validate_cve_ids_osv_confirms():
    """CVEs returned by OSV for the package are marked True."""
    osv_vulns = [
        {"id": "CVE-2024-1234", "severity": "HIGH",
         "summary": "XSS in jsoup", "aliases": ["GHSA-abc"]},
        {"id": "CVE-2023-5678", "severity": "MEDIUM",
         "summary": "DoS in jsoup", "aliases": []},
    ]
    with patch(
        "veripak.checkers.cves._osv_query_package",
        return_value=osv_vulns,
    ):
        result = validate_cve_ids(
            ["CVE-2024-1234", "CVE-2023-5678"],
            "jsoup", "java",
        )
    assert result == {
        "CVE-2024-1234": True,
        "CVE-2023-5678": True,
    }, f"All OSV-confirmed CVEs should be True, got {result}"


def test_validate_cve_ids_osv_rejects():
    """CVE not in OSV and not in NVD is marked False."""
    osv_vulns = [
        {"id": "CVE-2024-1234", "severity": "HIGH",
         "summary": "Real vuln", "aliases": []},
    ]
    with patch(
        "veripak.checkers.cves._osv_query_package",
        return_value=osv_vulns,
    ):
        with patch(
            "veripak.checkers.cves._nvd_fetch_by_id",
            return_value=None,
        ):
            result = validate_cve_ids(
                ["CVE-2024-1234", "CVE-2015-3117"],
                "jsoup", "java",
            )
    assert result["CVE-2024-1234"] is True, (
        "OSV-confirmed CVE should be True"
    )
    assert result["CVE-2015-3117"] is False, (
        "CVE not found in OSV or NVD should be False"
    )


def test_validate_cve_ids_nvd_fallback():
    """CVE missed by OSV but confirmed by NVD CPE match is True."""
    nvd_item = {
        "cve": {
            "id": "CVE-2023-9999",
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:jsoup:jsoup:1.15.3:*:*:*:*:*:*:*",
                    }],
                }],
            }],
        },
    }
    with patch(
        "veripak.checkers.cves._osv_query_package",
        return_value=[],
    ):
        with patch(
            "veripak.checkers.cves._nvd_fetch_by_id",
            return_value=nvd_item,
        ):
            result = validate_cve_ids(
                ["CVE-2023-9999"], "jsoup", "java",
            )
    assert result["CVE-2023-9999"] is True, (
        "NVD-confirmed CVE should be True"
    )


def test_validate_cve_ids_fault_tolerant():
    """When OSV raises an exception, all CVEs default to True."""
    with patch(
        "veripak.checkers.cves._osv_query_package",
        side_effect=OSError("connection refused"),
    ):
        result = validate_cve_ids(
            ["CVE-2024-1234", "CVE-2015-3117"],
            "jsoup", "java",
        )
    assert all(v is True for v in result.values()), (
        f"All CVEs should be True on OSV failure, got {result}"
    )
    assert len(result) == 2


def test_validate_cve_ids_nvd_only_ecosystem():
    """For NVD-only ecosystems (c, cpp, etc.), OSV is skipped entirely
    and validation goes straight to NVD CVE-ID lookup."""
    fake_nvd_item = {
        "cve": {
            "id": "CVE-2023-9999",
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:vendor:openssl:*:*:*:*:*:*:*:*",
                        "vulnerable": True,
                    }]
                }]
            }],
        }
    }
    with (
        patch(
            "veripak.checkers.cves._osv_query_package",
            side_effect=AssertionError("OSV should not be called"),
        ),
        patch(
            "veripak.checkers.cves._nvd_fetch_by_id",
            return_value=fake_nvd_item,
        ) as mock_nvd,
    ):
        result = validate_cve_ids(
            ["CVE-2023-9999"], "openssl", "c",
        )
    mock_nvd.assert_called_once()
    assert result["CVE-2023-9999"] is True, (
        f"NVD confirmed CVE with matching CPE should be True, got {result}"
    )


# ---------------------------------------------------------------------------
# eol.check_eol_heuristic
# ---------------------------------------------------------------------------


def _make_pypi_response(upload_time_iso: str, version: str = "2.0.0"):
    """Build a fake PyPI JSON API response with one release file."""
    return _json.dumps({
        "info": {"version": version},
        "releases": {
            version: [{"upload_time_iso_8601": upload_time_iso}],
        },
    }).encode()


def _make_npm_response(modified_time: str, latest_version: str = "3.0.0"):
    """Build a fake npm registry response."""
    return _json.dumps({
        "dist-tags": {"latest": latest_version},
        "time": {
            latest_version: modified_time,
            "modified": modified_time,
        },
    }).encode()


def _urlopen_factory(payload_bytes: bytes):
    """Return a mock suitable for urllib.request.urlopen context manager."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = payload_bytes
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def test_eol_heuristic_pypi_active():
    """PyPI package released 30 days ago -> active, medium confidence."""
    import datetime
    recent = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(days=30)
    ).isoformat()
    payload = _make_pypi_response(recent)

    with patch(
        "urllib.request.urlopen",
        return_value=_urlopen_factory(payload),
    ):
        result = check_eol_heuristic("requests", "python")

    assert result["eol"] is False, f"Expected eol=False, got {result}"
    assert result["project_status"] == "active"
    assert result["confidence"] == "medium"
    assert result["method"] == "release_date_heuristic"
    assert result["last_release_date"] is not None
    assert result["last_release_age_days"] < 365


def test_eol_heuristic_pypi_maintenance():
    """PyPI package released 2 years ago -> maintenance, low confidence."""
    import datetime
    old = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(days=730)
    ).isoformat()
    payload = _make_pypi_response(old)

    with patch(
        "urllib.request.urlopen",
        return_value=_urlopen_factory(payload),
    ):
        result = check_eol_heuristic("old-lib", "python")

    assert result["eol"] is None, (
        f"Expected eol=None for maintenance, got {result}"
    )
    assert result["project_status"] == "maintenance"
    assert result["confidence"] == "low"
    assert "HITL" in result["notes"]


def test_eol_heuristic_pypi_possibly_eol():
    """PyPI package released 4 years ago -> possibly_eol, eol=True."""
    import datetime
    very_old = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(days=1460)
    ).isoformat()
    payload = _make_pypi_response(very_old)

    with patch(
        "urllib.request.urlopen",
        return_value=_urlopen_factory(payload),
    ):
        result = check_eol_heuristic("abandoned-pkg", "python")

    assert result["eol"] is True, (
        f"Expected eol=True for 4-year-old package, got {result}"
    )
    assert result["project_status"] == "possibly_eol"
    assert result["confidence"] == "low"
    assert result["last_release_age_days"] >= 1095


def test_eol_heuristic_npm():
    """npm registry last modified date is parsed correctly."""
    import datetime
    recent = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(days=10)
    ).isoformat()
    payload = _make_npm_response(recent)

    with patch(
        "urllib.request.urlopen",
        return_value=_urlopen_factory(payload),
    ):
        result = check_eol_heuristic("express", "javascript")

    assert result["project_status"] == "active"
    assert result["confidence"] == "medium"
    assert result["last_release_date"] is not None


def test_eol_heuristic_unsupported_ecosystem():
    """Unsupported ecosystem returns notes explaining the limitation."""
    result = check_eol_heuristic("some-lib", "rust")

    assert result["eol"] is None
    assert result["last_release_date"] is None
    assert "not supported" in result["notes"]
    assert result["method"] == "release_date_heuristic"


def test_eol_heuristic_api_failure():
    """HTTP error from registry returns graceful fallback."""
    with patch(
        "urllib.request.urlopen",
        side_effect=Exception("connection refused"),
    ):
        result = check_eol_heuristic("requests", "python")

    assert result["eol"] is None
    assert result["last_release_date"] is None
    assert "Could not retrieve" in result["notes"]


# ---------------------------------------------------------------------------
# compute_urgency_floor — base cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("eol, hc_count, total_cves, complexity, has_critical, expected", [
    # EOL confirmed, 0 CVEs -> "high" (ceiling does NOT apply because eol=True)
    (True, 0, 0, "unknown", False, "high"),
    # EOL confirmed + HIGH/CRITICAL CVEs -> "immediate"
    (True, 1, 1, "unknown", False, "immediate"),
    # Not EOL, 0 CVEs -> "low" (ceiling irrelevant, already low)
    (False, 0, 0, "unknown", False, "low"),
    # Not EOL, has HIGH CVEs -> "medium"
    (False, 1, 1, "unknown", False, "medium"),
    # Not EOL, critical CVE flag -> "high"
    (False, 0, 1, "unknown", True, "high"),
    # EOL=None (uncertain), 0 CVEs -> "low" (floor says low, ceiling irrelevant)
    (None, 0, 0, "unknown", False, "low"),
    # Major version gap, 0 CVEs -> "medium"
    (False, 0, 0, "major", False, "medium"),
    # Rewrite complexity, 0 CVEs -> "medium"
    (False, 0, 0, "rewrite", False, "medium"),
    # Patch complexity, 0 CVEs -> "low"
    (False, 0, 0, "patch", False, "low"),
])
def test_compute_urgency_floor(eol, hc_count, total_cves, complexity, has_critical, expected):
    result = compute_urgency_floor(eol, hc_count, total_cves, complexity, has_critical)
    assert result == expected, (
        f"urgency_floor({eol=}, {hc_count=}, {total_cves=}, {complexity=}, {has_critical=}) "
        f"= {result!r}, expected {expected!r}"
    )


# ---------------------------------------------------------------------------
# Urgency ceiling — logic mirrored from summarize.py
# ---------------------------------------------------------------------------


def _apply_urgency_ceiling(summary: dict) -> dict:
    """Apply the same ceiling rule that summarize.py uses.

    Caps urgency at 'medium' when total_distinct_cves == 0 and eol is not True.
    """
    ceil_cves = summary.get("total_distinct_cves") or 0
    ceil_eol = summary.get("eol") is True
    if ceil_cves == 0 and not ceil_eol:
        urg = (summary.get("urgency") or "low").lower()
        if _URGENCY_ORDER.get(urg, 0) > _URGENCY_ORDER["medium"]:
            summary["urgency"] = "medium"
    return summary


def test_urgency_ceiling_caps_high_when_no_cves():
    """Ceiling caps urgency at 'medium' when CVEs=0 and eol is not confirmed."""
    summary = {"urgency": "high", "total_distinct_cves": 0, "eol": None}
    result = _apply_urgency_ceiling(summary)
    assert result["urgency"] == "medium", (
        f"Urgency should be capped at 'medium' with 0 CVEs and eol=None, "
        f"got {result['urgency']!r}"
    )


def test_urgency_ceiling_caps_immediate_when_no_cves():
    """Ceiling caps 'immediate' down to 'medium' when CVEs=0 and eol is not confirmed."""
    summary = {"urgency": "immediate", "total_distinct_cves": 0, "eol": False}
    result = _apply_urgency_ceiling(summary)
    assert result["urgency"] == "medium", (
        f"Urgency should be capped at 'medium' with 0 CVEs and eol=False, "
        f"got {result['urgency']!r}"
    )


def test_urgency_ceiling_does_not_cap_when_eol_confirmed():
    """Ceiling should NOT reduce urgency when EOL is confirmed True, even with 0 CVEs."""
    summary = {"urgency": "high", "total_distinct_cves": 0, "eol": True}
    result = _apply_urgency_ceiling(summary)
    assert result["urgency"] == "high", (
        f"Urgency should remain 'high' when EOL is confirmed, got {result['urgency']!r}"
    )


def test_urgency_ceiling_does_not_cap_when_cves_present():
    """Ceiling is a no-op when CVEs are present, even if eol is not confirmed."""
    summary = {"urgency": "high", "total_distinct_cves": 3, "eol": None}
    result = _apply_urgency_ceiling(summary)
    assert result["urgency"] == "high", (
        f"Urgency should remain 'high' when CVEs are present, got {result['urgency']!r}"
    )


@pytest.mark.parametrize("urg_val", ["low", "medium"])
def test_urgency_ceiling_noop_when_already_medium_or_lower(urg_val):
    """Ceiling is a no-op when urgency is already at or below 'medium'."""
    summary = {"urgency": urg_val, "total_distinct_cves": 0, "eol": None}
    result = _apply_urgency_ceiling(summary)
    assert result["urgency"] == urg_val, (
        f"Urgency {urg_val!r} should not be changed by ceiling, got {result['urgency']!r}"
    )
