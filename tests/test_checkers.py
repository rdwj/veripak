"""Structural unit tests for checker utilities — no network calls."""

import json as _json
from unittest.mock import MagicMock, patch

import pytest

from veripak.checkers.cves import (
    _filter_no_cpe_via_model,
    _nvd_fetch_by_cpe_name,
    _suggest_nvd_cpe,
    _version_in_cpe_range,
)
from veripak.checkers.download_discovery import (
    _extract_tarballs_from_html,
    _is_tarball,
)
from veripak.checkers.ecosystem import infer_ecosystem
from veripak.checkers.eol import (
    _extract_branch,
    _is_eol,
    _normalize_candidates,
    check_eol,
)
from veripak.checkers.versions import (
    _parse_json_response,
    _version_tuple,
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
