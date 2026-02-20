"""Structural unit tests for checker utilities — no network calls."""

import pytest

from veripak.checkers.versions import strip_v, is_stable, _parse_json_response


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
# _version_in_cpe_range
# ---------------------------------------------------------------------------

from veripak.checkers.cves import _version_in_cpe_range


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

from veripak.checkers.download_discovery import _is_tarball


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

from veripak.checkers.download_discovery import _extract_tarballs_from_html


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

from veripak.checkers.eol import _extract_branch, _is_eol, check_eol


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

import datetime


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

from unittest.mock import patch, MagicMock
import json as _json
import io


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
# cves._filter_no_cpe_via_model
# ---------------------------------------------------------------------------

from veripak.checkers.cves import _filter_no_cpe_via_model


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
