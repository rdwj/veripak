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
