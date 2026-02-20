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
