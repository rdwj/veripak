"""Unit tests for json_mode behaviour in model_caller.py.

Covers:
- OpenAI: response_format added when json_mode=True, absent otherwise
- OpenAI: response_format suppressed when tools are present
- OpenAI: retry-without-response_format on backend rejection
- Anthropic: assistant prefill (leading '{') added when json_mode=True
- Anthropic: no prefill without json_mode
- call_model_chat: json_mode threads through to OpenAI and Anthropic fallback
- _is_response_format_error helper
"""

from unittest.mock import MagicMock, patch

import pytest

import veripak.model_caller as mc

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_openai_response(content: str = '{"ok": true}') -> MagicMock:
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message.content = content
    resp.usage.prompt_tokens = 10
    resp.usage.completion_tokens = 20
    return resp


def _make_anthropic_response(text: str = '"key": "value"}') -> MagicMock:
    resp = MagicMock()
    block = MagicMock()
    block.type = "text"
    block.text = text
    resp.content = [block]
    resp.usage.input_tokens = 10
    resp.usage.output_tokens = 20
    return resp


def _openai_patches(backend: str = "openai", model: str = "test-model"):
    """Return a dict of common patches for OpenAI-backed calls."""
    return {
        "resolve": patch(
            "veripak.model_caller._resolve_model",
            return_value=(model, backend, None),
        ),
        "key": patch(
            "veripak.model_caller._load_openai_key",
            return_value="test-key",
        ),
        "client": patch("veripak.model_caller._get_openai_client"),
        # Prevent the Anthropic fallback from doing anything real
        "anth_key": patch(
            "veripak.model_caller._load_anthropic_key",
            return_value="test-key",
        ),
        "anth_client": patch("veripak.model_caller._get_anthropic_client"),
    }


# ---------------------------------------------------------------------------
# 1. OpenAI: response_format present when json_mode=True
# ---------------------------------------------------------------------------

def test_call_openai_adds_response_format_with_json_mode():
    mock_resp = _make_openai_response()

    with patch("veripak.model_caller._resolve_model",
               return_value=("test-model", "openai", None)), \
         patch("veripak.model_caller._load_openai_key", return_value="test-key"), \
         patch("veripak.model_caller._get_openai_client") as mock_get_client:

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_resp
        mock_get_client.return_value = mock_client

        result = mc.call_model("test", json_mode=True)

    _, kwargs = mock_client.chat.completions.create.call_args
    assert kwargs.get("response_format") == {"type": "json_object"}, (
        f"Expected response_format={{\"type\": \"json_object\"}}, got: "
        f"{kwargs.get('response_format')!r}"
    )
    assert result == '{"ok": true}'


# ---------------------------------------------------------------------------
# 2. OpenAI: response_format absent without json_mode
# ---------------------------------------------------------------------------

def test_call_openai_no_response_format_without_json_mode():
    mock_resp = _make_openai_response()

    with patch("veripak.model_caller._resolve_model",
               return_value=("test-model", "openai", None)), \
         patch("veripak.model_caller._load_openai_key", return_value="test-key"), \
         patch("veripak.model_caller._get_openai_client") as mock_get_client:

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_resp
        mock_get_client.return_value = mock_client

        mc.call_model("test")

    _, kwargs = mock_client.chat.completions.create.call_args
    assert "response_format" not in kwargs, (
        f"response_format should be absent when json_mode=False, got: "
        f"{kwargs.get('response_format')!r}"
    )


# ---------------------------------------------------------------------------
# 3. OpenAI: response_format suppressed when tools are present
# ---------------------------------------------------------------------------

def test_call_openai_no_response_format_when_tools_present():
    mock_resp = _make_openai_response()

    with patch("veripak.model_caller._resolve_model",
               return_value=("test-model", "openai", None)), \
         patch("veripak.model_caller._load_openai_key", return_value="test-key"), \
         patch("veripak.model_caller._get_openai_client") as mock_get_client:

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_resp
        mock_get_client.return_value = mock_client

        tools = [{"function": {"name": "my_tool", "parameters": {}}}]
        mc.call_model_chat(
            [{"role": "user", "content": "hi"}],
            tools=tools,
            json_mode=True,
        )

    _, kwargs = mock_client.chat.completions.create.call_args
    assert "response_format" not in kwargs, (
        f"response_format must be absent when tools are present, got: "
        f"{kwargs.get('response_format')!r}"
    )


# ---------------------------------------------------------------------------
# 4. OpenAI: retry without response_format on backend rejection
# ---------------------------------------------------------------------------

def test_call_openai_retries_without_response_format_on_rejection():
    mock_resp = _make_openai_response()
    rejection_exc = Exception("invalid request: response_format not supported")

    with patch("veripak.model_caller._resolve_model",
               return_value=("test-model", "openai", None)), \
         patch("veripak.model_caller._load_openai_key", return_value="test-key"), \
         patch("veripak.model_caller._get_openai_client") as mock_get_client:

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = [rejection_exc, mock_resp]
        mock_get_client.return_value = mock_client

        result = mc.call_model("test", json_mode=True)

    assert mock_client.chat.completions.create.call_count == 2, (
        f"Expected 2 calls (retry), got {mock_client.chat.completions.create.call_count}"
    )

    # First call must have included response_format
    first_kwargs = mock_client.chat.completions.create.call_args_list[0][1]
    assert first_kwargs.get("response_format") == {"type": "json_object"}, (
        f"First call should have response_format, got: {first_kwargs!r}"
    )

    # Second call must NOT have response_format
    second_kwargs = mock_client.chat.completions.create.call_args_list[1][1]
    assert "response_format" not in second_kwargs, (
        f"Second (retry) call must omit response_format, got: {second_kwargs!r}"
    )

    assert result == '{"ok": true}'


# ---------------------------------------------------------------------------
# 5. Anthropic: assistant prefill added when json_mode=True
# ---------------------------------------------------------------------------

def test_call_anthropic_prefills_with_json_mode():
    mock_resp = _make_anthropic_response('"key": "value"}')

    with patch("veripak.model_caller._resolve_model",
               return_value=("claude-haiku-4-5-20251001", "anthropic", None)), \
         patch("veripak.model_caller._load_anthropic_key", return_value="test-key"), \
         patch("veripak.model_caller._get_anthropic_client") as mock_get_client:

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_resp
        mock_get_client.return_value = mock_client

        result = mc.call_model("test", json_mode=True)

    _, kwargs = mock_client.messages.create.call_args
    msgs = kwargs.get("messages", [])
    assert msgs, "messages kwarg should not be empty"

    last_msg = msgs[-1]
    assert last_msg == {"role": "assistant", "content": "{"}, (
        f"Expected assistant prefill {{\"role\": \"assistant\", \"content\": \"{{\"}}, "
        f"got: {last_msg!r}"
    )

    # The prefill '{' should be prepended to the model's text output
    assert result.startswith("{"), f"Result should start with '{{', got: {result!r}"
    assert "key" in result, f"Result should contain 'key', got: {result!r}"


# ---------------------------------------------------------------------------
# 6. Anthropic: no prefill without json_mode
# ---------------------------------------------------------------------------

def test_call_anthropic_no_prefill_without_json_mode():
    mock_resp = _make_anthropic_response("some plain text")

    with patch("veripak.model_caller._resolve_model",
               return_value=("claude-haiku-4-5-20251001", "anthropic", None)), \
         patch("veripak.model_caller._load_anthropic_key", return_value="test-key"), \
         patch("veripak.model_caller._get_anthropic_client") as mock_get_client:

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_resp
        mock_get_client.return_value = mock_client

        mc.call_model("test")

    _, kwargs = mock_client.messages.create.call_args
    msgs = kwargs.get("messages", [])
    assistant_prefills = [
        m for m in msgs
        if m.get("role") == "assistant" and m.get("content") == "{"
    ]
    assert not assistant_prefills, (
        f"No assistant prefill expected when json_mode=False, found: {assistant_prefills!r}"
    )


# ---------------------------------------------------------------------------
# 7. call_model_chat: json_mode flows through to OpenAI
# ---------------------------------------------------------------------------

def test_call_model_chat_threads_json_mode_to_openai():
    mock_resp = _make_openai_response()

    with patch("veripak.model_caller._resolve_model",
               return_value=("test-model", "openai", None)), \
         patch("veripak.model_caller._load_openai_key", return_value="test-key"), \
         patch("veripak.model_caller._get_openai_client") as mock_get_client:

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_resp
        mock_get_client.return_value = mock_client

        mc.call_model_chat(
            [{"role": "user", "content": "hi"}],
            json_mode=True,
        )

    _, kwargs = mock_client.chat.completions.create.call_args
    assert kwargs.get("response_format") == {"type": "json_object"}, (
        f"call_model_chat with json_mode=True must pass response_format, got: "
        f"{kwargs.get('response_format')!r}"
    )


# ---------------------------------------------------------------------------
# 8. call_model_chat: json_mode falls back to Anthropic with prefill
# ---------------------------------------------------------------------------

def test_call_model_chat_threads_json_mode_to_anthropic_fallback():
    """When the primary OpenAI backend raises a non-format error, the Anthropic
    fallback should be invoked with the assistant prefill for json_mode=True."""
    mock_anth_resp = _make_anthropic_response('"val": 1}')

    with patch("veripak.model_caller._resolve_model",
               return_value=("test-model", "openai", None)), \
         patch("veripak.model_caller._load_openai_key", return_value="test-key"), \
         patch("veripak.model_caller._get_openai_client") as mock_get_openai, \
         patch("veripak.model_caller._load_anthropic_key", return_value="test-key"), \
         patch("veripak.model_caller._get_anthropic_client") as mock_get_anthropic:

        # Make the OpenAI primary fail with a generic (non-format) error
        mock_openai_client = MagicMock()
        mock_openai_client.chat.completions.create.side_effect = Exception("connection timeout")
        mock_get_openai.return_value = mock_openai_client

        mock_anth_client = MagicMock()
        mock_anth_client.messages.create.return_value = mock_anth_resp
        mock_get_anthropic.return_value = mock_anth_client

        mc.call_model_chat(
            [{"role": "user", "content": "hi"}],
            json_mode=True,
        )

    assert mock_anth_client.messages.create.called, (
        "Anthropic client should have been called as the fallback"
    )

    _, kwargs = mock_anth_client.messages.create.call_args
    msgs = kwargs.get("messages", [])
    assistant_prefills = [
        m for m in msgs
        if m.get("role") == "assistant" and m.get("content") == "{"
    ]
    assert assistant_prefills, (
        f"Anthropic fallback should include assistant prefill for json_mode=True, "
        f"messages were: {msgs!r}"
    )


# ---------------------------------------------------------------------------
# 9. call_model: json_mode falls back to Anthropic with prefill (issue #23)
# ---------------------------------------------------------------------------

def test_call_model_threads_json_mode_to_anthropic_fallback():
    """call_model: when primary OpenAI backend fails, Anthropic fallback
    should receive json_mode=True and add the assistant prefill."""
    mock_anth_resp = _make_anthropic_response('"val": 1}')

    with patch("veripak.model_caller._resolve_model",
               return_value=("test-model", "openai", None)), \
         patch("veripak.model_caller._load_openai_key", return_value="test-key"), \
         patch("veripak.model_caller._get_openai_client") as mock_get_openai, \
         patch("veripak.model_caller._load_anthropic_key", return_value="test-key"), \
         patch("veripak.model_caller._get_anthropic_client") as mock_get_anthropic:

        mock_openai_client = MagicMock()
        mock_openai_client.chat.completions.create.side_effect = Exception("connection timeout")
        mock_get_openai.return_value = mock_openai_client

        mock_anth_client = MagicMock()
        mock_anth_client.messages.create.return_value = mock_anth_resp
        mock_get_anthropic.return_value = mock_anth_client

        mc.call_model("test prompt", json_mode=True)

    assert mock_anth_client.messages.create.called, (
        "Anthropic client should have been called as fallback"
    )

    _, kwargs = mock_anth_client.messages.create.call_args
    msgs = kwargs.get("messages", [])
    assistant_prefills = [
        m for m in msgs
        if m.get("role") == "assistant" and m.get("content", "").strip().startswith("{")
    ]
    assert len(assistant_prefills) == 1, (
        f"Expected one assistant prefill for json_mode=True, found {len(assistant_prefills)}: "
        f"{assistant_prefills!r}"
    )


# ---------------------------------------------------------------------------
# 10. _is_response_format_error helper
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("message, expected", [
    ("invalid request: response_format not supported", True),
    ("model does not support json_object", True),
    ("json_mode is not available for this model", True),
    ("Response_Format conflict", True),   # case-insensitive
    ("JSON_OBJECT schema mismatch", True),
    ("connection timeout", False),
    ("authentication failed", False),
    ("rate limit exceeded", False),
    ("context length exceeded", False),
    ("", False),
])
def test_is_response_format_error(message, expected):
    exc = Exception(message)
    result = mc._is_response_format_error(exc)
    assert result is expected, (
        f"_is_response_format_error({message!r}) should be {expected}, got {result!r}"
    )
