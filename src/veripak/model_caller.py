"""OpenAI + Anthropic SDK wrapper: primary backend from config, Anthropic fallback.

Public API:
    call_model(prompt: str, system: str = "") -> str
    call_model_chat(messages: list, tools: list | None = None)
    reset_usage() -> None
    get_usage_summary() -> dict
"""

import json
import logging
import os
import threading
from types import SimpleNamespace

from . import config as cfg

logger = logging.getLogger(__name__)

_ANTHROPIC_FALLBACK_MODEL = "claude-haiku-4-5-20251001"

_usage_lock = threading.Lock()
_usage_records: list[dict] = []

# Lazy-initialized SDK clients, protected by _client_lock.
_client_lock = threading.Lock()
_clients: dict[str, object] = {}

# Pricing per 1M tokens: (prompt, completion)
_PRICING: dict[str, tuple[float, float]] = {
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "claude-haiku-4-5-20251001": (0.80, 4.00),
    "claude-sonnet-4-20250514": (3.00, 15.00),
    "claude-opus-4-20250514": (15.00, 75.00),
}


def _get_openai_client(base_url: str | None = None, api_key: str | None = None):
    """Return a cached OpenAI client for the given base_url."""
    import openai

    cache_key = f"openai:{base_url or 'default'}"
    with _client_lock:
        if cache_key not in _clients:
            kwargs: dict = {}
            if base_url:
                kwargs["base_url"] = base_url
            if api_key:
                kwargs["api_key"] = api_key
            _clients[cache_key] = openai.OpenAI(**kwargs)
        return _clients[cache_key]


def _get_anthropic_client(api_key: str | None = None):
    """Return a cached Anthropic client."""
    import anthropic

    cache_key = "anthropic"
    with _client_lock:
        if cache_key not in _clients:
            kwargs: dict = {}
            if api_key:
                kwargs["api_key"] = api_key
            _clients[cache_key] = anthropic.Anthropic(**kwargs)
        return _clients[cache_key]


def _resolve_model() -> tuple[str, str, str | None]:
    """Return (model_name, backend, base_url).

    Strips legacy provider prefixes (ollama/, openai/). For ollama/vllm,
    appends /v1 to base_url if not already present. For openai/anthropic,
    returns None for base_url.
    """
    backend = cfg.get("llm_backend", "ollama")
    model = cfg.get("llm_model", "gpt-oss:20b")
    base_url = cfg.get("llm_base_url") or os.environ.get(
        "OLLAMA_BASE_URL", "http://localhost:11434"
    )

    # Strip legacy provider prefixes
    if model.startswith("ollama/"):
        model = model[len("ollama/"):]
    elif model.startswith("openai/"):
        model = model[len("openai/"):]

    if backend == "ollama":
        if not base_url.rstrip("/").endswith("/v1"):
            base_url = base_url.rstrip("/") + "/v1"
        return model, backend, base_url

    if backend == "vllm":
        if not base_url.rstrip("/").endswith("/v1"):
            base_url = base_url.rstrip("/") + "/v1"
        return model, backend, base_url

    if backend in ("anthropic", "openai"):
        return model, backend, None

    # Unknown backend — treat as OpenAI-compatible
    return model, backend, base_url


def _load_anthropic_key() -> str | None:
    """Prefer env var, fall back to config."""
    return os.environ.get("ANTHROPIC_API_KEY") or cfg.get("anthropic_api_key")


def _load_openai_key() -> str | None:
    """Prefer env var, fall back to config."""
    return os.environ.get("OPENAI_API_KEY") or cfg.get("openai_api_key")


def _openai_api_key_for_backend(backend: str) -> str | None:
    """Return the appropriate API key for an OpenAI-compatible backend."""
    if backend == "ollama":
        return "ollama"
    if backend == "vllm":
        return "not-needed"
    if backend == "openai":
        return _load_openai_key()
    return None


def _normalize_messages(messages: list) -> list[dict]:
    """Convert a list of mixed dicts and response objects to a list of dicts.

    base.py appends response objects directly to the messages list, so we
    need to handle both dicts and objects with .role/.content/.tool_calls.
    """
    normalized = []
    for msg in messages:
        if isinstance(msg, dict):
            normalized.append(msg)
            continue

        raw_content = getattr(msg, "content", None)
        tool_calls = getattr(msg, "tool_calls", None)

        entry: dict = {"role": getattr(msg, "role", "assistant")}
        # When tool_calls are present, content should be None (not "").
        # The OpenAI API expects null content for tool-calling messages.
        if tool_calls:
            if raw_content:
                entry["content"] = raw_content
        else:
            entry["content"] = raw_content or ""

        if tool_calls:
            entry["tool_calls"] = []
            for tc in tool_calls:
                entry["tool_calls"].append({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                })

        normalized.append(entry)

    return normalized


def _estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Estimate cost in USD from token counts and the pricing table."""
    pricing = _PRICING.get(model)
    if not pricing:
        return 0.0
    prompt_rate, completion_rate = pricing
    return (prompt_tokens * prompt_rate + completion_tokens * completion_rate) / 1_000_000


def _record_usage(response, model: str, is_anthropic: bool = False) -> None:
    """Extract token usage from a response and append to _usage_records."""
    usage = getattr(response, "usage", None)
    if usage is None:
        return

    if is_anthropic:
        prompt_tokens = getattr(usage, "input_tokens", 0) or 0
        completion_tokens = getattr(usage, "output_tokens", 0) or 0
    else:
        prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
        completion_tokens = getattr(usage, "completion_tokens", 0) or 0

    total_tokens = prompt_tokens + completion_tokens
    cost = _estimate_cost(model, prompt_tokens, completion_tokens)

    record = {
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "estimated_cost_usd": cost,
    }
    with _usage_lock:
        _usage_records.append(record)


def reset_usage() -> None:
    """Clear all accumulated usage records."""
    with _usage_lock:
        _usage_records.clear()


def get_usage_summary() -> dict:
    """Return aggregate token usage across all recorded calls."""
    with _usage_lock:
        records = list(_usage_records)

    return {
        "total_calls": len(records),
        "prompt_tokens": sum(r["prompt_tokens"] for r in records),
        "completion_tokens": sum(r["completion_tokens"] for r in records),
        "total_tokens": sum(r["total_tokens"] for r in records),
        "estimated_cost_usd": sum(r["estimated_cost_usd"] for r in records),
    }


# ---------------------------------------------------------------------------
# Anthropic format conversion
# ---------------------------------------------------------------------------

def _messages_to_anthropic(messages: list[dict]) -> tuple[str, list[dict]]:
    """Convert OpenAI-format messages to Anthropic format.

    Returns (system_str, anthropic_messages).
    Merges consecutive same-role messages as required by the Anthropic API.
    """
    system_parts: list[str] = []
    raw_messages: list[dict] = []

    for msg in messages:
        role = msg["role"]
        content = msg.get("content", "") or ""

        if role == "system":
            system_parts.append(content)
            continue

        if role == "tool":
            entry = {
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": msg["tool_call_id"],
                    "content": content,
                }],
            }
            raw_messages.append(entry)
            continue

        if role == "assistant":
            tool_calls = msg.get("tool_calls")
            if tool_calls:
                blocks = []
                if content:
                    blocks.append({"type": "text", "text": content})
                for tc in tool_calls:
                    fn = tc["function"]
                    try:
                        input_val = json.loads(fn["arguments"])
                    except (json.JSONDecodeError, TypeError):
                        input_val = {}
                    blocks.append({
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": fn["name"],
                        "input": input_val,
                    })
                raw_messages.append({"role": "assistant", "content": blocks})
            else:
                raw_messages.append({"role": "assistant", "content": content})
            continue

        # user or anything else
        raw_messages.append({"role": "user", "content": content})

    # Merge consecutive same-role messages
    merged: list[dict] = []
    for msg in raw_messages:
        if merged and merged[-1]["role"] == msg["role"]:
            prev_content = merged[-1]["content"]
            curr_content = msg["content"]

            # Normalize both to lists of content blocks
            if isinstance(prev_content, str):
                prev_content = [{"type": "text", "text": prev_content}] if prev_content else []
            if isinstance(curr_content, str):
                curr_content = [{"type": "text", "text": curr_content}] if curr_content else []

            merged[-1]["content"] = prev_content + curr_content
        else:
            merged.append(msg)

    return "\n".join(system_parts), merged


def _tools_to_anthropic(tools: list[dict]) -> list[dict]:
    """Convert OpenAI tool schemas to Anthropic format."""
    result = []
    for tool in tools:
        fn = tool["function"]
        result.append({
            "name": fn["name"],
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
        })
    return result


def _anthropic_response_to_openai(response) -> SimpleNamespace:
    """Convert an Anthropic response to OpenAI-compatible SimpleNamespace."""
    content_text = ""
    tool_calls = []

    for block in response.content:
        if block.type == "text":
            content_text += block.text
        elif block.type == "tool_use":
            tool_calls.append(SimpleNamespace(
                id=block.id,
                type="function",
                function=SimpleNamespace(
                    name=block.name,
                    arguments=json.dumps(block.input),
                ),
            ))

    return SimpleNamespace(
        role="assistant",
        content=content_text,
        tool_calls=tool_calls or None,
    )


# ---------------------------------------------------------------------------
# Primary call helpers
# ---------------------------------------------------------------------------

def _call_openai(model: str, messages: list[dict], base_url: str | None,
                 api_key: str | None, tools: list | None = None):
    """Make a chat completion call via the OpenAI SDK. Returns the raw response."""
    client = _get_openai_client(base_url=base_url, api_key=api_key)
    kwargs: dict = {"model": model, "messages": messages}
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"
    resp = client.chat.completions.create(**kwargs)
    return resp


def _call_anthropic(model: str, messages: list[dict], tools: list | None = None):
    """Make a messages call via the Anthropic SDK. Returns an OpenAI-shaped object."""
    api_key = _load_anthropic_key()
    client = _get_anthropic_client(api_key=api_key)

    system_str, anthropic_msgs = _messages_to_anthropic(messages)

    kwargs: dict = {
        "model": model,
        "messages": anthropic_msgs,
        "max_tokens": 4096,
    }
    if system_str:
        kwargs["system"] = system_str
    if tools:
        kwargs["tools"] = _tools_to_anthropic(tools)

    resp = client.messages.create(**kwargs)
    _record_usage(resp, model, is_anthropic=True)
    return _anthropic_response_to_openai(resp)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def call_model(prompt: str, system: str = "") -> str:
    """Call the configured LLM; fall back to Anthropic on failure.

    Raises RuntimeError if both the primary and the fallback fail.
    """
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    model, backend, base_url = _resolve_model()

    primary_error: Exception | None = None
    try:
        if backend == "anthropic":
            result = _call_anthropic(model, messages)
            return result.content or ""
        else:
            api_key = _openai_api_key_for_backend(backend)
            resp = _call_openai(model, messages, base_url, api_key)
            _record_usage(resp, model)
            return resp.choices[0].message.content or ""
    except Exception as exc:
        primary_error = exc

    # --- Anthropic fallback ---
    anthropic_error: Exception | None = None
    try:
        result = _call_anthropic(_ANTHROPIC_FALLBACK_MODEL, messages)
        return result.content or ""
    except Exception as exc:
        anthropic_error = exc

    raise RuntimeError(
        f"model_caller: both primary backend and Anthropic fallback failed.\n"
        f"  Primary ({model}) error: {primary_error!r}\n"
        f"  Anthropic fallback error: {anthropic_error!r}"
    )


def call_model_chat(messages: list, tools: list | None = None):
    """Multi-turn call returning the full message object (supports tool_calls).

    Falls back to Anthropic if the primary backend fails.
    Raises RuntimeError if both fail.
    """
    model, backend, base_url = _resolve_model()
    normalized = _normalize_messages(messages)

    primary_error: Exception | None = None
    try:
        if backend == "anthropic":
            return _call_anthropic(model, normalized, tools=tools)
        else:
            api_key: str | None = None
            if backend == "ollama":
                api_key = "ollama"
            elif backend == "vllm":
                api_key = "not-needed"
            resp = _call_openai(model, normalized, base_url, api_key, tools=tools)
            _record_usage(resp, model)
            return resp.choices[0].message
    except Exception as exc:
        primary_error = exc

    # --- Anthropic fallback ---
    anthropic_error: Exception | None = None
    try:
        return _call_anthropic(_ANTHROPIC_FALLBACK_MODEL, normalized, tools=tools)
    except Exception as exc:
        anthropic_error = exc

    raise RuntimeError(
        f"model_caller: both primary backend and Anthropic fallback failed.\n"
        f"  Primary ({model}) error: {primary_error!r}\n"
        f"  Anthropic fallback error: {anthropic_error!r}"
    )
