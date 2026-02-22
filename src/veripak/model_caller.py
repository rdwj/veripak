"""liteLLM wrapper: primary backend from config, Anthropic fallback.

Public API:
    call_model(prompt: str, system: str = "") -> str
"""

import os
import threading

from . import config as cfg

_ANTHROPIC_FALLBACK_MODEL = "claude-haiku-4-5-20251001"

_OLLAMA_PREFIX = "ollama/"
_VLLM_PREFIX = "openai/"

_usage_lock = threading.Lock()
_usage_records: list[dict] = []


def _record_usage(resp, model: str) -> None:
    """Extract token usage from a litellm response and append to _usage_records."""
    import litellm

    usage = getattr(resp, "usage", None)
    if usage is None:
        return

    try:
        cost = litellm.completion_cost(completion_response=resp)
    except Exception:
        cost = 0.0

    record = {
        "model": model,
        "prompt_tokens": getattr(usage, "prompt_tokens", 0) or 0,
        "completion_tokens": getattr(usage, "completion_tokens", 0) or 0,
        "total_tokens": getattr(usage, "total_tokens", 0) or 0,
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


def _resolve_model() -> tuple[str, str | None]:
    """Return (model_string_for_litellm, api_base_or_None)."""
    backend = cfg.get("llm_backend", "ollama")
    model = cfg.get("llm_model", "gpt-oss:20b")
    base_url = cfg.get("llm_base_url") or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")

    if backend == "ollama":
        if not model.startswith(_OLLAMA_PREFIX):
            model = _OLLAMA_PREFIX + model
        return model, base_url

    if backend == "vllm":
        if not model.startswith(_VLLM_PREFIX):
            model = _VLLM_PREFIX + model
        return model, base_url

    if backend in ("anthropic", "openai"):
        # litellm routes these by prefix; no base_url override needed
        return model, None

    # Unknown backend — pass through as-is
    return model, base_url


def _load_anthropic_key() -> str | None:
    """Prefer env var, fall back to config."""
    return os.environ.get("ANTHROPIC_API_KEY") or cfg.get("anthropic_api_key")


def call_model(prompt: str, system: str = "") -> str:
    """Call the configured LLM; fall back to Anthropic on failure.

    Raises RuntimeError if both the primary and the fallback fail.
    """
    import litellm

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    model, api_base = _resolve_model()

    primary_error: Exception | None = None
    try:
        kwargs: dict = {"model": model, "messages": messages}
        if api_base:
            kwargs["api_base"] = api_base
        resp = litellm.completion(**kwargs)
        _record_usage(resp, model)
        return resp.choices[0].message.content or ""
    except Exception as exc:
        primary_error = exc

    # --- Anthropic fallback ---
    anthropic_key = _load_anthropic_key()
    anthropic_error: Exception | None = None
    try:
        kwargs = {"model": _ANTHROPIC_FALLBACK_MODEL, "messages": messages}
        if anthropic_key:
            os.environ.setdefault("ANTHROPIC_API_KEY", anthropic_key)
            kwargs["api_key"] = anthropic_key
        resp = litellm.completion(**kwargs)
        _record_usage(resp, _ANTHROPIC_FALLBACK_MODEL)
        return resp.choices[0].message.content or ""
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
    import litellm

    model, api_base = _resolve_model()

    primary_error: Exception | None = None
    try:
        kwargs: dict = {"model": model, "messages": messages}
        if api_base:
            kwargs["api_base"] = api_base
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        resp = litellm.completion(**kwargs)
        _record_usage(resp, model)
        return resp.choices[0].message
    except Exception as exc:
        primary_error = exc

    # --- Anthropic fallback ---
    anthropic_key = _load_anthropic_key()
    anthropic_error: Exception | None = None
    try:
        kwargs = {"model": _ANTHROPIC_FALLBACK_MODEL, "messages": messages}
        if anthropic_key:
            os.environ.setdefault("ANTHROPIC_API_KEY", anthropic_key)
            kwargs["api_key"] = anthropic_key
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        resp = litellm.completion(**kwargs)
        _record_usage(resp, _ANTHROPIC_FALLBACK_MODEL)
        return resp.choices[0].message
    except Exception as exc:
        anthropic_error = exc

    raise RuntimeError(
        f"model_caller: both primary backend and Anthropic fallback failed.\n"
        f"  Primary ({model}) error: {primary_error!r}\n"
        f"  Anthropic fallback error: {anthropic_error!r}"
    )
