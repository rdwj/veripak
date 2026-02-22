"""Tavily web search wrapper."""

import json
import random
import time
import urllib.error
import urllib.request

from . import config

_TAVILY_URL = "https://api.tavily.com/search"
_USER_AGENT = "veripak/0.1"


def search(query: str, max_results: int = 5) -> list[dict]:
    """Search Tavily and return a list of result dicts.

    Each dict has keys: url, title, content.
    Raises RuntimeError if the API key is not configured or all retries fail.
    """
    api_key = config.get("tavily_api_key") or ""
    if not api_key:
        raise RuntimeError(
            "tavily_api_key not set. Run `veripak config` to configure."
        )

    payload = json.dumps({
        "api_key": api_key,
        "query": query,
        "search_depth": "basic",
        "max_results": max_results,
    }).encode()

    result = _search_with_backoff(payload)
    if result is None:
        raise RuntimeError(
            f"Tavily search failed for query: {query!r} (all retries exhausted)"
        )

    return [
        {
            "url": r.get("url", ""),
            "title": r.get("title", ""),
            "content": r.get("content", ""),
        }
        for r in result.get("results", [])
    ]


def _search_with_backoff(payload: bytes, max_retries: int = 6) -> dict | None:
    """POST to the Tavily search API with exponential backoff on HTTP 429.

    Returns the parsed JSON dict on success, or None on failure.
    """
    delay = 1.0
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(
                _TAVILY_URL,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": _USER_AGENT,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < max_retries - 1:
                jitter = random.uniform(0.0, delay * 0.25)
                time.sleep(min(delay + jitter, 60.0))
                delay = min(delay * 2, 60.0)
            else:
                return None
        except Exception:
            return None
    return None
