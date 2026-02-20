"""veripak configuration: read/write ~/.config/veripak/config.json."""

import json
from pathlib import Path
from typing import Any, Optional

_CONFIG_DIR = Path.home() / ".config" / "veripak"
_CONFIG_FILE = _CONFIG_DIR / "config.json"

# Module-level cache; populated lazily by load_config()
_cache: Optional[dict] = None


def config_path() -> Path:
    """Return the path to the config file."""
    return _CONFIG_FILE


def load_config() -> dict:
    """Read config from disk and cache it. Returns {} if the file does not exist."""
    global _cache
    if _cache is not None:
        return _cache
    if not _CONFIG_FILE.exists():
        _cache = {}
        return _cache
    try:
        _cache = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        _cache = {}
    return _cache


def save_config(cfg: dict) -> None:
    """Write cfg to disk, creating the directory if needed. Refreshes the cache."""
    global _cache
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _CONFIG_FILE.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    _cache = cfg


def get(key: str, default: Any = None) -> Any:
    """Return a single value from the loaded config, or default if not present."""
    return load_config().get(key, default)
