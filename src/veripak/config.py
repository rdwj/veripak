"""veripak configuration: read/write ~/.config/veripak/config.json.

Config resolution order (first non-empty wins):
  1. ~/.config/veripak/config.json
  2. .env file in CWD (KEY=VALUE format, mapped to config keys)
"""

import json
from pathlib import Path
from typing import Any

_CONFIG_DIR = Path.home() / ".config" / "veripak"
_CONFIG_FILE = _CONFIG_DIR / "config.json"

# Map environment variable names to config keys.
_ENV_TO_CONFIG = {
    "ANTHROPIC_API_KEY": "anthropic_api_key",
    "TAVILY_API_KEY": "tavily_api_key",
    "NVD_API_KEY": "nvd_api_key",
}

# Module-level cache; populated lazily by load_config()
_cache: dict | None = None


def config_path() -> Path:
    """Return the path to the config file."""
    return _CONFIG_FILE


def _load_dotenv() -> dict:
    """Parse a .env file in the CWD and return mapped config keys.

    Only picks up variables listed in _ENV_TO_CONFIG.
    Ignores comments, blank lines, and export prefixes.
    """
    dotenv_path = Path.cwd() / ".env"
    if not dotenv_path.exists():
        return {}

    result = {}
    try:
        for line in dotenv_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("'\"")
            config_key = _ENV_TO_CONFIG.get(key)
            if config_key and value:
                result[config_key] = value
    except OSError:
        pass
    return result


def load_config() -> dict:
    """Read config from disk and cache it. Returns {} if the file does not exist.

    Merges .env values as defaults for any config keys that are empty or missing.
    """
    global _cache
    if _cache is not None:
        return _cache

    if not _CONFIG_FILE.exists():
        cfg = {}
    else:
        try:
            cfg = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            cfg = {}

    # Fill empty config values from .env
    dotenv_vals = _load_dotenv()
    for key, value in dotenv_vals.items():
        if not cfg.get(key):
            cfg[key] = value

    _cache = cfg
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
