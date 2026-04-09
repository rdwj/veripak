"""Tests for veripak config set/get/list subcommands."""

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from veripak.cli import main


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def fake_config(tmp_path):
    """Patch config internals to use a temp file, returning the path.

    Also clears _ENV_TO_CONFIG so real environment variables don't leak
    into tests.
    """
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text("{}", encoding="utf-8")

    with (
        patch("veripak.config._CONFIG_FILE", cfg_file),
        patch("veripak.config._CONFIG_DIR", tmp_path),
        patch("veripak.config._ENV_TO_CONFIG", {}),
        patch("veripak.config._cache", None),
    ):
        yield cfg_file


# -------------------------------------------------------------------
# config set
# -------------------------------------------------------------------


class TestConfigSet:
    def test_set_valid_key(self, runner, fake_config):
        result = runner.invoke(main, ["config", "set", "llm_model", "gpt-4"])
        assert result.exit_code == 0, result.output
        assert "Set llm_model = gpt-4" in result.output
        saved = json.loads(fake_config.read_text())
        assert saved["llm_model"] == "gpt-4"

    def test_set_backend_valid(self, runner, fake_config):
        result = runner.invoke(main, ["config", "set", "llm_backend", "anthropic"])
        assert result.exit_code == 0, result.output
        assert "Set llm_backend = anthropic" in result.output

    def test_set_backend_invalid(self, runner, fake_config):
        result = runner.invoke(main, ["config", "set", "llm_backend", "banana"])
        assert result.exit_code != 0
        assert "Invalid backend" in result.output

    def test_set_unknown_key(self, runner, fake_config):
        result = runner.invoke(main, ["config", "set", "bogus_key", "val"])
        assert result.exit_code != 0
        assert "Unknown key" in result.output

    def test_set_api_key_masked_in_output(self, runner, fake_config):
        result = runner.invoke(
            main, ["config", "set", "tavily_api_key", "sk-secret-1234"],
        )
        assert result.exit_code == 0, result.output
        assert "sk-s..." in result.output
        assert "sk-secret-1234" not in result.output
        # But the real value is persisted
        saved = json.loads(fake_config.read_text())
        assert saved["tavily_api_key"] == "sk-secret-1234"

    def test_set_short_api_key_fully_masked(self, runner, fake_config):
        result = runner.invoke(
            main, ["config", "set", "nvd_api_key", "abcd"],
        )
        assert result.exit_code == 0, result.output
        assert "****" in result.output

    def test_set_preserves_existing_keys(self, runner, fake_config):
        fake_config.write_text(
            json.dumps({"llm_model": "old-model", "llm_backend": "ollama"}),
        )
        import veripak.config as _cfg
        _cfg._cache = None

        result = runner.invoke(
            main, ["config", "set", "llm_model", "new-model"],
        )
        assert result.exit_code == 0, result.output
        saved = json.loads(fake_config.read_text())
        assert saved["llm_model"] == "new-model"
        assert saved["llm_backend"] == "ollama"

    @pytest.mark.parametrize("backend", ["ollama", "anthropic", "openai", "vllm"])
    def test_set_all_valid_backends(self, runner, fake_config, backend):
        result = runner.invoke(
            main, ["config", "set", "llm_backend", backend],
        )
        assert result.exit_code == 0, result.output


# -------------------------------------------------------------------
# config get
# -------------------------------------------------------------------


class TestConfigGet:
    def test_get_existing_key(self, runner, fake_config):
        fake_config.write_text(json.dumps({"llm_model": "gpt-4"}))
        import veripak.config as _cfg
        _cfg._cache = None

        result = runner.invoke(main, ["config", "get", "llm_model"])
        assert result.exit_code == 0, result.output
        assert "gpt-4" in result.output

    def test_get_missing_key_exits_1(self, runner, fake_config):
        result = runner.invoke(main, ["config", "get", "no_such_key"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_get_api_key_masked(self, runner, fake_config):
        fake_config.write_text(
            json.dumps({"anthropic_api_key": "sk-ant-secret-value"}),
        )
        import veripak.config as _cfg
        _cfg._cache = None

        result = runner.invoke(main, ["config", "get", "anthropic_api_key"])
        assert result.exit_code == 0, result.output
        assert "sk-a..." in result.output
        assert "sk-ant-secret-value" not in result.output


# -------------------------------------------------------------------
# config list
# -------------------------------------------------------------------


class TestConfigList:
    def test_list_all_keys(self, runner, fake_config):
        fake_config.write_text(json.dumps({
            "llm_backend": "ollama",
            "llm_model": "gpt-4",
        }))
        import veripak.config as _cfg
        _cfg._cache = None

        result = runner.invoke(main, ["config", "list"])
        assert result.exit_code == 0, result.output
        assert "llm_backend = ollama" in result.output
        assert "llm_model = gpt-4" in result.output

    def test_list_masks_api_keys(self, runner, fake_config):
        fake_config.write_text(json.dumps({
            "tavily_api_key": "tvly-supersecret",
            "llm_model": "gpt-4",
        }))
        import veripak.config as _cfg
        _cfg._cache = None

        result = runner.invoke(main, ["config", "list"])
        assert result.exit_code == 0, result.output
        assert "tvly..." in result.output
        assert "tvly-supersecret" not in result.output
        assert "llm_model = gpt-4" in result.output

    def test_list_empty_config(self, runner, fake_config):
        result = runner.invoke(main, ["config", "list"])
        assert result.exit_code == 0, result.output
        assert "No configuration values set." in result.output

    def test_list_sorted_output(self, runner, fake_config):
        fake_config.write_text(json.dumps({
            "llm_model": "gpt-4",
            "llm_backend": "ollama",
            "llm_base_url": "http://localhost:11434",
        }))
        import veripak.config as _cfg
        _cfg._cache = None

        result = runner.invoke(main, ["config", "list"])
        assert result.exit_code == 0, result.output
        lines = [
            ln for ln in result.output.strip().splitlines() if "=" in ln
        ]
        keys = [ln.split(" = ")[0] for ln in lines]
        assert keys == sorted(keys), (
            f"Output should be sorted by key, got: {keys}"
        )


# -------------------------------------------------------------------
# config (no subcommand) triggers interactive wizard
# -------------------------------------------------------------------


class TestConfigInteractive:
    def test_bare_config_triggers_wizard(self, runner, fake_config):
        """'veripak config' with no subcommand runs the interactive wizard."""
        result = runner.invoke(
            main, ["config"],
            input="ollama\ngpt-4\nhttp://localhost:11434\n\n\n\n",
        )
        assert result.exit_code == 0, result.output
        assert "Config saved to" in result.output
