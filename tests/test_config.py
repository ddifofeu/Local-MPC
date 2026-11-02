"""I3 / I5: configuration guards and secret handling."""

import json
from pathlib import Path

import pytest

import orchestrator as orch

ROOT = Path(__file__).resolve().parent.parent


def load(tmp_path, cfg):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(cfg))
    return orch.OrchestratorConfig.load(str(p))


def test_template_loads():
    cfg = orch.OrchestratorConfig.load(str(ROOT / "config.template.json"))
    assert set(cfg.local_endpoints) == {orch.ModelProvider.LOCAL_M5, orch.ModelProvider.LOCAL_M970}


def test_api_keys_in_config_refused(tmp_path):
    with pytest.raises(PermissionError):
        load(tmp_path, {"api_keys": {"anthropic": "sk-ant-x"}})


def test_plain_http_local_endpoint_refused(tmp_path):
    with pytest.raises(ValueError):
        load(tmp_path, {"local_endpoints": {"local_m5": {"base_url": "http://m5.lan:8001", "model": "m"}}})


@pytest.mark.parametrize("cfg", [
    {"privacy_keywords": {"critical": "foo"}},
    {"privacy_keywords": {"secret": ["x"]}},
    {"privacy_keywords": {"high": [""]}},
    {"limits": {"max_concurrency": 0}},
    {"limits": {"rate_per_minute": "30"}},
    {"limits": {"rate_per_min": 30}},
    {"local_endpoints": {"claude_api": {"base_url": "https://x", "model": "m"}}},
], ids=["kw_string", "kw_level", "kw_empty", "limit_zero", "limit_str", "limit_typo", "cloud_as_local"])
def test_malformed_config_refused(tmp_path, cfg):
    with pytest.raises(ValueError):
        load(tmp_path, cfg)


@pytest.fixture
def secret_dir(tmp_path, monkeypatch):
    d = tmp_path / "secrets"
    d.mkdir()
    (d / "anthropic_api_key").write_text("sk-ant-api03-FILESECRET\n")
    (d / "anthropic_api_key").chmod(0o400)
    monkeypatch.setenv("ORCH_SECRETS_DIR", str(d))
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    monkeypatch.delenv("ORCH_ALLOW_ENV_SECRETS", raising=False)
    return d


def test_world_readable_secret_refused(secret_dir):
    (secret_dir / "anthropic_api_key").chmod(0o644)
    with pytest.raises(PermissionError):
        orch.load_secret("anthropic_api_key")


def test_secret_file_loaded_and_redacted(secret_dir):
    s = orch.load_secret("anthropic_api_key")
    assert s.reveal() == "sk-ant-api03-FILESECRET"
    assert "FILESECRET" not in repr(s) + str(s)


def test_env_key_scrubbed_when_file_wins(secret_dir, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-ENV")
    assert orch.load_secret("anthropic_api_key").reveal() == "sk-ant-api03-FILESECRET"
    assert "ANTHROPIC_API_KEY" not in __import__("os").environ


def test_env_key_ignored_and_scrubbed_by_default(monkeypatch, tmp_path):
    monkeypatch.setenv("ORCH_SECRETS_DIR", str(tmp_path))
    monkeypatch.delenv("ORCH_ALLOW_ENV_SECRETS", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-ENV")
    assert orch.load_secret("anthropic_api_key") is None
    assert "ANTHROPIC_API_KEY" not in __import__("os").environ
