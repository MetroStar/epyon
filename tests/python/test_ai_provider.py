"""AI provider switch: openai / local / auto."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "web"))
from api import openai_summary as o  # noqa: E402


def setup(monkeypatch, tmp_path, cfg):
    monkeypatch.setattr(o, "AI_CONFIG_FILE", tmp_path / "ai.json")
    o.write_ai_config(cfg)
    monkeypatch.setenv("OPENAI_BASE_URL", "http://172.16.0.5:11435/v1")
    monkeypatch.setenv("OPENAI_MODEL", "gemma-local")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real")


def test_openai_provider_ignores_local_env(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path, {"provider": "openai", "openai_model": "gpt-4o"})
    assert o.get_base_url() is None
    assert o.get_model() == "gpt-4o"
    assert o.get_api_key() == "sk-real"


def test_local_provider_never_sends_real_key(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path, {"provider": "local"})
    assert o.get_base_url() == "http://172.16.0.5:11435/v1"
    assert o.get_model() == "gemma-local"
    assert o.get_api_key() != "sk-real"


def test_auto_keeps_existing_precedence(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path, {})
    assert o.get_provider() == "auto"
    assert o.get_model() == "gemma-local"
    assert o.get_api_key() == "sk-real"


def test_completion_kwargs_by_model():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "sa", Path(__file__).resolve().parents[2] / "scripts/shell/run-stig-assessment.py")
    sa = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sa)
    gpt5 = sa._completion_kwargs("gpt-5.5", 300)
    assert "max_tokens" not in gpt5 and "temperature" not in gpt5
    assert gpt5["max_completion_tokens"] >= 8000
    legacy = sa._completion_kwargs("gpt-4o-mini", 300, 7)
    assert legacy["max_tokens"] == 300 and legacy["temperature"] == 0 and legacy["seed"] == 7
    assert "max_completion_tokens" not in sa._completion_kwargs("gemma4-31b", 300)
