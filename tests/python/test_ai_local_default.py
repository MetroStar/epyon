import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "web"))

from api import openai_summary as ai  # noqa: E402

LOCAL_MODEL = "gemma4-31b-q8-128k:2026-09-03"


def _clean(monkeypatch, cfg=None):
    monkeypatch.setattr(ai, "read_ai_config", lambda: dict(cfg or {}))
    for var in ("OPENAI_BASE_URL", "OPENAI_MODEL", "OPENAI_LOCAL_API_KEY"):
        monkeypatch.delenv(var, raising=False)


def test_defaults_to_local_endpoint_and_model(monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-secret")
    assert ai.get_base_url() == "http://localhost:11434/v1"
    assert ai.get_model() == LOCAL_MODEL
    assert ai.get_api_key() != "sk-real-secret"


def test_openai_only_when_explicitly_selected(monkeypatch):
    _clean(monkeypatch, {"provider": "openai"})
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-secret")
    assert ai.get_base_url() is None
    assert ai.get_api_key() == "sk-real-secret"


def test_explicit_base_url_still_wins(monkeypatch):
    _clean(monkeypatch, {"base_url": "http://ollama.internal:11434/v1"})
    assert ai.get_base_url() == "http://ollama.internal:11434/v1"


def _assess():
    spec = importlib.util.spec_from_file_location("assess_ai", REPO_ROOT / "scripts/shell/run-stig-assessment.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_stig_script_defaults_match_web_defaults():
    mod = _assess()
    assert mod.DEFAULT_LOCAL_BASE_URL == ai.DEFAULT_LOCAL_BASE_URL
    assert mod.DEFAULT_LOCAL_MODEL == ai.DEFAULT_LOCAL_MODEL == LOCAL_MODEL
