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


def test_openai_provider_client_targets_public_api_despite_env(monkeypatch, tmp_path):
    import asyncio
    import openai

    setup(monkeypatch, tmp_path, {"provider": "openai", "openai_model": "gpt-4o"})
    seen = {}

    class FakeClient:
        def __init__(self, api_key, base_url):
            seen["base_url"] = base_url
            raise RuntimeError("stop")

    monkeypatch.setattr(openai, "AsyncOpenAI", FakeClient)
    try:
        asyncio.run(o._chat_completion([{"role": "user", "content": "hi"}], max_tokens=5, temperature=0))
    except RuntimeError:
        pass
    assert seen["base_url"] == "https://api.openai.com/v1"


def test_limit_kwargs_by_model():
    assert o._limit_kwargs("gpt-5.5", 900, 0.3) == {"max_completion_tokens": 8000}
    assert o._limit_kwargs("o3-mini", 12000, 0.3) == {"max_completion_tokens": 12000}
    assert o._limit_kwargs("gpt-4o-mini", 900, 0.3) == {"max_tokens": 900, "temperature": 0.3}
    assert o._limit_kwargs("gemma4:26b", 900, 0.3) == {"max_tokens": 900, "temperature": 0.3}


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


def _load_sa():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "sa2", Path(__file__).resolve().parents[2] / "scripts/shell/run-stig-assessment.py")
    sa = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sa)
    return sa


def test_local_profile_shrinks_context(monkeypatch):
    sa = _load_sa()
    monkeypatch.delenv("EPYON_STIG_CODE_BYTES", raising=False)
    assert sa._code_bytes_default() == sa.MAX_CODE_BYTES_PER_BATCH
    sa._LOCAL_MODEL = True
    assert sa._code_bytes_default() == sa.LOCAL_CODE_BYTES_PER_BATCH
    monkeypatch.setenv("EPYON_STIG_CODE_BYTES", "12000")
    assert sa._code_bytes_default() == 12000
    assert sa.LOCAL_BATCH_SIZE_DEFAULT < sa.BATCH_SIZE_DEFAULT


def test_prompt_leads_with_controls_and_ends_with_contract():
    sa = _load_sa()
    captured = {}

    class Msg:
        content = "[]"

    class Resp:
        usage = None
        choices = [type("C", (), {"message": Msg, "finish_reason": "stop"})]

    class Client:
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    captured.update(kw)
                    return Resp

    sa._LOCAL_MODEL = True
    ctrl = [{"vuln_id": "V-1", "title": "t", "check_content": "c", "fix_text": "f"}]
    sa.call_openai(Client, "gemma", ctrl, "CODE", "MANIFEST", {}, "", "", "DOCS", "Not JSON.")
    user = captured["messages"][1]["content"]
    assert user.index("V-1") < user.index("MANIFEST") < user.index("CODE")
    assert user.rstrip().endswith("no markdown fences.")
    assert "Not JSON." in user
