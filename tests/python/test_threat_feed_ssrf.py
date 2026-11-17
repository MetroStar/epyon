import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "shell" / "run-model-provenance-check.py"
spec = importlib.util.spec_from_file_location("model_provenance", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com/feed.json",
    "http://127.0.0.1/feed.json",
    "http://localhost:8000/feed.json",
    "http://169.254.169.254/latest/meta-data",
    "http://10.0.0.5/feed.json",
    "https://user:pw@example.com/feed.json",
])
def test_feed_url_rejects_unsafe_targets(url):
    with pytest.raises(ValueError):
        mod.validate_feed_url(url)


def test_private_feed_allowed_only_with_opt_in(monkeypatch):
    monkeypatch.setenv("EPYON_ALLOW_PRIVATE_THREAT_FEED", "true")
    assert mod.validate_feed_url("http://10.0.0.5/feed.json")


def test_feed_url_accepts_public_literal():
    assert mod.validate_feed_url("https://8.8.8.8/feed.json") == "https://8.8.8.8/feed.json"
