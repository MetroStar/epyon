"""Settings-uploaded STIG guidance: store validation and endpoints."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "web"))

from api import main as api_main  # noqa: E402
from api import stig_policy_store as store  # noqa: E402


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(store, "ORG_RULES_FILE", tmp_path / "org-rules.md")
    return tmp_path


def test_validation_rejects_bad_text():
    for bad in ("", "   ", "a\x00b", "x" * 5000, 5):
        with pytest.raises(ValueError):
            store.validate_text(bad, 4000)


def test_reference_names_cannot_escape_the_data_dir(data_dir):
    path = store.reference_path("../../etc/passwd")
    assert path.parent == data_dir / "references"
    with pytest.raises(ValueError):
        store.reference_path("../..")


def test_scan_env_points_at_saved_files(data_dir):
    assert store.scan_env("My App") == {}
    store.save_org_rules("rule")
    store.save_reference("My App", "ref")
    env = store.scan_env("my-app")
    assert env["EPYON_STIG_POLICY_EXTRA_FILE"].endswith("org-rules.md")
    assert env["EPYON_STIG_REFERENCE_FILE"].endswith("my-app.md")
    assert "EPYON_STIG_REFERENCE_FILE" not in store.scan_env("other")


def test_endpoints_round_trip(data_dir):
    client = TestClient(api_main.app)
    assert client.post("/api/stig/policy", json={"content": "Org rule"}).status_code == 200
    assert client.get("/api/stig/policy").json()["org_rules"].strip() == "Org rule"
    assert client.post("/api/stig/policy", json={"content": "x" * 9000}).status_code == 400
    assert client.post("/api/applications/demo/stig-reference", json={"content": "ref"}).status_code == 200
    assert client.get("/api/applications/demo/stig-reference").json()["content"].strip() == "ref"
    assert client.get("/api/stig/policy").json()["references"] == ["demo"]
    assert client.delete("/api/applications/demo/stig-reference").json()["removed"] is True
    assert client.delete("/api/stig/policy").json()["org_rules"] == ""
