import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest


SCRIPTS = Path(__file__).resolve().parents[2] / "scripts/shell"
spec = importlib.util.spec_from_file_location("scan_cache", SCRIPTS / "scan_cache.py")
cache_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache_module)
sys.modules["scan_cache"] = cache_module


def test_cache_ttl_corruption_capacity_and_identity(tmp_path, capsys):
    cache = cache_module.JsonCache(tmp_path, ttl=30, max_entries=2)
    cache.put("a", {"id": "a"})
    assert cache.get("a") == {"id": "a"}
    assert cache.get("b") is None
    with patch.object(cache_module.time, "time", return_value=time.time() + 31):
        assert cache.get("a") is None
    cache.put("b", {})
    cache.put("c", {})
    assert len(list(tmp_path.glob("*.json"))) == 2
    path = tmp_path / (cache_module.fingerprint("b") + ".json")
    path.write_text("invalid")
    assert cache.get("b") is None
    assert "invalid scan cache" in capsys.readouterr().err


def test_global_rate_limit_serializes_processes(tmp_path):
    script = """
import sys, time
from scan_cache import nvd_request_slot
with nvd_request_slot(sys.argv[1], 0.1):
    print(time.time(), flush=True)
    time.sleep(0.02)
"""
    env = dict(os.environ, PYTHONPATH=str(SCRIPTS))
    processes = [
        subprocess.Popen([sys.executable, "-c", script, str(tmp_path)], env=env, stdout=subprocess.PIPE, text=True)
        for _ in range(3)
    ]
    starts = sorted(float(process.communicate(timeout=10)[0]) for process in processes)
    assert all(process.returncode == 0 for process in processes)
    assert all(right - left >= 0.10 for left, right in zip(starts, starts[1:]))


def run_enrichment(scan, cache_dir, response, key=""):
    source = (SCRIPTS / "enrich-findings.sh").read_text().split("<<'PYEOF'\n", 1)[1].split("\nPYEOF", 1)[0]
    kev = scan / "kev.json"
    kev.write_text('{"vulnerabilities":[]}')
    calls = []

    class Response:
        def __enter__(self):
            import io
            return io.StringIO(json.dumps(response))

        def __exit__(self, *args):
            pass

    def request(req, **kwargs):
        calls.append(req)
        return Response()

    with (
        patch.dict(os.environ, {"EPYON_CACHE_DIR": str(cache_dir), "NVD_API_KEY": key}),
        patch.object(sys, "argv", ["enrich", str(scan / "security-findings-summary.json"), str(kev)]),
        patch("urllib.request.urlopen", side_effect=request),
        patch.object(cache_module.time, "sleep"),
    ):
        exec(compile(source, "enrich-findings.sh", "exec"), {})
    return calls


def test_nvd_warm_cache_has_zero_requests_and_retains_findings(tmp_path):
    scan = tmp_path / "scan"
    scan.mkdir()
    findings = {"critical_findings": [{"vulnerability_id": "CVE-2026-1234", "evidence": "unchanged"}]}
    report = scan / "security-findings-summary.json"
    report.write_text(json.dumps(findings))
    response = {"vulnerabilities": [{"cve": {"id": "CVE-2026-1234", "published": "2026-01-01"}}]}
    calls = run_enrichment(scan, tmp_path / "cache", response, "test-secret")
    assert len(calls) == 1
    assert calls[0].get_header("Apikey") == "test-secret"
    first = json.loads(report.read_text())
    report.write_text(json.dumps(findings))
    assert run_enrichment(scan, tmp_path / "cache", response) == []
    second = json.loads(report.read_text())
    assert first["critical_findings"] == second["critical_findings"]
    assert second["enrichment"]["nvd_cache_hits"] == 1
    assert second["enrichment"]["nvd_cache_misses"] == 0
    assert "test-secret" not in "".join(path.read_text() for path in (tmp_path / "cache").rglob("*.json"))


def test_nvd_empty_response_is_not_cached(tmp_path):
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "security-findings-summary.json").write_text(json.dumps({
        "high_findings": [{"id": "CVE-2026-1234"}],
    }))
    assert len(run_enrichment(scan, tmp_path / "cache", {"vulnerabilities": []})) == 1
    assert len(run_enrichment(scan, tmp_path / "cache", {"vulnerabilities": []})) == 1


@pytest.fixture
def assessor(monkeypatch):
    spec = importlib.util.spec_from_file_location("performance_assessor", SCRIPTS / "run-stig-assessment.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("EPYON_STIG_FORMAT", "legacy")
    monkeypatch.setenv("EPYON_REQUIRE_COMPLETE", "true")
    monkeypatch.setenv("EPYON_STIG_MODEL_REVISION", "a" * 64)
    monkeypatch.setenv("EPYON_STIG_CONCURRENCY", "2")
    return module


def repository(root):
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "auth.java").write_text("requireAuthentication();")
    subprocess.run(["git", "-C", str(root), "add", "auth.java"], check=True)
    return root


def test_stig_identity_invalidates_source_model_and_context(tmp_path, monkeypatch, assessor):
    root = repository(tmp_path / "repo")
    inputs = {"model": "local:1", "stig": {"version": 1}, "findings": "none"}
    key = assessor._stig_reuse_key(str(root), inputs)
    assert key and assessor._stig_reuse_key(str(root), inputs) == key
    for changed in [
        {**inputs, "model": "local:2"},
        {**inputs, "stig": {"version": 2}},
        {**inputs, "findings": "new vulnerability"},
    ]:
        assert assessor._stig_reuse_key(str(root), changed) != key
    monkeypatch.setenv("EPYON_STIG_MODEL_REVISION", "b" * 64)
    assert assessor._stig_reuse_key(str(root), inputs) != key
    monkeypatch.setenv("EPYON_STIG_MODEL_REVISION", "a" * 64)
    (root / "auth.java").write_text("allowAll();")
    assert assessor._stig_reuse_key(str(root), inputs) != key
    (root / "auth.java").write_text("requireAuthentication();")
    (root / "new.conf").write_text("auth=false")
    assert assessor._stig_reuse_key(str(root), inputs) != key
    monkeypatch.delenv("EPYON_STIG_MODEL_REVISION")
    assert assessor._stig_reuse_key(str(root), inputs) is None


def assess_fixture(assessor, root, scan):
    scan.mkdir()
    controls = [
        {"vuln_id": f"V-{i}", "number": i, "title": "Require authentication",
         "severity": "medium", "check_content": "Review auth.java", "fix_text": "Require auth",
         "rule_id": f"SV-{i}", "group_id": f"V-{i}"}
        for i in range(1, 13)
    ]
    assessor._assess_stig(
        stig_data={"controls": controls, "stig_name": "ASD"},
        stig_path="asd.xml", source_files=[("auth.java", (root / "auth.java").read_text())],
        manual_docs=[], scan_dir=scan, app_name="fixture", model="local:1",
        batch_size=3, delay=0, api_key="local", base_url="http://localhost:11434/v1",
        scan_date="2026-10-31", slug="asd", is_primary=True, target_dir=str(root),
    )
    return json.loads((scan / "stig-results-asd.json").read_text())


def fake_client(monkeypatch, assessor):
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=lambda **kwargs: object()))
    monkeypatch.setattr(assessor, "check_stig_applicability", lambda *args: (True, "Applicable", 0, 0))


def test_parallel_assessment_complete_and_exact_warm_reuse(tmp_path, monkeypatch, assessor):
    root = repository(tmp_path / "repo")
    monkeypatch.setenv("EPYON_CACHE_DIR", str(tmp_path / "cache"))
    fake_client(monkeypatch, assessor)
    lock = threading.Lock()
    state = {"active": 0, "maximum": 0, "calls": 0}

    def call(client, model, batch, *args):
        with lock:
            state["active"] += 1
            state["maximum"] = max(state["maximum"], state["active"])
            state["calls"] += 1
        time.sleep(0.03)
        with lock:
            state["active"] -= 1
        return [
            {"vuln_id": control["vuln_id"], "status": "Open",
             "confidence": 90, "evidence": "auth.java reviewed"}
            for control in batch
        ], 100, 50

    monkeypatch.setattr(assessor, "call_openai", call)
    cold = assess_fixture(assessor, root, tmp_path / "cold")
    assert cold["assessment_complete"] and not cold["failed_batches"]
    assert len(cold["assessments"]) == 12 and state["maximum"] == 2 and state["calls"] == 4
    warm = assess_fixture(assessor, root, tmp_path / "warm")
    assert warm["reused"] and state["calls"] == 4
    assert warm["assessments"] == cold["assessments"]
    assert warm["token_usage"]["total_tokens"] == 0
    entry = next((tmp_path / "cache/stig").glob("*.json"))
    cached = json.loads(entry.read_text())
    cached["created"] -= 86401
    entry.write_text(json.dumps(cached))
    expired = assess_fixture(assessor, root, tmp_path / "expired")
    assert not expired["reused"] and state["calls"] == 8
    (root / "auth.java").write_text("allowAll();")
    changed = assess_fixture(assessor, root, tmp_path / "changed")
    assert not changed["reused"] and state["calls"] == 12


def test_parallel_failures_are_not_cached_or_marked_complete(tmp_path, monkeypatch, assessor):
    root = repository(tmp_path / "repo")
    monkeypatch.setenv("EPYON_CACHE_DIR", str(tmp_path / "cache"))
    fake_client(monkeypatch, assessor)
    calls = []

    def invalid(*args):
        calls.append(1)
        raise ValueError("Missing or duplicate controls")

    monkeypatch.setattr(assessor, "call_openai", invalid)
    scan = tmp_path / "failed"
    with pytest.raises(SystemExit, match="incomplete"):
        assess_fixture(assessor, root, scan)
    result = json.loads((scan / "stig-results-asd.json").read_text())
    assert not result["assessment_complete"]
    assert result["failed_batches"] == [1, 2, 3, 4]
    assert len(result["assessments"]) == 12 and len(calls) == 12
    assert not list((tmp_path / "cache" / "stig").glob("*.json"))


def test_incomplete_cached_control_set_is_rejected(tmp_path, monkeypatch, assessor):
    root = repository(tmp_path / "repo")
    monkeypatch.setenv("EPYON_CACHE_DIR", str(tmp_path / "cache"))
    fake_client(monkeypatch, assessor)
    monkeypatch.setattr(assessor, "call_openai", lambda client, model, batch, *args: ([
        {"vuln_id": c["vuln_id"], "status": "Open", "confidence": 90, "evidence": "auth.java"}
        for c in batch
    ], 1, 1))
    assess_fixture(assessor, root, tmp_path / "first")
    cache_file = next((tmp_path / "cache/stig").glob("*.json"))
    cached = json.loads(cache_file.read_text())
    del cached["data"]["assessments"]["V-1"]
    cache_file.write_text(json.dumps(cached))
    result = assess_fixture(assessor, root, tmp_path / "second")
    assert not result["reused"] and len(result["assessments"]) == 12
