"""Run STIG for selected controls: carry-forward engine behaviour and the stig-run endpoint."""
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "web"))
from api import main as api_main  # noqa: E402

SLUG = "asd"
APP = "midas-ui"
CONTROLS = [
    {"number": i, "vuln_id": f"V-{i}", "group_id": f"V-{i}", "rule_id": f"SV-{i}r1", "severity": "high",
     "title": "t", "check_content": "c", "fix_text": "f"}
    for i in (1, 2, 3)
]
PREV = {
    "V-1": {"status": "Not a Finding", "evidence": "old one", "confidence": 90},
    "V-2": {"status": "Open", "evidence": "old two", "confidence": 40},
    "V-3": {"status": "Open", "evidence": "old three", "confidence": 40, "carried_forward_from": "origin_scan"},
}


def _engine():
    spec = importlib.util.spec_from_file_location("epyon_stig_rerun", ROOT / "scripts" / "shell" / "run-stig-assessment.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["epyon_stig_rerun"] = mod
    spec.loader.exec_module(mod)
    return mod


def _prev_scan(tmp_path: Path) -> Path:
    prev = tmp_path / "scans" / f"{APP}_2026-11-20_10-00-00"
    prev.mkdir(parents=True)
    (prev / f"stig-results-{SLUG}.json").write_text(json.dumps({"assessments": PREV}))
    return prev


def _run(tmp_path, monkeypatch, only, reply):
    monkeypatch.setenv("EPYON_STIG_EDITS_DIR", str(tmp_path / "edits"))
    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=lambda **kw: object()))
    mod = _engine()
    prev = _prev_scan(tmp_path)
    calls = []

    def fake_call(client, model, batch, *rest):
        calls.append([c["vuln_id"] for c in batch])
        return reply(batch), 1, 1

    monkeypatch.setattr(mod, "call_openai", fake_call)
    mod._RERUN = {"only": set(only), "carry_dir": prev, "parent": prev.name, "by": "ana"}
    scan = tmp_path / "scans" / f"{APP}_2026-11-21_10-00-00"
    scan.mkdir()
    mod._assess_stig(
        stig_data={"stig_name": "ASD", "release_info": "V6R5", "controls": CONTROLS, "source_format": "xccdf", "total_controls": 3},
        stig_path="x.xml", source_files=[], manual_docs=[], scan_dir=scan, app_name=APP, model="m", batch_size=5,
        delay=0, api_key="k", base_url="http://localhost:11434/v1", scan_date="2026-11-21", slug=SLUG,
        is_primary=True, target_dir=str(tmp_path),
    )
    out = json.loads((scan / f"stig-results-{SLUG}.json").read_text())
    return out, calls, prev


def test_only_selected_control_is_reassessed_and_others_carry_forward(tmp_path, monkeypatch):
    out, calls, prev = _run(tmp_path, monkeypatch, ["V-2"], lambda b: [
        {"vuln_id": "V-2", "status": "Not a Finding", "evidence": "fixed", "confidence": 95}])
    a = out["assessments"]
    assert calls == [["V-2"]]
    assert a["V-2"]["status"] == "Not a Finding" and a["V-2"]["reassessed"]["parent_scan_id"] == prev.name
    assert "carried_forward_from" not in a["V-2"]
    assert a["V-1"]["evidence"] == "old one" and a["V-1"]["carried_forward_from"] == prev.name
    assert a["V-3"]["carried_forward_from"] == "origin_scan"
    assert out["rerun"]["controls"] == ["V-2"] and out["rerun"]["by"] == "ana"


def test_frozen_selected_control_is_reassessed_when_explicitly_requested(tmp_path, monkeypatch):
    out, calls, _ = _run(tmp_path, monkeypatch, ["V-1"], lambda b: [
        {"vuln_id": "V-1", "status": "Open", "evidence": "regressed", "confidence": 80}])
    assert calls == [["V-1"]] and out["assessments"]["V-1"]["status"] == "Open"


def test_failed_rerun_keeps_the_earlier_result(tmp_path, monkeypatch):
    def boom(batch):
        raise ValueError("endpoint down")
    mod_exit = None
    try:
        out, _, _ = _run(tmp_path, monkeypatch, ["V-2"], boom)
    except SystemExit as exc:
        mod_exit = exc
    assert mod_exit is not None  # too many failed batches is reported as a failure
    written = next((tmp_path / "scans").glob(f"{APP}_2026-11-21*")) / f"stig-results-{SLUG}.json"
    a = json.loads(written.read_text())["assessments"]["V-2"]
    assert a["evidence"] == "old two" and a["rerun_failed"] is True


@pytest.fixture
def client(tmp_path, monkeypatch):
    for name in ("2026-11-20_10-00-00", "2026-11-22_10-00-00"):
        d = tmp_path / "scans" / f"{APP}_{name}"
        d.mkdir(parents=True)
        (d / f"stig-results-{SLUG}.json").write_text(json.dumps({"assessments": PREV}))
    monkeypatch.setattr(api_main, "EPYON_ROOT", tmp_path)
    monkeypatch.setattr(api_main, "_cached_find_scan_dirs", lambda *a, **k: sorted((tmp_path / "scans").iterdir()))
    started = []

    async def fake_job(*args):
        started.append(args)

    from api import jobs
    monkeypatch.setattr(jobs, "run_stig_rerun_job", fake_job)
    c = TestClient(api_main.app)
    c.started = started
    return c


def test_stig_run_validates_ids_and_caps_size(client):
    sid = f"{APP}_2026-11-22_10-00-00"
    assert client.post(f"/api/scans/{sid}/stig-run", json={"vuln_ids": []}).status_code == 400
    assert client.post(f"/api/scans/{sid}/stig-run", json={"vuln_ids": ["V-999"]}).status_code == 400
    assert client.post(f"/api/scans/{sid}/stig-run", json={"vuln_ids": [f"V-{i}" for i in range(51)]}).status_code == 400
    assert client.post(f"/api/scans/{sid}/stig-run", json={"vuln_ids": ["bad id;"]}).status_code == 400


def test_stig_run_offers_newer_scan_and_requires_override_for_closed_controls(client):
    old = f"{APP}_2026-11-20_10-00-00"
    r = client.post(f"/api/scans/{old}/stig-run", json={"vuln_ids": ["V-2"]})
    assert r.status_code == 409 and r.json()["code"] == "newer_scan"
    latest = f"{APP}_2026-11-22_10-00-00"
    assert r.json()["latest_scan_id"] == latest
    locked = client.post(f"/api/scans/{old}/stig-run", json={"vuln_ids": ["V-1"], "use_latest": True})
    assert locked.status_code == 409 and locked.json()["code"] == "locked_controls"
    ok = client.post(f"/api/scans/{old}/stig-run", json={"vuln_ids": ["V-1", "V-2"], "use_latest": True, "confirm_override": True})
    assert ok.status_code == 202 and ok.json()["parent_scan_id"] == latest


def test_rerun_job_creates_new_scan_with_parent_and_runs_engine_with_only(tmp_path, monkeypatch):
    import asyncio
    from api import jobs

    root = tmp_path / "root"
    (root / "scripts" / "shell").mkdir(parents=True)
    (root / "scripts" / "shell" / "run-stig-assessment.py").write_text(
        "import sys, pathlib\n"
        "a = sys.argv\n"
        "scan = pathlib.Path(a[a.index('--scan-dir') + 1])\n"
        "(scan / 'args.txt').write_text(' '.join(a))\n"
    )
    (root / "VERSION").write_text("9.9.9\n")
    target = tmp_path / "src"
    target.mkdir()
    parent = root / "scans" / f"{APP}_2026-11-20_10-00-00"
    parent.mkdir(parents=True)
    (parent / "scan-metadata.json").write_text(json.dumps({"target_name": APP, "target_directory": str(target)}))
    monkeypatch.setattr(jobs, "_ai_env", lambda env, name: env.update({"OPENAI_MODEL": "m"}))
    done = []
    monkeypatch.setattr(jobs, "_on_scan_complete_cb", lambda app, scan: done.append((app, scan)))
    job = jobs.create_job("rerun-test", APP, "stig")
    asyncio.run(jobs.run_stig_rerun_job("rerun-test", APP, parent, ["V-2"], "ana", root))
    assert job["status"] == "completed", job
    new = root / "scans" / job["scan_name"]
    meta = json.loads((new / "scan-metadata.json").read_text())
    assert meta["scan_type"] == "stig" and meta["parent_scan_id"] == parent.name
    args = (new / "args.txt").read_text()
    assert "--only V-2" in args and f"--carry-from {parent}" in args
    assert done == [(APP, job["scan_name"])]
