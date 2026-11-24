"""Projects API: create, edit, delete; a repo can belong to several projects."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "web"))

from api import main as api_main  # noqa: E402
from api import projects_store  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(projects_store, "PROJECTS_FILE", tmp_path / "projects.json")
    return TestClient(api_main.app)


def _body(**over):
    body = {"name": "Customer Portal", "jira_project_key": "ato",
            "repos": [{"app": "midas", "role": "backend"}, {"app": "midas-ui", "role": "frontend"}]}
    body.update(over)
    return body


def test_create_and_list(client):
    r = client.post("/api/projects", json=_body())
    assert r.status_code == 201
    project = r.json()
    assert project["id"] == "customer-portal"
    assert project["jira_project_key"] == "ATO"
    listed = client.get("/api/projects").json()
    assert [p["id"] for p in listed["projects"]] == ["customer-portal"]
    assert "frontend" in listed["roles"]


def test_repo_can_belong_to_several_projects(client):
    client.post("/api/projects", json=_body())
    r = client.post("/api/projects", json=_body(name="Platform", repos=[{"app": "midas-ui", "role": "frontend"}]))
    assert r.status_code == 201
    assert len(client.get("/api/projects").json()["projects"]) == 2


@pytest.mark.parametrize("bad", [
    {"name": ""},
    {"jira_project_key": "1bad"},
    {"repos": [{"app": "../etc", "role": "backend"}]},
    {"repos": [{"app": "midas", "role": "wizard"}]},
    {"repos": [{"app": "midas", "role": "backend"}, {"app": "midas", "role": "frontend"}]},
])
def test_rejects_invalid_input(client, bad):
    assert client.post("/api/projects", json=_body(**bad)).status_code == 400


def test_duplicate_name_rejected(client):
    client.post("/api/projects", json=_body())
    assert client.post("/api/projects", json=_body()).status_code == 400


def test_update_and_delete(client):
    client.post("/api/projects", json=_body())
    r = client.put("/api/projects/customer-portal", json=_body(repos=[{"app": "midas", "role": "backend"}]))
    assert r.status_code == 200
    assert r.json()["repos"] == [{"app": "midas", "role": "backend"}]
    assert client.put("/api/projects/missing", json=_body()).status_code == 404
    assert client.delete("/api/projects/customer-portal").status_code == 200
    assert client.delete("/api/projects/customer-portal").status_code == 404


def _stig(slug, **statuses):
    return [{"slug": slug, "stig_name": slug, "controls": [
        {"vuln_id": v, "number": i, "severity": "high", "title": v, "status": st, "evidence": ""}
        for i, (v, st) in enumerate(statuses.items())]}]


def test_rollup_needs_every_part_satisfied():
    from api import projects_rollup as r
    comps = [
        {"app": "midas", "role": "backend", "stigs": _stig("asd", V1="Not a Finding", V2="Not a Finding", V3="Open")},
        {"app": "midas-ui", "role": "frontend", "stigs": _stig("asd", V1="Not a Finding", V2="Open", V3="Open")},
    ]
    out = {c["vuln_id"]: c for c in r.rollup(comps)[0]["controls"]}
    assert out["V1"]["status"] == "Not a Finding"
    assert out["V2"]["status"] == "Open" and "midas-ui (frontend) is Open" in out["V2"]["reason"]
    assert out["V3"]["status"] == "Open"


def test_rollup_unscanned_repo_blocks_pass_and_other_stig_is_skipped():
    from api import projects_rollup as r
    comps = [
        {"app": "midas", "role": "backend", "stigs": _stig("asd", V1="Not a Finding") + _stig("pg", P1="Not a Finding")},
        {"app": "midas-ui", "role": "frontend", "stigs": None},
    ]
    assert {c["vuln_id"]: c["status"] for c in r.rollup(comps)[0]["controls"]} == {"V1": "Not Reviewed"}
    comps[1]["stigs"] = _stig("asd", V1="Not a Finding")
    by_slug = {s["slug"]: s for s in r.rollup(comps)}
    assert by_slug["asd"]["controls"][0]["status"] == "Not a Finding"
    assert by_slug["pg"]["controls"][0]["status"] == "Not a Finding"


def test_rollup_not_applicable_only_when_all_parts_are():
    from api import projects_rollup as r
    assert r.rollup_status(["Not Applicable", "Not Applicable"]) == "Not Applicable"
    assert r.rollup_status(["Not Applicable", "Not a Finding"]) == "Not a Finding"
    assert r.rollup_status(["Not a Finding", "Not Reviewed"]) == "Not Reviewed"


def test_rollup_endpoint_without_scans_and_unknown_project(client):
    client.post("/api/projects", json={"name": "Customer Portal", "repos": [{"app": "midas", "role": "backend"}]})
    r = client.get("/api/projects/customer-portal/stig-rollup")
    assert r.status_code == 200
    assert r.json()["components"][0]["scan_id"] is None and r.json()["stigs"] == []
    assert client.get("/api/projects/nope/stig-rollup").status_code == 404


def test_policy_excludes_roles_that_are_not_required():
    from api import projects_rollup as r
    comps = [
        {"app": "midas", "role": "backend", "stigs": _stig("asd", V1="Not a Finding", V2="Not a Finding")},
        {"app": "midas-ui", "role": "frontend", "stigs": _stig("asd", V1="Open", V2="Open")},
    ]
    out = {c["vuln_id"]: c for c in r.rollup(comps, {"v1": ["backend"], "v2": ["infra"]})[0]["controls"]}
    assert out["V1"]["status"] == "Not a Finding"
    assert [p["required"] for p in out["V1"]["parts"]] == [True, False]
    assert out["V2"]["status"] == "Not Reviewed" and "required role: infra" in out["V2"]["reason"]


def test_load_policy_validates(tmp_path):
    from api import projects_rollup as r
    f = tmp_path / "p.json"
    assert r.load_policy(f) == ({}, "")
    f.write_text('{"controls": {"V-1": {"required_roles": ["Backend"]}}}')
    assert r.load_policy(f) == ({"v-1": ["backend"]}, "")
    f.write_text('{"controls": {"V-1": {"required_roles": []}}}')
    assert r.load_policy(f)[1]
    f.write_text("{not json")
    assert r.load_policy(f)[1]


def test_rollup_parts_carry_detail_and_control_text_once():
    from api import projects_rollup as r
    stig = [{"slug": "asd-v6r5", "stig_name": "ASD", "controls": [
        {"vuln_id": "APSC-DV-1", "group_id": "V-1", "rule_id": "SV-1r9_rule", "severity": "high", "title": "t",
         "status": "Open", "evidence": "e", "check_content": "check", "fix_text": "fix", "confidence": 40}]}]
    row = r.rollup([{"app": "a", "role": "backend", "scan_id": "a_1", "stigs": stig}])[0]["controls"][0]
    assert row["rule_id"] == "SV-1r9_rule" and row["check_content"] == "check" and row["fix_text"] == "fix"
    part = row["parts"][0]
    assert part["scan_id"] == "a_1" and part["detail"]["confidence"] == 40 and "check_content" not in part["detail"]


def test_release_label_uses_version_and_release_not_conventions_version():
    from api.stig_entries import _release_label
    assert _release_label("1.10.0", "u-asd-stig-v6r5-manual-xccdf") == "V6R5"
    assert _release_label("V6R5, 30 Sep 2026", "x") == "V6R5, 30 Sep 2026"
    xccdf = Path(__file__).resolve().parents[2] / "configuration" / "stigs" / "U_ASD_STIG_V6R5_Manual-xccdf.xml"
    import subprocess
    out = subprocess.run([sys.executable, str(xccdf.parents[2] / "scripts" / "shell" / "parse-stig-cklb.py"), str(xccdf)],
                         capture_output=True, text=True)
    assert '"release_info": "V6R5, 30 Sep 2026"' in out.stdout, out.stderr[-300:]
