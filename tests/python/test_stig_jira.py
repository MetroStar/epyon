"""MID-4536: STIG gaps to Jira as one summary comment plus one ticket per real gap."""
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "shell"))
sys.path.insert(0, str(ROOT / "web"))

import stig_jira  # noqa: E402
import stig_records  # noqa: E402
from api import jira_client as real_jc  # noqa: E402


class FakeJira:
    """Stands in for api.jira_client; records calls and keeps the ticket map in memory."""

    _get_lock = staticmethod(real_jc._get_lock)
    finding_fingerprint = staticmethod(real_jc.finding_fingerprint)

    def __init__(self, tmp, project="MID", creds=True, fail=False, search=None):
        self._DATA_DIR = tmp
        self.project, self.creds, self.fail = project, creds, fail
        self.search = search or {}
        self.tmap, self.comments, self.created, self.links = {}, [], [], []

    def read_config(self, app_name=None):
        if not self.creds:
            return {}
        return {"base_url": "https://x", "email": "a@b", "api_token": "t", "project_key": self.project}

    def read_ticket_map(self):
        return dict(self.tmap)

    def write_ticket_map(self, tmap):
        self.tmap = dict(tmap)

    async def search_issue_keys(self, cfg, jql, n=5):
        for needle, keys in self.search.items():
            if needle in jql:
                return keys
        return []

    async def add_comment(self, cfg, key, text):
        if self.fail:
            raise RuntimeError("jira down")
        self.comments.append((key, text))
        return True

    async def create_ticket(self, cfg, finding, app, epic_key=None, issue_type=None, triage_note=None):
        if self.fail:
            raise RuntimeError("jira down")
        key = f"{cfg['project_key']}-{100 + len(self.created)}"
        self.created.append((key, finding["id"]))
        return key

    async def link_issues(self, cfg, a, b, t="Relates"):
        self.links.append((a, b))
        return True


def make_scan(tmp, statuses, evidence="Config reads x."):
    scan = tmp / "scan"
    scan.mkdir(exist_ok=True)
    controls = [
        {"vuln_id": f"APSC-DV-00000{i}", "group_id": f"V-{100 + i}", "title": f"Control {i}", "severity": "high"}
        for i in range(len(statuses))
    ]
    (scan / "stig-controls-app.json").write_text(json.dumps({"stig_name": "ASD", "controls": controls}))
    res = {c["vuln_id"]: {"status": s, "evidence": evidence, "confidence": 90} for c, s in zip(controls, statuses)}
    (scan / "stig-results-app.json").write_text(json.dumps({"assessments": res}))
    return scan


def target_with_index(tmp, line):
    d = tmp / "target" / "docs" / "stig-reviews"
    d.mkdir(parents=True)
    (d / "README.md").write_text(f"# STIG Review Record\n\nTracked in Jira by {line}.\n")
    return tmp / "target"


def run(jc, tmp, scan, target=None):
    return asyncio.run(stig_jira.post("myapp", target or tmp / "target", scan, jc))


def test_twenty_open_one_comment_one_ticket_each_no_dupes_on_rerun(tmp_path):
    jc = FakeJira(tmp_path)
    scan = make_scan(tmp_path, ["Open"] * 20)
    target = target_with_index(tmp_path, "MID-4000")
    first = run(jc, tmp_path, scan, target)
    assert first["status"] == "posted"
    assert len(jc.comments) == 1 and jc.comments[0][0] == "MID-4000"
    assert len(jc.created) == 20 and len(jc.links) == 20
    assert all(b == "MID-4000" for _, b in jc.links)
    run(jc, tmp_path, scan, target)
    assert len(jc.created) == 20  # fingerprint check: no duplicates


def test_index_tracker_used_without_creating_one(tmp_path, monkeypatch):
    monkeypatch.setenv("EPYON_STIG_JIRA_CREATE_TRACKER", "true")
    jc = FakeJira(tmp_path)
    scan = make_scan(tmp_path, ["Open"])
    r = run(jc, tmp_path, scan, target_with_index(tmp_path, "MID-4000"))
    assert r["tracker"] == "MID-4000" and r["tracker_source"] == "index"
    assert all(fid != "STIG review tracking" for _, fid in jc.created)


def test_tracker_from_other_project_is_never_reused(tmp_path):
    jc = FakeJira(tmp_path, project="SAP")
    scan = make_scan(tmp_path, ["Open"])
    r = run(jc, tmp_path, scan, target_with_index(tmp_path, "MID-4000"))
    assert r["status"] == "no_tracker" and jc.comments == [] and jc.created == []


def test_existing_open_tracker_found_by_search(tmp_path):
    jc = FakeJira(tmp_path, search={'labels = "stig-tracking"': ["MID-77"]})
    r = run(jc, tmp_path, make_scan(tmp_path, ["Open"]), tmp_path / "nowhere")
    assert r["tracker"] == "MID-77" and r["tracker_source"] == "existing"


def test_no_tracker_creates_only_when_opted_in(tmp_path, monkeypatch):
    jc = FakeJira(tmp_path)
    assert run(jc, tmp_path, make_scan(tmp_path, ["Open"]), tmp_path / "nowhere")["status"] == "no_tracker"
    monkeypatch.setenv("EPYON_STIG_JIRA_CREATE_TRACKER", "true")
    r = run(jc, tmp_path, make_scan(tmp_path, ["Open"]), tmp_path / "nowhere")
    assert r["tracker_source"] == "created"


def test_only_open_or_changed_posted_and_unreviewed_not_ticketed(tmp_path):
    jc = FakeJira(tmp_path)
    target = target_with_index(tmp_path, "MID-4000")
    run(jc, tmp_path, make_scan(tmp_path, ["Open", "Not a Finding", "Not Reviewed"]), target)
    assert [fid for _, fid in jc.created] == ["V-100"]
    first = jc.comments[0][1]
    assert "V-100" in first and "V-101" not in first and "V-102" not in first
    jc.comments.clear()
    run(jc, tmp_path, make_scan(tmp_path, ["Open", "Not a Finding", "Not Reviewed"]), target)
    assert "V-101" not in jc.comments[0][1]  # unchanged passing control stays out
    run(jc, tmp_path, make_scan(tmp_path, ["Open", "Not a Finding", "Not Reviewed"], "Config reads y."), target)
    assert "V-101" in jc.comments[1][1]  # evidence changed on a passing control


def test_jira_down_or_no_credentials_never_raises(tmp_path):
    scan = make_scan(tmp_path, ["Open"])
    target = target_with_index(tmp_path, "MID-4000")
    assert run(FakeJira(tmp_path, creds=False), tmp_path, scan, target)["status"] == "no_credentials"
    assert run(FakeJira(tmp_path, fail=True), tmp_path, scan, target)["status"] == "error"


def test_ticket_cap_and_comment_truncation(tmp_path, monkeypatch):
    monkeypatch.setenv("EPYON_STIG_JIRA_MAX_TICKETS", "3")
    jc = FakeJira(tmp_path)
    run(jc, tmp_path, make_scan(tmp_path, ["Open"] * 60), target_with_index(tmp_path, "MID-4000"))
    assert len(jc.created) == 3
    assert "and 20 more" in jc.comments[0][1]


def test_same_app_two_projects_kept_separate(tmp_path):
    scan = make_scan(tmp_path, ["Open"])
    a, b = FakeJira(tmp_path, project="MID"), FakeJira(tmp_path, project="SAP")
    run(a, tmp_path, scan, target_with_index(tmp_path, "MID-1"))
    shared = a.tmap
    b.tmap = dict(shared)
    (tmp_path / "target" / "docs" / "stig-reviews" / "README.md").write_text("Tracked in Jira by SAP-2.\n")
    run(b, tmp_path, scan, tmp_path / "target")
    assert len(b.created) == 1 and b.created[0][0].startswith("SAP-")


def test_tracker_key_parsing_and_publish_keeps_it(tmp_path):
    assert stig_records.tracker_key("Tracked in Jira by MID-12.", "MID") == "MID-12"
    assert stig_records.tracker_key("Tracked in Jira by MID-12.", "SAP") == ""
    assert stig_records.tracker_key("no tracking ticket yet") == ""


def test_publish_keeps_tracker_named_in_published_index(tmp_path):
    scan = tmp_path / "scan"
    controls = [{"vuln_id": "APSC-DV-000001", "group_id": "V-1", "title": "t", "severity": "high",
                 "check_content": "c", "fix_text": "f"}]
    res = {"APSC-DV-000001": {"status": "Open", "evidence": "e", "confidence": 50}}
    stig_records.write_records(scan / "stig-reviews-app", controls, res, app_name="app",
                               scan_date="2026-10-22", stig_name="ASD", release_info="r",
                               model="m", has_api_key=False)
    target = target_with_index(tmp_path, "MID-4000")
    stig_records.publish_records(scan, target)
    index = (target / "docs" / "stig-reviews" / "README.md").read_text()
    assert stig_records.tracker_key(index, "MID") == "MID-4000"


def manual(jc, scan, picks, **kw):
    cfg = {**jc.read_config(), "project_key": kw.pop("project", "SAP")}
    return asyncio.run(stig_jira.create_manual(jc, cfg, "myapp", scan, picks, **kw))


def test_manual_creates_in_chosen_board_without_tracker(tmp_path):
    jc = FakeJira(tmp_path, project="MID")
    scan = make_scan(tmp_path, ["Open", "Not a Finding"])
    r = manual(jc, scan, [("app", "APSC-DV-000000"), ("app", "APSC-DV-000001")])
    assert [k for k, _ in jc.created] == ["SAP-100", "SAP-101"]
    assert jc.links == [] and jc.comments == []
    assert r["created"][0]["issue_key"] == "SAP-100"


def test_manual_dedupes_per_board_and_links_tracker(tmp_path):
    jc = FakeJira(tmp_path)
    scan = make_scan(tmp_path, ["Open"])
    pick = [("app", "APSC-DV-000000")]
    manual(jc, scan, pick, tracker="SAP-9")
    assert jc.links == [("SAP-100", "SAP-9")]
    again = manual(jc, scan, pick)
    assert again["already_exists"] and len(jc.created) == 1
    manual(jc, scan, pick, project="IRIS")  # another board is a separate ticket
    assert len(jc.created) == 2


def test_manual_rejects_other_project_tracker_and_unknown_control(tmp_path):
    jc = FakeJira(tmp_path)
    scan = make_scan(tmp_path, ["Open"])
    try:
        manual(jc, scan, [("app", "APSC-DV-000000")], tracker="MID-1")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    r = manual(jc, scan, [("app", "NOPE")])
    assert r["ineligible"][0]["reason"] == "unknown_control" and jc.created == []
