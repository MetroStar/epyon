"""Workflow inputs are data, never executable shell source."""

import re
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"


@pytest.mark.parametrize("filename", ["epyon-scan.yml", "scan-public-repo.yml"])
def test_inputs_are_not_interpolated_into_shell(filename):
    workflow = yaml.safe_load((WORKFLOWS / filename).read_text())
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            assert not re.search(r"\$\{\{\s*inputs\.", step.get("run", "")), step["name"]


def test_external_clone_treats_shell_syntax_as_url_data(tmp_path):
    workflow = yaml.safe_load((WORKFLOWS / "epyon-scan.yml").read_text())
    step = next(step for step in workflow["jobs"]["security-scan"]["steps"]
                if step["name"] == "Clone External Target Repository")
    marker = tmp_path / "injected"
    url = f'https://example.invalid/repo"; touch "{marker}"; #'
    script = 'git() { printf "%s\\n" "$@" > clone-args; mkdir -p target-repo; }\n'
    env = {"REPO_URL": url, "SUBDIR": "", "PR_NUMBER": "", "TARGET_REF": "", "SCAN_MODE": "quick"}
    result = subprocess.run(
        ["bash", "-eu", "-c", script + step["run"]],
        cwd=tmp_path, env=env, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    assert url in (tmp_path / "clone-args").read_text()


def test_self_scan_uses_the_proposed_scanner_revision():
    workflow = yaml.safe_load((WORKFLOWS / "scan-private-repo.yml").read_text())
    job = workflow["jobs"]["security-scan-pr"]
    assert job["uses"] == "./.github/workflows/epyon-scan.yml"
    assert job["with"]["scanner_ref"] == "${{ github.sha }}"
    assert job["permissions"]["id-token"] == "write"
