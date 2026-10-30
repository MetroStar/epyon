"""Contract for selecting scanner source independently of the workflow ref."""

from pathlib import Path

import pytest
import yaml


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/epyon-scan.yml"


@pytest.mark.parametrize("scanner_ref", [None, "demo/quartz-evaluator", "a" * 40])
def test_scanner_checkout_uses_explicit_ref_or_main_default(scanner_ref):
    workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
    spec = workflow["on"]["workflow_call"]["inputs"]["scanner_ref"]
    assert spec == {
        "description": "Epyon scanner branch, tag, or commit SHA (independent of the workflow ref)",
        "required": "false",
        "default": "main",
        "type": "string",
    }
    checkouts = [
        step["with"]
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if step.get("with", {}).get("repository") == "MetroStar/epyon"
    ]
    assert len(checkouts) == 1
    assert checkouts[0]["ref"] == "${{ inputs.scanner_ref }}"
    resolved = {"scanner_ref": spec["default"]}
    if scanner_ref is not None:
        resolved["scanner_ref"] = scanner_ref
    assert resolved["scanner_ref"] == ("main" if scanner_ref is None else scanner_ref)
