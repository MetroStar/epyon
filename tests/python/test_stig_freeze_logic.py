"""Unit tests for the STIG assessment freeze/stability policy.

Covers the token-efficiency fix: controls that repeatedly land on
"Open" with confidence 0 (no static evidence found — common for
runtime-only controls on apps without a traditional session/login
system) should stop being re-sent to the AI every scan once that
exact outcome has already repeated once.
"""
from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def stig_assessment():
    import importlib.util
    import sys

    path = REPO_ROOT / "scripts" / "shell" / "run-stig-assessment.py"
    spec = importlib.util.spec_from_file_location("epyon_run_stig_assessment", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["epyon_run_stig_assessment"] = module
    spec.loader.exec_module(module)
    return module


def test_no_previous_assessment_is_not_frozen(stig_assessment):
    assert stig_assessment.compute_frozen_assessment({}) is None


def test_fresh_open_zero_confidence_is_not_frozen_yet(stig_assessment):
    """First time a control lands on Open/0, it must still be re-assessed —
    the freeze only kicks in once that result has already repeated."""
    prev = {"status": "Open", "confidence": 0, "evidence": "no evidence found"}
    assert stig_assessment.compute_frozen_assessment(prev) is None


def test_repeated_open_zero_confidence_freezes(stig_assessment):
    prev = {
        "status": "Open",
        "confidence": 0,
        "evidence": "no evidence found",
        "stable_count": 1,
    }
    frozen = stig_assessment.compute_frozen_assessment(prev)
    assert frozen is not None
    assert frozen["status"] == "Open"
    assert frozen["confidence"] == 0
    assert frozen["locked_by_stability"] is True
    assert frozen["locked_by_previous"] is True
    assert frozen["stable_count"] == 1


def test_open_with_nonzero_confidence_is_not_stability_frozen(stig_assessment):
    """Only confidence-0 Open results are eligible for the stability freeze —
    a control with partial evidence (confidence > 0) should still be re-assessed."""
    prev = {"status": "Open", "confidence": 35, "stable_count": 3}
    assert stig_assessment.compute_frozen_assessment(prev) is None


def test_high_confidence_not_a_finding_is_frozen(stig_assessment):
    prev = {"status": "Not a Finding", "confidence": 90, "evidence": "satisfied"}
    frozen = stig_assessment.compute_frozen_assessment(prev)
    assert frozen is not None
    assert frozen["status"] == "Not a Finding"
    assert frozen.get("locked_by_stability", False) is False


def test_low_confidence_not_a_finding_is_reassessed(stig_assessment):
    prev = {"status": "Not a Finding", "confidence": 50, "evidence": "maybe satisfied"}
    assert stig_assessment.compute_frozen_assessment(prev) is None


def test_human_locked_control_is_always_frozen_regardless_of_status(stig_assessment):
    prev = {"status": "Open", "confidence": 10, "locked_by_human": True}
    frozen = stig_assessment.compute_frozen_assessment(prev)
    assert frozen is not None
    assert frozen["locked_by_human"] is True
