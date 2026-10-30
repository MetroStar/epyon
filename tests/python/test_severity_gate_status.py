"""compute_gate_status() drives the dashboard FAIL/PASS chip: FAIL on any
Critical or 5+ High findings. (check-severity-gate.sh keeps its own CI
threshold of 4.)
"""
from __future__ import annotations


def test_passes_with_no_findings(parsers):
    assert parsers.compute_gate_status(0, 0, 0, 0) == "pass"


def test_passes_with_high_findings_below_threshold(parsers):
    assert parsers.compute_gate_status(0, 1, 0, 0) == "pass"
    assert parsers.compute_gate_status(0, 4, 0, 0) == "pass"


def test_fails_when_high_findings_meet_threshold(parsers):
    assert parsers.compute_gate_status(0, 5, 0, 0) == "fail"
    assert parsers.compute_gate_status(0, 6, 0, 0) == "fail"


def test_misconfig_high_counts_toward_the_same_threshold(parsers):
    assert parsers.compute_gate_status(0, 4, 0, 1) == "fail"
    assert parsers.compute_gate_status(0, 3, 0, 1) == "pass"


def test_any_critical_finding_always_fails(parsers):
    assert parsers.compute_gate_status(1, 0, 0, 0) == "fail"


def test_any_misconfig_critical_finding_always_fails(parsers):
    # e.g. a TruffleHog secret or ClamAV malware hit — always FAIL, no threshold.
    assert parsers.compute_gate_status(0, 0, 1, 0) == "fail"


def test_custom_high_threshold_is_respected(parsers):
    assert parsers.compute_gate_status(0, 2, 0, 0, high_threshold=2) == "fail"
    assert parsers.compute_gate_status(0, 1, 0, 0, high_threshold=2) == "pass"
