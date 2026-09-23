"""Regression tests for the live mobile code scanner accuracy endpoint.

The Performance dashboard previously showed hardcoded F1/precision/recall
values for the mobile code scanner. This suite verifies the values are now
computed live by running the scanner against its labeled test corpus.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from web.api import main as api_main


def test_mobile_code_accuracy_computes_live_metrics():
    """The metrics should match a direct run of the validation corpus."""
    api_main._mobile_code_accuracy_cache = None
    metrics = api_main._cached_mobile_code_accuracy()

    assert metrics["total_expected_findings"] == 9
    assert metrics["true_positives"] == 9
    assert metrics["false_negatives"] == 0
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0


def test_mobile_code_accuracy_endpoint_returns_metrics():
    api_main._mobile_code_accuracy_cache = None
    client = TestClient(api_main.app)

    response = client.get("/api/metrics/mobile-code-accuracy")

    assert response.status_code == 200
    body = response.json()
    assert "f1_score" in body
    assert "precision" in body
    assert "recall" in body
    assert "true_positives" in body
    assert "false_positives" in body


def test_mobile_code_accuracy_is_cached_between_calls():
    api_main._mobile_code_accuracy_cache = None

    first = api_main._cached_mobile_code_accuracy()
    cached_ref = api_main._mobile_code_accuracy_cache
    second = api_main._cached_mobile_code_accuracy()

    assert first == second
    # Cache entry timestamp should be unchanged (no recomputation happened).
    assert api_main._mobile_code_accuracy_cache[1] == cached_ref[1]
