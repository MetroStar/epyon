"""Tests for the "hide tools that did not run" layers_requested plumbing:
jobs.py's mode->layer-set resolver and parsers.py's scan-metadata passthrough.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "web"))

from api import jobs  # noqa: E402
from api.parsers import load_scan  # noqa: E402


def test_quick_mode_excludes_ml_and_mode_gated_layers():
    layers = jobs._resolve_layers_requested("quick", None, run_garak=False, run_stig=False)
    assert layers == ["1", "2", "7", "8", "8.5", "8.6", "11.7", "11.8"]
    for ml_layer in ("14", "15", "18", "19", "20"):
        assert ml_layer not in layers


def test_nightly_and_full_modes_include_ml_layers_but_not_stig_or_garak():
    for mode in ("nightly", "full"):
        layers = jobs._resolve_layers_requested(mode, None, run_garak=False, run_stig=False)
        for ml_layer in ("14", "15", "18", "19"):
            assert ml_layer in layers
        assert "12" not in layers
        assert "13" not in layers
        assert "20" not in layers  # ML Runtime is always opt-in


def test_stig_mode_requests_only_layer_13():
    layers = jobs._resolve_layers_requested("stig", None, run_garak=False, run_stig=False)
    assert layers == ["13"]


def test_garak_and_stig_flags_add_their_layers_on_top_of_mode_defaults():
    layers = jobs._resolve_layers_requested("full", None, run_garak=True, run_stig=True)
    assert "12" in layers
    assert "13" in layers


def test_explicit_layer_picker_selection_overrides_mode_defaults():
    # User explicitly selected only SBOM (1) and Trivy (7) on the Run Scan page,
    # even though scan_type=full would otherwise request a much larger set.
    layers = jobs._resolve_layers_requested("full", ["1", "7"], run_garak=False, run_stig=False)
    assert layers == ["1", "7"]


def test_local_model_scan_requests_only_picklescan_and_modelcard():
    layers = jobs._resolve_layers_requested("local_model", None, run_garak=False, run_stig=False)
    assert layers == ["14", "15"]
    # Layer picker selections are ignored for local_model scans (fixed layer set).
    layers_with_picker = jobs._resolve_layers_requested(
        "local_model", ["1", "2"], run_garak=False, run_stig=False
    )
    assert layers_with_picker == ["14", "15"]


def test_load_scan_passes_through_layers_requested_from_metadata(tmp_path):
    scan_dir = tmp_path / "myapp_2026-01-01_00-00-00"
    scan_dir.mkdir()
    (scan_dir / "scan-metadata.json").write_text(json.dumps({
        "scan_type": "quick",
        "target_name": "myapp",
        "layers_requested": ["1", "2", "7", "8"],
    }))
    data = load_scan(scan_dir, REPO_ROOT)
    assert data["layers_requested"] == ["1", "2", "7", "8"]


def test_load_scan_omits_layers_requested_when_metadata_lacks_it(tmp_path):
    scan_dir = tmp_path / "myapp_2026-01-01_00-00-00"
    scan_dir.mkdir()
    (scan_dir / "scan-metadata.json").write_text(json.dumps({
        "scan_type": "full",
        "target_name": "myapp",
    }))
    data = load_scan(scan_dir, REPO_ROOT)
    assert "layers_requested" not in data
