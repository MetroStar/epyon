"""Placeholder (no-AI) STIG results must not count as a STIG run."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "web"))
from api import main  # noqa: E402


def _write(d, assessments):
    (d / "stig-results-app.json").write_text(json.dumps({"assessments": assessments}))


def test_placeholder_is_ignored(tmp_path):
    _write(tmp_path, {"V-1": {"status": "Not Reviewed",
                              "evidence": "STIG assessment skipped: OPENAI_API_KEY not configured.",
                              "confidence": 0}})
    assert main._real_stig_files(tmp_path) == []


def test_real_results_are_kept(tmp_path):
    _write(tmp_path, {"V-1": {"status": "Open", "evidence": "x", "confidence": 60}})
    assert len(main._real_stig_files(tmp_path)) == 1
