import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "stig_assessment", Path(__file__).resolve().parents[2] / "scripts/shell/run-stig-assessment.py")
stig = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(stig)


def test_omitted_file_list_is_capped():
    files = [(f"src/module_{i}.py", "x = 1\n" * 400) for i in range(500)]
    control = {"vuln_id": "APSC-DV-000010", "check_content": "x"}
    out = stig.build_code_context_for_batch(files, [control], max_bytes=4000)
    assert out.count("  src/module_") <= stig._MAX_OMITTED_PATHS_LISTED + 5
    assert "more" in out
    assert len(out) < 12_000

