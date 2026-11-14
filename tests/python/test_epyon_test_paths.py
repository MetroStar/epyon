import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "shell"))
import epyon_test_paths as tp  # noqa: E402


def test_directory_names_match_at_any_depth_only():
    for p in ("tests/a.py", "src/tests_unit/a.py", "a/__tests__/b.js", "/workspace/tests/fixtures/x", "Fixtures/x", "spec/a.rb"):
        assert tp.is_test_path(p), p
    for p in (".github/a.yml", "src/latest/a.py", "src/spectrum/a", "tests", "src/test_helper.py"):
        assert not tp.is_test_path(p), p


def test_target_itself_under_tests_is_not_excluded():
    assert not tp.is_test_path("/home/u/tests/app/src/a.py", "/home/u/tests/app")
    assert tp.is_test_path("/home/u/tests/app/tests/a.py", "/home/u/tests/app")


def test_default_rules_and_opt_out(tmp_path):
    ignore = tmp_path / ".epyon-ignore.yml"
    assert any(r["value"] == "**/fixtures/**" for r in tp.merge_default_rules([], ignore))
    ignore.write_text("include_tests: true\nignores: []\n")
    assert tp.merge_default_rules([], ignore) == []
