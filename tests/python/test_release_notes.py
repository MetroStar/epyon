"""Release notes assembly and PR check (MID-4491)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "release_notes", REPO_ROOT / "scripts/shell/release-notes.py"
)
rn = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rn)

BODY = """## Description
stuff

## Release notes

<!-- template guidance -->

### Added
- New **thing**
- Another thing

### Fixed
* A bug

### Other
- ignored heading

## Screenshots
- not a note
"""


def test_extract_notes_reads_kinds_and_ignores_comments_and_unknown_headings():
    assert rn.extract_notes(BODY) == {
        "Added": ["New **thing**", "Another thing"],
        "Fixed": ["A bug"],
    }


def test_extract_notes_empty_for_missing_or_unfilled_block():
    assert rn.extract_notes(None) == {}
    assert rn.extract_notes("## Description\nx") == {}
    assert rn.extract_notes("## Release notes\n\n<!-- ### Added\n- x -->\n") == {}
    assert rn.extract_notes("## Release notes\n\n### Added\n\n") == {}


def test_check_pr_requires_block_or_label():
    assert rn.check_pr(BODY, []) is None
    assert rn.check_pr("nothing", ["no-release-notes"]) is None
    message = rn.check_pr("nothing", ["bug"])
    assert "Release notes" in message and "no-release-notes" in message


def test_render_body_groups_by_kind_with_pr_numbers():
    prs = [
        {"number": 7, "title": "b", "body": "## Release notes\n### Fixed\n- Fix seven"},
        {"number": 5, "title": "a", "body": BODY},
        {"number": 6, "title": "c", "body": "no block"},
    ]
    out = rn.render_body(prs, "v1.2.3", "v1.2.2")
    assert out.index("### Added") < out.index("### Fixed")
    assert "- New **thing** (#5)" in out and "- Fix seven (#7)" in out
    assert out.index("(#5)") < out.index("(#7)")
    assert "#6" not in out and "Changes since v1.2.2." in out


def test_render_body_without_notes_says_so():
    assert "No release notes were recorded for v1.0.0" in rn.render_body([], "v1.0.0", "v0.9.0")


def test_cli_check_pr_exit_codes(tmp_path, capsys):
    event = tmp_path / "e.json"
    event.write_text(json.dumps({"pull_request": {"body": "x", "labels": []}}))
    assert rn.main(["check-pr", "--event", str(event)]) == 1
    assert "::error::" in capsys.readouterr().out
    event.write_text(json.dumps({"pull_request": {"body": "x", "labels": [{"name": "no-release-notes"}]}}))
    assert rn.main(["check-pr", "--event", str(event)]) == 0


def test_cli_body_rejects_bad_tags_and_first_release(capsys, monkeypatch):
    assert rn.main(["body", "--repo", "o/r", "--tag", "main"]) == 2
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    assert rn.main(["body", "--repo", "o/r", "--tag", "v1.0.0"]) == 0
    assert "First tagged release" in capsys.readouterr().out
