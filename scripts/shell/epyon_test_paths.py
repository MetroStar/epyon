#!/usr/bin/env python3
"""Single source of truth for "test paths" that Epyon never counts as findings.

Anything under a tests*/, test/, __tests__/, fixtures/ or spec/ directory (at any
depth, relative to the scan target) is deliberately excluded from scans and scoring. It is
reported as suppressed ("test path"), not dropped silently. A repository opts back in with
`include_tests: true` at the top level of its `.epyon-ignore.yml`.

Readers (shell, web parsers, ML layers, Score Card) use this module so the list cannot drift.
CLI (used by shell):
  epyon_test_paths.py merge-cache <ignore-file> <cache.json>   add the default rules to a rule cache
  epyon_test_paths.py is-test <path> [<root>]                  exit 0 if the path is a test path
  epyon_test_paths.py filter-null <root>                       drop test paths from NUL-delimited stdin
"""
import fnmatch
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

TEST_DIR_GLOBS = ("tests*", "test", "__tests__", "fixtures", "spec")
REASON = "Test path (default exclusion): tests and fixtures are never scored or reported as findings."
APPROVED_BY = "epyon-default"
SUPPRESSION_LABEL = "test path"


def _normalize(path: str, root: Optional[str] = None) -> str:
    p = str(path or "").replace("\\", "/")
    if root:
        r = str(root).replace("\\", "/").rstrip("/")
        if r and p.startswith(r + "/"):
            p = p[len(r) + 1:]
    for prefix in ("/workspace/", "/github/workspace/"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def is_test_path(path: str, root: Optional[str] = None) -> bool:
    """True when a directory component of the (target-relative) path is a test directory."""
    parts = [s for s in _normalize(path, root).lower().split("/") if s]
    return any(fnmatch.fnmatch(seg, glob) for seg in parts[:-1] for glob in TEST_DIR_GLOBS)


def default_ignore_rules() -> List[Dict[str, Any]]:
    """The default exclusions as `type: path` ignore rules (glob form used by the suppression pipeline)."""
    rules = []
    for glob in TEST_DIR_GLOBS:
        for value in (f"{glob}/**", f"**/{glob}/**"):
            rules.append({
                "type": "path", "value": value, "reason": REASON, "expires": "",
                "approved_by": APPROVED_BY, "paths": [], "expired": False, "default": True,
            })
    return rules


def include_tests(ignore_file: Optional[Path]) -> bool:
    """True when the repository's .epyon-ignore.yml sets `include_tests: true`."""
    if not ignore_file or not Path(ignore_file).is_file():
        return False
    try:
        import yaml
        data = yaml.safe_load(Path(ignore_file).read_text(encoding="utf-8")) or {}
    except Exception:
        return False
    return isinstance(data, dict) and data.get("include_tests") is True


def merge_default_rules(rules: List[Dict[str, Any]], ignore_file: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Rules plus the default test-path rules (unless the repository opted in to scanning tests)."""
    if include_tests(ignore_file):
        return list(rules)
    have = {(str(r.get("type", "")).lower(), str(r.get("value", "")).lower()) for r in rules}
    return list(rules) + [r for r in default_ignore_rules() if ("path", r["value"].lower()) not in have]


def _merge_cache(ignore_file: str, cache: str) -> None:
    cache_path = Path(cache)
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception:
        data = {"ignores": []}
    data["include_tests"] = include_tests(Path(ignore_file))  # recorded so readers of the snapshot honour the opt-in
    data["ignores"] = merge_default_rules(data.get("ignores", []), Path(ignore_file))
    cache_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "merge-cache":
        _merge_cache(sys.argv[2], sys.argv[3])
    elif len(sys.argv) >= 3 and sys.argv[1] == "filter-null":
        keep_tests = include_tests(Path(sys.argv[2]) / ".epyon-ignore.yml")
        for item in sys.stdin.buffer.read().split(b"\0"):
            path = item.decode("utf-8", "surrogateescape")
            if path and (keep_tests or not is_test_path(path, sys.argv[2])):
                sys.stdout.buffer.write(path.encode("utf-8", "surrogateescape") + b"\0")
    elif len(sys.argv) >= 3 and sys.argv[1] == "is-test":
        sys.exit(0 if is_test_path(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None) else 1)
    else:
        print(__doc__)
        sys.exit(2)
