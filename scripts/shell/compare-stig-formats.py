#!/usr/bin/env python3
"""Compare a legacy-format and an etk-format STIG scan of the same target (MID-4537).

Usage: compare-stig-formats.py --legacy SCAN_DIR --etk SCAN_DIR [--label NAME]
Prints a markdown table of status counts and evidence quality, and the controls
whose status differs. Paste the output into the rollout ticket.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

STATUSES = ("Open", "Not a Finding", "Not Applicable", "Not Reviewed")
_CITE = re.compile(r"File:\s*\S+")


def load(scan_dir: Path) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for path in sorted(scan_dir.glob("stig-results-*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for vid, entry in (data.get("assessments", data) if isinstance(data, dict) else {}).items():
            if isinstance(entry, dict):
                merged[f"{path.stem[len('stig-results-'):]}:{vid}"] = entry
    return merged


def summarize(results: dict[str, dict[str, Any]], scan_dir: Path) -> dict[str, Any]:
    counts = {s: sum(1 for e in results.values() if e.get("status") == s) for s in STATUSES}
    evidence = [str(e.get("evidence", "")) for e in results.values()]
    n = len(results) or 1
    return {
        "total": len(results),
        "counts": counts,
        "avg_confidence": round(sum(int(e.get("confidence") or 0) for e in results.values()) / n, 1),
        "avg_evidence_chars": round(sum(len(t) for t in evidence) / n),
        "with_file_citation": sum(1 for t in evidence if _CITE.search(t)),
        "citation_failures": sum(1 for e in results.values() if e.get("citation_failures")),
        "records": sum(1 for _ in scan_dir.glob("stig-reviews-*/v-*.md")),
    }


def render(label: str, legacy: Path, etk: Path) -> str:
    lr, er = load(legacy), load(etk)
    ls, es = summarize(lr, legacy), summarize(er, etk)
    rows = [("Controls", "total")] + [(s, s) for s in STATUSES] + [
        ("Avg confidence", "avg_confidence"), ("Avg evidence length (chars)", "avg_evidence_chars"),
        ("Evidence with a File: citation", "with_file_citation"),
        ("Controls with failed citation checks", "citation_failures"), ("Review records written", "records"),
    ]

    def value(summary: dict[str, Any], key: str) -> Any:
        return summary["counts"][key] if key in STATUSES else summary[key]

    out = [f"## STIG format comparison: {label}", "", "| Metric | legacy | etk |", "|---|---|---|"]
    out += [f"| {name} | {value(ls, key)} | {value(es, key)} |" for name, key in rows]
    changed = [
        f"- {k}: {lr[k].get('status')} -> {er[k].get('status')}"
        for k in sorted(set(lr) & set(er)) if lr[k].get("status") != er[k].get("status")
    ]
    out += ["", f"Controls whose status differs: {len(changed)}"] + changed[:50]
    if len(changed) > 50:
        out.append(f"- ...and {len(changed) - 50} more")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy", required=True, type=Path)
    parser.add_argument("--etk", required=True, type=Path)
    parser.add_argument("--label", default="target")
    args = parser.parse_args(argv)
    for d in (args.legacy, args.etk):
        if not d.is_dir():
            print(f"Not a directory: {d}", file=sys.stderr)
            return 2
    print(render(args.label, args.legacy, args.etk), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
