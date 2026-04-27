#!/usr/bin/env python3
"""
parse-stig-cklb.py — Extract STIG controls from a .cklb (JSON) checklist file.

The CKLB format (Checklist Builder) stores STIG data as JSON with the structure:
  { "stigs": [{ "rules": [...] }] }

Usage:
    python3 parse-stig-cklb.py <cklb_path> [--output <output_path>]

Output:
    JSON with { "stig_name", "total_controls", "controls": [...] }
    Writes to stdout unless --output is specified.
"""

import json
import sys
import argparse
from pathlib import Path


def parse_cklb(cklb_path: str) -> dict:
    """Parse a .cklb file and return structured control data."""
    with open(cklb_path, encoding="utf-8") as f:
        data = json.load(f)

    stigs = data.get("stigs", [])
    if not stigs:
        raise ValueError(f"No STIGs found in {cklb_path}")

    stig = stigs[0]
    rules = stig.get("rules", [])
    if not rules:
        raise ValueError(f"No rules found in STIG: {stig.get('stig_name', '?')}")

    controls = []
    for i, rule in enumerate(rules, start=1):
        controls.append({
            "number":           i,
            "vuln_id":          rule.get("rule_version", ""),   # APSC-DV-XXXXXX
            "group_id":         rule.get("group_id", ""),       # V-XXXXXX
            "rule_id":          rule.get("rule_id", ""),        # SV-XXXXXXXXXX
            "severity":         rule.get("severity", ""),
            "title":            rule.get("rule_title", ""),
            "check_content":    rule.get("check_content", ""),
            "fix_text":         rule.get("fix_text", ""),
            "discussion":       rule.get("discussion", ""),
            "srg_id":           rule.get("srg_id", ""),
            "ccis":             rule.get("ccis", []),
            # Existing checklist status (not_reviewed by default in fresh checklists)
            "existing_status":  rule.get("status", "not_reviewed"),
        })

    return {
        "stig_name":      stig.get("stig_name", "Unknown STIG"),
        "display_name":   stig.get("display_name", ""),
        "stig_id":        stig.get("stig_id", ""),
        "release_info":   stig.get("release_info", ""),
        "version":        stig.get("version", ""),
        "total_controls": len(controls),
        "controls":       controls,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse a DISA STIG .cklb checklist file into structured JSON"
    )
    parser.add_argument("cklb_path", help="Path to the .cklb file")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    args = parser.parse_args()

    try:
        result = parse_cklb(args.cklb_path)
    except FileNotFoundError:
        print(f"[ERROR] CKLB file not found: {args.cklb_path}", file=sys.stderr)
        sys.exit(1)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[ERROR] Failed to parse CKLB: {e}", file=sys.stderr)
        sys.exit(1)

    output_json = json.dumps(result, indent=2)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_json, encoding="utf-8")
        print(
            f"[INFO] Parsed {result['total_controls']} controls from "
            f"'{result['stig_name']}' → {args.output}",
            file=sys.stderr,
        )
    else:
        print(output_json)


if __name__ == "__main__":
    main()
