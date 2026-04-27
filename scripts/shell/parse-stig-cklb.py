#!/usr/bin/env python3
"""
parse-stig-cklb.py — Extract STIG controls from a STIG source file.

Supports two formats:
  .cklb  — Checklist Builder JSON  { "stigs": [{ "rules": [...] }] }
  .xml   — XCCDF 1.1 XML           <Benchmark><Group><Rule>...

Usage:
    python3 parse-stig-cklb.py <stig_file> [--output <output_path>]

Output:
    JSON with { "stig_name", "release_info", "total_controls", "controls": [...] }
    Writes to stdout unless --output is specified.

Adding a new STIG:
    Place a .cklb or XCCDF .xml file in configuration/stigs/ and the pipeline
    will automatically pick it up on the next nightly/stig scan.
"""

import json
import re
import sys
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.1"


# ---------------------------------------------------------------------------
# CKLB (JSON) parser
# ---------------------------------------------------------------------------

def _parse_cklb_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    stigs = data.get("stigs", [])
    if not stigs:
        raise ValueError(f"No STIGs found in {path}")

    stig = stigs[0]
    rules = stig.get("rules", [])
    if not rules:
        raise ValueError(f"No rules found in STIG: {stig.get('stig_name', '?')}")

    controls = []
    for i, rule in enumerate(rules, start=1):
        controls.append({
            "number":          i,
            "vuln_id":         rule.get("rule_version", ""),
            "group_id":        rule.get("group_id", ""),
            "rule_id":         rule.get("rule_id", ""),
            "severity":        rule.get("severity", ""),
            "title":           rule.get("rule_title", ""),
            "check_content":   rule.get("check_content", ""),
            "fix_text":        rule.get("fix_text", ""),
            "discussion":      rule.get("discussion", ""),
            "srg_id":          rule.get("srg_id", ""),
            "ccis":            rule.get("ccis", []),
            "existing_status": rule.get("status", "not_reviewed"),
        })

    return {
        "stig_name":      stig.get("stig_name", "Unknown STIG"),
        "display_name":   stig.get("display_name", ""),
        "stig_id":        stig.get("stig_id", ""),
        "release_info":   stig.get("release_info", ""),
        "version":        stig.get("version", ""),
        "source_file":    str(path),
        "source_format":  "cklb",
        "total_controls": len(controls),
        "controls":       controls,
    }


# ---------------------------------------------------------------------------
# XCCDF (XML) parser
# ---------------------------------------------------------------------------

def _xccdf_text(element, tag: str, ns: str = XCCDF_NS) -> str:
    """Return stripped text of the first matching child element, or ''."""
    child = element.find(f"{{{ns}}}{tag}")
    return (child.text or "").strip() if child is not None else ""


def _strip_xccdf_description(raw: str) -> str:
    """Strip XCCDF embedded XML tags from a description field."""
    return re.sub(r"<[^>]+>", " ", raw).strip()


def _parse_xccdf_xml(path: str) -> dict:
    tree = ET.parse(path)
    root = tree.getroot()

    ns = XCCDF_NS
    # Benchmark-level metadata
    stig_name = _xccdf_text(root, "title")
    release_info = ""
    for pt in root.findall(f"{{{ns}}}plain-text"):
        if pt.text:
            release_info = pt.text.strip()

    groups = root.findall(f"{{{ns}}}Group")
    if not groups:
        raise ValueError(f"No XCCDF Groups found in {path}")

    controls = []
    for i, group in enumerate(groups, start=1):
        group_id = group.get("id", "")
        rule_el = group.find(f"{{{ns}}}Rule")
        if rule_el is None:
            continue

        # Strip trailing "_rule" suffix from rule id to match CKLB convention
        raw_rule_id = rule_el.get("id", "")
        rule_id = raw_rule_id.removesuffix("_rule") if raw_rule_id.endswith("_rule") else raw_rule_id

        severity    = rule_el.get("severity", "")
        vuln_id     = _xccdf_text(rule_el, "version")       # APSC-DV-XXXXXX
        title       = _xccdf_text(rule_el, "title")
        fix_text    = _xccdf_text(rule_el, "fixtext")

        # discussion lives inside <description> wrapped in <VulnDiscussion> tags
        raw_desc = _xccdf_text(rule_el, "description")
        disc_match = re.search(r"<VulnDiscussion>(.*?)</VulnDiscussion>", raw_desc, re.DOTALL)
        discussion = disc_match.group(1).strip() if disc_match else _strip_xccdf_description(raw_desc)

        # check-content
        check_el = rule_el.find(f"{{{ns}}}check")
        check_content = ""
        if check_el is not None:
            cc_el = check_el.find(f"{{{ns}}}check-content")
            check_content = (cc_el.text or "").strip() if cc_el is not None else ""

        # CCIs from <ident> elements
        ccis = [
            ident.text for ident in rule_el.findall(f"{{{ns}}}ident")
            if ident.text and ident.text.startswith("CCI-")
        ]

        # SRG from the parent Group title
        srg_id = _xccdf_text(group, "title")

        controls.append({
            "number":          i,
            "vuln_id":         vuln_id,
            "group_id":        group_id,
            "rule_id":         rule_id,
            "severity":        severity,
            "title":           title,
            "check_content":   check_content,
            "fix_text":        fix_text,
            "discussion":      discussion,
            "srg_id":          srg_id,
            "ccis":            ccis,
            "existing_status": "not_reviewed",
        })

    return {
        "stig_name":      stig_name,
        "display_name":   stig_name,
        "stig_id":        Path(path).stem,
        "release_info":   release_info,
        "version":        release_info,
        "source_file":    str(path),
        "source_format":  "xccdf",
        "total_controls": len(controls),
        "controls":       controls,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_stig(path: str) -> dict:
    """Auto-detect format (.cklb JSON or XCCDF XML) and parse a STIG file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"STIG file not found: {path}")

    suffix = p.suffix.lower()

    if suffix == ".cklb":
        return _parse_cklb_json(path)

    if suffix == ".xml":
        return _parse_xccdf_xml(path)

    # Try JSON first, fall back to XML
    try:
        return _parse_cklb_json(path)
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        return _parse_xccdf_xml(path)
    except ET.ParseError as e:
        raise ValueError(f"Could not parse {path} as CKLB JSON or XCCDF XML: {e}") from e


# Keep old name for backward compatibility with any direct callers
parse_cklb = parse_stig


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse a DISA STIG file (.cklb JSON or XCCDF XML) into structured JSON"
    )
    parser.add_argument("stig_path", help="Path to the STIG file (.cklb or XCCDF .xml)")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    args = parser.parse_args()

    try:
        result = parse_stig(args.stig_path)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[ERROR] Failed to parse STIG file: {e}", file=sys.stderr)
        sys.exit(1)

    output_json = json.dumps(result, indent=2)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_json, encoding="utf-8")
        print(
            f"[INFO] Parsed {result['total_controls']} controls from "
            f"'{result['stig_name']}' [{result['source_format'].upper()}] → {args.output}",
            file=sys.stderr,
        )
    else:
        print(output_json)


if __name__ == "__main__":
    main()
