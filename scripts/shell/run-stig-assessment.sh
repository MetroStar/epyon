#!/bin/bash

# Layer 13 - STIG Compliance Assessment Script
# Maps Epyon scan tool findings to APPSTIG (Application Security and Development STIG)
# Release 4, Version 6, Benchmark Date 01 Oct 2025
#
# Outputs (all in $SCAN_DIR/stig/):
#   stig-results.json                 Machine-readable results array (read by parsers.py)
#   {SCAN_ID}_stig-assessment.cklb    Populated STIG Viewer 3.x checklist (if template provided)
#   {SCAN_ID}_stig-results.xccdf.xml  XCCDF XML format
#   {SCAN_ID}_stig-summary.md         Markdown compliance table
#   {SCAN_ID}_stig-assessment.html    Rich standalone HTML compliance report

set -uo pipefail

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ── Help ─────────────────────────────────────────────────────────────────────
show_help() {
    echo -e "${WHITE}Layer 13 - STIG Compliance Assessment${NC}"
    echo ""
    echo "Usage: $0"
    echo ""
    echo "Environment Variables:"
    echo "  SCAN_DIR              Path to the scan output directory (required)"
    echo "  TARGET_DIR            Path to the scanned repository (required)"
    echo "  STIG_CKLB_TEMPLATE    Path to STIG Viewer 3.x .cklb template"
    echo "                        (default: TARGET_DIR/.epyon/stig-template.cklb)"
    echo "  RUN_OSCAP             Set to 'true' to run OpenSCAP if available (default: false)"
    echo ""
    echo "Output:"
    echo "  Results saved to: SCAN_DIR/stig/"
    exit 0
}

for arg in "$@"; do
    case $arg in
        -h|--help) show_help ;;
    esac
done

# ── Resolve paths ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EPYON_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_DIR="$EPYON_ROOT/configuration"

# Source scan directory template if available
if [[ -f "$SCRIPT_DIR/scan-directory-template.sh" ]]; then
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/scan-directory-template.sh"
fi

SCAN_DIR="${SCAN_DIR:-}"
TARGET_DIR="${TARGET_DIR:-}"

if [[ -z "$SCAN_DIR" ]]; then
    echo -e "${RED}[ERROR] SCAN_DIR is not set${NC}"
    exit 1
fi
if [[ -z "$TARGET_DIR" ]]; then
    echo -e "${RED}[ERROR] TARGET_DIR is not set${NC}"
    exit 1
fi

SCAN_ID="$(basename "$SCAN_DIR")"
STIG_DIR="$SCAN_DIR/stig"
mkdir -p "$STIG_DIR"

# Resolve template path
STIG_CKLB_TEMPLATE="${STIG_CKLB_TEMPLATE:-$TARGET_DIR/.epyon/stig-template.cklb}"
RUN_OSCAP="${RUN_OSCAP:-false}"

CROSSWALK_FILE="$CONFIG_DIR/stig-crosswalk.json"
FINDINGS_SUMMARY="$SCAN_DIR/security-findings-summary.json"

echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Layer 13 - STIG Compliance Assessment               ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo -e "${CYAN}Scan ID:   $SCAN_ID${NC}"
echo -e "${CYAN}STIG:      Application Security and Development STIG R4V6${NC}"
echo -e "${CYAN}Output:    $STIG_DIR${NC}"
echo ""

# ── Validate crosswalk ───────────────────────────────────────────────────────
if [[ ! -f "$CROSSWALK_FILE" ]]; then
    echo -e "${RED}[ERROR] STIG crosswalk not found: $CROSSWALK_FILE${NC}"
    exit 1
fi

# ── Check findings summary ───────────────────────────────────────────────────
if [[ ! -f "$FINDINGS_SUMMARY" ]]; then
    echo -e "${YELLOW}[WARNING] No security-findings-summary.json found at $FINDINGS_SUMMARY${NC}"
    echo -e "${YELLOW}[WARNING] Generating STIG results with Not_Reviewed for all tool-mapped controls${NC}"
    FINDINGS_SUMMARY=""
fi

# ── Check template ────────────────────────────────────────────────────────────
HAVE_TEMPLATE=false
if [[ -f "$STIG_CKLB_TEMPLATE" ]]; then
    HAVE_TEMPLATE=true
    echo -e "${GREEN}[INFO] STIG template found: $STIG_CKLB_TEMPLATE${NC}"
else
    echo -e "${YELLOW}[WARNING] STIG template not found: $STIG_CKLB_TEMPLATE${NC}"
    echo -e "${YELLOW}[WARNING] Skipping .cklb population. Copy .epyon/stig-template.cklb.example to${NC}"
    echo -e "${YELLOW}[WARNING] $TARGET_DIR/.epyon/stig-template.cklb to enable .cklb output.${NC}"
fi

echo ""

# ── Python-based assessment engine ───────────────────────────────────────────
python3 - <<PYEOF
import json, sys, os, datetime, html as html_lib

scan_id     = "${SCAN_ID}"
stig_dir    = "${STIG_DIR}"
crosswalk_f = "${CROSSWALK_FILE}"
findings_f  = "${FINDINGS_SUMMARY}"
template_f  = "${STIG_CKLB_TEMPLATE}"
have_tpl    = "${HAVE_TEMPLATE}" == "true"
ts_utc      = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
ts_date     = datetime.datetime.utcnow().strftime("%Y-%m-%d")

# ── Load crosswalk ────────────────────────────────────────────────────────
with open(crosswalk_f) as f:
    crosswalk_data = json.load(f)
crosswalk = crosswalk_data.get("controls", {})  # group_id -> control def

# ── Load findings summary ─────────────────────────────────────────────────
findings = {}   # tool_base_lower -> {ran: bool, has_findings: bool}
if findings_f and os.path.isfile(findings_f):
    with open(findings_f) as f:
        summary_doc = json.load(f)
    summary = summary_doc.get("summary", {})
    tools_analyzed = summary.get("tools_analyzed", [])
    all_findings = (
        summary_doc.get("critical_findings", []) +
        summary_doc.get("high_findings", []) +
        summary_doc.get("medium_findings", []) +
        summary_doc.get("low_findings", [])
    )
    for t in tools_analyzed:
        base = t.split("-")[0].split("_")[0].lower()
        findings[base] = {"ran": True, "has_findings": False}
    for finding in all_findings:
        base = finding.get("tool", "").split("-")[0].split("_")[0].lower()
        if base in findings:
            findings[base]["has_findings"] = True

def tool_ran(name):
    return findings.get(name.lower(), {}).get("ran", False)

def tool_has_findings(name):
    return findings.get(name.lower(), {}).get("has_findings", False)

# ── Build master rule list ────────────────────────────────────────────────
# If the template is available, iterate all its rules (all 286) so every
# control appears in the output. Crosswalk provides tool-derived status for
# the controls it covers; everything else defaults to Not_Reviewed.
if have_tpl:
    with open(template_f) as f:
        cklb_for_rules = json.load(f)
    master_rules = cklb_for_rules["stigs"][0]["rules"]
else:
    # Fallback: only the crosswalk controls
    master_rules = [
        {"group_id": gid, "rule_id": ctrl.get("rule_id",""),
         "rule_title": ctrl.get("title",""), "severity": ctrl.get("severity","medium")}
        for gid, ctrl in crosswalk.items()
    ]

# ── Evaluate each control ─────────────────────────────────────────────────
results = []
for rule in master_rules:
    group_id = rule.get("group_id", "")
    rule_id  = rule.get("rule_id", "") or rule.get("rule_id_src", "")
    # Templates have rule_title; fallback crosswalk uses title key
    title    = rule.get("rule_title") or rule.get("title") or rule.get("group_title", "")
    severity = rule.get("severity", "medium")

    # Check crosswalk for tool-mapped assessment
    ctrl     = crosswalk.get(group_id, {})
    mappings = ctrl.get("tool_mappings", [])

    final_status   = ctrl.get("default_status", "Not_Reviewed")
    final_evidence = ctrl.get("default_evidence", "")
    source_tool    = "N/A"

    for mapping in mappings:
        tool = mapping["tool"]
        if not tool_ran(tool):
            continue
        source_tool = tool
        if tool_has_findings(tool):
            final_status   = mapping.get("on_finding", "Open")
            final_evidence = mapping.get("on_finding_evidence", "")
        else:
            final_status   = mapping.get("on_clean", "NotAFinding")
            final_evidence = mapping.get("on_clean_evidence", "")
        break

    results.append({
        "group_id":     group_id,
        "rule_id":      rule_id,
        "title":        title,
        "severity":     severity,
        "status":       final_status,
        "evidence":     final_evidence,
        "source_tool":  source_tool,
        "evaluated_at": ts_utc,
    })

# ── Summary counts ─────────────────────────────────────────────────────────
counts = {"NotAFinding": 0, "Open": 0, "Not_Applicable": 0, "Not_Reviewed": 0}
for r in results:
    counts[r["status"]] = counts.get(r["status"], 0) + 1

total = len(results)
print(f"  Controls evaluated (from crosswalk): {total}")
print(f"  Not a Finding : {counts.get('NotAFinding', 0)}")
print(f"  Open          : {counts.get('Open', 0)}")
print(f"  Not Applicable: {counts.get('Not_Applicable', 0)}")
print(f"  Not Reviewed  : {counts.get('Not_Reviewed', 0)}")
print("")

# ── Output D: stig-results.json ───────────────────────────────────────────
out_json = os.path.join(stig_dir, "stig-results.json")
with open(out_json, "w") as f:
    json.dump(results, f, indent=2)
print(f"  [OK] stig-results.json")

# ── Output C: populated .cklb (STIG Viewer 3.x JSON) ─────────────────────
if have_tpl:
    # Build lookup: group_id -> result
    result_map = {r["group_id"]: r for r in results}
    
    for stig in cklb_for_rules.get("stigs", []):
        for rule in stig.get("rules", []):
            gid = rule.get("group_id", "")
            if gid in result_map:
                r = result_map[gid]
                rule["status"]          = r["status"]
                rule["finding_details"] = r["evidence"]
                rule["comments"]        = (
                    f"Auto-assessed by Epyon Layer 13 on {ts_date}. "
                    f"Source tool: {r['source_tool']}."
                )
    
    out_cklb = os.path.join(stig_dir, f"{scan_id}_stig-assessment.cklb")
    with open(out_cklb, "w") as f:
        json.dump(cklb_for_rules, f, indent=2)
    print(f"  [OK] {scan_id}_stig-assessment.cklb")

# ── Output E: Markdown summary ─────────────────────────────────────────────
sev_order = {"high": 0, "medium": 1, "low": 2}
sorted_results = sorted(results, key=lambda r: (sev_order.get(r["severity"], 9), r["group_id"]))

md_lines = [
    f"# STIG Compliance Assessment — {scan_id}",
    "",
    f"**STIG**: Application Security and Development Security Technical Implementation Guide",
    f"**Release**: 4 | **Version**: 6 | **Benchmark Date**: 01 Oct 2025",
    f"**Evaluated**: {ts_utc}",
    "",
    "## Summary",
    "",
    f"| Status | Count |",
    f"|--------|-------|",
    f"| Not a Finding | {counts.get('NotAFinding', 0)} |",
    f"| Open | {counts.get('Open', 0)} |",
    f"| Not Applicable | {counts.get('Not_Applicable', 0)} |",
    f"| Not Reviewed | {counts.get('Not_Reviewed', 0)} |",
    f"| **Total (crosswalk)** | **{total}** |",
    "",
    f"> Note: Only {total} controls are in the Epyon crosswalk. "
    f"The remaining controls default to Not_Reviewed and require manual assessment.",
    "",
    "## Control Results",
    "",
    "| # | Group ID | Rule ID | Severity | Status | Source Tool | Evidence |",
    "|---|----------|---------|----------|--------|-------------|----------|",
]
for i, r in enumerate(sorted_results, 1):
    evidence_short = r["evidence"][:120].replace("|", "\\|") + ("…" if len(r["evidence"]) > 120 else "")
    md_lines.append(
        f"| {i} | {r['group_id']} | {r['rule_id']} | {r['severity']} | "
        f"{r['status']} | {r['source_tool']} | {evidence_short} |"
    )

out_md = os.path.join(stig_dir, f"{scan_id}_stig-summary.md")
with open(out_md, "w") as f:
    f.write("\n".join(md_lines) + "\n")
print(f"  [OK] {scan_id}_stig-summary.md")

# ── Output F: XCCDF XML ───────────────────────────────────────────────────
xccdf_lines = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"',
    '           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
    '           id="Application_Security_Development_STIG_R4V6">',
    f'  <title>Application Security and Development STIG R4V6 - {scan_id}</title>',
    f'  <description>Epyon Layer 13 STIG assessment for scan {scan_id}</description>',
    f'  <TestResult id="epyon_stig_{scan_id}" start-time="{ts_utc}" end-time="{ts_utc}">',
    f'    <title>Epyon STIG Assessment - {ts_date}</title>',
    f'    <organization>Epyon Automated Assessment</organization>',
]
status_map = {
    "NotAFinding":   "pass",
    "Open":          "fail",
    "Not_Applicable": "notapplicable",
    "Not_Reviewed":  "notchecked",
}
for r in results:
    xccdf_status = status_map.get(r["status"], "unknown")
    safe_evidence = r["evidence"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    xccdf_lines += [
        f'    <rule-result idref="{r["rule_id"]}" time="{ts_utc}" severity="{r["severity"]}">',
        f'      <result>{xccdf_status}</result>',
        f'      <message severity="info">{safe_evidence}</message>',
        f'    </rule-result>',
    ]
xccdf_lines += [
    '  </TestResult>',
    '</Benchmark>',
]

out_xml = os.path.join(stig_dir, f"{scan_id}_stig-results.xccdf.xml")
with open(out_xml, "w") as f:
    f.write("\n".join(xccdf_lines) + "\n")
print(f"  [OK] {scan_id}_stig-results.xccdf.xml")

# ── Output G: HTML compliance report ─────────────────────────────────────
def sev_color(sev):
    return {"high": "#e5534b", "medium": "#d4a72c", "low": "#57ab5a"}.get(sev, "#8b949e")

def status_color(st):
    return {
        "NotAFinding":   "#57ab5a",
        "Open":          "#e5534b",
        "Not_Applicable":"#8b949e",
        "Not_Reviewed":  "#d4a72c",
    }.get(st, "#8b949e")

def status_label(st):
    return {
        "NotAFinding":   "Not a Finding",
        "Open":          "Open",
        "Not_Applicable":"Not Applicable",
        "Not_Reviewed":  "Not Reviewed",
    }.get(st, st)

h = html_lib.escape

# Build severity badge rows for summary
sev_counts = {"high": 0, "medium": 0, "low": 0}
for r in results:
    sev_counts[r["severity"]] = sev_counts.get(r["severity"], 0) + 1

rows_html = ""
for r in sorted_results:
    sc = status_color(r["status"])
    sevc = sev_color(r["severity"])
    rows_html += f"""
        <tr>
          <td><code>{h(r['group_id'])}</code></td>
          <td style="font-size:11px;color:#8b949e">{h(r['rule_id'])}</td>
          <td><span style="background:{sevc};color:#0d1117;border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700">{h(r['severity'].upper())}</span></td>
          <td><span style="background:{sc};color:#0d1117;border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700">{h(status_label(r['status']))}</span></td>
          <td style="font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{h(r['title'])}">{h(r['title'][:100])}</td>
          <td><span style="background:#21262d;color:#58a6ff;border-radius:4px;padding:1px 6px;font-size:11px">{h(r['source_tool'])}</span></td>
          <td style="font-size:11px;color:#8b949e;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{h(r['evidence'])}">{h(r['evidence'][:120])}</td>
        </tr>"""

html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>STIG Compliance Report - {h(scan_id)}</title>
<style>
  :root {{
    --bg: #0d1117; --bg-card: #161b22; --border: #30363d;
    --text: #c9d1d9; --text-dim: #8b949e;
    --clean: #57ab5a; --open: #e5534b; --na: #8b949e; --nr: #d4a72c;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; padding: 2rem; }}
  h1 {{ font-size: 1.4rem; font-weight: 600; margin-bottom: .25rem; }}
  .meta {{ color: var(--text-dim); font-size: .82rem; margin-bottom: 1.5rem; }}
  .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
  .stat-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: .75rem 1.25rem; min-width: 130px; text-align: center; }}
  .stat-card .val {{ font-size: 2rem; font-weight: 700; }}
  .stat-card .lbl {{ font-size: .75rem; color: var(--text-dim); margin-top: .15rem; }}
  .stat-card.clean .val {{ color: var(--clean); }}
  .stat-card.open  .val {{ color: var(--open); }}
  .stat-card.na    .val {{ color: var(--na); }}
  .stat-card.nr    .val {{ color: var(--nr); }}
  .section {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; }}
  .section-title {{ font-size: .75rem; font-weight: 600; text-transform: uppercase; letter-spacing: .08em; color: var(--text-dim); margin-bottom: .75rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ text-align: left; padding: .4rem .6rem; border-bottom: 1px solid var(--border); color: var(--text-dim); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; white-space: nowrap; }}
  td {{ padding: .4rem .6rem; border-bottom: 1px solid #21262d; vertical-align: middle; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1c2128; }}
  code {{ font-family: 'SFMono-Regular',Consolas,monospace; font-size: 11px; background: #21262d; padding: 1px 5px; border-radius: 4px; }}
  .badge {{ border-radius: 4px; padding: 1px 7px; font-size: 11px; font-weight: 700; display: inline-block; }}
  footer {{ color: var(--text-dim); font-size: .75rem; margin-top: 2rem; text-align: center; }}
</style>
</head>
<body>
<h1>STIG Compliance Report</h1>
<div class="meta">
  Scan: <strong>{h(scan_id)}</strong> &nbsp;|&nbsp;
  STIG: Application Security and Development R4V6 &nbsp;|&nbsp;
  Evaluated: {h(ts_utc)} &nbsp;|&nbsp;
  Generated by Epyon Layer 13
</div>

<div class="stats">
  <div class="stat-card clean"><div class="val">{counts.get('NotAFinding', 0)}</div><div class="lbl">Not a Finding</div></div>
  <div class="stat-card open"><div class="val">{counts.get('Open', 0)}</div><div class="lbl">Open</div></div>
  <div class="stat-card na"><div class="val">{counts.get('Not_Applicable', 0)}</div><div class="lbl">Not Applicable</div></div>
  <div class="stat-card nr"><div class="val">{counts.get('Not_Reviewed', 0)}</div><div class="lbl">Not Reviewed</div></div>
  <div class="stat-card"><div class="val">{total}</div><div class="lbl">Controls (Crosswalk)</div></div>
</div>

<div class="section">
  <div class="section-title">Control Results</div>
  <table>
    <thead>
      <tr>
        <th>Group ID</th>
        <th>Rule ID</th>
        <th>Severity</th>
        <th>Status</th>
        <th>Title</th>
        <th>Source Tool</th>
        <th>Evidence</th>
      </tr>
    </thead>
    <tbody>{rows_html}
    </tbody>
  </table>
</div>

<footer>
  Generated by Epyon Security Platform &mdash; Layer 13 STIG Compliance Assessment &mdash; {h(ts_utc)}
</footer>
</body>
</html>
"""

out_html = os.path.join(stig_dir, f"{scan_id}_stig-assessment.html")
with open(out_html, "w") as f:
    f.write(html_content)
print(f"  [OK] {scan_id}_stig-assessment.html")

print("")
print(f"  STIG assessment complete. Results in: {stig_dir}")
PYEOF

PYTHON_RC=$?
if [[ $PYTHON_RC -ne 0 ]]; then
    echo -e "${RED}[ERROR] STIG assessment Python engine failed (exit $PYTHON_RC)${NC}"
    exit $PYTHON_RC
fi

# ── Optional: OpenSCAP (Phase 2 opt-in) ──────────────────────────────────────
if [[ "${RUN_OSCAP:-false}" == "true" ]]; then
    SCAP_CONTENT="$TARGET_DIR/.epyon/scap-content.xml"
    if command -v oscap &>/dev/null && [[ -f "$SCAP_CONTENT" ]]; then
        echo -e "${CYAN}[INFO] Running OpenSCAP evaluation...${NC}"
        OSCAP_RESULTS="$STIG_DIR/${SCAN_ID}_oscap-results.xml"
        OSCAP_HTML="$STIG_DIR/${SCAN_ID}_oscap-report.html"
        oscap xccdf eval \
            --results "$OSCAP_RESULTS" \
            --report "$OSCAP_HTML" \
            "$SCAP_CONTENT" 2>/dev/null || true
        if [[ -f "$OSCAP_RESULTS" ]]; then
            echo -e "${GREEN}[INFO] OpenSCAP results: $OSCAP_RESULTS${NC}"
        fi
    else
        if ! command -v oscap &>/dev/null; then
            echo -e "${YELLOW}[INFO] RUN_OSCAP=true but oscap binary not found — skipping${NC}"
        elif [[ ! -f "$SCAP_CONTENT" ]]; then
            echo -e "${YELLOW}[INFO] RUN_OSCAP=true but $SCAP_CONTENT not found — skipping${NC}"
        fi
    fi
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Layer 13 - STIG Assessment Complete                 ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
