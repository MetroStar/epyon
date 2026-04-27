#!/usr/bin/env python3
"""
run-stig-assessment.py — AI-powered STIG compliance assessment engine.

Reads controls from a parsed CKLB JSON file, walks the target application
source tree, batches controls with relevant code context, and calls the
OpenAI API to produce per-control status + evidence assessments.

Outputs:
  {SCAN_DIR}/findings.md     — Full formatted findings report
  {SCAN_DIR}/stig-results.json — Raw JSON assessment results

Usage:
    python3 run-stig-assessment.py \\
        --cklb     <path/to/appsecdev.cklb> \\
        --target   <path/to/app/source> \\
        --scan-dir <path/to/scan/output/dir> \\
        --app-name <ApplicationName> \\
        [--model   gpt-4.1] \\
        [--batch-size 20] \\
        [--delay   1.0]

Environment:
    OPENAI_API_KEY   Required. OpenAI API key.
    OPENAI_MODEL     Optional. Overrides --model flag (default: gpt-4.1).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SOURCE_EXTENSIONS = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".java", ".rb", ".cs",
    ".sh", ".bash", ".zsh",
    ".yml", ".yaml",
    ".json", ".toml", ".cfg", ".ini",
    ".tf", ".hcl",
}

INCLUDE_FILENAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env.example", ".env.template", "Makefile", "justfile",
    "README.md", "SECURITY.md",
}

EXCLUDE_DIR_PREFIXES = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "coverage", ".coverage", ".tox", ".mypy_cache",
    ".pytest_cache", ".eggs", "*.egg-info",
}

MAX_CODE_BYTES_PER_BATCH = 55_000   # ~55 KB per API call
MAX_FILE_BYTES = 12_000             # skip very large individual files
BATCH_SIZE_DEFAULT = 20             # controls per API call

STATUS_MAP = {
    "not_reviewed":   "Not Reviewed",
    "open":           "Open",
    "not_a_finding":  "Not a Finding",
    "not_applicable": "Not Applicable",
}

FALLBACK_EVIDENCE = (
    "Control-specific implementation evidence was not demonstrably satisfied "
    "from repository artifacts alone; disposition set to Open pending "
    "system-level validation and artifact collection."
)

SYSTEM_PROMPT = """You are a DISA STIG compliance analyst conducting a static repository review \
for the Application Security and Development (AppSecDev) STIG V5R3 (286 controls).

For each control provided you will analyse the supplied source code and return a structured \
compliance assessment. You MUST respond with a valid JSON array and nothing else. \
No markdown fences, no explanation text — only the JSON array.

Each element of the array MUST have exactly these three fields:
  "vuln_id"  : the exact APSC-DV-XXXXXX identifier from the input
  "status"   : exactly one of "Open", "Not a Finding", "Not Applicable", "Not Reviewed"
  "evidence" : concise assessment text — 1-3 sentences or bullet points (prefix each bullet with "- ")

Status selection guidance:
  "Not Applicable" — The control is structurally impossible for this application type \
(e.g., SOAP/WS-Security controls for a REST-only service; session controls for a stateless \
CLI tool). State the architectural reason clearly.
  "Not a Finding"  — You can cite specific files/classes/functions that directly and \
completely satisfy the control requirement. Name the file path and code construct.
  "Open"           — The control is applicable but full compliance cannot be confirmed \
from static repository artifacts alone. May require runtime validation, IdP/infra config, \
or organisational policy artefacts.
  "Not Reviewed"   — The control can ONLY be assessed dynamically (pen test, runtime \
observation, interview) and has zero static-analysis indicators. Use sparingly.

When no relevant code is found for a control, set status to "Open" and use this exact evidence text:
"Control-specific implementation evidence was not demonstrably satisfied from repository artifacts alone; \
disposition set to Open pending system-level validation and artifact collection."

Return ONLY the JSON array."""


# ---------------------------------------------------------------------------
# CKLB parser (inline — same logic as parse-stig-cklb.py)
# ---------------------------------------------------------------------------

def parse_cklb(cklb_path: str) -> dict[str, Any]:
    with open(cklb_path, encoding="utf-8") as f:
        data = json.load(f)

    stigs = data.get("stigs", [])
    if not stigs:
        raise ValueError(f"No STIGs found in {cklb_path}")

    stig = stigs[0]
    rules = stig.get("rules", [])

    controls = []
    for i, rule in enumerate(rules, start=1):
        controls.append({
            "number":        i,
            "vuln_id":       rule.get("rule_version", ""),
            "group_id":      rule.get("group_id", ""),
            "rule_id":       rule.get("rule_id", ""),
            "severity":      rule.get("severity", ""),
            "title":         rule.get("rule_title", ""),
            "check_content": rule.get("check_content", ""),
            "fix_text":      rule.get("fix_text", ""),
        })

    return {
        "stig_name":      stig.get("stig_name", "Unknown STIG"),
        "total_controls": len(controls),
        "controls":       controls,
    }


# ---------------------------------------------------------------------------
# Source file collection
# ---------------------------------------------------------------------------

def _is_excluded_dir(dirname: str) -> bool:
    return dirname.startswith(".") and dirname not in {".github", ".env.example"} \
        or dirname in EXCLUDE_DIR_PREFIXES


def collect_source_files(target_dir: str) -> list[tuple[str, str]]:
    """Return list of (rel_path, content) for relevant source files."""
    root = Path(target_dir).resolve()
    files: list[tuple[str, str]] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue

        # Skip excluded directories anywhere in the path
        parts = path.relative_to(root).parts
        if any(_is_excluded_dir(p) for p in parts[:-1]):
            continue

        rel = str(path.relative_to(root))
        name = path.name
        ext = path.suffix.lower()

        if name not in INCLUDE_FILENAMES and ext not in SOURCE_EXTENSIONS:
            continue

        # Skip minified/lock files
        if any(pattern in name for pattern in (".min.js", ".lock", "-lock.json", ".map")):
            continue

        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            continue
        if size == 0:
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        files.append((rel, content))

    return files


def extract_keywords(check_content: str) -> list[str]:
    """Extract meaningful keywords from a STIG check_content field."""
    # Strip common boilerplate phrases and extract meaningful terms
    stopwords = {
        "the", "and", "or", "if", "is", "are", "to", "of", "in", "a", "an",
        "for", "this", "that", "it", "be", "not", "with", "on", "at", "by",
        "from", "as", "has", "have", "will", "was", "were", "all", "its",
        "when", "which", "their", "there", "than", "then", "into", "also",
        "application", "must", "should", "require", "requirement", "finding",
        "review", "verify", "ensure", "check", "configured", "provide",
    }
    words = re.findall(r"\b[a-z]{4,}\b", check_content.lower())
    return [w for w in words if w not in stopwords][:30]


def rank_files_by_relevance(
    files: list[tuple[str, str]],
    keywords: list[str],
) -> list[tuple[str, str]]:
    """Sort files by keyword hit count (descending), preserving all."""
    kw_set = set(keywords)

    def score(item: tuple[str, str]) -> int:
        rel, content = item
        lower = content.lower()
        return sum(1 for kw in kw_set if kw in lower)

    return sorted(files, key=score, reverse=True)


def build_code_context(
    files: list[tuple[str, str]],
    keywords: list[str],
    max_bytes: int = MAX_CODE_BYTES_PER_BATCH,
) -> str:
    """Select and concatenate source files up to max_bytes budget."""
    ranked = rank_files_by_relevance(files, keywords)
    parts: list[str] = []
    total = 0

    for rel, content in ranked:
        snippet = f"### FILE: {rel}\n```\n{content}\n```\n"
        snippet_bytes = len(snippet.encode())
        if total + snippet_bytes > max_bytes:
            # Try to include a truncated version for highly-ranked files
            if not parts:
                available = max_bytes - total - len(f"### FILE: {rel}\n```\n...\n```\n")
                if available > 200:
                    truncated = content.encode()[:available].decode(errors="replace")
                    parts.append(f"### FILE: {rel}\n```\n{truncated}\n... [truncated]\n```\n")
            break
        parts.append(snippet)
        total += snippet_bytes

    if not parts:
        return "(No relevant source files found for this control group)"
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# OpenAI call
# ---------------------------------------------------------------------------

def call_openai(
    client: Any,
    model: str,
    controls_batch: list[dict[str, Any]],
    code_context: str,
) -> list[dict[str, Any]]:
    """Call GPT with a batch of controls + code context, return assessed list."""
    controls_json = json.dumps(
        [
            {
                "vuln_id":       c["vuln_id"],
                "title":         c["title"],
                "check_content": c["check_content"],
            }
            for c in controls_batch
        ],
        indent=2,
    )

    user_message = (
        f"Controls to assess:\n{controls_json}\n\n"
        f"Application source code:\n{code_context}"
    )

    response = client.chat.completions.create(
        model=model,
        temperature=0.1,
        max_tokens=4096,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_message},
        ],
    )

    raw = response.choices[0].message.content.strip()

    # Strip markdown code fences if the model added them anyway
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    return json.loads(raw)


# ---------------------------------------------------------------------------
# Findings markdown renderer
# ---------------------------------------------------------------------------

def render_findings_md(
    app_name: str,
    stig_name: str,
    controls: list[dict[str, Any]],
    assessments: dict[str, dict[str, str]],
    scan_date: str,
) -> str:
    # Count statuses
    counts: dict[str, int] = {
        "Open": 0, "Not a Finding": 0, "Not Applicable": 0, "Not Reviewed": 0,
    }
    for c in controls:
        status = assessments.get(c["vuln_id"], {}).get("status", "Open")
        counts[status] = counts.get(status, 0) + 1

    lines: list[str] = []
    lines.append(f"# {app_name} STIG Findings Assessment")
    lines.append("")
    lines.append(f"Total STIGs Assessed: {len(controls)}")
    lines.append("")
    lines.append("| Status | Count |")
    lines.append("|---|---|")
    for label in ("Open", "Not a Finding", "Not Applicable", "Not Reviewed"):
        if counts.get(label, 0) > 0:
            lines.append(f"| {label} | {counts[label]} |")
    lines.append("")

    for c in controls:
        vuln_id = c["vuln_id"]
        rule_id = c["rule_id"]
        number  = c["number"]
        sev     = c["severity"]
        title   = c["title"]
        fix     = c["fix_text"].strip()

        assessed = assessments.get(vuln_id, {})
        status   = assessed.get("status",   "Open")
        evidence = assessed.get("evidence", FALLBACK_EVIDENCE).strip()

        lines.append(f"### {number}. {vuln_id} | {rule_id}")
        lines.append("")
        lines.append(f"- Rule ID: {rule_id}")
        lines.append(f"- Severity: {sev}")
        lines.append(f"- Rule Title: {title}")
        lines.append("")
        lines.append(f"Status: {status}")
        lines.append("")
        lines.append("Evidence:")
        lines.append(f"- Static repository review completed on {scan_date}.")

        # Render evidence — if it already contains bullet lines, emit as-is;
        # otherwise wrap as a single bullet point.
        for evline in evidence.splitlines():
            evline = evline.strip()
            if not evline:
                continue
            if evline.startswith("- "):
                lines.append(evline)
            else:
                lines.append(f"- {evline}")

        lines.append("")
        lines.append("Remediation:")
        lines.append(fix if fix else "N/A")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-powered STIG assessment engine (AppSecDev STIG V5R3)"
    )
    parser.add_argument("--cklb",       required=True, help="Path to .cklb checklist file")
    parser.add_argument("--target",     required=True, help="Path to application source directory")
    parser.add_argument("--scan-dir",   required=True, help="Path to scan output directory")
    parser.add_argument("--app-name",   required=True, help="Application name for report header")
    parser.add_argument("--model",      default="gpt-4.1", help="OpenAI model (default: gpt-4.1)")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE_DEFAULT,
                        help=f"Controls per API call (default: {BATCH_SIZE_DEFAULT})")
    parser.add_argument("--delay",      type=float, default=1.0,
                        help="Seconds between API calls (default: 1.0)")
    args = parser.parse_args()

    # Env var overrides
    model = os.environ.get("OPENAI_MODEL", args.model)
    api_key = os.environ.get("OPENAI_API_KEY", "")

    if not api_key:
        print(
            "[WARNING] OPENAI_API_KEY is not set — STIG assessment requires an API key. "
            "Generating report with 'Not Reviewed' status for all controls.",
            file=sys.stderr,
        )

    # ── Parse CKLB ────────────────────────────────────────────────────────
    print(f"[INFO] Parsing CKLB: {args.cklb}", file=sys.stderr)
    try:
        cklb = parse_cklb(args.cklb)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    controls = cklb["controls"]
    stig_name = cklb["stig_name"]
    print(f"[INFO] Loaded {len(controls)} controls from '{stig_name}'", file=sys.stderr)

    # ── Persist parsed controls for audit trail ────────────────────────────
    scan_dir = Path(args.scan_dir)
    scan_dir.mkdir(parents=True, exist_ok=True)
    controls_path = scan_dir / "stig-controls.json"
    controls_path.write_text(json.dumps(cklb, indent=2), encoding="utf-8")
    print(f"[INFO] Controls written to {controls_path}", file=sys.stderr)

    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # ── Collect source files ───────────────────────────────────────────────
    print(f"[INFO] Collecting source files from {args.target}", file=sys.stderr)
    source_files = collect_source_files(args.target)
    print(f"[INFO] Collected {len(source_files)} source files", file=sys.stderr)

    # ── Assess controls ────────────────────────────────────────────────────
    assessments: dict[str, dict[str, str]] = {}

    if not api_key:
        # No API key — mark everything Not Reviewed
        for c in controls:
            assessments[c["vuln_id"]] = {
                "status":   "Not Reviewed",
                "evidence": "STIG assessment skipped: OPENAI_API_KEY not configured.",
            }
    else:
        try:
            from openai import OpenAI  # type: ignore[import]
        except ImportError:
            print(
                "[ERROR] The 'openai' Python package is not installed. "
                "Run: pip install openai",
                file=sys.stderr,
            )
            sys.exit(1)

        client = OpenAI(api_key=api_key)

        batches = [
            controls[i : i + args.batch_size]
            for i in range(0, len(controls), args.batch_size)
        ]
        total_batches = len(batches)

        print(
            f"[INFO] Submitting {total_batches} batches of up to {args.batch_size} controls each "
            f"to {model}",
            file=sys.stderr,
        )

        for idx, batch in enumerate(batches, start=1):
            print(
                f"[INFO] Batch {idx}/{total_batches}: controls "
                f"{batch[0]['vuln_id']} → {batch[-1]['vuln_id']}",
                file=sys.stderr,
            )

            # Build combined keywords for this batch to find relevant files
            all_kw: list[str] = []
            for c in batch:
                all_kw.extend(extract_keywords(c["check_content"]))

            code_context = build_code_context(source_files, all_kw)

            try:
                results = call_openai(client, model, batch, code_context)
            except json.JSONDecodeError as e:
                print(f"[WARNING] Batch {idx} returned invalid JSON: {e}", file=sys.stderr)
                results = []
            except Exception as e:  # pylint: disable=broad-except
                print(f"[WARNING] Batch {idx} API error: {e}", file=sys.stderr)
                results = []

            # Merge results; fall back for any missing controls
            assessed_ids = set()
            for item in results:
                vid = item.get("vuln_id", "")
                if vid:
                    assessments[vid] = {
                        "status":   item.get("status", "Open"),
                        "evidence": item.get("evidence", FALLBACK_EVIDENCE),
                    }
                    assessed_ids.add(vid)

            for c in batch:
                if c["vuln_id"] not in assessed_ids:
                    assessments[c["vuln_id"]] = {
                        "status":   "Open",
                        "evidence": FALLBACK_EVIDENCE,
                    }

            if idx < total_batches:
                time.sleep(args.delay)

    # ── Write raw JSON results ─────────────────────────────────────────────
    results_path = scan_dir / "stig-results.json"
    results_path.write_text(json.dumps(assessments, indent=2), encoding="utf-8")
    print(f"[INFO] Raw assessment results written to {results_path}", file=sys.stderr)

    # ── Render findings.md ─────────────────────────────────────────────────
    md = render_findings_md(
        app_name=args.app_name,
        stig_name=stig_name,
        controls=controls,
        assessments=assessments,
        scan_date=scan_date,
    )

    findings_path = scan_dir / "findings.md"
    findings_path.write_text(md, encoding="utf-8")
    print(f"[INFO] Findings report written to {findings_path}", file=sys.stderr)

    # ── Print summary ──────────────────────────────────────────────────────
    counts: dict[str, int] = {}
    for v in assessments.values():
        s = v.get("status", "Open")
        counts[s] = counts.get(s, 0) + 1

    print("", file=sys.stderr)
    print("STIG Assessment Summary", file=sys.stderr)
    print("──────────────────────────────", file=sys.stderr)
    for label in ("Open", "Not a Finding", "Not Applicable", "Not Reviewed"):
        n = counts.get(label, 0)
        if n:
            print(f"  {label:<20} {n}", file=sys.stderr)
    print(f"  {'Total':<20} {len(controls)}", file=sys.stderr)
    print("", file=sys.stderr)


if __name__ == "__main__":
    main()
