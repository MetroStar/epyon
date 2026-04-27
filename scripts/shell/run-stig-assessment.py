#!/usr/bin/env python3
"""
run-stig-assessment.py — AI-powered STIG compliance assessment engine.

Reads controls from one or more STIG source files (.cklb JSON or XCCDF XML),
walks the target application source tree, batches controls with relevant
code context, and calls the OpenAI API to produce per-control assessments.

Outputs (per STIG):
  {SCAN_DIR}/findings.md              — Primary findings report (first/only STIG)
  {SCAN_DIR}/findings-{slug}.md       — Per-STIG report when multiple STIGs present
  {SCAN_DIR}/stig-controls-{slug}.json
  {SCAN_DIR}/stig-results-{slug}.json

Usage:
    # Single STIG file (.cklb or XCCDF .xml):
    python3 run-stig-assessment.py \\
        --cklb     <path/to/appsecdev.cklb|xccdf.xml> \\
        --target   <path/to/app/source> \\
        --scan-dir <path/to/scan/output/dir> \\
        --app-name <ApplicationName>

    # Directory of STIG files (processes all .cklb and .xml files):
    python3 run-stig-assessment.py \\
        --stigs-dir configuration/stigs \\
        --target    <path/to/app/source> \\
        --scan-dir  <path/to/scan/output/dir> \\
        --app-name  <ApplicationName>

Environment:
    OPENAI_API_KEY   Required. OpenAI API key.
    OPENAI_MODEL     Optional. Overrides --model flag (default: gpt-4.1).

Adding a new STIG:
    Drop any .cklb or XCCDF .xml file into configuration/stigs/ — it will be
    picked up automatically on the next nightly/stig scan run.
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
# STIG parser — delegates to parse-stig-cklb.py (supports .cklb and XCCDF)
# ---------------------------------------------------------------------------

def _load_parser() -> Any:
    """Import parse_stig from sibling parse-stig-cklb.py."""
    import importlib.util
    script_dir = Path(__file__).parent
    spec = importlib.util.spec_from_file_location(
        "parse_stig_cklb", script_dir / "parse-stig-cklb.py"
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def parse_stig_file(path: str) -> dict[str, Any]:
    """Parse any supported STIG file (.cklb or XCCDF .xml)."""
    mod = _load_parser()
    return mod.parse_stig(path)


def slug_from_stig(stig: dict[str, Any], path: str) -> str:
    """Derive a filesystem-safe slug from a STIG dict."""
    name = Path(path).stem
    # Normalise to lowercase alphanumeric + hyphens
    import re as _re
    return _re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


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

def _assess_stig(
    stig_data: dict[str, Any],
    stig_path: str,
    source_files: list[tuple[str, str]],
    scan_dir: Path,
    app_name: str,
    model: str,
    batch_size: int,
    delay: float,
    api_key: str,
    scan_date: str,
    slug: str,
    is_primary: bool,
) -> None:
    """Run assessment for a single STIG and write output files."""
    controls  = stig_data["controls"]
    stig_name = stig_data["stig_name"]

    print(f"[INFO] [{slug}] Loaded {len(controls)} controls from '{stig_name}'", file=sys.stderr)

    # Persist parsed controls
    controls_path = scan_dir / f"stig-controls-{slug}.json"
    controls_path.write_text(json.dumps(stig_data, indent=2), encoding="utf-8")
    print(f"[INFO] [{slug}] Controls written to {controls_path}", file=sys.stderr)

    assessments: dict[str, dict[str, str]] = {}

    if not api_key:
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
                "[ERROR] The 'openai' Python package is not installed. Run: pip install openai",
                file=sys.stderr,
            )
            sys.exit(1)

        client = OpenAI(api_key=api_key)
        batches = [controls[i : i + batch_size] for i in range(0, len(controls), batch_size)]
        total_batches = len(batches)

        print(
            f"[INFO] [{slug}] Submitting {total_batches} batches of up to {batch_size} controls "
            f"to {model}",
            file=sys.stderr,
        )

        for idx, batch in enumerate(batches, start=1):
            print(
                f"[INFO] [{slug}] Batch {idx}/{total_batches}: "
                f"{batch[0]['vuln_id']} → {batch[-1]['vuln_id']}",
                file=sys.stderr,
            )

            all_kw: list[str] = []
            for c in batch:
                all_kw.extend(extract_keywords(c["check_content"]))
            code_context = build_code_context(source_files, all_kw)

            try:
                results = call_openai(client, model, batch, code_context)
            except json.JSONDecodeError as e:
                print(f"[WARNING] [{slug}] Batch {idx} returned invalid JSON: {e}", file=sys.stderr)
                results = []
            except Exception as e:  # pylint: disable=broad-except
                print(f"[WARNING] [{slug}] Batch {idx} API error: {e}", file=sys.stderr)
                results = []

            assessed_ids: set[str] = set()
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
                    assessments[c["vuln_id"]] = {"status": "Open", "evidence": FALLBACK_EVIDENCE}

            if idx < total_batches:
                time.sleep(delay)

    # Write raw results
    results_path = scan_dir / f"stig-results-{slug}.json"
    results_path.write_text(json.dumps(assessments, indent=2), encoding="utf-8")
    print(f"[INFO] [{slug}] Raw results written to {results_path}", file=sys.stderr)

    # Render findings markdown
    md = render_findings_md(
        app_name=app_name,
        stig_name=stig_name,
        controls=controls,
        assessments=assessments,
        scan_date=scan_date,
    )

    # Named file always written; also write findings.md for the primary STIG
    named_path = scan_dir / f"findings-{slug}.md"
    named_path.write_text(md, encoding="utf-8")
    print(f"[INFO] [{slug}] Findings written to {named_path}", file=sys.stderr)

    if is_primary:
        primary_path = scan_dir / "findings.md"
        primary_path.write_text(md, encoding="utf-8")
        print(f"[INFO] [{slug}] Primary findings.md → {primary_path}", file=sys.stderr)

    # Summary
    counts: dict[str, int] = {}
    for v in assessments.values():
        counts[v.get("status", "Open")] = counts.get(v.get("status", "Open"), 0) + 1
    print(f"", file=sys.stderr)
    print(f"  [{slug}] Summary", file=sys.stderr)
    print(f"  " + "─" * 30, file=sys.stderr)
    for label in ("Open", "Not a Finding", "Not Applicable", "Not Reviewed"):
        n = counts.get(label, 0)
        if n:
            print(f"    {label:<22} {n}", file=sys.stderr)
    print(f"    {'Total':<22} {len(controls)}", file=sys.stderr)
    print(f"", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-powered STIG compliance assessment engine"
    )
    # STIG source — mutually exclusive: single file or directory
    stig_group = parser.add_mutually_exclusive_group(required=True)
    stig_group.add_argument(
        "--cklb",
        help="Path to a single STIG file (.cklb JSON or XCCDF .xml). "
             "Use --stigs-dir to process multiple STIGs.",
    )
    stig_group.add_argument(
        "--stigs-dir",
        help="Directory containing one or more STIG files (.cklb or .xml). "
             "All supported files are processed automatically.",
    )
    parser.add_argument("--target",     required=True, help="Path to application source directory")
    parser.add_argument("--scan-dir",   required=True, help="Path to scan output directory")
    parser.add_argument("--app-name",   required=True, help="Application name for report header")
    parser.add_argument("--model",      default="gpt-4.1", help="OpenAI model (default: gpt-4.1)")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE_DEFAULT,
                        help=f"Controls per API call (default: {BATCH_SIZE_DEFAULT})")
    parser.add_argument("--delay",      type=float, default=1.0,
                        help="Seconds between API calls (default: 1.0)")
    args = parser.parse_args()

    model   = os.environ.get("OPENAI_MODEL", args.model)
    api_key = os.environ.get("OPENAI_API_KEY", "")

    if not api_key:
        print(
            "[WARNING] OPENAI_API_KEY is not set — generating report with "
            "'Not Reviewed' status for all controls.",
            file=sys.stderr,
        )

    scan_dir  = Path(args.scan_dir)
    scan_dir.mkdir(parents=True, exist_ok=True)
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # ── Resolve STIG file list ─────────────────────────────────────────────
    stig_files: list[Path] = []
    if args.cklb:
        stig_files = [Path(args.cklb)]
    else:
        stigs_dir = Path(args.stigs_dir)
        if not stigs_dir.is_dir():
            print(f"[ERROR] --stigs-dir not found: {stigs_dir}", file=sys.stderr)
            sys.exit(1)
        stig_files = sorted(
            p for p in stigs_dir.iterdir()
            if p.suffix.lower() in (".cklb", ".xml") and p.is_file()
        )
        if not stig_files:
            print(
                f"[ERROR] No .cklb or .xml STIG files found in {stigs_dir}",
                file=sys.stderr,
            )
            sys.exit(1)

    print(f"[INFO] Found {len(stig_files)} STIG file(s) to process", file=sys.stderr)
    for sf in stig_files:
        print(f"         {sf.name}", file=sys.stderr)
    print("", file=sys.stderr)

    # ── Collect source files once (shared across all STIGs) ────────────────
    print(f"[INFO] Collecting source files from {args.target}", file=sys.stderr)
    source_files = collect_source_files(args.target)
    print(f"[INFO] Collected {len(source_files)} source files", file=sys.stderr)
    print("", file=sys.stderr)

    # ── Process each STIG ─────────────────────────────────────────────────
    for i, stig_path in enumerate(stig_files):
        print(f"[INFO] Processing STIG {i + 1}/{len(stig_files)}: {stig_path.name}", file=sys.stderr)
        try:
            stig_data = parse_stig_file(str(stig_path))
        except (FileNotFoundError, ValueError) as e:
            print(f"[ERROR] Failed to parse {stig_path.name}: {e}", file=sys.stderr)
            continue

        slug = slug_from_stig(stig_data, str(stig_path))
        is_primary = (i == 0)  # first STIG also writes findings.md

        _assess_stig(
            stig_data=stig_data,
            stig_path=str(stig_path),
            source_files=source_files,
            scan_dir=scan_dir,
            app_name=args.app_name,
            model=model,
            batch_size=args.batch_size,
            delay=args.delay,
            api_key=api_key,
            scan_date=scan_date,
            slug=slug,
            is_primary=is_primary,
        )


if __name__ == "__main__":
    main()
