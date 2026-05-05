#!/usr/bin/env python3
"""
run-stig-assessment.py — AI-powered STIG compliance assessment engine.

Reads controls from one or more STIG source files (.cklb JSON or XCCDF XML),
walks the target application source tree, batches controls with relevant
code context, and calls the OpenAI API to produce per-control assessments.

Outputs (per STIG):
  {SCAN_DIR}/findings-{app}.md              — Primary findings report (first/only STIG)
  {SCAN_DIR}/findings-{app}-{slug}.md       — Per-STIG report when multiple STIGs present
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

MAX_CODE_BYTES_PER_BATCH = 250_000  # ~250 KB per API call — GPT-4.1 has 1M token context
MAX_FILE_BYTES = 50_000             # include files up to 50 KB
BATCH_SIZE_DEFAULT = 10             # controls per API call (smaller = more focused)

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

SYSTEM_PROMPT = """You are a certified DISA STIG compliance analyst performing a thorough \
static source-code review. Your task is to assess a set of DISA STIG controls against the \
complete source code of an application repository.

You will be given:
1. A manifest listing EVERY file in the repository so you understand the full scope.
2. The full content of as many files as fit within this context window, prioritised by \
relevance to the controls being assessed.
3. A list of controls to assess.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ASSESSMENT METHODOLOGY — follow this exactly
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

For EACH control:

STEP 1 — Read the check_content carefully. Identify the specific technical requirement \
(e.g. "passwords must be stored as cryptographic hashes", "TLS 1.2 minimum", \
"session timeout ≤ 15 minutes").

STEP 2 — Search EVERY provided file for evidence. Look for:
  - Configuration values (exact setting names and their literal values)
  - Function/method names that implement the requirement
  - Middleware, decorators, annotations that enforce the control
  - Import statements or dependency declarations that bring in relevant libraries
  - Environment variable references that configure the requirement
  - Comments or documentation that describe the implementation

STEP 3 — Extract EXACT literals. When you find evidence, copy the exact value from \
the source code (e.g. `hashIterations(27500)`, `SESSION_TIMEOUT = 900`, \
`TLSv1.2`). Do not paraphrase — quote the actual code.

STEP 4 — Cross-reference against the requirement. State explicitly whether what you \
found satisfies the control criterion and why (e.g. "27,500 iterations exceeds the \
NIST SP 800-63B minimum of 10,000 for PBKDF2").

STEP 5 — Assign status:
  "Not a Finding"  — Specific named artifacts in specific files directly and completely \
satisfy the control. You have cited the exact file path and the exact value/construct.
  "Not Applicable" — The control is architecturally impossible for this application type. \
State the specific architectural reason (e.g., "This is a stateless REST API with no \
server-side session management; session-count controls do not apply").
  "Open"           — Applicable but full compliance cannot be confirmed from static \
artifacts alone. Describe what partial evidence exists and precisely what is missing \
(e.g., "TLS is configured in nginx.conf but cipher suite ordering is not specified").
  "Not Reviewed"   — Purely runtime/dynamic with zero static-analysis indicators. \
Use ONLY when the control genuinely cannot be assessed without live system access.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EVIDENCE FORMAT — match this example exactly
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Example of the evidence quality and format required:

  "evidence": "Keycloak realm configuration enforces cryptographic storage of passwords.\\n- File: deploy/keycloak/dev-realm.json — passwordPolicy: \\"hashIterations(27500)\\"\\n- Algorithm: PBKDF2-SHA256 with random per-user salt\\n- Iteration count 27,500 exceeds NIST SP 800-63B minimum (10,000 for PBKDF2)\\n- Passwords stored only as one-way cryptographic hashes; plaintext never persisted\\n- Authentication: credential verification performed server-side via cryptographic comparison\\n- Requirement: SATISFIED — cryptographic password storage enforced via Keycloak realm policy"

Key rules for evidence:
  - Always start with a one-sentence summary of what the control requires and what you found.
  - Use bullet points (prefix "- ") for each piece of evidence.
  - Every bullet that references code MUST include: File path, the exact setting/function \
name, and its literal value from the source.
  - Where a value can be compared to a standard or threshold, make that comparison explicit.
  - End with "- Requirement: SATISFIED — [reason]" or "- Requirement: NOT SATISFIED — [reason]" \
or "- Requirement: PARTIALLY SATISFIED — [what is present, what is missing]".
  - Never use generic boilerplate like "the application implements this control". \
Always cite specific artifacts.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RESPONSE FORMAT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

You MUST respond with a valid JSON array and NOTHING ELSE. \
No markdown fences, no explanation — only the JSON array.

Each element MUST have exactly these three fields:
  "vuln_id"  : the exact APSC-DV-XXXXXX identifier from the input
  "status"   : exactly one of "Open", "Not a Finding", "Not Applicable", "Not Reviewed"
  "evidence" : detailed, specific, file-cited evidence following the format above

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


def slug_from_app_name(app_name: str) -> str:
    """Derive a filesystem-safe slug from an application name."""
    return re.sub(r"[^a-z0-9]+", "-", app_name.lower()).strip("-")


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


def build_repo_manifest(files: list[tuple[str, str]]) -> str:
    """Build a compact file tree listing all files in the repo."""
    lines = ["Repository file manifest (all files):", ""]
    for rel, _ in sorted(files, key=lambda x: x[0]):
        lines.append(f"  {rel}")
    return "\n".join(lines)


def build_app_profile(app_name: str, files: list[tuple[str, str]]) -> str:
    """Build a compact technology-stack summary from the collected source files."""
    from collections import Counter

    ext_counts: Counter[str] = Counter()
    key_files_found: list[str] = []

    _KEY_FILES = {
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        "requirements.txt", "setup.py", "pyproject.toml", "setup.cfg",
        "package.json", "package-lock.json", "yarn.lock",
        "go.mod", "go.sum",
        "pom.xml", "build.gradle", "build.gradle.kts",
        "Gemfile", "Gemfile.lock",
        "Cargo.toml",
        "composer.json",
        "*.tf",  # checked separately
        "Makefile", "justfile",
    }

    for rel, _ in files:
        fname = Path(rel).name
        ext = Path(rel).suffix.lower()
        if ext:
            ext_counts[ext] += 1
        if fname in _KEY_FILES:
            key_files_found.append(fname)

    _EXT_LABEL: dict[str, str] = {
        ".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript/React",
        ".js": "JavaScript", ".jsx": "JavaScript/React",
        ".go": "Go", ".java": "Java", ".rb": "Ruby", ".cs": "C#",
        ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
        ".tf": "Terraform", ".hcl": "HCL",
        ".yml": "YAML", ".yaml": "YAML",
        ".json": "JSON", ".toml": "TOML",
    }

    type_parts = [
        f"{_EXT_LABEL.get(ext, ext.lstrip('.'))} ({cnt})"
        for ext, cnt in ext_counts.most_common(10)
    ]

    lines = [
        f"Application: {app_name}",
        f"File types: {', '.join(type_parts) if type_parts else 'unknown'}",
    ]
    if key_files_found:
        lines.append(f"Key files: {', '.join(sorted(set(key_files_found)))}")
    else:
        lines.append("Key files: none detected")

    return "\n".join(lines)


def build_code_context(
    files: list[tuple[str, str]],
    keywords: list[str],
    max_bytes: int = MAX_CODE_BYTES_PER_BATCH,
) -> str:
    """Include as many source files as fit in max_bytes, ranked by relevance.

    All files are always considered — keyword scoring only determines priority
    so the most relevant files fill the budget first, but lower-scoring files
    are included if space remains.
    """
    ranked = rank_files_by_relevance(files, keywords)
    parts: list[str] = []
    total = 0
    skipped: list[str] = []

    for rel, content in ranked:
        snippet = f"### FILE: {rel}\n```\n{content}\n```\n"
        snippet_bytes = len(snippet.encode())
        if total + snippet_bytes > max_bytes:
            skipped.append(rel)
            continue
        parts.append(snippet)
        total += snippet_bytes

    if skipped:
        parts.append(
            f"### NOTE: {len(skipped)} additional file(s) exceeded context budget "
            f"and were not included:\n"
            + "\n".join(f"  {r}" for r in skipped)
            + "\n"
        )

    if not parts:
        return "(No source files found in target directory)"
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# STIG applicability pre-check
# ---------------------------------------------------------------------------

_APPLICABILITY_SYSTEM_PROMPT = """\
You are a DISA STIG scoping analyst. Your sole task is to decide whether a \
given DISA STIG is in scope for a described software application.

A STIG is NOT applicable when the technology it governs (e.g. a specific \
endpoint-security product, database engine, operating system, or network device) \
is clearly absent from the application's tech stack.

A STIG IS applicable when the application uses, embeds, or depends on the \
technology the STIG governs, or when the application's purpose or stack is \
general enough that the STIG could reasonably apply.

When in doubt, return applicable=true.

Reply ONLY with valid JSON — no markdown, no explanation:
{"applicable": true, "reason": "one sentence"}"""


def check_stig_applicability(
    client: Any,
    model: str,
    stig_data: dict[str, Any],
    app_profile: str,
) -> tuple[bool, str]:
    """Ask OpenAI whether a STIG applies to this application.

    Returns (applicable: bool, reason: str).
    Defaults to (True, ...) on any error so the full assessment still runs.
    """
    stig_name    = stig_data.get("stig_name", "Unknown STIG")
    release_info = stig_data.get("release_info", "")
    sample_titles = [
        c["title"] for c in stig_data.get("controls", [])[:5]
    ]

    user_message = (
        f"STIG: {stig_name}\n"
        f"Release: {release_info}\n"
        f"Sample control titles:\n"
        + "\n".join(f"  - {t}" for t in sample_titles)
        + f"\n\n{app_profile}"
    )

    try:
        response = client.chat.completions.create(
            model=model,
            temperature=0,
            max_tokens=300,
            messages=[
                {"role": "system", "content": _APPLICABILITY_SYSTEM_PROMPT},
                {"role": "user",   "content": user_message},
            ],
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
        parsed = json.loads(raw)
        applicable = bool(parsed.get("applicable", True))
        reason     = str(parsed.get("reason", "")).strip()
        return applicable, reason
    except Exception as exc:  # pylint: disable=broad-except
        return True, f"Applicability check failed ({exc}) — proceeding with full assessment"


# ---------------------------------------------------------------------------
# OpenAI call
# ---------------------------------------------------------------------------

def call_openai(
    client: Any,
    model: str,
    controls_batch: list[dict[str, Any]],
    code_context: str,
    repo_manifest: str = "",
) -> list[dict[str, Any]]:
    """Call GPT with a batch of controls + full repo manifest + code context."""
    controls_json = json.dumps(
        [
            {
                "vuln_id":       c["vuln_id"],
                "title":         c["title"],
                "check_content": c["check_content"],
                "fix_text":      c["fix_text"],
            }
            for c in controls_batch
        ],
        indent=2,
    )

    manifest_section = f"{repo_manifest}\n\n" if repo_manifest else ""

    user_message = (
        f"{manifest_section}"
        f"Controls to assess ({len(controls_batch)} total):\n{controls_json}\n\n"
        f"Application source code (examine every file carefully):\n{code_context}"
    )

    response = client.chat.completions.create(
        model=model,
        temperature=0.1,
        max_tokens=8192,
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

        # Render evidence — preserve bullet lines as-is; wrap plain sentences as bullets.
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
# CKLB output renderer
# ---------------------------------------------------------------------------

# Map our human-readable statuses back to the CKLB status field values
_STATUS_TO_CKLB: dict[str, str] = {
    "Open":           "open",
    "Not a Finding":  "not_a_finding",
    "Not Applicable": "not_applicable",
    "Not Reviewed":   "not_reviewed",
}


def render_findings_cklb(
    app_name: str,
    stig_data: dict[str, Any],
    assessments: dict[str, dict[str, str]],
    scan_date: str,
) -> dict[str, Any]:
    """Build a CKLB-compatible JSON structure from parsed controls and assessments."""
    import uuid as _uuid

    stig_uuid = stig_data.get("stig_id") or str(_uuid.uuid4())

    rules: list[dict[str, Any]] = []
    for c in stig_data["controls"]:
        vuln_id = c["vuln_id"]
        assessed = assessments.get(vuln_id, {})
        cklb_status = _STATUS_TO_CKLB.get(assessed.get("status", "Open"), "open")
        evidence = assessed.get("evidence", "").strip()

        rule: dict[str, Any] = {
            "uuid":                     str(_uuid.uuid4()),
            "stig_uuid":                stig_uuid,
            "target_key":               None,
            "stig_ref":                 None,
            "group_id":                 c.get("group_id", ""),
            "rule_id":                  c.get("rule_id", ""),
            "rule_id_src":              c.get("rule_id", "") + "_rule",
            "weight":                   "10.0",
            "classification":           "Unclassified",
            "severity":                 c.get("severity", ""),
            "rule_version":             vuln_id,
            "group_title":              c.get("title", ""),
            "rule_title":               c.get("title", ""),
            "fix_text":                 c.get("fix_text", ""),
            "false_positives":          "",
            "false_negatives":          "",
            "discussion":               c.get("discussion", ""),
            "check_content":            c.get("check_content", ""),
            "documentable":             "false",
            "mitigations":              "",
            "potential_impacts":        "",
            "third_party_tools":        "",
            "mitigation_control":       "",
            "responsibility":           "",
            "security_override_guidance": "",
            "ia_controls":              "",
            "check_content_ref":        {"href": "", "name": "M"},
            "legacy_ids":               [],
            "ccis":                     c.get("ccis", []),
            "group_tree":               [
                {
                    "id":          c.get("group_id", ""),
                    "title":       c.get("srg_id", ""),
                    "description": "<GroupDescription></GroupDescription>",
                }
            ],
            "createdAt":                f"{scan_date}T00:00:00.000Z",
            "updatedAt":                f"{scan_date}T00:00:00.000Z",
            "STIGUuid":                 stig_uuid,
            "status":                   cklb_status,
            "overrides":                {},
            "comments":                 "",
            "finding_details":          evidence,
            "srg_id":                   c.get("srg_id", ""),
        }
        rules.append(rule)

    stig_entry: dict[str, Any] = {
        "stig_name":            stig_data.get("stig_name", ""),
        "display_name":         stig_data.get("display_name") or stig_data.get("stig_name", ""),
        "stig_id":              stig_data.get("stig_id", ""),
        "release_info":         stig_data.get("release_info", ""),
        "version":              stig_data.get("version", ""),
        "uuid":                 stig_uuid,
        "reference_identifier": "",
        "size":                 len(rules),
        "rules":                rules,
    }

    return {
        "title":        app_name,
        "id":           str(_uuid.uuid4()),
        "stigs":        [stig_entry],
        "active":       True,
        "mode":         2,
        "has_path":     False,
        "target_data": {
            "target_type":    "Computing",
            "host_name":      app_name,
            "ip_address":     "",
            "mac_address":    "",
            "fqdn":           "",
            "comments":       f"Generated by Epyon STIG assessment on {scan_date}",
            "role":           "None",
            "is_web_database": False,
            "technology_area": "",
            "web_db_site":    "",
            "web_db_instance": "",
            "classification": None,
        },
        "cklb_version": "1.0",
    }


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

        # ── Applicability pre-check ───────────────────────────────────────
        app_profile = build_app_profile(app_name, source_files)
        applicable, applicability_reason = check_stig_applicability(
            client, model, stig_data, app_profile
        )
        if not applicable:
            print(
                f"[SKIP] [{slug}] STIG not applicable — {applicability_reason}",
                file=sys.stderr,
            )
            return
        print(
            f"[INFO] [{slug}] STIG applicable — {applicability_reason}",
            file=sys.stderr,
        )
        # ─────────────────────────────────────────────────────────────────

        batches = [controls[i : i + batch_size] for i in range(0, len(controls), batch_size)]
        total_batches = len(batches)

        # Build repo manifest once — sent with every batch so the model always
        # knows the full file tree even if some files exceed the context budget.
        repo_manifest = build_repo_manifest(source_files)

        print(
            f"[INFO] [{slug}] Submitting {total_batches} batches of up to {batch_size} controls "
            f"to {model} (context budget: {MAX_CODE_BYTES_PER_BATCH // 1024}KB/batch, "
            f"{len(source_files)} source files)",
            file=sys.stderr,
        )

        for idx, batch in enumerate(batches, start=1):
            print(
                f"[INFO] [{slug}] Batch {idx}/{total_batches}: "
                f"{batch[0]['vuln_id']} → {batch[-1]['vuln_id']}",
                file=sys.stderr,
            )

            # Gather keywords from all controls in this batch to prioritise
            # the most relevant files, then fill remaining budget with others.
            all_kw: list[str] = []
            for c in batch:
                all_kw.extend(extract_keywords(c["check_content"]))
            code_context = build_code_context(source_files, all_kw)

            try:
                results = call_openai(client, model, batch, code_context, repo_manifest)
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

    app_slug = slug_from_app_name(app_name)

    # Named file always written; also write findings-{app_slug}.md for the primary STIG
    named_path = scan_dir / f"findings-{app_slug}-{slug}.md"
    named_path.write_text(md, encoding="utf-8")
    print(f"[INFO] [{slug}] Findings written to {named_path}", file=sys.stderr)

    if is_primary:
        primary_path = scan_dir / f"findings-{app_slug}.md"
        primary_path.write_text(md, encoding="utf-8")
        print(f"[INFO] [{slug}] Primary findings-{app_slug}.md → {primary_path}", file=sys.stderr)
    # Render and write CKLB output
    cklb_data = render_findings_cklb(
        app_name=app_name,
        stig_data=stig_data,
        assessments=assessments,
        scan_date=scan_date,
    )
    cklb_named = scan_dir / f"findings-{app_slug}-{slug}.cklb"
    cklb_named.write_text(json.dumps(cklb_data, indent=2), encoding="utf-8")
    print(f"[INFO] [{slug}] CKLB written to {cklb_named}", file=sys.stderr)

    if is_primary:
        cklb_primary = scan_dir / f"findings-{app_slug}.cklb"
        cklb_primary.write_text(json.dumps(cklb_data, indent=2), encoding="utf-8")
        print(f"[INFO] [{slug}] Primary findings-{app_slug}.cklb → {cklb_primary}", file=sys.stderr)
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
