#!/usr/bin/env python3
"""
run-stig-assessment.py — AI-powered STIG compliance assessment engine.

Reads controls from one or more STIG source files (.cklb JSON or XCCDF XML),
walks the target application source tree (including all markdown/JSON files 
with existing findings or compliance documentation), batches controls with 
relevant code context, and calls the OpenAI API to produce per-control assessments.

STIG Applicability Detection:
    Before processing, the script detects the technology stack in use (databases,
    app servers, frameworks, languages) and automatically filters STIGs based on
    applicability. For example:
    - PostgreSQL STIG only runs if PostgreSQL imports/config detected
    - Tomcat STIG only runs if Tomcat classes/server.xml detected
    - .NET STIG only runs if .csproj files or C# code detected
    - ASD (Application Security Development) STIG always runs (applies to all apps)
    
    This prevents false positives from controls that don't apply to your application.

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
    OPENAI_API_KEY   Required for OpenAI. Optional for local models that don't require auth.
    OPENAI_MODEL     Optional. Overrides --model flag (default: gpt-4o-mini).
    OPENAI_BASE_URL  Optional. Override the API endpoint. Use this to point at a
                     local inference server (Ollama, LM Studio, vLLM, LocalAI, etc.)
                     that exposes an OpenAI-compatible /v1/chat/completions endpoint.

                     Common local model endpoints:
                       Ollama:    http://localhost:11434/v1
                       LM Studio: http://localhost:1234/v1
                       vLLM:      http://localhost:8000/v1
                       LocalAI:   http://localhost:8080/v1

                     When OPENAI_BASE_URL points to localhost / RFC1918 / cluster-
                     internal addresses, OPENAI_API_KEY is optional (set it to any
                     non-empty string, e.g. 'local', to satisfy the SDK validation).

                     A self-hosted base_url must resolve to localhost, a private IP,
                     a Kubernetes service hostname, or a host listed in
                     EPYON_AI_ALLOWED_HOSTS (comma-separated) — public non-OpenAI
                     endpoints are blocked to prevent credential exfiltration.

Status Change Validation:
    When previous scan results exist in the parent scans/ directory, the AI will
    validate status changes and require concrete, file-cited evidence for any change.
    This prevents frivolous status changes while allowing evidence text refinement.
    
    Behavior by environment:
    - Web UI / Local Scans: Previous results automatically loaded, status changes validated
    - GitHub Actions CI: scans/ directory not persisted, all assessments treated as fresh
    
    Status changes require one of:
    - New code/config files that satisfy or violate the control
    - Specific modifications to existing files with exact changes cited
    - Architectural changes that make control applicable/inapplicable
    
    The AI may NOT change status based on rephrased evidence, speculation, or
    "further analysis needed" without concrete repository artifacts.

Adding a new STIG:
    Drop any .cklb or XCCDF .xml file into configuration/stigs/ — it will be
    picked up automatically on the next nightly/stig scan run and filtered
    based on detected technologies.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SOURCE_EXTENSIONS = {
    # Application code
    ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".java", ".rb", ".cs",
    ".rs", ".kt", ".kts", ".php", ".vue", ".svelte",
    ".c", ".cpp", ".h", ".hpp",
    # Shell / scripting
    ".sh", ".bash", ".zsh",
    # Config / markup
    ".yml", ".yaml",
    ".json", ".toml", ".cfg", ".ini", ".properties", ".conf",
    ".xml",
    # IaC / build
    ".tf", ".hcl", ".gradle",
    # Templates
    ".html", ".htm", ".jinja2", ".j2", ".tpl",
    # Database
    ".sql",
    # Documentation
    ".md",
}

INCLUDE_FILENAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env.example", ".env.template", "Makefile", "justfile",
    "nginx.conf", "httpd.conf", "web.xml",
    "pom.xml", "build.gradle", "settings.gradle",
}

EXCLUDE_DIR_PREFIXES = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "coverage", ".coverage", ".tox", ".mypy_cache",
    ".pytest_cache", ".eggs",
    # Note: *.egg-info directories are handled via endswith() in _is_excluded_dir
}

# Context budget — bytes are NOT tokens.  For dense source code (Python/JS/shell)
# the OpenAI cl100k_base tokeniser produces roughly 1 token per 2–3 bytes, so
# 250 KB of code ≈ 83 k–125 k tokens, far exceeding gpt-4o-mini's 128 K limit
# once the manifest, system prompt, and controls are added.  Use a conservative
# 60 KB ceiling which yields ≈ 20 k–30 k code tokens regardless of code density.
MAX_CODE_BYTES_PER_BATCH = 60_000   # 60 KB ≈ 20–30 k tokens — safe for 128 K ctx models
MAX_FILE_BYTES = 25_000             # truncate (not skip) files larger than 25 KB
_MAX_MANIFEST_LINES = 150           # cap repo manifest to 150 paths (150 × 60 chars / 4 ≈ 2 300 tokens)
BATCH_SIZE_DEFAULT = 5              # controls per API call — smaller batches give each control more context

# Valid canonical status values — any model output is normalized to these before storage.
VALID_STATUSES: frozenset[str] = frozenset({
    "Not a Finding",
    "Not Applicable",
    "Open",
    "Not Reviewed",
})

# Normalisation map: handles common model variations → canonical value.
_STATUS_ALIASES: dict[str, str] = {
    "not a finding":  "Not a Finding",
    "not_a_finding":  "Not a Finding",
    "notafinding":    "Not a Finding",
    "not applicable": "Not Applicable",
    "not_applicable": "Not Applicable",
    "notapplicable":  "Not Applicable",
    "n/a":            "Not Applicable",
    "na":             "Not Applicable",
    "open":           "Open",
    "not reviewed":   "Not Reviewed",
    "not_reviewed":   "Not Reviewed",
    "notreviewed":    "Not Reviewed",
}


def normalize_status(raw: str | None) -> str:
    """Return a canonical STIG status from any model-returned string.

    Falls back to 'Open' if the value cannot be recognized — never stores an
    invalid status that would silently break freeze logic or UI rendering.
    """
    if raw is None:
        return "Open"
    if raw in VALID_STATUSES:
        return raw
    candidate = _STATUS_ALIASES.get(raw.strip().lower())
    return candidate if candidate else "Open"


# Minimum confidence that a non-Open status must carry to be stored as-is.
# A model that returns "Not a Finding" with confidence < this threshold is
# untrustworthy — we downgrade to "Open" rather than risk a false satisfaction.
_MIN_CONFIDENCE_FOR_CLOSED_STATUS = 40

# Maximum retries for a single batch before falling back to Open.
# 3 attempts: attempt 1 = full code budget + manifest; attempt 2 = halved code
# budget + manifest; attempt 3 = halved code budget, NO manifest (last resort).
_MAX_BATCH_RETRIES = 3

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

# ---------------------------------------------------------------------------
# Local / self-hosted endpoint helpers
# ---------------------------------------------------------------------------

_OPENAI_PUBLIC_HOSTS: frozenset[str] = frozenset({
    "api.openai.com",
    "openai.azure.com",
})


def _hostname(url: str) -> str:
    """Return the lowercase hostname from a URL, or '' on parse failure."""
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:  # pragma: no cover
        return ""


def _is_internal_host(host: str) -> bool:
    """True for localhost, RFC1918 addresses, and cluster-internal names."""
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    if host.endswith((".svc", ".svc.cluster.local", ".cluster.local",
                      ".local", ".internal")):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _base_url_allowed(base_url: str) -> bool:
    """Guard against SSRF: only allow public OpenAI hosts, internal/private
    addresses (local models), or operator-allowlisted hosts.

    Blocks public non-OpenAI hostnames so a real API key cannot be silently
    exfiltrated to an attacker-controlled endpoint.
    """
    host = _hostname(base_url)
    if not host:
        return False
    if host in _OPENAI_PUBLIC_HOSTS or _is_internal_host(host):
        return True
    allow = os.environ.get("EPYON_AI_ALLOWED_HOSTS", "")
    return host in {h.strip().lower() for h in allow.split(",") if h.strip()}

SYSTEM_PROMPT = """You are a certified DISA STIG compliance analyst performing a thorough \
static source-code review. Your task is to assess a set of DISA STIG controls against the \
complete source code of an application repository.

You will be given:
1. A manifest listing EVERY file in the repository so you understand the full scope.
2. Security findings from the current scan (vulnerabilities, secrets, IaC issues, malware) \
   from tools like Grype, Trivy, TruffleHog, Checkov, ClamAV.
3. Risk acceptance/suppression rules (.epyon-ignore.yml) showing what findings have been \
   accepted as risks with justifications and approvals.
4. **Manual STIG documentation** from the target repository (e.g., docs/stig-findings.md, \
   COMPLIANCE.md, STIG.md) containing human-authored STIG assessments, manual overrides, \
   compliance notes, and human-verified evidence. **THESE FILES TAKE PRIORITY** — if a \
   human has explicitly documented a control as satisfied with specific evidence, respect \
   that assessment unless you find concrete code changes that invalidate it.
5. The full content of as many source files as fit within this context window, prioritised by \
   relevance to the controls being assessed.
6. A list of controls to assess.

Use the security findings to inform vulnerability management, secrets handling, and secure \
configuration controls. Use the suppression rules to understand the organization's risk \
management practices and exception handling policies. **Most importantly, defer to manual \
STIG documentation when present** — human security assessors have already reviewed these \
controls and their judgments should only be overridden when you can cite specific code \
changes that materially affect compliance.

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

STEP 5 — CONFIRM or UPDATE using the previous finding:

Every control includes a "previous_status" and "previous_evidence" field from the last scan.

  IF previous_status is present:
    1. Re-read the previous_evidence. Locate the exact files and values it cites in the \
current source code.
    2. If those artifacts STILL EXIST and STILL SATISFY (or still fail) the control → \
CONFIRM: output the same status. You may refresh the evidence text to reflect any minor \
wording improvements, but do not change the status.
    3. If the artifacts have CHANGED, DISAPPEARED, or NEW artifacts materially alter \
compliance → UPDATE: output the new status with fully re-cited evidence.
    4. If you cannot find any of the previously cited files or values → treat as a fresh \
assessment and provide new evidence.

  IF previous_status is null (first scan for this control):
    Assess from scratch using STEPS 1–4.

  KEY RULE: A status change MUST be backed by a specific file path and literal value that \
differs from what the previous_evidence cited. Rephrasing, vague observations, or \
"further review needed" are NOT acceptable reasons to change status.

Status definitions:
  "Not a Finding"  — Specific named artifacts in specific files directly and completely \
satisfy the control. You have cited the exact file path and the exact value/construct.
  "Not Applicable" — The control is architecturally impossible for this application type. \
State the specific architectural reason (e.g., "This is a stateless REST API with no \
server-side session management; session-count controls do not apply").
  "Open"           — Use this as the DEFAULT when compliance cannot be fully confirmed. \
This includes runtime controls, missing configs, inferred-but-not-explicit settings, \
and anything where full compliance cannot be demonstrated from static artifacts alone. \
Describe what partial evidence exists and precisely what is missing.
  "Not Reviewed"   — RESERVED for the absolute rarest cases: controls that are 100% \
runtime-only AND have zero static indicators whatsoever (no config, no code, no \
infrastructure-as-code). If there is ANY static artifact even partially relevant to \
the control, use "Open" instead. When in doubt, use "Open". \
Do NOT use "Not Reviewed" simply because a control is hard to assess statically.

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

Each element MUST have exactly these four fields:
  "vuln_id"    : the exact APSC-DV-XXXXXX identifier from the input
  "status"     : exactly one of "Open", "Not a Finding", "Not Applicable", "Not Reviewed"
  "evidence"   : detailed, specific, file-cited evidence following the format above
  "confidence" : integer 0–100 representing your certainty in the assessment
                   90–100 = direct named artifact satisfies the control without ambiguity
                   70–89  = strong evidence but minor gaps (e.g. config value set, runtime not observable)
                   40–69  = partial evidence; key artifacts missing or inferred
                   1–39   = very little static evidence; status is mostly inferred from architecture
                   0      = no relevant evidence found; status is a best guess

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
# Previous scan results lookup
# ---------------------------------------------------------------------------

def find_previous_scan_dirs(current_scan_dir: Path, app_name: str) -> list[Path]:
    """Return all previous scan directories for the same app, newest first.

    Args:
        current_scan_dir: Path to current scan directory
        app_name: Application name

    Returns:
        List of previous scan directories sorted newest-first (may be empty)
    """
    app_slug = slug_from_app_name(app_name)
    scans_root = current_scan_dir.parent  # scans/

    if not scans_root.exists() or not scans_root.is_dir():
        return []

    pattern = f"{app_slug}_*"
    return sorted(
        [d for d in scans_root.glob(pattern) if d.is_dir() and d != current_scan_dir],
        reverse=True,  # newest first
    )


def find_previous_scan_dir(current_scan_dir: Path, app_name: str) -> Path | None:
    """Find the most recent previous scan directory for the same app.

    Args:
        current_scan_dir: Path to current scan directory
        app_name: Application name

    Returns:
        Path to previous scan directory, or None if no previous scan exists
    """
    dirs = find_previous_scan_dirs(current_scan_dir, app_name)
    return dirs[0] if dirs else None


def load_previous_stig_results(previous_scan_dir: Path, slug: str) -> dict[str, dict[str, Any]]:
    """Load previous STIG assessment results for the given STIG slug.
    
    Args:
        previous_scan_dir: Path to previous scan directory
        slug: STIG slug (e.g., 'u-asd-stig-v6r4-manual-xccdf')
    
    Returns:
        Dict mapping vuln_id -> {status, evidence, confidence}, or empty dict if not found
    """
    results_file = previous_scan_dir / f"stig-results-{slug}.json"
    
    if not results_file.exists():
        return {}
    
    try:
        data = json.loads(results_file.read_text(encoding="utf-8"))
        return data.get("assessments", {})
    except Exception as e:
        print(f"[WARNING] Failed to load previous STIG results from {results_file}: {e}", file=sys.stderr)
        return {}


# ---------------------------------------------------------------------------
# Source file collection
# ---------------------------------------------------------------------------

# Hidden directories that contain security-relevant config and should be scanned
_ALLOWED_HIDDEN_DIRS = {
    ".github",
    ".circleci", ".drone", ".gitlab",
    ".devcontainer", ".helm",
}

# Compliance-relevant markdown/JSON files (case-insensitive stem matching)
# Only these markdown/JSON files will be collected to avoid context overflow
_COMPLIANCE_DOCS = {
    "readme", "security", "compliance", "stig", "findings", 
    "audit", "controls", "assessment", "ato", "isso",
    "vulnerabilities", "cve", "changelog", "contributing",
}


def _is_compliance_relevant_doc(path: Path) -> bool:
    """Check if a markdown/JSON file is compliance-relevant.
    
    Priority files for STIG assessment:
    - docs/stig-findings.md, docs/security/stig-findings.md: Manual STIG assessments and overrides
    - COMPLIANCE.md, STIG.md, SECURITY.md: Human-authored compliance documentation
    - Any file in docs/, documentation/, .github/, .compliance/, security/ directories
    - Files with compliance keywords: findings, audit, controls, assessment, etc.
    
    These files are collected as context for the AI STIG assessment and should
    contain human-verified evidence that takes priority over automated assessments.
    """
    ext = path.suffix.lower()
    if ext not in {".md", ".json"}:
        return False
    
    stem_lower = path.stem.lower()
    
    # Allow any markdown/JSON in these specific directories (includes nested paths)
    if any(part in {".github", "docs", "documentation", ".compliance", "security"} for part in path.parts):
        return True
    
    # Check if filename stem matches known compliance docs
    for keyword in _COMPLIANCE_DOCS:
        if keyword in stem_lower:
            return True
    
    return False


def _is_excluded_dir(dirname: str) -> bool:
    if dirname in EXCLUDE_DIR_PREFIXES:
        return True
    if dirname.endswith(".egg-info"):
        return True
    return dirname.startswith(".") and dirname not in _ALLOWED_HIDDEN_DIRS


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

        # For markdown/JSON, only collect compliance-relevant docs
        if ext in {".md", ".json"}:
            if not _is_compliance_relevant_doc(path):
                continue
        elif name not in INCLUDE_FILENAMES and ext not in SOURCE_EXTENSIONS:
            continue

        # Never send actual .env files — they may contain live secrets.
        # (.env.example and .env.template are safe templates and remain allowed.)
        if name == ".env" or (name.startswith(".env.") and name not in {".env.example", ".env.template"}):
            continue

        # Skip minified/lock files
        if any(pattern in name for pattern in (".min.js", ".lock", "-lock.json", ".map")):
            continue

        size = path.stat().st_size
        if size == 0:
            continue

        try:
            if size > MAX_FILE_BYTES:
                # Truncate rather than skip — large files still contain evidence
                with path.open("rb") as fh:
                    raw = fh.read(MAX_FILE_BYTES)
                content = raw.decode("utf-8", errors="replace") + (
                    f"\n[... TRUNCATED — file is {size:,} bytes; "
                    f"showing first {MAX_FILE_BYTES:,} bytes only]"
                )
            else:
                content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        files.append((rel, content))

    return files


def collect_security_findings(scan_dir: Path, max_findings: int = 3) -> str:
    """Load security findings from the current scan for additional context.
    
    Args:
        scan_dir: Path to scan directory containing security-findings-summary.json
        max_findings: Maximum findings per severity to include (default 3 for token budget)
    
    Returns a formatted string with summary of vulnerabilities, secrets, and issues
    found by other security tools. Returns empty string if no findings available.
    """
    findings_file = scan_dir / "security-findings-summary.json"
    if not findings_file.exists():
        return ""
    
    try:
        with findings_file.open(encoding="utf-8") as f:
            data = json.load(f)
        
        summary = data.get("summary", {})
        total_critical = summary.get("total_critical", 0)
        total_high = summary.get("total_high", 0)
        total_medium = summary.get("total_medium", 0)
        total_low = summary.get("total_low", 0)
        
        lines = [
            "SECURITY SCAN FINDINGS (Current Scan):",
            f"Critical: {total_critical}, High: {total_high}, Medium: {total_medium}, Low: {total_low}",
            f"Tools: {', '.join(summary.get('tools_analyzed', []))}",
            "",
        ]
        
        # Include only top findings (limited for token budget)
        for severity, findings in [
            ("Critical", data.get("critical_findings", [])),
            ("High", data.get("high_findings", [])),
        ]:
            if findings and max_findings > 0:
                lines.append(f"{severity} (top {min(max_findings, len(findings))}):")  
                for finding in findings[:max_findings]:
                    tool = finding.get("tool", "unknown")
                    cve = finding.get("id", finding.get("cve", "N/A"))
                    pkg = finding.get("package", finding.get("artifact", ""))
                    lines.append(f"  [{tool}] {cve} in {pkg}" if pkg else f"  [{tool}] {cve}")
                lines.append("")
        
        enrichment = data.get("enrichment", {})
        if enrichment.get("cisa_kev_total", 0) > 0:
            lines.append(f"⚠️ {enrichment['cisa_kev_total']} CISA KEV findings")
        
        return "\n".join(lines)
    except Exception as e:
        print(f"[WARNING] Failed to load security findings: {e}", file=sys.stderr)
        return ""


def collect_suppression_rules(target_dir: str, max_rules: int = 10) -> str:
    """Load suppression rules from .epyon-ignore.yml for risk management context.
    
    Args:
        target_dir: Target repository directory
        max_rules: Maximum rules to include (default 10 for token budget)
    
    Returns a formatted string showing accepted risks and their justifications.
    Returns empty string if no suppression file exists.
    """
    target_path = Path(target_dir).resolve()
    ignore_file = target_path / ".epyon-ignore.yml"
    
    if not ignore_file.exists():
        return ""
    
    try:
        with ignore_file.open(encoding="utf-8") as f:
            import yaml
            data = yaml.safe_load(f) or {}
        
        rules = data.get("rules", [])
        if not rules:
            return ""
        
        lines = [
            f"RISK ACCEPTANCE / SUPPRESSION RULES ({len(rules)} total):",
            "",
        ]
        
        for i, rule in enumerate(rules[:max_rules], 1):
            rule_type = rule.get("type", "unknown")
            value = rule.get("value", rule.get("id", "N/A"))
            reason = rule.get("reason", "No reason provided")
            approved_by = rule.get("approved_by", "Unknown")
            
            lines.append(f"{i}. {rule_type}: {value}")
            lines.append(f"   Reason: {reason} (approved: {approved_by})")
        
        if len(rules) > max_rules:
            lines.append(f"... and {len(rules) - max_rules} more")
        
        return "\n".join(lines)
    except Exception as e:
        print(f"[WARNING] Failed to load suppression rules: {e}", file=sys.stderr)
        return ""


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
    """Build a compact file tree listing all files in the repo.

    Capped at _MAX_MANIFEST_LINES paths to avoid blowing the model's context
    window when scanning large repositories.  The full list of collected source
    files is sorted alphabetically; the first _MAX_MANIFEST_LINES entries are
    shown and any remainder is summarised as a truncation note.
    """
    sorted_rels = sorted(rel for rel, _ in files)
    truncated = len(sorted_rels) > _MAX_MANIFEST_LINES
    shown = sorted_rels[:_MAX_MANIFEST_LINES]
    lines = ["Repository file manifest (selected files):", ""]
    for rel in shown:
        lines.append(f"  {rel}")
    if truncated:
        omitted = len(sorted_rels) - _MAX_MANIFEST_LINES
        lines.append(
            f"\n  [... {omitted} additional file(s) omitted from manifest to stay within context budget]"
        )
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

    # Signals that indicate an interactive web UI / user sessions
    _WEB_FRAMEWORK_IMPORTS = [
        "flask", "django", "fastapi", "starlette", "tornado", "aiohttp",
        "express", "koa", "hapi", "next", "nuxt", "react", "vue", "angular",
        "rails", "sinatra", "spring", "quarkus", "gin", "echo", "fiber",
        "actix", "rocket", "axum",
    ]
    _SESSION_SIGNALS = [
        "session", "login", "logout", "logoff", "authenticate", "cookie",
        "jwt", "oauth", "saml", "sso", "auth", "user.password", "password",
    ]
    _UI_FILE_PATTERNS = [
        ".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".erb", ".jinja",
        ".jinja2", ".j2", ".hbs", ".ejs",
    ]

    has_web_framework = False
    has_session_logic = False
    has_ui_files = False
    has_login_routes: list[str] = []

    for rel, content in files:
        fname = Path(rel).name
        ext = Path(rel).suffix.lower()
        if ext:
            ext_counts[ext] += 1
        if fname in _KEY_FILES:
            key_files_found.append(fname)

        content_lower = content.lower()

        # Check for web framework imports / usage
        if not has_web_framework:
            for fw in _WEB_FRAMEWORK_IMPORTS:
                if fw in content_lower:
                    has_web_framework = True
                    break

        # Check for session/auth signals
        if not has_session_logic:
            for sig in _SESSION_SIGNALS:
                if sig in content_lower:
                    has_session_logic = True
                    break

        # Check for UI template/component files
        if ext in _UI_FILE_PATTERNS:
            has_ui_files = True

        # Look for login/logoff route definitions
        if any(kw in content_lower for kw in ("route", "path", "endpoint", "@app.")):
            if any(kw in content_lower for kw in ("login", "logout", "logoff", "signin", "signout")):
                has_login_routes.append(rel)

    _EXT_LABEL: dict[str, str] = {
        ".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript/React",
        ".js": "JavaScript", ".jsx": "JavaScript/React",
        ".go": "Go", ".java": "Java", ".rb": "Ruby", ".cs": "C#",
        ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
        ".tf": "Terraform", ".hcl": "HCL",
        ".yml": "YAML", ".yaml": "YAML",
        ".json": "JSON", ".toml": "TOML",
        ".html": "HTML", ".htm": "HTML",
        ".vue": "Vue", ".svelte": "Svelte",
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

    # Append UI/session characteristics so the applicability check has full context
    ui_traits: list[str] = []
    if has_web_framework:
        ui_traits.append("uses a web framework")
    if has_ui_files:
        ui_traits.append("contains UI template/component files (HTML/JSX/Vue/etc.)")
    if has_session_logic:
        ui_traits.append("contains session/authentication logic (login, logout, cookies, JWT, etc.)")
    if has_login_routes:
        ui_traits.append(
            f"defines login/logout routes (e.g. {', '.join(has_login_routes[:3])})"
        )

    if ui_traits:
        lines.append("UI/session characteristics: " + "; ".join(ui_traits))
    else:
        lines.append(
            "UI/session characteristics: no web framework, UI files, or session/auth "
            "signals detected — likely a CLI tool, background service, or library"
        )

    return "\n".join(lines)


def detect_technologies(files: list[tuple[str, str]]) -> dict[str, Any]:
    """Detect technologies in use from source files and dependencies.
    
    Returns dict with:
        - databases: list of detected databases (postgresql, mysql, mongodb, etc.)
        - app_servers: list of detected app servers (tomcat, jboss, jetty, etc.)
        - frameworks: list of detected frameworks (.NET, Spring, Django, etc.)
        - languages: list of primary languages detected
        - has_web_ui: bool indicating if this is a web application
    """
    from collections import Counter
    
    result: dict[str, Any] = {
        "databases": set(),
        "app_servers": set(),
        "frameworks": set(),
        "languages": set(),
        "has_web_ui": False,
    }
    
    # Database detection patterns
    _DB_PATTERNS = {
        "postgresql": ["postgresql", "postgres", "psycopg", "pg_", "libpq", "pgcrypto"],
        "mysql": ["mysql", "mariadb", "pymysql", "mysql-connector", "jdbc:mysql"],
        "mongodb": ["mongodb", "mongoose", "pymongo", "mongo"],
        "oracle": ["oracle", "oracledb", "cx_oracle", "jdbc:oracle"],
        "mssql": ["mssql", "sqlserver", "pymssql", "tedious", "jdbc:sqlserver"],
        "redis": ["redis", "jedis", "ioredis", "redis-py"],
        "cassandra": ["cassandra", "datastax"],
    }
    
    # App server detection patterns
    _SERVER_PATTERNS = {
        "tomcat": ["tomcat", "catalina", "org.apache.tomcat", "servlet-api"],
        "jetty": ["jetty", "org.eclipse.jetty"],
        "jboss": ["jboss", "wildfly", "org.jboss"],
        "websphere": ["websphere", "was", "com.ibm.websphere"],
        "weblogic": ["weblogic", "oracle.weblogic"],
    }
    
    # Framework detection patterns
    _FRAMEWORK_PATTERNS = {
        "dotnet": [".csproj", ".vbproj", ".fsproj", "Microsoft.", "System.", "netcoreapp", "netstandard"],
        "spring": ["springframework", "spring-boot", "spring-web", "spring-data"],
        "django": ["django", "from django", "import django"],
        "flask": ["from flask", "import flask", "Flask(__name__)"],
        "fastapi": ["from fastapi", "import fastapi", "FastAPI()"],
        "rails": ["activesupport", "activerecord", "actionpack", "rails"],
        "express": ["express", "require('express')", "from 'express'"],
    }
    
    # Language detection from extensions
    ext_counts: Counter[str] = Counter()
    for rel, _ in files:
        ext = Path(rel).suffix.lower()
        if ext:
            ext_counts[ext] += 1
    
    # Map extensions to languages
    _EXT_TO_LANG = {
        ".py": "python",
        ".java": "java",
        ".cs": "csharp",
        ".rb": "ruby",
        ".go": "go",
        ".js": "javascript",
        ".ts": "typescript",
    }
    for ext, count in ext_counts.most_common(5):
        if ext in _EXT_TO_LANG and count >= 3:  # require at least 3 files
            result["languages"].add(_EXT_TO_LANG[ext])
    
    # Scan file contents for technology signals
    for rel, content in files:
        content_lower = content.lower()
        
        # Check databases
        for db, patterns in _DB_PATTERNS.items():
            if any(p in content_lower for p in patterns):
                result["databases"].add(db)
        
        # Check app servers
        for server, patterns in _SERVER_PATTERNS.items():
            if any(p in content_lower for p in patterns):
                result["app_servers"].add(server)
        
        # Check frameworks
        for fw, patterns in _FRAMEWORK_PATTERNS.items():
            if any(p in content_lower or p in content for p in patterns):
                result["frameworks"].add(fw)
        
        # Check for web UI signals
        if not result["has_web_ui"]:
            web_signals = [
                "flask", "django", "fastapi", "express", "react", "vue", "angular",
                "@app.route", "@router", "render_template", "http.server",
                "<html", "<body", "<!doctype html",
            ]
            if any(sig in content_lower for sig in web_signals):
                result["has_web_ui"] = True
    
    # Convert sets to sorted lists for JSON serialization
    result["databases"] = sorted(result["databases"])
    result["app_servers"] = sorted(result["app_servers"])
    result["frameworks"] = sorted(result["frameworks"])
    result["languages"] = sorted(result["languages"])
    
    return result


def is_stig_applicable(stig_filename: str, stig_name: str, tech_stack: dict[str, Any]) -> tuple[bool, str]:
    """Check if a STIG is applicable to the detected technology stack.
    
    Returns:
        (applicable, reason) - bool and explanation string
    """
    filename_lower = stig_filename.lower()
    stig_name_lower = stig_name.lower()
    
    # ASD STIG (Application Security Development) is always applicable
    # Match specifically: "u_asd_stig" or "application security" in name
    if ("u_asd_stig" in filename_lower or "_asd_" in filename_lower or 
        (("application" in stig_name_lower or "appsec" in stig_name_lower) and 
         ("security" in stig_name_lower or "development" in stig_name_lower))):
        return (True, "Application Security Development STIG applies to all applications")
    
    # Database STIGs - check if database is detected
    if "postgres" in filename_lower or "postgres" in stig_name_lower:
        if "postgresql" in tech_stack["databases"]:
            return (True, f"PostgreSQL detected in codebase: {tech_stack['databases']}")
        return (False, f"PostgreSQL STIG not applicable - databases detected: {tech_stack['databases'] or 'none'}")
    
    if "mysql" in filename_lower or "mysql" in stig_name_lower:
        if "mysql" in tech_stack["databases"]:
            return (True, f"MySQL detected in codebase: {tech_stack['databases']}")
        return (False, f"MySQL STIG not applicable - databases detected: {tech_stack['databases'] or 'none'}")
    
    if "mongodb" in filename_lower or "mongo" in stig_name_lower:
        if "mongodb" in tech_stack["databases"]:
            return (True, f"MongoDB detected in codebase: {tech_stack['databases']}")
        return (False, f"MongoDB STIG not applicable - databases detected: {tech_stack['databases'] or 'none'}")
    
    if "oracle" in filename_lower or "oracle" in stig_name_lower:
        if "oracle" in tech_stack["databases"]:
            return (True, f"Oracle detected in codebase: {tech_stack['databases']}")
        return (False, f"Oracle STIG not applicable - databases detected: {tech_stack['databases'] or 'none'}")
    
    if "database" in filename_lower and "srg" in filename_lower:
        if tech_stack["databases"]:
            return (True, f"Database SRG applicable - databases detected: {tech_stack['databases']}")
        return (False, f"Database SRG not applicable - no databases detected")
    
    # App server STIGs
    if "tomcat" in filename_lower or "tomcat" in stig_name_lower:
        if "tomcat" in tech_stack["app_servers"]:
            return (True, f"Tomcat detected in codebase: {tech_stack['app_servers']}")
        return (False, f"Tomcat STIG not applicable - app servers detected: {tech_stack['app_servers'] or 'none'}")
    
    if "jetty" in filename_lower or "jetty" in stig_name_lower:
        if "jetty" in tech_stack["app_servers"]:
            return (True, f"Jetty detected in codebase: {tech_stack['app_servers']}")
        return (False, f"Jetty STIG not applicable - app servers detected: {tech_stack['app_servers'] or 'none'}")
    
    if "jboss" in filename_lower or "wildfly" in filename_lower:
        if "jboss" in tech_stack["app_servers"]:
            return (True, f"JBoss/WildFly detected in codebase: {tech_stack['app_servers']}")
        return (False, f"JBoss STIG not applicable - app servers detected: {tech_stack['app_servers'] or 'none'}")
    
    # Framework STIGs
    if "dotnet" in filename_lower or ".net" in filename_lower or "dot_net" in filename_lower or "_dotnet_" in filename_lower or "_ms_" in filename_lower:
        if "dotnet" in tech_stack["frameworks"] or "csharp" in tech_stack["languages"]:
            return (True, f".NET detected - frameworks: {tech_stack['frameworks']}, languages: {tech_stack['languages']}")
        return (False, f".NET STIG not applicable - frameworks detected: {tech_stack['frameworks'] or 'none'}, languages: {tech_stack['languages'] or 'none'}")
    
    if "spring" in filename_lower or "spring" in stig_name_lower:
        if "spring" in tech_stack["frameworks"]:
            return (True, f"Spring framework detected: {tech_stack['frameworks']}")
        return (False, f"Spring STIG not applicable - frameworks detected: {tech_stack['frameworks'] or 'none'}")

    # Kubernetes / container STIGs
    if "kubernetes" in filename_lower or "k8s" in filename_lower or "kubernetes" in stig_name_lower:
        if "kubernetes" in tech_stack.get("infrastructure", []) or any(
            f in (" ".join(tech_stack.get("frameworks", [])) + " ".join(tech_stack.get("languages", []))).lower()
            for f in ("kubernetes", "k8s", "helm")
        ):
            return (True, f"Kubernetes/container tech detected")
        return (False, f"Kubernetes STIG not applicable - no Kubernetes/container tech detected")

    if "nginx" in filename_lower or "nginx" in stig_name_lower:
        if "nginx" in tech_stack.get("app_servers", []):
            return (True, f"Nginx detected: {tech_stack['app_servers']}")
        return (False, f"Nginx STIG not applicable - app servers detected: {tech_stack.get('app_servers') or 'none'}")

    if "redis" in filename_lower or "redis" in stig_name_lower:
        if "redis" in tech_stack.get("databases", []):
            return (True, f"Redis detected: {tech_stack['databases']}")
        return (False, f"Redis STIG not applicable - databases detected: {tech_stack.get('databases') or 'none'}")

    if "node" in filename_lower and ("stig" in filename_lower or "srg" in filename_lower):
        if "nodejs" in tech_stack.get("languages", []) or "javascript" in tech_stack.get("languages", []):
            return (True, f"Node.js detected: {tech_stack.get('languages')}")
        return (False, f"Node.js STIG not applicable - languages detected: {tech_stack.get('languages') or 'none'}")

    # Default: unrecognized STIG type — do NOT run by default.
    # Only the ASD STIG and explicitly matched STIGs should run automatically.
    return (False, f"STIG type not recognized — skipping to avoid scanning against non-applicable controls. "
                   f"To force-include, set STIGS_FILE to target this STIG directly.")


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


# How many of the top-ranked files each control is guaranteed in the context window.
# With the smaller default batch size (5 controls), 8 files per control = up to 40
# unique files in the priority pool before the global budget fill.
_GUARANTEED_FILES_PER_CONTROL = 3  # was 8; reduced to keep batch token budget in check


def extract_manual_stig_docs(files: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Separate manual STIG documentation from regular source files.
    
    Returns (manual_docs, remaining_files) where manual_docs are compliance-relevant
    markdown/JSON files that contain human-authored STIG assessments and should be
    presented to the AI separately with high priority.
    
    Manual docs are identified by:
    - Path contains: docs/, documentation/, .github/, .compliance/, security/
    - Filename matches: stig-findings.md, findings.md, COMPLIANCE.md, STIG.md, SECURITY.md
    - Filename contains: stig, findings, compliance, audit, controls, assessment
    
    Examples of paths that will be detected:
    - docs/stig-findings.md
    - docs/security/stig-findings.md
    - documentation/compliance/findings.md
    - .github/COMPLIANCE.md
    - STIG.md (at repo root)
    """
    manual_docs: list[tuple[str, str]] = []
    remaining: list[tuple[str, str]] = []
    
    for rel, content in files:
        path = Path(rel)
        stem_lower = path.stem.lower()
        
        is_manual_doc = False
        
        # Check directory path - matches both docs/file.md and docs/security/file.md
        if any(part in {"docs", "documentation", ".github", ".compliance", "security"} for part in path.parts):
            if path.suffix.lower() in {".md", ".json"}:
                is_manual_doc = True
        
        # Check filename patterns (catches files at repo root or in any directory)
        if path.suffix.lower() in {".md", ".json"}:
            manual_keywords = {"stig", "findings", "compliance", "audit", "controls", "assessment", "security"}
            if any(keyword in stem_lower for keyword in manual_keywords):
                is_manual_doc = True
        
        if is_manual_doc:
            manual_docs.append((rel, content))
        else:
            remaining.append((rel, content))
    
    return manual_docs, remaining


def build_code_context_for_batch(
    files: list[tuple[str, str]],
    controls_batch: list[dict[str, Any]],
    max_bytes: int = MAX_CODE_BYTES_PER_BATCH,
) -> str:
    """Build code context that guarantees each control's most-relevant files.

    Problem with the naive combined-keyword approach: files relevant to only
    one control get crowded out by files relevant to many controls, so the AI
    never sees the specific artifacts needed to satisfy that control.

    This function:
      1. Gives each control a guaranteed slot of its top-N most-relevant files
         (ranked by that control's keywords alone).
      2. Fills remaining budget with globally-ranked files (combined keywords).
      3. Deduplicates — each file appears only once regardless of how many
         controls need it.

    Result: every control is guaranteed to have at least some of its most
    relevant files present, even when sharing a batch with 9 other controls.
    """
    file_dict = {rel: content for rel, content in files}

    # Step 1 — per-control guaranteed files (ordered: most-shared first)
    from collections import Counter as _Counter
    slot_counts: _Counter[str] = _Counter()
    per_control_tops: dict[str, list[str]] = {}  # vuln_id -> [rel, ...]
    for c in controls_batch:
        kw = extract_keywords(c["check_content"])
        # Include the vuln_id itself (e.g. "APSC-DV-000070") as a keyword so
        # that any file with the control ID cited in a comment always scores
        # highest — this is the most reliable signal that a file implements
        # a specific control (developers often annotate compliance code with
        # the STIG ID).
        kw.append(c["vuln_id"].lower())
        ranked = rank_files_by_relevance(files, kw)
        top_rels = [rel for rel, _ in ranked[:_GUARANTEED_FILES_PER_CONTROL]]
        per_control_tops[c["vuln_id"]] = top_rels
        for rel in top_rels:
            slot_counts[rel] += 1

    # Priority order: files needed by most controls first, then alphabetically
    priority_rels = [rel for rel, _ in slot_counts.most_common()]

    # Step 2 — global fallback ranked by combined keywords
    all_kw: list[str] = []
    for c in controls_batch:
        all_kw.extend(extract_keywords(c["check_content"]))
        all_kw.append(c["vuln_id"].lower())
    global_ranked = [rel for rel, _ in rank_files_by_relevance(files, all_kw)]

    # Step 3 — merge: priority first, then globally ranked, deduped
    seen: set[str] = set()
    ordered_rels: list[str] = []
    for rel in priority_rels + global_ranked:
        if rel not in seen:
            seen.add(rel)
            ordered_rels.append(rel)

    # Step 4 — fill within budget
    parts: list[str] = []
    total = 0
    skipped: list[str] = []

    for rel in ordered_rels:
        content = file_dict.get(rel, "")
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

When in doubt, return applicable=false. Only return applicable=true when the \
STIG technology is clearly present in or directly relevant to this application.

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
        top_p=1.0,
        seed=42,
        max_tokens=300,
        messages=[
            {"role": "system", "content": _APPLICABILITY_SYSTEM_PROMPT},
            {"role": "user",   "content": user_message},
        ],
    )
        usage = response.usage
        prompt_tokens     = usage.prompt_tokens     if usage else 0
        completion_tokens = usage.completion_tokens if usage else 0
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
        parsed = json.loads(raw)
        applicable = bool(parsed.get("applicable", True))
        reason     = str(parsed.get("reason", "")).strip()
        return applicable, reason, prompt_tokens, completion_tokens
    except Exception as exc:  # pylint: disable=broad-except
        return False, f"Applicability check failed ({exc}) — skipping STIG to avoid scanning non-applicable controls", 0, 0


# ---------------------------------------------------------------------------
# OpenAI call
# ---------------------------------------------------------------------------

def call_openai(
    client: Any,
    model: str,
    controls_batch: list[dict[str, Any]],
    code_context: str,
    repo_manifest: str = "",
    previous_assessments: dict[str, dict[str, Any]] | None = None,
    security_findings: str = "",
    suppression_rules: str = "",
    manual_stig_docs: str = "",
) -> tuple[list[dict[str, Any]], int, int]:
    """Call GPT with a batch of controls + full repo manifest + code context.
    
    Args:
        client: OpenAI client instance
        model: Model name (e.g., 'gpt-4o-mini')
        controls_batch: List of control dicts to assess
        code_context: Application source code
        repo_manifest: Full file tree listing
        previous_assessments: Optional dict mapping vuln_id -> previous assessment results
        security_findings: Current scan's security findings summary
        suppression_rules: Risk acceptance/suppression rules from .epyon-ignore.yml
        manual_stig_docs: Human-authored STIG assessments (stig-findings.md, COMPLIANCE.md, etc.)
    
    Returns:
        Tuple of (parsed_results, prompt_tokens, completion_tokens)
    """
    previous_assessments = previous_assessments or {}
    
    controls_json = json.dumps(
        [
            {
                "vuln_id":           c["vuln_id"],
                "title":             c["title"],
                "check_content":     c["check_content"],
                "fix_text":          c["fix_text"],
                "previous_status":   previous_assessments.get(c["vuln_id"], {}).get("status"),
                "previous_evidence": previous_assessments.get(c["vuln_id"], {}).get("evidence"),
            }
            for c in controls_batch
        ],
        indent=2,
    )

    manifest_section = f"{repo_manifest}\n\n" if repo_manifest else ""
    security_section = f"{security_findings}\n\n" if security_findings else ""
    suppression_section = f"{suppression_rules}\n\n" if suppression_rules else ""
    
    # Manual STIG documentation gets top priority placement - presented BEFORE code
    manual_docs_section = ""
    if manual_stig_docs:
        manual_docs_section = (
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "MANUAL STIG DOCUMENTATION (PRIORITY — DEFER TO THESE ASSESSMENTS)\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "\n"
            "The following files contain human-authored STIG assessments, manual overrides,\n"
            "compliance notes, and verified evidence. THESE TAKE ABSOLUTE PRIORITY.\n"
            "\n"
            "DO NOT override these manual assessments unless you find SPECIFIC CODE CHANGES\n"
            "that materially invalidate the documented assessment. If a human has documented\n"
            "a control as satisfied with evidence, RESPECT that assessment.\n"
            "\n"
            f"{manual_stig_docs}\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "\n"
        )

    user_message = (
        f"{manifest_section}"
        f"{security_section}"
        f"{suppression_section}"
        f"{manual_docs_section}"
        f"Controls to assess ({len(controls_batch)} total):\n{controls_json}\n\n"
        f"Application source code (examine every file carefully):\n{code_context}"
    )

    # Derive a deterministic seed from the batch vuln_ids so the same controls
    # always get the same seed regardless of which run number this is.
    import hashlib as _hashlib
    _seed_input = ",".join(c["vuln_id"] for c in controls_batch).encode()
    _seed = int(_hashlib.sha256(_seed_input).hexdigest()[:8], 16) % (2**31)

    response = client.chat.completions.create(
        model=model,
        temperature=0,
        top_p=1.0,
        seed=_seed,
        max_tokens=8192,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_message},
        ],
    )

    usage = response.usage
    prompt_tokens     = usage.prompt_tokens     if usage else 0
    completion_tokens = usage.completion_tokens if usage else 0

    raw = response.choices[0].message.content.strip()

    # Strip markdown code fences if the model added them anyway
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    return json.loads(raw), prompt_tokens, completion_tokens


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
        status   = assessed.get("status",     "Open")
        evidence = assessed.get("evidence",   FALLBACK_EVIDENCE).strip()
        confidence = assessed.get("confidence", 0)

        lines.append(f"### {number}. {vuln_id} | {rule_id}")
        lines.append("")
        lines.append(f"- Rule ID: {rule_id}")
        lines.append(f"- Severity: {sev}")
        lines.append(f"- Rule Title: {title}")
        lines.append("")
        lines.append(f"Status: {status}")
        lines.append(f"Confidence: {confidence}/100")
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
        evidence   = assessed.get("evidence",   "").strip()
        confidence = assessed.get("confidence", 0)

        finding_details = evidence
        if finding_details:
            finding_details += f"\n\nConfidence: {confidence}/100"
        else:
            finding_details = f"Confidence: {confidence}/100"

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
            "finding_details":          finding_details,
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
    manual_docs: list[tuple[str, str]],
    scan_dir: Path,
    app_name: str,
    model: str,
    batch_size: int,
    delay: float,
    api_key: str,
    base_url: str,
    scan_date: str,
    slug: str,
    is_primary: bool,
    target_dir: str,
) -> None:
    """Run assessment for a single STIG and write output files.
    
    Args:
        manual_docs: Human-authored STIG documentation files (stig-findings.md, etc.)
                     that will be presented to AI with priority
    """
    controls  = stig_data["controls"]
    stig_name = stig_data["stig_name"]

    print(f"[INFO] [{slug}] Loaded {len(controls)} controls from '{stig_name}'", file=sys.stderr)

    # Persist parsed controls
    controls_path = scan_dir / f"stig-controls-{slug}.json"
    controls_path.write_text(json.dumps(stig_data, indent=2), encoding="utf-8")
    print(f"[INFO] [{slug}] Controls written to {controls_path}", file=sys.stderr)
    
    # Collect additional context for AI assessments (limited to avoid context overflow)
    # These will be reduced further on retry if context_length_exceeded occurs
    security_findings_context = collect_security_findings(scan_dir, max_findings=3)
    suppression_rules_context = collect_suppression_rules(target_dir, max_rules=10)
    
    if security_findings_context:
        print(f"[INFO] [{slug}] Loaded security findings from current scan (limited for token budget)", file=sys.stderr)
    if suppression_rules_context:
        print(f"[INFO] [{slug}] Loaded suppression rules from .epyon-ignore.yml (limited for token budget)", file=sys.stderr)
    
    # Build manual STIG documentation string for AI priority context
    manual_docs_context = ""
    if manual_docs:
        parts = []
        for rel, content in manual_docs:
            parts.append(f"### FILE: {rel}\n```\n{content}\n```\n")
        manual_docs_context = "\n".join(parts)
        print(f"[INFO] [{slug}] Loaded {len(manual_docs)} manual STIG documentation file(s) for priority context", file=sys.stderr)

    assessments: dict[str, dict[str, str]] = {}
    total_prompt_tokens     = 0
    total_completion_tokens = 0

    if not api_key:
        for c in controls:
            assessments[c["vuln_id"]] = {
                "status":     "Not Reviewed",
                "evidence":   "STIG assessment skipped: OPENAI_API_KEY not configured.",
                "confidence": 0,
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

        client = OpenAI(api_key=api_key, **(dict(base_url=base_url) if base_url else {}))

        # ── Applicability pre-check ───────────────────────────────────────
        # Use all files (code + manual docs) for app profile to get complete picture
        all_files_for_profile = source_files + manual_docs
        app_profile = build_app_profile(app_name, all_files_for_profile)
        applicable, applicability_reason, appl_pt, appl_ct = check_stig_applicability(
            client, model, stig_data, app_profile
        )
        total_prompt_tokens     = appl_pt
        total_completion_tokens = appl_ct
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
        # Include both code files and manual docs in the manifest.
        all_files_for_manifest = source_files + manual_docs
        repo_manifest = build_repo_manifest(all_files_for_manifest)

        # Always load previous STIG results when available. The model uses them
        # to confirm unchanged findings or update when evidence has changed.
        # This is the primary mechanism for scan-to-scan consistency.
        # Walk backwards through ALL previous scans for this app until we find
        # one that has a results file for this specific STIG slug — the most
        # recent scan may not have run a STIG assessment at all.
        previous_assessments: dict[str, dict[str, Any]] = {}
        previous_scan_used: Path | None = None
        for candidate in find_previous_scan_dirs(scan_dir, app_name):
            loaded = load_previous_stig_results(candidate, slug)
            if loaded:
                previous_assessments = loaded
                previous_scan_used = candidate
                break

        if previous_scan_used:
            print(
                f"[INFO] [{slug}] Loaded {len(previous_assessments)} previous assessments "
                f"from {previous_scan_used.name} — model will confirm or update each finding",
                file=sys.stderr,
            )
        else:
            print(
                f"[INFO] [{slug}] No previous scan found — all controls assessed fresh",
                file=sys.stderr,
            )

        # ── Freeze stable controls ────────────────────────────────────────────
        # Controls that were assessed as "Not a Finding" or "Not Applicable" with
        # confidence ≥ 85 in the previous scan are carried forward unchanged.
        # This prevents high-confidence closed controls from flip-flopping between
        # runs and builds trust in the scan results.
        # Only "Open" and "Not Reviewed" controls are re-assessed each run.
        _FREEZE_STATUSES    = {"Not a Finding", "Not Applicable"}
        _FREEZE_MIN_CONF    = 85
        frozen_assessments: dict[str, dict[str, Any]] = {}
        controls_to_assess: list[dict[str, Any]] = []

        for ctrl in controls:
            vid  = ctrl["vuln_id"]
            prev = previous_assessments.get(vid, {})
            prev_status     = prev.get("status", "")
            prev_conf       = prev.get("confidence", 0)
            locked_by_human = bool(prev.get("locked_by_human", False))
            if locked_by_human or (prev_status in _FREEZE_STATUSES and prev_conf >= _FREEZE_MIN_CONF):
                frozen_assessments[vid] = {
                    "status":             prev_status,
                    "evidence":           prev.get("evidence", ""),
                    "confidence":         prev_conf,
                    "locked_by_previous": True,
                    "locked_by_human":    locked_by_human,
                }
            else:
                controls_to_assess.append(ctrl)

        frozen_count = len(frozen_assessments)
        if frozen_count:
            human_locked = sum(1 for v in frozen_assessments.values() if v.get("locked_by_human"))
            print(
                f"[INFO] [{slug}] Freezing {frozen_count} stable controls "
                f"({human_locked} human-locked, remainder automatically frozen: status in {_FREEZE_STATUSES!r} "
                f"with confidence ≥ {_FREEZE_MIN_CONF}) "
                f"— {len(controls_to_assess)} controls will be re-assessed",
                file=sys.stderr,
            )
            assessments.update(frozen_assessments)

        # Sort controls by vuln_id before batching so identical control sets always
        # produce identical batches regardless of STIG file parse order.  Deterministic
        # batching is necessary for reproducible scan-to-scan results.
        controls_to_assess.sort(key=lambda c: c["vuln_id"])

        # Re-batch only the controls that need re-assessment
        batches      = [controls_to_assess[i : i + batch_size] for i in range(0, len(controls_to_assess), batch_size)]
        total_batches = len(batches)
        # ─────────────────────────────────────────────────────────────────

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

            # Retry loop — up to _MAX_BATCH_RETRIES attempts on JSON/API failure
            # before falling back to Open.  On context_length_exceeded we progressively
            # reduce ALL context sources: code budget, manifest, findings, suppressions, manual docs.
            results: list[dict[str, Any]] = []
            last_err: str = ""
            code_budget = MAX_CODE_BYTES_PER_BATCH
            active_manifest = repo_manifest  # may be dropped on overflow
            active_findings = security_findings_context
            active_suppressions = suppression_rules_context
            active_manual_docs = manual_docs_context
            for attempt in range(1, _MAX_BATCH_RETRIES + 1):
                # (Re)build context — uses current code_budget, which may have
                # been reduced on a previous context_length_exceeded error.
                code_context = build_code_context_for_batch(
                    source_files, batch, max_bytes=code_budget
                )
                try:
                    results, batch_pt, batch_ct = call_openai(
                        client, model, batch, code_context, active_manifest, previous_assessments,
                        active_findings, active_suppressions, active_manual_docs
                    )
                    total_prompt_tokens     += batch_pt
                    total_completion_tokens += batch_ct
                    print(
                        f"[INFO] [{slug}] Batch {idx} tokens — "
                        f"prompt: {batch_pt:,}  completion: {batch_ct:,}  "
                        f"total so far: {total_prompt_tokens + total_completion_tokens:,}",
                        file=sys.stderr,
                    )
                    last_err = ""
                    break  # success
                except json.JSONDecodeError as e:
                    last_err = f"invalid JSON: {e}"
                    print(
                        f"[WARNING] [{slug}] Batch {idx} attempt {attempt}/{_MAX_BATCH_RETRIES} — {last_err}",
                        file=sys.stderr,
                    )
                except Exception as e:  # pylint: disable=broad-except
                    last_err = f"API error: {e}"
                    err_str = str(e)
                    if "context_length_exceeded" in err_str:
                        # Progressive reduction strategy on context overflow:
                        # Attempt 1: Drop findings/suppressions (but keep manual docs), keep manifest, halve code
                        # Attempt 2: Drop manual docs + manifest too, restore full code budget
                        # Attempt 3: Halve code again as last resort
                        if attempt == 1:
                            print(
                                f"[WARNING] [{slug}] Batch {idx} attempt {attempt}/{_MAX_BATCH_RETRIES} — "
                                f"{last_err}  →  dropping findings/suppressions, reducing code {code_budget // 1024}KB → {code_budget // 2 // 1024}KB",
                                file=sys.stderr,
                            )
                            active_findings = ""
                            active_suppressions = ""
                            code_budget = max(10_000, code_budget // 2)
                        elif attempt == 2:
                            print(
                                f"[WARNING] [{slug}] Batch {idx} attempt {attempt}/{_MAX_BATCH_RETRIES} — "
                                f"{last_err}  →  dropping manual docs + manifest, restoring code budget to {MAX_CODE_BYTES_PER_BATCH // 1024}KB",
                                file=sys.stderr,
                            )
                            active_manual_docs = ""
                            active_manifest = ""
                            code_budget = MAX_CODE_BYTES_PER_BATCH
                        else:
                            new_budget = max(10_000, code_budget // 2)
                            print(
                                f"[WARNING] [{slug}] Batch {idx} attempt {attempt}/{_MAX_BATCH_RETRIES} — "
                                f"{last_err}  →  reducing code budget {code_budget // 1024}KB → {new_budget // 1024}KB",
                                file=sys.stderr,
                            )
                            code_budget = new_budget
                    else:
                        print(
                            f"[WARNING] [{slug}] Batch {idx} attempt {attempt}/{_MAX_BATCH_RETRIES} — {last_err}",
                            file=sys.stderr,
                        )
            if last_err:
                print(
                    f"[WARNING] [{slug}] Batch {idx} failed after {_MAX_BATCH_RETRIES} attempts — "
                    f"controls will be marked Open/0",
                    file=sys.stderr,
                )

            assessed_ids: set[str] = set()
            for item in results:
                vid = item.get("vuln_id", "")
                if vid:
                    raw_conf = item.get("confidence", 0)
                    try:
                        conf = min(100, max(0, int(raw_conf)))
                    except (TypeError, ValueError):
                        conf = 0

                    # Normalize status to canonical enum value
                    status = normalize_status(item.get("status"))

                    # Confidence floor: a non-Open assessment with very low confidence
                    # is untrustworthy.  Downgrade to Open so it gets re-assessed when
                    # the model has better context rather than being carried forward as
                    # a false satisfaction.
                    if status in ("Not a Finding", "Not Applicable") and conf < _MIN_CONFIDENCE_FOR_CLOSED_STATUS:
                        print(
                            f"[WARNING] [{slug}] {vid}: status '{status}' downgraded to 'Open' "
                            f"(confidence {conf} < minimum {_MIN_CONFIDENCE_FOR_CLOSED_STATUS})",
                            file=sys.stderr,
                        )
                        status = "Open"

                    assessments[vid] = {
                        "status":     status,
                        "evidence":   item.get("evidence", FALLBACK_EVIDENCE),
                        "confidence": conf,
                    }
                    assessed_ids.add(vid)
            for c in batch:
                if c["vuln_id"] not in assessed_ids:
                    assessments[c["vuln_id"]] = {
                        "status":     "Open",
                        "evidence":   FALLBACK_EVIDENCE,
                        "confidence": 0,
                    }

            if idx < total_batches:
                time.sleep(delay)

    # Write raw results
    results_path = scan_dir / f"stig-results-{slug}.json"
    output_data: dict[str, Any] = {
        "assessments": assessments,
        "token_usage": {
            "prompt_tokens":     total_prompt_tokens     if api_key else 0,
            "completion_tokens": total_completion_tokens if api_key else 0,
            "total_tokens":      (total_prompt_tokens + total_completion_tokens) if api_key else 0,
        },
    }
    results_path.write_text(json.dumps(output_data, indent=2), encoding="utf-8")
    if api_key:
        print(
            f"[INFO] [{slug}] Token usage — "
            f"prompt: {total_prompt_tokens:,}  "
            f"completion: {total_completion_tokens:,}  "
            f"total: {total_prompt_tokens + total_completion_tokens:,}",
            file=sys.stderr,
        )
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
    parser.add_argument("--model",      default="gpt-4o-mini", help="OpenAI model (default: gpt-4o-mini)")
    parser.add_argument("--base-url",   default="",
                        help="Override the OpenAI API base URL (e.g. http://localhost:11434/v1 for Ollama). "
                             "Also read from OPENAI_BASE_URL env var.")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE_DEFAULT,
                        help=f"Controls per API call (default: {BATCH_SIZE_DEFAULT})")
    parser.add_argument("--delay",      type=float, default=1.0,
                        help="Seconds between API calls (default: 1.0)")
    args = parser.parse_args()

    model    = os.environ.get("OPENAI_MODEL", args.model)
    api_key  = os.environ.get("OPENAI_API_KEY", "")
    base_url = os.environ.get("OPENAI_BASE_URL", args.base_url).strip()

    # Validate base_url if provided — SSRF guard
    if base_url:
        parsed = urllib.parse.urlparse(base_url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            print(
                f"[ERROR] --base-url / OPENAI_BASE_URL is not a valid http(s) URL: {base_url}",
                file=sys.stderr,
            )
            sys.exit(1)
        if not _base_url_allowed(base_url):
            print(
                f"[ERROR] --base-url host is not allowed.\n"
                f"  Allowed: public OpenAI API, localhost, private/RFC1918 addresses, "
                f"Kubernetes service hostnames, or hosts in EPYON_AI_ALLOWED_HOSTS.\n"
                f"  Got: {base_url}",
                file=sys.stderr,
            )
            sys.exit(1)

    # Local models often don't require a real API key
    # Accept a placeholder ('local', 'ollama', etc.) to satisfy the SDK
    if not api_key and base_url and _is_internal_host(_hostname(base_url)):
        api_key = "local"
        print(
            "[INFO] Local model endpoint detected — using placeholder API key. "
            "Set OPENAI_API_KEY if your server requires authentication.",
            file=sys.stderr,
        )

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
    
    # ── Extract manual STIG documentation ──────────────────────────────────
    manual_docs, code_files = extract_manual_stig_docs(source_files)
    if manual_docs:
        print(f"[INFO] Found {len(manual_docs)} manual STIG documentation file(s):", file=sys.stderr)
        for rel, _ in manual_docs:
            print(f"         - {rel}", file=sys.stderr)
    
    # Use code_files (without manual docs) for keyword ranking to avoid ranking bias
    # Manual docs will be presented separately with priority
    source_files_for_ranking = code_files
    print("", file=sys.stderr)

    # ── Detect technology stack ───────────────────────────────────────────
    print(f"[INFO] Detecting technology stack...", file=sys.stderr)
    tech_stack = detect_technologies(source_files)
    print(f"[INFO] Technologies detected:", file=sys.stderr)
    if tech_stack["languages"]:
        print(f"         Languages: {', '.join(tech_stack['languages'])}", file=sys.stderr)
    if tech_stack["frameworks"]:
        print(f"         Frameworks: {', '.join(tech_stack['frameworks'])}", file=sys.stderr)
    if tech_stack["databases"]:
        print(f"         Databases: {', '.join(tech_stack['databases'])}", file=sys.stderr)
    if tech_stack["app_servers"]:
        print(f"         App Servers: {', '.join(tech_stack['app_servers'])}", file=sys.stderr)
    print(f"         Web UI: {'Yes' if tech_stack['has_web_ui'] else 'No'}", file=sys.stderr)
    print("", file=sys.stderr)

    # ── Filter STIGs by applicability ─────────────────────────────────────
    applicable_stigs: list[tuple[Path, dict, str, bool]] = []  # (path, data, slug, is_primary)
    skipped_stigs: list[tuple[str, str]] = []  # (filename, reason)
    
    for i, stig_path in enumerate(stig_files):
        try:
            stig_data = parse_stig_file(str(stig_path))
        except (FileNotFoundError, ValueError) as e:
            print(f"[ERROR] Failed to parse {stig_path.name}: {e}", file=sys.stderr)
            continue
        
        stig_name = stig_data.get("stig_name", "")
        slug = slug_from_stig(stig_data, str(stig_path))
        
        # Check applicability
        is_applicable, reason = is_stig_applicable(stig_path.name, stig_name, tech_stack)
        
        if is_applicable:
            is_primary = (len(applicable_stigs) == 0)  # first applicable STIG is primary
            applicable_stigs.append((stig_path, stig_data, slug, is_primary))
            print(f"[INFO] ✓ {stig_path.name} is applicable", file=sys.stderr)
            print(f"       → {reason}", file=sys.stderr)
        else:
            skipped_stigs.append((stig_path.name, reason))
            print(f"[INFO] ✗ {stig_path.name} skipped (not applicable)", file=sys.stderr)
            print(f"       → {reason}", file=sys.stderr)
    
    print("", file=sys.stderr)
    
    if not applicable_stigs:
        print(f"[WARNING] No applicable STIGs found for this application.", file=sys.stderr)
        print(f"[WARNING] Tech stack: {tech_stack}", file=sys.stderr)
        sys.exit(0)
    
    print(f"[INFO] Processing {len(applicable_stigs)} applicable STIG(s)", file=sys.stderr)
    if skipped_stigs:
        print(f"[INFO] Skipped {len(skipped_stigs)} non-applicable STIG(s)", file=sys.stderr)
    print("", file=sys.stderr)

    # ── Process each applicable STIG ──────────────────────────────────────
    for stig_path, stig_data, slug, is_primary in applicable_stigs:
        print(f"[INFO] Processing: {stig_path.name}", file=sys.stderr)

        _assess_stig(
            stig_data=stig_data,
            stig_path=str(stig_path),
            source_files=source_files_for_ranking,  # code files only (manual docs shown separately)
            manual_docs=manual_docs,  # human-authored STIG documentation
            scan_dir=scan_dir,
            app_name=args.app_name,
            model=model,
            batch_size=args.batch_size,
            delay=args.delay,
            api_key=api_key,
            base_url=base_url,
            scan_date=scan_date,
            slug=slug,
            is_primary=is_primary,
            target_dir=args.target,
        )


if __name__ == "__main__":
    main()
