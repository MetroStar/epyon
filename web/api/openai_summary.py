"""
OpenAI executive summary — generates an AI-powered narrative summary
of scan findings using the OpenAI Chat Completions API.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_HERE = Path(__file__).parent
AI_CONFIG_FILE = _HERE / ".." / "ai-config.json"


def _strip_code_fence(text: str) -> str:
    """Remove an outer fenced code block that some models wrap their Markdown output in."""
    import re

    t = text.strip()
    # Strip leading ```[lang] ... ``` wrapper (case-insensitive, supports \r\n and lang like 'markdown')
    stripped = re.sub(r"^```[\w-]*\r?\n", "", t, count=1, flags=re.IGNORECASE)
    if stripped != t:
        stripped = re.sub(r"\r?\n```\s*$", "", stripped)
    return stripped.strip()


def read_ai_config() -> dict:
    try:
        return json.loads(AI_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_ai_config(cfg: dict) -> None:
    AI_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    AI_CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def get_api_key() -> str | None:
    cfg = read_ai_config()
    if cfg.get("api_key"):
        return cfg["api_key"]
    env_key = os.environ.get("OPENAI_API_KEY")
    if env_key:
        return env_key
    # Self-hosted, OpenAI-compatible backends (Ollama, vLLM, LocalAI, an
    # in-cluster AI gateway, ...) typically do not authenticate requests, but
    # the OpenAI SDK still refuses to initialize with an empty key. When a
    # custom (non-OpenAI) base URL is configured, fall back to a non-secret
    # placeholder so summaries work without a real key. A genuine
    # api.openai.com endpoint still returns None here and surfaces the
    # "key not configured" guidance.
    if _is_self_hosted(get_base_url()):
        return _PLACEHOLDER_API_KEY
    return None


# Default model used when neither the UI config nor the environment specify one.
DEFAULT_MODEL = "gpt-4o-mini"


def get_model() -> str:
    """Resolve the chat model name.

    Precedence (mirrors get_api_key): the UI-managed ai-config.json wins so a
    value chosen in Settings is honored, then the OPENAI_MODEL environment
    variable (so deployments such as Quartz can point the web summaries at a
    self-hosted model like gemma4:26b without touching the UI), and finally a
    hard-coded default.
    """
    cfg = read_ai_config()
    return cfg.get("model") or os.environ.get("OPENAI_MODEL") or DEFAULT_MODEL


# A non-secret placeholder used when talking to a self-hosted, OpenAI-compatible
# endpoint that does not authenticate requests. The OpenAI SDK rejects an empty
# api_key, so we supply a dummy one whenever a non-OpenAI base URL is configured.
_PLACEHOLDER_API_KEY = "sk-local-noauth"

# Substrings identifying the real, authenticated OpenAI API. A request to one of
# these genuinely requires a user-supplied key, so we never substitute a
# placeholder for them.
_OPENAI_PUBLIC_HOSTS = ("api.openai.com",)


def get_base_url() -> str | None:
    """Resolve the OpenAI-compatible base URL.

    Precedence mirrors get_api_key()/get_model(): the UI-managed ai-config.json
    wins, then the OPENAI_BASE_URL environment variable, then None (the SDK's
    default, i.e. the public OpenAI API). The OpenAI SDK only auto-reads the
    environment variable, so a base URL chosen in the Settings UI must be passed
    to the client explicitly (see the AsyncOpenAI call sites below).
    """
    cfg = read_ai_config()
    return cfg.get("base_url") or os.environ.get("OPENAI_BASE_URL") or None


def _is_self_hosted(base_url: str | None) -> bool:
    """True when base_url points at something other than the public OpenAI API."""
    if not base_url:
        return False
    return not any(host in base_url for host in _OPENAI_PUBLIC_HOSTS)


# Maps scan_type values to human-readable classification used in prompts.
_CONTINUOUS_SCAN_TYPES = {"nightly"}
_EVALUATED_SCAN_LABELS: dict[str, str] = {
    "full":         "comprehensive point-in-time assessment",
    "quick":        "pull-request / development check",
    "stig":         "one-time STIG compliance assessment",
    "baseline":     "baseline establishment scan",
    "huggingface":  "model security evaluation",
}


def _classify_scan(scan_type: str) -> tuple[str, str]:
    """
    Returns (classification, description) where classification is
    'continuous' or 'evaluated'.
    """
    if scan_type in _CONTINUOUS_SCAN_TYPES:
        return (
            "continuous",
            "nightly automated monitoring scan — part of the ongoing security programme",
        )
    label = _EVALUATED_SCAN_LABELS.get(scan_type, "point-in-time evaluation")
    return "evaluated", label


_SYSTEM_PROMPT = (
    "You are a senior cybersecurity analyst. "
    "You will be given structured scan findings from an automated security scan "
    "of a software application, along with a scan_classification field that is "
    "either 'continuous' or 'evaluated'. "
    "IMPORTANT: if scan_classification is 'evaluated', open the summary with a "
    "prominent callout (e.g. > ⚠️ **One-time evaluation**) stating that this is "
    "a point-in-time scan and NOT part of the routine monitoring programme, so "
    "executives should not draw trend conclusions from it. "
    "If scan_classification is 'continuous', frame the summary in terms of the "
    "ongoing security posture and note whether findings have changed from prior "
    "nightly runs if trend data is available. "
    "Produce a concise executive summary (3–5 paragraphs) written for a non-technical "
    "stakeholder such as a CISO or program manager. "
    "The summary should: "
    "(1) state the overall risk posture, "
    "(2) highlight the most critical or impactful findings, "
    "(3) call out any secret/credential leaks or malware detections, "
    "(4) mention end-of-life components if present, "
    "(5) close with a prioritised remediation recommendation. "
    "Use plain language. Do not include raw CVE numbers unless essential. "
    "Format using Markdown with a short # heading per paragraph."
)


def _build_user_message(scan_id: str, scan_meta: dict, findings: dict) -> str:
    summary  = findings.get("summary", {})
    critical = findings.get("critical_findings", [])
    high     = findings.get("high_findings", [])

    critical_samples = critical[:15]
    high_samples     = high[:10]

    scan_type = scan_meta.get("scan_type", "")
    classification, classification_desc = _classify_scan(scan_type)

    payload = {
        "scan_id":               scan_id,
        "target":                scan_meta.get("target", ""),
        "scan_type":             scan_type,
        "scan_classification":   classification,
        "scan_classification_note": classification_desc,
        "timestamp":             scan_meta.get("timestamp", ""),
        "tools_used":            scan_meta.get("tools_analyzed", []),
        "counts": {
            "critical": summary.get("total_critical", 0),
            "high":     summary.get("total_high", 0),
            "medium":   summary.get("total_medium", 0),
            "low":      summary.get("total_low", 0),
        },
        "critical_findings_sample": [
            {
                "tool":    f.get("tool"),
                "id":      f.get("id"),
                "package": f.get("package"),
                "title":   f.get("title"),
                "target":  f.get("target"),
            }
            for f in critical_samples
        ],
        "high_findings_sample": [
            {
                "tool":    f.get("tool"),
                "id":      f.get("id"),
                "package": f.get("package"),
                "title":   f.get("title"),
            }
            for f in high_samples
        ],
    }

    if scan_meta.get("stig_total"):
        payload["stig"] = {
            "total":   scan_meta["stig_total"],
            "open":    scan_meta.get("stig_open", 0),
            "passing": scan_meta.get("stig_pass", 0),
            "n_a":     scan_meta.get("stig_na", 0),
        }

    return (
        "Please produce an executive summary for the following security scan results:\n\n"
        + json.dumps(payload, indent=2)
    )


async def generate_summary(scan_id: str, scan_meta: dict, findings: dict) -> str:
    api_key = get_api_key()
    if not api_key:
        raise RuntimeError(
            "OpenAI API key not configured. "
            "Add it in Settings or set OPENAI_API_KEY."
        )

    try:
        from openai import AsyncOpenAI
    except ImportError:
        raise RuntimeError("The 'openai' package is not installed. Run: pip install openai")

    model = get_model()

    client = AsyncOpenAI(api_key=api_key, base_url=get_base_url())
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": _build_user_message(scan_id, scan_meta, findings)},
        ],
        max_tokens=1200,
        temperature=0.3,
    )
    return response.choices[0].message.content or ""


_TECHNICAL_SYSTEM_PROMPT = (
    "You are a senior cybersecurity engineer writing a technical security brief for a development team. "
    "You will be given structured scan findings from an automated security scan of a software application. "
    "Produce a detailed technical summary that engineers can act on immediately. "
    "The summary should: "
    "(1) state the overall risk posture with specific severity counts per tool, "
    "(2) list every critical finding with exact CVE ID, CVSS score, affected package, affected version, "
    "and the recommended fixed version or remediation command, "
    "(3) call out all high findings with the same detail, grouped by tool, "
    "(4) detail any secrets or credentials detected — include file path and secret type (masked value), "
    "with priority rotation guidance, "
    "(5) list end-of-life components with their EOL date and recommended upgrade path, "
    "(6) summarise IaC/configuration findings from Checkov with check IDs and the misconfigured resource, "
    "(7) list open STIG controls by ID if present, "
    "(8) close with a prioritised remediation checklist ordered by risk impact. "
    "Be precise and technical. Include exact package names, versions, CVE IDs, and CVSS scores. "
    "Format using Markdown: use ## headings per tool/category, use bullet lists for findings, "
    "use inline code (backticks) for package names, CVE IDs, versions, and file paths."
)


def _build_technical_user_message(scan_id: str, scan_meta: dict, findings: dict) -> str:
    summary  = findings.get("summary", {})
    critical = findings.get("critical_findings", [])
    high     = findings.get("high_findings", [])
    medium   = findings.get("medium_findings", [])

    def _fmt_finding(f: dict) -> dict:
        return {
            "tool":          f.get("tool"),
            "id":            f.get("id"),
            "package":       f.get("package"),
            "version":       f.get("version"),
            "fixed_version": f.get("fixed_version"),
            "cvss":          f.get("cvss"),
            "title":         f.get("title"),
            "target":        f.get("target"),
            "severity":      f.get("severity"),
        }

    payload: dict = {
        "scan_id":    scan_id,
        "target":     scan_meta.get("target", ""),
        "scan_type":  scan_meta.get("scan_type", ""),
        "timestamp":  scan_meta.get("timestamp", ""),
        "tools_used": scan_meta.get("tools_analyzed", []),
        "counts": {
            "critical": summary.get("total_critical", 0),
            "high":     summary.get("total_high", 0),
            "medium":   summary.get("total_medium", 0),
            "low":      summary.get("total_low", 0),
        },
        "critical_findings": [_fmt_finding(f) for f in critical[:50]],
        "high_findings":     [_fmt_finding(f) for f in high[:50]],
        "medium_findings_sample": [_fmt_finding(f) for f in medium[:20]],
    }

    if scan_meta.get("stig_total"):
        payload["stig"] = {
            "total":    scan_meta["stig_total"],
            "open":     scan_meta.get("stig_open", 0),
            "passing":  scan_meta.get("stig_pass", 0),
            "n_a":      scan_meta.get("stig_na", 0),
            "reports":  [r.get("slug") for r in scan_meta.get("stig_reports", [])],
        }

    return (
        "Please produce a technical security summary for the following scan results:\n\n"
        + json.dumps(payload, indent=2)
    )


async def generate_technical_summary(scan_id: str, scan_meta: dict, findings: dict) -> str:
    api_key = get_api_key()
    if not api_key:
        raise RuntimeError(
            "OpenAI API key not configured. "
            "Add it in Settings or set OPENAI_API_KEY."
        )

    try:
        from openai import AsyncOpenAI
    except ImportError:
        raise RuntimeError("The 'openai' package is not installed. Run: pip install openai")

    model = get_model()

    client = AsyncOpenAI(api_key=api_key, base_url=get_base_url())
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _TECHNICAL_SYSTEM_PROMPT},
            {"role": "user",   "content": _build_technical_user_message(scan_id, scan_meta, findings)},
        ],
        max_tokens=1600,
        temperature=0.2,
    )
    return response.choices[0].message.content or ""


def _split_apps_by_classification(apps: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split apps into (continuous, evaluated) using the monitored flag.
    Falls back to scan_type classification when the flag is absent."""
    continuous, evaluated = [], []
    for a in apps:
        if a.get("monitored") is True:
            continuous.append(a)
        elif a.get("monitored") is False:
            evaluated.append(a)
        else:
            # flag not present — fall back to scan_type
            classification, _ = _classify_scan(a.get("scan_type", ""))
            (continuous if classification == "continuous" else evaluated).append(a)
    return continuous, evaluated


def _app_summary_entry(a: dict, include_samples: bool = False) -> dict:
    entry: dict = {
        "name":     a["name"],
        "critical": a["critical"],
        "high":     a["high"],
        "medium":   a["medium"],
        "low":      a["low"],
        "tools":    a.get("tools_analyzed", []),
    }
    if include_samples:
        entry["critical_findings_sample"] = a.get("critical_sample", [])[:5]
    return entry


async def generate_global_summary(apps: list[dict], metrics: dict | None = None) -> str:
    api_key = get_api_key()
    if not api_key:
        raise RuntimeError(
            "OpenAI API key not configured. "
            "Add it in Settings or set OPENAI_API_KEY."
        )

    try:
        from openai import AsyncOpenAI
    except ImportError:
        raise RuntimeError("The 'openai' package is not installed. Run: pip install openai")

    model = get_model()

    continuous, evaluated = _split_apps_by_classification(apps)

    def _totals(subset: list[dict]) -> dict:
        return {
            "critical": sum(a["critical"] for a in subset),
            "high":     sum(a["high"]     for a in subset),
            "medium":   sum(a["medium"]   for a in subset),
            "low":      sum(a["low"]      for a in subset),
        }

    payload = {
        "scope":             "all_applications",
        "application_count": len(apps),
        "continuously_monitored": {
            "note":              "These applications run nightly automated scans and represent the ongoing security posture.",
            "application_count": len(continuous),
            "totals":            _totals(continuous),
            "applications":      [_app_summary_entry(a, include_samples=True) for a in continuous],
        },
        "point_in_time_evaluations": {
            "note":              "These are one-off assessments. Do NOT use their counts in trend or posture calculations for the continuous programme.",
            "application_count": len(evaluated),
            "totals":            _totals(evaluated),
            "applications":      [_app_summary_entry(a, include_samples=True) for a in evaluated],
        },
    }
    if metrics:
        payload["programme_metrics"] = metrics

    user_msg = (
        "Produce the executive security brief for the following data:\n\n"
        + json.dumps(payload, indent=2)
    )

    client = AsyncOpenAI(api_key=api_key, base_url=get_base_url())
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _GLOBAL_EXEC_SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        max_tokens=1400,
        temperature=0.3,
    )
    return _strip_code_fence(response.choices[0].message.content or "")


async def generate_global_technical_summary(apps: list[dict], metrics: dict | None = None) -> str:
    """Technical summary across all applications for the overview dashboard."""
    api_key = get_api_key()
    if not api_key:
        raise RuntimeError(
            "OpenAI API key not configured. "
            "Add it in Settings or set OPENAI_API_KEY."
        )

    try:
        from openai import AsyncOpenAI
    except ImportError:
        raise RuntimeError("The 'openai' package is not installed. Run: pip install openai")

    model = get_model()

    continuous, evaluated = _split_apps_by_classification(apps)

    def _tech_entry(a: dict) -> dict:
        return {
            "name":              a["name"],
            "critical":          a["critical"],
            "high":              a["high"],
            "medium":            a["medium"],
            "low":               a["low"],
            "tools":             a.get("tools_analyzed", []),
            "critical_findings": a.get("critical_sample", [])[:15],
            "high_findings":     a.get("high_sample", [])[:10],
        }

    def _totals(subset: list[dict]) -> dict:
        return {
            "critical": sum(a["critical"] for a in subset),
            "high":     sum(a["high"]     for a in subset),
            "medium":   sum(a["medium"]   for a in subset),
            "low":      sum(a["low"]      for a in subset),
        }

    payload = {
        "scope":             "all_applications",
        "application_count": len(apps),
        "continuously_monitored": {
            "note":              "Nightly automated scans — counts reflect the live security posture of the programme.",
            "application_count": len(continuous),
            "totals":            _totals(continuous),
            "applications":      [_tech_entry(a) for a in continuous],
        },
        "point_in_time_evaluations": {
            "note":              "One-off assessments — exclude from posture trend calculations.",
            "application_count": len(evaluated),
            "totals":            _totals(evaluated),
            "applications":      [_tech_entry(a) for a in evaluated],
        },
    }
    if metrics:
        payload["programme_metrics"] = metrics

    user_msg = (
        "Produce the technical security brief for the following data:\n\n"
        + json.dumps(payload, indent=2)
    )

    client = AsyncOpenAI(api_key=api_key, base_url=get_base_url())
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _GLOBAL_TECH_SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        max_tokens=1800,
        temperature=0.2,
    )
    return _strip_code_fence(response.choices[0].message.content or "")


async def generate_global_isso_summary(apps: list[dict], metrics: dict | None = None) -> str:
    """ISSO-focused summary covering NIST/STIG controls, evidence, validation status,
    POA&M risk statements, and system/mission context."""
    api_key = get_api_key()
    if not api_key:
        raise RuntimeError(
            "OpenAI API key not configured. "
            "Add it in Settings or set OPENAI_API_KEY."
        )

    try:
        from openai import AsyncOpenAI
    except ImportError:
        raise RuntimeError("The 'openai' package is not installed. Run: pip install openai")

    model = get_model()

    continuous, evaluated = _split_apps_by_classification(apps)

    def _isso_entry(a: dict) -> dict:
        return {
            "name":              a["name"],
            "critical":          a["critical"],
            "high":              a["high"],
            "medium":            a["medium"],
            "low":               a["low"],
            "tools":             a.get("tools_analyzed", []),
            "stig_summary":      a.get("stig_summary"),          # open/pass/na totals
            "suppressed_count":  a.get("suppressed_count", 0),
            "suppressed_sample": a.get("suppressed_sample", []), # type/severity/reason
            "critical_findings": a.get("critical_sample", [])[:12],
            "high_findings":     a.get("high_sample", [])[:8],
        }

    def _totals(subset: list[dict]) -> dict:
        return {
            "critical": sum(a["critical"] for a in subset),
            "high":     sum(a["high"]     for a in subset),
            "medium":   sum(a["medium"]   for a in subset),
            "low":      sum(a["low"]      for a in subset),
        }

    payload = {
        "scope":             "all_applications",
        "application_count": len(apps),
        "continuously_monitored": {
            "note":              "Nightly automated scans — authoritative posture data for ATO/cATO.",
            "application_count": len(continuous),
            "totals":            _totals(continuous),
            "applications":      [_isso_entry(a) for a in continuous],
        },
        "point_in_time_evaluations": {
            "note":              "One-off assessments — treat as spot audits, not posture trend data.",
            "application_count": len(evaluated),
            "totals":            _totals(evaluated),
            "applications":      [_isso_entry(a) for a in evaluated],
        },
    }
    if metrics:
        payload["programme_metrics"] = metrics

    user_msg = (
        "Produce the ISSO compliance brief for the following data:\n\n"
        + json.dumps(payload, indent=2)
    )

    client = AsyncOpenAI(api_key=api_key, base_url=get_base_url())
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _GLOBAL_ISSO_SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        max_tokens=2000,
        temperature=0.2,
    )
    return _strip_code_fence(response.choices[0].message.content or "")


# ── Per-finding fix suggestion ─────────────────────────────────

_GLOBAL_EXEC_SYSTEM_PROMPT = (
    "You are a senior cybersecurity analyst writing a cross-portfolio executive security brief "
    "for a CISO or program manager. "
    "You will receive aggregated scan data for multiple applications, already separated into "
    "two groups: 'continuously_monitored' (nightly automated scans that represent the ongoing "
    "security posture) and 'point_in_time_evaluations' (one-off assessments that must NOT be "
    "used to draw trend conclusions). "
    "You will also receive a 'programme_metrics' block with programme-level KPIs; incorporate "
    "the most relevant of these into your summary under a dedicated ## Programme Health Metrics "
    "section placed BEFORE the per-group sections. Cover: "
    "(a) SLA compliance — using the 'sla_compliance' block, report how many resolved finding instances exceeded their severity-tiered deadline (the 'exceeded_sla' field per severity). "
    "These are counts of unique tool+CVE+package tuples that were remediated late — the same CVE affecting 5 packages counts as 5 instances, NOT 5 separate CVEs. "
    "Do NOT call them 'CVEs'; call them 'finding instances' or 'resolved findings'. "
    "Explain what the numbers mean: e.g. 'Critical: 222 resolved finding instances were fixed past the 7-day deadline (24.5% on-time compliance)'. "
    "Call out any severity tier where compliance_pct is below 80%. "
    "(b) weighted risk score per application — highlight the highest-scoring app and any trends; "
    "(c) suppressed/accepted-risk count — flag if it is disproportionately high relative to open findings; "
    "(d) secret detection — name any app with verified secrets; "
    "(e) recurrence rate and first-time fix rate — comment on engineering maturity if recurrence is high; "
    "(f) MTTR/MTTD if available. "
    "Structure your response as a SINGLE document with these top-level sections, in order, using ## headings:\n"
    "  ## Programme Health Metrics\n"
    "  ## Continuously Monitored Applications\n"
    "  ## Point-in-Time Evaluations\n"
    "Each per-group section should cover: overall risk posture, the most critical findings, "
    "any secret/credential leaks or malware, and a prioritised remediation recommendation. "
    "If a group has zero applications, still include its ## heading and state that explicitly. "
    "Open the '## Point-in-Time Evaluations' section with a > ⚠️ blockquote reminding "
    "executives not to draw trend conclusions from one-off assessments. "
    "Do NOT produce a combined or blended summary across both groups. "
    "Use plain language and Markdown formatting."
)

_GLOBAL_TECH_SYSTEM_PROMPT = (
    "You are a senior security engineer writing a cross-portfolio technical security brief "
    "for development and operations teams. "
    "You will receive aggregated scan data for multiple applications, already separated into "
    "two groups: 'continuously_monitored' (nightly automated scans) and "
    "'point_in_time_evaluations' (one-off assessments). "
    "You will also receive a 'programme_metrics' block; incorporate the most actionable of "
    "these into a ## Programme KPIs section placed BEFORE the per-group sections. Include: "
    "SLA exceeded-CVE counts per severity (use 'exceeded_sla' field; explain these are CVEs fixed past their deadline, not live incidents), MTTR/MTTD values, recurrence rate and first-time fix rate, "
    "weighted risk score per app (flag the highest), verified secret counts per app, "
    "and suppressed-finding counts with a note if suppression is unusually high. "
    "Structure your response as a SINGLE document with these sections, in order, using ## headings:\n"
    "  ## Programme KPIs\n"
    "  ## Continuously Monitored Applications\n"
    "  ## Point-in-Time Evaluations\n"
    "Each per-group section should cover: vulnerability totals per severity, notable CVEs and packages, "
    "tool-specific findings, and concrete remediation steps. "
    "If a group has zero applications, still include its ## heading and state that explicitly. "
    "Do NOT merge or aggregate totals across both groups. "
    "Use Markdown formatting with ### sub-headings per application where helpful."
)

_GLOBAL_ISSO_SYSTEM_PROMPT = (
    "You are a senior Information System Security Officer (ISSO) writing a formal compliance brief "
    "for ATO package review, cATO continuous monitoring, or eMASS upload preparation. "
    "Your audience is ISSOs, ISSMs, AOs, and auditors — not developers or executives. "
    "You will receive aggregated scan data for multiple applications already separated into "
    "'continuously_monitored' (nightly automated scans that represent the live system posture) "
    "and 'point_in_time_evaluations' (one-off spot audits). "
    "You will also receive 'programme_metrics' KPIs and, where available, STIG assessment summaries "
    "(open/pass/not-applicable counts), suppression records (accepted risks with type and reason), "
    "and finding samples with CVE IDs, tool names, packages, and severity. "
    "\n\nStructure your response as a SINGLE Markdown document with EXACTLY these top-level ## sections in order:\n"
    "  ## Compliance Posture Summary\n"
    "  ## Control Mapping & STIG Validation\n"
    "  ## Evidence & Artifact Traceability\n"
    "  ## Validation Status (Verified vs False Positive)\n"
    "  ## Accepted Risk (Suppressed Findings)\n"
    "  ## POA&M-Aligned Risk Statements\n"
    "  ## Continuously Monitored Systems\n"
    "  ## Point-in-Time Evaluations\n"
    "\nGuidance for each section:\n"
    "**## Compliance Posture Summary** — one-paragraph ATO/cATO status overview per severity tier; "
    "call out any critical or high open findings that must be remediated before an ATO can be granted or maintained.\n"
    "**## Control Mapping & STIG Validation** — map critical/high findings to NIST SP 800-53 control "
    "families (e.g. SI-2 Flaw Remediation, IA-5 Authenticator Management, SC-28 Protection at Rest, "
    "CM-6 Configuration Settings, AC-2 Account Management). "
    "Where STIG data is available, report open/pass/NA counts per STIG and flag CAT I (critical) "
    "open controls by name if inferable.\n"
    "**## Evidence & Artifact Traceability** — describe what automated tool outputs serve as evidence "
    "(e.g. Trivy SCA reports → SI-2 evidence, Gitleaks scan → IA-5 evidence, STIG assessments → "
    "CM-6/CM-7 evidence, SBOM → SA-12/SA-15 evidence). Note scan date as evidence timestamp.\n"
    "**## Validation Status (Verified vs False Positive)** — using suppression records and finding data, "
    "estimate the breakdown of confirmed vulnerabilities vs accepted/suppressed/false-positive items "
    "per application. Flag any app where suppression count is suspiciously high relative to open findings.\n"
    "**## Accepted Risk (Suppressed Findings)** — enumerate suppressed findings by application; "
    "include finding type, severity, and stated reason. Note which items require formal Risk Acceptance "
    "memos if the reason is 'accepted risk' rather than 'false positive' or 'not applicable'.\n"
    "**## POA&M-Aligned Risk Statements** — produce a concise POA&M-style risk entry for EACH "
    "critical finding and each open CAT I STIG control, in the format:\n"
    "  - **System**: <app name> | **Control**: <NIST control ID> | **Weakness**: <brief description> | "
    "**Risk**: <impact if unmitigated> | **Recommended Mitigation**: <action> | "
    "**Suggested Completion**: <30/60/90/180-day window based on severity>\n"
    "**## Continuously Monitored Systems** — per-application breakdown of vuln counts, STIG posture, "
    "suppression rate, and key compliance concerns.\n"
    "**## Point-in-Time Evaluations** — open with a > ⚠️ blockquote reminding auditors these are "
    "spot assessments, not continuous posture. Then summarise each evaluated system.\n"
    "\nIMPORTANT: Do NOT invent CVE IDs, control numbers, or tool names not present in the data. "
    "If STIG data is absent for an application, state 'No STIG assessment available'. "
    "Use Markdown formatting with ### sub-headings per application in the per-system sections. "
    "Do NOT wrap your entire response in a fenced code block (no ```markdown or ``` wrapper). "
    "Output only plain Markdown text."
)

_APP_ISSO_SYSTEM_PROMPT = (
    "You are a senior Information System Security Officer (ISSO) writing a formal single-application "
    "compliance brief for ATO package review, cATO continuous monitoring, or eMASS submission. "
    "Your audience is the ISSO, ISSM, Authorizing Official (AO), and auditors — not developers or executives. "
    "You will receive comprehensive scan data for ONE application: full vulnerability findings with CVE/GHSA "
    "IDs and CVSS scores, STIG assessment results (open/pass/NA per control with vuln_id and title), "
    "suppression records (accepted risks with type, severity, value, and reason), scan history, "
    "and programme-level KPIs. "
    "\n\nStructure your response as a SINGLE Markdown document with EXACTLY these ## sections in order:\n"
    "  ## System Compliance Overview\n"
    "  ## Control Mapping & STIG Validation\n"
    "  ## Evidence & Artifact Traceability\n"
    "  ## Vulnerability Risk Assessment\n"
    "  ## Accepted Risk Register\n"
    "  ## POA&M Entries\n"
    "  ## Continuous Monitoring Assessment\n"
    "  ## Recommendations\n"
    "\nDetailed guidance:\n"
    "**## System Compliance Overview** — two concise paragraphs giving the ATO/cATO status for this "
    "specific application. State overall risk level (High/Medium/Low), open critical and high vuln counts, "
    "STIG posture (open CAT I/II counts if available), and whether the system is suitable for ATO in "
    "its current state. Name the application explicitly.\n"
    "**## Control Mapping & STIG Validation** — map EVERY critical finding and EVERY high finding to its "
    "NIST SP 800-53 rev 5 control family using the exact CVE or GHSA ID from the data. "
    "Key mappings: dependency vulns → SI-2 Flaw Remediation; secrets/credentials → IA-5, AC-2; "
    "container misconfigs → CM-6, CM-7; IaC/config issues → CM-2, CM-6; EOL software → SA-22, CM-11; "
    "SBOM gaps → SA-12, SA-15; insecure comms/crypto → SC-8, SC-28; injection vulns → SI-10, SI-16. "
    "Where STIG data is present, list EVERY open control by vuln_id and title under a ### STIG Open Controls "
    "sub-heading, noting CAT severity. Group by NIST family with ### sub-headings.\n"
    "**## Evidence & Artifact Traceability** — for each tool that ran, state: tool name, scan date, "
    "what it covers (SCA/secrets/IaC/STIG/SBOM), and which NIST controls the output satisfies as evidence. "
    "Example row: '`trivy` SCA scan (DATE) → SI-2, SA-12 evidence'. "
    "List any NIST control families that have NO automated evidence from any tool.\n"
    "**## Vulnerability Risk Assessment** — structured entries. For EACH critical finding:\n"
    "  - **ID**: CVE/GHSA | **Package**: name@version → fixedVersion | **CVSS**: score | "
    "**NIST Control**: ID | **Risk**: one-sentence impact if unmitigated | **Fix Available**: Yes/No\n"
    "Then the same format for high findings. Group under ### Critical Findings and ### High Findings.\n"
    "**## Accepted Risk Register** — for EACH suppressed finding produce one bullet:\n"
    "  - **Finding**: value | **Type**: type | **Severity**: sev | **Tool**: tool | "
    "**Reason**: stated reason | **Disposition**: 'Risk Acceptance Memo required' if reason is "
    "'accepted_risk', otherwise 'No memo required (false positive / not applicable)'\n"
    "If no suppressions, state 'No accepted risks on record.'\n"
    "**## POA&M Entries** — one entry per critical finding AND per open STIG control in this format:\n"
    "  - **Weakness**: brief description | **Threat Vector**: how it could be exploited | "
    "**Control Deficiency**: NIST control ID | **Risk Level**: Critical or High | "
    "**Countermeasures in Place**: any mitigating controls already applied | "
    "**Responsible Party**: System Owner | "
    "**Scheduled Completion**: 30 days (Critical) / 90 days (High) / 180 days (Medium)\n"
    "**## Continuous Monitoring Assessment** — using the scan_history array, summarise: "
    "scan cadence (daily/weekly/ad-hoc), total scan count, whether critical count is trending "
    "up/flat/down across recent scans, and whether continuous monitoring obligations appear met.\n"
    "**## Recommendations** — a numbered priority list of the top 5–8 actions the system owner "
    "must take next, each referencing the relevant NIST control and giving a time target.\n"
    "\nCRITICAL RULES: "
    "Use ONLY CVE IDs, GHSA IDs, package names, and STIG vuln_ids that appear in the input data — "
    "do not hallucinate identifiers. "
    "If stig is null, state 'No STIG assessment data available' in the STIG sections. "
    "Do NOT wrap your response in a fenced code block. Output only plain Markdown text."
)


async def generate_app_isso_summary(
    app_name: str,
    scan_meta: dict,
    findings: dict,
    stig_detail: list[dict] | None,
    suppressions: list[dict],
    scan_history: list[dict],
    metrics: dict | None = None,
) -> str:
    """Detailed ISSO compliance brief for a single application."""
    api_key = get_api_key()
    if not api_key:
        raise RuntimeError(
            "OpenAI API key not configured. "
            "Add it in Settings or set OPENAI_API_KEY."
        )

    try:
        from openai import AsyncOpenAI
    except ImportError:
        raise RuntimeError("The 'openai' package is not installed. Run: pip install openai")

    model = get_model()

    critical       = findings.get("critical_findings", [])
    high           = findings.get("high_findings", [])
    summary_counts = findings.get("summary", {})

    payload: dict = {
        "application": app_name,
        "scan_date":   scan_meta.get("timestamp", ""),
        "scan_type":   scan_meta.get("scan_type", ""),
        "tools_used":  scan_meta.get("tools_analyzed", []),
        "vulnerability_counts": {
            "critical": summary_counts.get("total_critical", scan_meta.get("critical", 0)),
            "high":     summary_counts.get("total_high",     scan_meta.get("high", 0)),
            "medium":   summary_counts.get("total_medium",   scan_meta.get("medium", 0)),
            "low":      summary_counts.get("total_low",      scan_meta.get("low", 0)),
        },
        "critical_findings": [
            {
                "id":            f.get("id"),
                "title":         f.get("title"),
                "tool":          f.get("tool"),
                "package":       f.get("package"),
                "version":       f.get("version"),
                "fixed_version": f.get("fixed_version"),
                "cvss":          f.get("cvss"),
            }
            for f in critical[:20]
        ],
        "high_findings": [
            {
                "id":            f.get("id"),
                "title":         f.get("title"),
                "tool":          f.get("tool"),
                "package":       f.get("package"),
                "version":       f.get("version"),
                "fixed_version": f.get("fixed_version"),
                "cvss":          f.get("cvss"),
            }
            for f in high[:15]
        ],
        "scan_history":        scan_history,
        "suppressed_count":    len(suppressions),
        "suppressed_findings": [
            {
                "type":     s.get("type", ""),
                "value":    s.get("value", ""),
                "severity": s.get("severity", ""),
                "reason":   s.get("reason", ""),
                "tool":     s.get("tool", ""),
            }
            for s in suppressions[:30]
        ],
    }

    if stig_detail:
        open_controls = [c for c in stig_detail if c.get("status") == "Open"]
        payload["stig"] = {
            "total": len(stig_detail),
            "open":  len(open_controls),
            "pass":  sum(1 for c in stig_detail if c.get("status") == "Not a Finding"),
            "na":    sum(1 for c in stig_detail if c.get("status") in ("Not Applicable", "Not Reviewed")),
            "open_controls": [
                {
                    "vuln_id":  c.get("vuln_id"),
                    "title":    c.get("title"),
                    "severity": c.get("severity"),
                }
                for c in open_controls[:30]
            ],
        }
    else:
        payload["stig"] = None

    if metrics:
        payload["programme_metrics"] = {
            k: metrics.get(k)
            for k in ("sla_compliance", "mttr_days", "mttd_days",
                      "recurrence_rate_pct", "first_time_fix_pct")
        }

    user_msg = (
        f"Produce the ISSO compliance brief for {app_name}:\n\n"
        + json.dumps(payload, indent=2)
    )

    client = AsyncOpenAI(api_key=api_key, base_url=get_base_url())
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _APP_ISSO_SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        max_tokens=2400,
        temperature=0.2,
    )
    return _strip_code_fence(response.choices[0].message.content or "")


_FIX_SYSTEM_PROMPT = (
    "You are a senior security engineer providing a precise, actionable remediation plan "
    "for a single security finding from an automated scan. "
    "Be direct and concrete. Do not repeat the vulnerability description at length. "
    "Structure your response with these Markdown sections:\n"
    "## Fix\n"
    "The exact steps to remediate — for dependency vulnerabilities include the specific "
    "upgrade command (e.g. `pip install package==x.y.z`, `npm install package@x.y.z`). "
    "For IaC findings include the corrected configuration snippet. "
    "For secrets include rotation steps and how to move the secret to an env var or vault. "
    "For EOL components include the migration path.\n\n"
    "## Why\n"
    "One short paragraph explaining the security impact and attack surface.\n\n"
    "## Verify\n"
    "A one-liner command or step the developer can run to confirm the fix is applied.\n\n"
    "Use inline code for all package names, versions, commands, and file paths. "
    "Be specific — never say 'upgrade to the latest version'; always give the exact version."
)


async def generate_fix_suggestion(finding: dict) -> str:
    api_key = get_api_key()
    if not api_key:
        raise RuntimeError(
            "OpenAI API key not configured. "
            "Add it in Settings or set OPENAI_API_KEY."
        )

    try:
        from openai import AsyncOpenAI
    except ImportError:
        raise RuntimeError("The 'openai' package is not installed. Run: pip install openai")

    model = get_model()

    user_msg = (
        "Provide a remediation plan for the following security finding:\n\n"
        + json.dumps(finding, indent=2)
    )

    client = AsyncOpenAI(api_key=api_key, base_url=get_base_url())
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _FIX_SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        max_tokens=800,
        temperature=0.1,
    )
    return response.choices[0].message.content or ""
