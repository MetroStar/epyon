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
    return os.environ.get("OPENAI_API_KEY") or None


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

    cfg   = read_ai_config()
    model = cfg.get("model") or "gpt-4o-mini"

    client = AsyncOpenAI(api_key=api_key)
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

    cfg   = read_ai_config()
    model = cfg.get("model") or "gpt-4o-mini"

    client = AsyncOpenAI(api_key=api_key)
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

    cfg   = read_ai_config()
    model = cfg.get("model") or "gpt-4o-mini"

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

    client = AsyncOpenAI(api_key=api_key)
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _GLOBAL_EXEC_SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        max_tokens=1400,
        temperature=0.3,
    )
    return response.choices[0].message.content or ""


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

    cfg   = read_ai_config()
    model = cfg.get("model") or "gpt-4o-mini"

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

    client = AsyncOpenAI(api_key=api_key)
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _GLOBAL_TECH_SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        max_tokens=1800,
        temperature=0.2,
    )
    return response.choices[0].message.content or ""


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
    "(a) SLA compliance — call out any severity tier that is breaching SLA targets; "
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
    "SLA breach counts per severity, MTTR/MTTD values, recurrence rate and first-time fix rate, "
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

    cfg   = read_ai_config()
    model = cfg.get("model") or "gpt-4o-mini"

    user_msg = (
        "Provide a remediation plan for the following security finding:\n\n"
        + json.dumps(finding, indent=2)
    )

    client = AsyncOpenAI(api_key=api_key)
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
