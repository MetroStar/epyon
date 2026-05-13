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


_SYSTEM_PROMPT = (
    "You are a senior cybersecurity analyst. "
    "You will be given structured scan findings from an automated security scan "
    "of a software application. "
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

    payload = {
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


async def generate_global_summary(apps: list[dict]) -> str:
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

    totals = {
        "critical": sum(a["critical"] for a in apps),
        "high":     sum(a["high"]     for a in apps),
        "medium":   sum(a["medium"]   for a in apps),
        "low":      sum(a["low"]      for a in apps),
    }

    payload = {
        "scope":             "all_applications",
        "application_count": len(apps),
        "totals":            totals,
        "applications": [
            {
                "name":     a["name"],
                "critical": a["critical"],
                "high":     a["high"],
                "medium":   a["medium"],
                "low":      a["low"],
                "tools":    a.get("tools_analyzed", []),
                "critical_findings_sample": a.get("critical_sample", [])[:5],
            }
            for a in apps
        ],
    }

    user_msg = (
        "Please produce an executive summary for the following aggregated security scan results "
        "across all tracked applications:\n\n"
        + json.dumps(payload, indent=2)
    )

    client = AsyncOpenAI(api_key=api_key)
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        max_tokens=1400,
        temperature=0.3,
    )
    return response.choices[0].message.content or ""


async def generate_global_technical_summary(apps: list[dict]) -> str:
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

    totals = {
        "critical": sum(a["critical"] for a in apps),
        "high":     sum(a["high"]     for a in apps),
        "medium":   sum(a["medium"]   for a in apps),
        "low":      sum(a["low"]      for a in apps),
    }

    payload = {
        "scope":             "all_applications",
        "application_count": len(apps),
        "totals":            totals,
        "applications": [
            {
                "name":              a["name"],
                "critical":          a["critical"],
                "high":              a["high"],
                "medium":            a["medium"],
                "low":               a["low"],
                "tools":             a.get("tools_analyzed", []),
                "critical_findings": a.get("critical_sample", [])[:15],
                "high_findings":     a.get("high_sample", [])[:10],
            }
            for a in apps
        ],
    }

    user_msg = (
        "Please produce a detailed technical security summary across all applications "
        "for the following aggregated scan results:\n\n"
        + json.dumps(payload, indent=2)
    )

    client = AsyncOpenAI(api_key=api_key)
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _TECHNICAL_SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
        max_tokens=1800,
        temperature=0.2,
    )
    return response.choices[0].message.content or ""
