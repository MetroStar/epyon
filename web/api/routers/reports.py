"""Epyon Web — reports routes."""
from __future__ import annotations

from pathlib import Path
from typing import Optional
import json
import time

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi import Response
from pydantic import BaseModel

from .. import openai_summary
from .. import parsers
from .. import scorecard as scorecard_store
from .metrics import get_metrics
from .. import main as api_main

router = APIRouter()

@router.post("/api/applications/{name}/isso-summary")
async def app_isso_summary(name: str, response: Response):
    """Per-application ISSO compliance brief: NIST control mapping, STIG, POA&M, accepted risk."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(name):
        raise HTTPException(400, "Invalid application name")

    all_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    target_entries: list[tuple] = []
    for d in all_dirs:
        meta = parsers.parse_dir_name(d.name)
        if meta["target"] == name:
            target_entries.append((d, meta["timestamp"]))

    if not target_entries:
        raise HTTPException(404, f"No scans found for application '{name}'")

    # Sort newest first
    target_entries.sort(key=lambda x: x[1], reverse=True)

    # Best comprehensive scan dir for vuln findings
    def _best_scan_dir(entries: list[tuple]) -> object:
        for d, _ in entries:
            st = (parsers._read_json(d / "scan-metadata.json") or {}).get("scan_type", "")
            if st in api_main._COMPREHENSIVE_SCAN_TYPES:
                return d
        return entries[0][0]

    scan_dir  = _best_scan_dir(target_entries)
    scan_meta = parsers.load_scan(scan_dir, api_main.EPYON_ROOT)
    # Prefer the pre-built deduplicated summary; fall back to raw parse only if absent
    findings  = parsers.load_enriched_findings(scan_dir) or parsers.parse_scan_findings(scan_dir)

    # STIG: walk newest-first until we find a scan with stig-results-*.json files;
    # merge all controls from that scan into a single flat list.
    stig_detail: list[dict] | None = None
    for candidate, _ in target_entries:
        stig_files = api_main._real_stig_files(candidate)
        if not stig_files:
            continue
        merged: list[dict] = []
        for sf in stig_files:
            try:
                raw = json.loads(sf.read_text(encoding="utf-8"))
                results = raw.get("assessments", raw) if "assessments" in raw else raw
                # Load matching controls file
                slug = sf.stem[len("stig-results-"):]
                cf = candidate / f"stig-controls-{slug}.json"
                controls_data: dict = {}
                try:
                    controls_data = json.loads(cf.read_text(encoding="utf-8"))
                except Exception:
                    pass
                for c in controls_data.get("controls", []):
                    vid = c.get("vuln_id", "")
                    assessed = results.get(vid, {})
                    merged.append({
                        "vuln_id":  vid,
                        "title":    c.get("title", ""),
                        "severity": c.get("severity", ""),
                        "status":   assessed.get("status", "Not Reviewed"),
                    })
            except Exception:
                pass
        if merged:
            stig_detail = merged
            break

    # Suppressions: walk newest-first until non-empty
    suppressions: list[dict] = []
    for candidate, _ in target_entries:
        batch = parsers.parse_suppressed_findings(candidate)
        if batch:
            suppressions = batch
            break

    # Scan history: last 8 scans, summary counts only
    scan_history = [
        {
            "timestamp": m.get("timestamp", ""),
            "scan_type": m.get("scan_type", ""),
            "critical":  m.get("critical", 0),
            "high":      m.get("high", 0),
            "medium":    m.get("medium", 0),
            "low":       m.get("low", 0),
        }
        for m in (
            parsers.load_scan(d, api_main.EPYON_ROOT)
            for d, _ in target_entries[:8]
        )
    ]

    _metrics = _build_summary_metrics()

    try:
        summary = await openai_summary.generate_app_isso_summary(
            app_name=name,
            scan_meta=scan_meta,
            findings=findings,
            stig_detail=stig_detail,
            suppressions=suppressions,
            scan_history=scan_history,
            metrics=_metrics,
        )
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"OpenAI request failed: {exc}")

    return {"app": name, "summary": summary}


# ── Executive summary ─────────────────────────────────────────

@router.post("/api/scans/{scan_id}/executive-summary")
async def exec_summary(scan_id: str, response: Response):
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")

    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")

    scan_meta = parsers.load_scan(matched, api_main.EPYON_ROOT)
    findings  = parsers.parse_scan_findings(matched)

    try:
        summary = await openai_summary.generate_summary(scan_id, scan_meta, findings)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"OpenAI request failed: {exc}")

    return {"scan_id": scan_id, "summary": summary}


@router.post("/api/scans/{scan_id}/technical-summary")
async def technical_summary(scan_id: str, response: Response):
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")

    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")

    scan_meta = parsers.load_scan(matched, api_main.EPYON_ROOT)
    findings  = parsers.parse_scan_findings(matched)

    try:
        summary = await openai_summary.generate_technical_summary(scan_id, scan_meta, findings)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"OpenAI request failed: {exc}")

    return {"scan_id": scan_id, "summary": summary}


@router.post("/api/scans/{scan_id}/scorecard")
async def calculate_scorecard(scan_id: str, response: Response):
    """Calculate security scorecard for an existing scan"""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")

    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")

    scan_dir = api_main.EPYON_ROOT / "scans" / scan_id
    trl_script = api_main.SCRIPTS_DIR / "generate-trl-score.py"

    if not trl_script.exists():
        raise HTTPException(500, "TRL scoring script not found")

    # The scorecard needs the consolidated findings summary, which is only
    # produced by a full run of the scan pipeline (generate-scan-findings-summary.sh).
    # Older/interrupted/partial scans (e.g. one tool crashed before consolidation
    # ran) legitimately won't have it — that's a data-availability problem, not a
    # server error, so surface it as 422 with an actionable message instead of a
    # generic 500 that looks like a bug.
    # The Score Card is built from the whole scan history of the app, so any scan
    # of this app with consolidated findings is enough.
    app_prefix = scan_id.rsplit("_", 2)[0] + "_"
    if not any((d / "security-findings-summary.json").exists()
               for d in (api_main.EPYON_ROOT / "scans").glob(f"{app_prefix}*") if d.is_dir() and d.name <= scan_id):
        raise HTTPException(
            422,
            "Score Card unavailable: this scan doesn't have consolidated findings "
            "data (security-findings-summary.json). This happens with older or "
            "interrupted scans. Re-run the scan to generate a Score Card.",
        )

    # Keep the previous assessment when its scoring version differs, so the UI
    # can show old vs new after a rescore. Never overwrite an existing snapshot.
    trl_file = scan_dir / "trl-assessment.json"
    prev_file = scan_dir / "trl-assessment.previous.json"
    try:
        prior = json.loads(trl_file.read_text(encoding="utf-8")) if trl_file.exists() else None
    except Exception:
        prior = None
    if isinstance(prior, dict) and prior.get("scoring_version") != SCORECARD_SCORING_VERSION \
            and not prev_file.exists():
        prev_file.write_text(json.dumps(prior, indent=2), encoding="utf-8")

    # Run TRL calculation
    import subprocess
    result = subprocess.run(
        ["python3", str(trl_script), "--scan-dir", str(scan_dir)],
        capture_output=True,
        text=True,
        timeout=60,
    )

    if result.returncode != 0:
        raise HTTPException(500, f"Score calculation failed: {result.stderr}")

    # Read and return the result
    trl_file = scan_dir / "trl-assessment.json"
    if not trl_file.exists():
        raise HTTPException(500, "Score assessment file not generated")

    try:
        trl_data = json.loads(trl_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(500, f"Failed to parse score results: {exc}")

    return _scorecard_payload(scan_id, scan_dir, trl_data)


SCORECARD_SCORING_VERSION = "2.0"


class ScorecardSignoffBody(BaseModel):
    reviewer: str
    comment: Optional[str] = None


def _scorecard_payload(scan_id: str, scan_dir: Path, trl_data: dict) -> dict:
    payload = {"scan_id": scan_id, **trl_data}
    payload["signoff"] = scorecard_store.get_signoff(scan_id, trl_data)
    prev_file = scan_dir / "trl-assessment.previous.json"
    if prev_file.exists():
        try:
            prev = json.loads(prev_file.read_text(encoding="utf-8"))
            payload["previous"] = {
                "scoring_version": prev.get("scoring_version", "1.0"),
                "trl_level": prev.get("trl_level"),
                "weighted_score": prev.get("weighted_score"),
                "dimension_scores": {k: {"score": v.get("score")}
                                     for k, v in (prev.get("dimension_scores") or {}).items()},
            }
        except Exception:
            pass
    return payload


def _current_scorecard(scan_id: str) -> tuple:
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dir = api_main.EPYON_ROOT / "scans" / scan_id
    trl_file = scan_dir / "trl-assessment.json"
    if not trl_file.is_file():
        raise HTTPException(404, "No Score Card has been calculated for this scan")
    try:
        trl = json.loads(trl_file.read_text(encoding="utf-8"))
    except Exception:
        raise HTTPException(500, "Failed to parse score results")
    if trl.get("scoring_version") != SCORECARD_SCORING_VERSION:
        raise HTTPException(409, "This Score Card uses an older scoring version; recalculate it first")
    return scan_dir, trl


@router.put("/api/scans/{scan_id}/scorecard/signoff")
async def sign_off_scorecard(scan_id: str, body: ScorecardSignoffBody, response: Response):
    """Record that a named reviewer accepted the current Score Card."""
    api_main._sec_headers(response)
    _, trl = _current_scorecard(scan_id)
    try:
        return scorecard_store.save_signoff(scan_id, trl, body.reviewer, body.comment)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.delete("/api/scans/{scan_id}/scorecard/signoff")
async def revoke_scorecard_signoff(scan_id: str, response: Response):
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    return {"removed": scorecard_store.clear_signoff(scan_id)}


@router.get("/api/scans/{scan_id}/scorecard/evidence")
async def download_scorecard_evidence(scan_id: str, response: Response):
    """Download the Score Card, hash manifest and source artifacts as a zip."""
    api_main._sec_headers(response)
    scan_dir, trl = _current_scorecard(scan_id)
    data = scorecard_store.build_evidence_zip(
        api_main.EPYON_ROOT / "scans", scan_id, trl, scorecard_store.get_signoff(scan_id, trl))
    return Response(
        content=data,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{scan_id}-scorecard-evidence.zip"',
            **{k: v for k, v in response.headers.items()},
        },
    )


@router.post("/api/executive-summary")
async def global_exec_summary(response: Response):
    api_main._sec_headers(response)
    hidden    = api_main._load_hidden_apps()
    monitored = api_main._load_monitored_apps()
    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)

    # Collect all scan dirs per target, then choose the latest comprehensive scan
    # (full/nightly) for vulnerability data. Fall back to absolute latest if no
    # comprehensive scan exists for a target.
    by_target_all: dict[str, list[tuple]] = {}  # target -> [(dir, timestamp), ...]
    for d in scan_dirs:
        meta = parsers.parse_dir_name(d.name)
        target = meta["target"]
        if target in hidden:
            continue
        by_target_all.setdefault(target, []).append((d, meta["timestamp"]))

    if not by_target_all:
        raise HTTPException(404, "No scans found")

    def _best_scan_dir(entries: list[tuple]) -> object:
        entries_sorted = sorted(entries, key=lambda x: x[1], reverse=True)
        for d, _ in entries_sorted:
            st = (parsers._read_json(d / "scan-metadata.json") or {}).get("scan_type", "")
            if st in api_main._COMPREHENSIVE_SCAN_TYPES:
                return d
        return entries_sorted[0][0]  # fallback to absolute latest

    apps = []
    for target, entries in sorted(by_target_all.items()):
        scan_dir  = _best_scan_dir(entries)
        scan_meta = parsers.load_scan(scan_dir, api_main.EPYON_ROOT)
        findings  = parsers.parse_scan_findings(scan_dir)
        apps.append({
            "name":           target,
            "monitored":      target in monitored,
            "scan_type":      scan_meta.get("scan_type", "full"),
            "critical":       scan_meta.get("critical", 0),
            "high":           scan_meta.get("high", 0),
            "medium":         scan_meta.get("medium", 0),
            "low":            scan_meta.get("low", 0),
            "tools_analyzed": scan_meta.get("tools_analyzed", []),
            "critical_sample": [
                {"tool": f.get("tool"), "id": f.get("id"), "package": f.get("package"), "title": f.get("title")}
                for f in findings.get("critical_findings", [])[:5]
            ],
        })

    # Pull programme-level metrics (uses cache if warm)
    _metrics = _build_summary_metrics()

    try:
        summary = await openai_summary.generate_global_summary(apps, metrics=_metrics)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"OpenAI request failed: {exc}")

    return {"summary": summary, "application_count": len(apps)}


def _build_summary_metrics() -> dict:
    """Return a trimmed metrics dict for injection into AI summary prompts.
    Uses the in-memory cache when warm to avoid redundant computation."""
    # get_metrics() stamps _metrics_cache_ts with time.monotonic(), so the
    # freshness check here must use the same clock — comparing it against
    # time.time() (wall clock) made this check always look stale, meaning
    # this always recomputed metrics from scratch instead of using the cache.
    if api_main._metrics_cache and (time.monotonic() - api_main._metrics_cache_ts) < api_main._METRICS_TTL:
        m = api_main._metrics_cache
    else:
        # Cache is cold — compute now with a throwaway Response object so that
        # _sec_headers doesn't receive None.
        m = get_metrics(Response())
    if not m:
        return {}

    # Latest risk score per app
    risk_by_app: dict[str, int] = {}
    for pt in (m.get("risk_trend") or []):
        risk_by_app[pt["target"]] = pt["score"]

    # Latest secret counts per app
    secret_by_app: dict[str, dict] = {}
    for target, pts in (m.get("secret_trend_by_target") or {}).items():
        if pts:
            latest = pts[-1]
            secret_by_app[target] = {
                "verified":   latest.get("verified", 0),
                "unverified": latest.get("unverified", 0),
            }

    # Suppression counts per app
    sup_by_app: dict[str, int] = {
        t: len(v) for t, v in (m.get("suppression", {}).get("by_target") or {}).items()
    }

    sla = m.get("sla_compliance") or {}

    # Remap by_severity: rename 'breached' -> 'exceeded_sla' for cleaner AI output
    raw_by_sev = sla.get("by_severity", {})
    by_sev_for_ai = {}
    for sev, d in raw_by_sev.items():
        by_sev_for_ai[sev] = {
            "sla_days":     d.get("sla_days"),
            "within_sla":   d.get("within", 0),
            "exceeded_sla": d.get("breached", 0),
            "compliance_pct": d.get("pct"),
        }

    return {
        "sla_compliance": {
            "note":           "SLA counts are per resolved finding instance (unique tool + CVE ID + package combination). The same CVE affecting multiple packages counts once per package. 'exceeded_sla' = instances fixed AFTER the severity deadline (Critical ≤7d, High ≤30d, Medium ≤90d, Low ≤180d). Source: Epyon scan history.",
            "overall_pct":    sla.get("overall_pct"),
            "total_within_sla":   sla.get("total_within", 0),
            "total_exceeded_sla": sla.get("total_breached", 0),
            "by_severity":    by_sev_for_ai,
        },
        "recurrence_rate_pct":  m.get("recurrence_rate_pct"),
        "first_time_fix_pct":   m.get("first_time_fix_pct"),
        "total_resolved":       m.get("total_resolved", 0),
        "total_suppressed":     m.get("suppression", {}).get("total", 0),
        "risk_score_by_app":    risk_by_app,
        "secrets_by_app":       secret_by_app,
        "suppressed_by_app":    sup_by_app,
        "mttr_days":            m.get("mttr_days"),
        "mttd_days":            m.get("mttd_days"),
    }


@router.post("/api/technical-summary")
async def global_technical_summary(response: Response):
    api_main._sec_headers(response)
    hidden    = api_main._load_hidden_apps()
    monitored = api_main._load_monitored_apps()
    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)

    by_target_all: dict[str, list[tuple]] = {}
    for d in scan_dirs:
        meta = parsers.parse_dir_name(d.name)
        target = meta["target"]
        if target in hidden:
            continue
        by_target_all.setdefault(target, []).append((d, meta["timestamp"]))

    if not by_target_all:
        raise HTTPException(404, "No scans found")

    def _best_scan_dir(entries: list[tuple]) -> object:
        entries_sorted = sorted(entries, key=lambda x: x[1], reverse=True)
        for d, _ in entries_sorted:
            st = (parsers._read_json(d / "scan-metadata.json") or {}).get("scan_type", "")
            if st in api_main._COMPREHENSIVE_SCAN_TYPES:
                return d
        return entries_sorted[0][0]

    apps = []
    for target, entries in sorted(by_target_all.items()):
        scan_dir  = _best_scan_dir(entries)
        scan_meta = parsers.load_scan(scan_dir, api_main.EPYON_ROOT)
        findings  = parsers.parse_scan_findings(scan_dir)
        apps.append({
            "name":           target,
            "monitored":      target in monitored,
            "scan_type":      scan_meta.get("scan_type", "full"),
            "critical":       scan_meta.get("critical", 0),
            "high":           scan_meta.get("high", 0),
            "medium":         scan_meta.get("medium", 0),
            "low":            scan_meta.get("low", 0),
            "tools_analyzed": scan_meta.get("tools_analyzed", []),
            "critical_sample": [
                {
                    "tool": f.get("tool"), "id": f.get("id"),
                    "package": f.get("package"), "version": f.get("version"),
                    "fixed_version": f.get("fixed_version"), "cvss": f.get("cvss"),
                    "title": f.get("title"),
                }
                for f in findings.get("critical_findings", [])[:15]
            ],
            "high_sample": [
                {
                    "tool": f.get("tool"), "id": f.get("id"),
                    "package": f.get("package"), "version": f.get("version"),
                    "fixed_version": f.get("fixed_version"), "cvss": f.get("cvss"),
                    "title": f.get("title"),
                }
                for f in findings.get("high_findings", [])[:10]
            ],
        })

    _metrics = _build_summary_metrics()

    try:
        summary = await openai_summary.generate_global_technical_summary(apps, metrics=_metrics)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"OpenAI request failed: {exc}")

    return {"summary": summary, "application_count": len(apps)}


@router.post("/api/isso-summary")
async def global_isso_summary(response: Response):
    """ISSO compliance brief covering NIST/STIG controls, evidence, POA&M risk statements."""
    api_main._sec_headers(response)
    hidden    = api_main._load_hidden_apps()
    monitored = api_main._load_monitored_apps()
    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)

    by_target_all: dict[str, list[tuple]] = {}
    for d in scan_dirs:
        meta   = parsers.parse_dir_name(d.name)
        target = meta["target"]
        if target in hidden:
            continue
        by_target_all.setdefault(target, []).append((d, meta["timestamp"]))

    if not by_target_all:
        raise HTTPException(404, "No scans found")

    def _best_scan_dir(entries: list[tuple]) -> object:
        entries_sorted = sorted(entries, key=lambda x: x[1], reverse=True)
        for d, _ in entries_sorted:
            st = (parsers._read_json(d / "scan-metadata.json") or {}).get("scan_type", "")
            if st in api_main._COMPREHENSIVE_SCAN_TYPES:
                return d
        return entries_sorted[0][0]

    apps = []
    for target, entries in sorted(by_target_all.items()):
        scan_dir  = _best_scan_dir(entries)
        scan_meta = parsers.load_scan(scan_dir, api_main.EPYON_ROOT)
        findings  = parsers.parse_scan_findings(scan_dir)

        # All scan dirs for this target, newest first
        all_dirs_sorted = [d for d, _ in sorted(entries, key=lambda x: x[1], reverse=True)]

        # STIG summary: use the most recent scan that has stig-results-*.json
        stig_open = stig_pass = stig_na = stig_nr = stig_total = 0
        for candidate in all_dirs_sorted:
            stig_files = api_main._real_stig_files(candidate)
            if not stig_files:
                continue
            for sf in stig_files:
                try:
                    raw = json.loads(sf.read_text(encoding="utf-8"))
                    res = raw.get("assessments", raw) if "assessments" in raw else raw
                    stig_open  += sum(1 for v in res.values() if v.get("status") == "Open")
                    stig_pass  += sum(1 for v in res.values() if v.get("status") == "Not a Finding")
                    stig_na    += sum(1 for v in res.values() if v.get("status") == "Not Applicable")
                    stig_nr    += sum(1 for v in res.values() if v.get("status") == "Not Reviewed")
                    stig_total += len(res)
                except Exception:
                    pass
            if stig_total:
                break  # found the most recent scan with STIG data
        stig_summary = {"open": stig_open, "pass": stig_pass, "na": stig_na, "nr": stig_nr, "total": stig_total} if stig_total else None

        # Suppressions: use the most recent scan that has non-empty suppressed-findings.md
        suppressions: list[dict] = []
        for candidate in all_dirs_sorted:
            batch = parsers.parse_suppressed_findings(candidate)
            if batch:
                suppressions = batch
                break
        sup_sample = [
            {"type": s.get("type", ""), "severity": s.get("severity", ""), "reason": s.get("reason", "")}
            for s in suppressions[:20]
        ]

        apps.append({
            "name":           target,
            "monitored":      target in monitored,
            "scan_type":      scan_meta.get("scan_type", "full"),
            "critical":       scan_meta.get("critical", 0),
            "high":           scan_meta.get("high", 0),
            "medium":         scan_meta.get("medium", 0),
            "low":            scan_meta.get("low", 0),
            "tools_analyzed": scan_meta.get("tools_analyzed", []),
            "stig_summary":   stig_summary,
            "suppressed_count": len(suppressions),
            "suppressed_sample": sup_sample,
            "critical_sample": [
                {
                    "tool": f.get("tool"), "id": f.get("id"),
                    "package": f.get("package"), "version": f.get("version"),
                    "title": f.get("title"), "cvss": f.get("cvss"),
                }
                for f in findings.get("critical_findings", [])[:12]
            ],
            "high_sample": [
                {
                    "tool": f.get("tool"), "id": f.get("id"),
                    "package": f.get("package"), "version": f.get("version"),
                    "title": f.get("title"), "cvss": f.get("cvss"),
                }
                for f in findings.get("high_findings", [])[:8]
            ],
        })

    _metrics = _build_summary_metrics()

    try:
        summary = await openai_summary.generate_global_isso_summary(apps, metrics=_metrics)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, f"OpenAI request failed: {exc}")

    return {"summary": summary, "application_count": len(apps)}


# ── Word (docx) export ─────────────────────────────────────────────────────
class _SummaryExportBody(BaseModel):
    exec_summary:  Optional[str] = None
    tech_summary:  Optional[str] = None
    isso_summary:  Optional[str] = None


@router.post("/api/export/summary-docx")
def export_summary_docx(body: _SummaryExportBody, response: Response):
    """Convert AI-generated Markdown summaries to a .docx download."""
    api_main._sec_headers(response)
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor, Inches
        from docx.enum.text import WD_ALIGN_PARAGRAPH
    except ImportError:
        raise HTTPException(500, "python-docx is not installed. Run: pip install python-docx")

    import io, re
    from datetime import datetime, timezone

    doc = Document()

    # ── Page margins ──
    for section in doc.sections:
        section.top_margin    = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin   = Inches(1.2)
        section.right_margin  = Inches(1.2)

    # ── Cover header ──
    title_para = doc.add_heading("Epyon Security Analysis", level=0)
    title_para.alignment = WD_ALIGN_PARAGRAPH.LEFT
    run = title_para.runs[0]
    run.font.size  = Pt(22)
    run.font.color.rgb = RGBColor(0x1a, 0x1a, 0x1a)

    meta = doc.add_paragraph()
    meta.alignment = WD_ALIGN_PARAGRAPH.LEFT
    mr = meta.add_run(
        f"Generated: {datetime.now(timezone.utc).strftime('%B %d, %Y')}  |  AI-Assisted Report  |  Confidential"
    )
    mr.font.size  = Pt(9)
    mr.font.color.rgb = RGBColor(0x55, 0x55, 0x55)

    doc.add_paragraph()  # spacer

    def _add_markdown(md_text: str, section_label: str) -> None:
        """Render a Markdown string into the Word document."""
        heading_para = doc.add_heading(section_label, level=1)
        heading_para.runs[0].font.size = Pt(14)

        for line in md_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("### "):
                doc.add_heading(stripped[4:], level=3)
            elif stripped.startswith("## "):
                doc.add_heading(stripped[3:], level=2)
            elif stripped.startswith("# "):
                doc.add_heading(stripped[2:], level=2)
            elif stripped.startswith("> "):
                # Blockquote — indent paragraph
                p = doc.add_paragraph(stripped[2:])
                p.paragraph_format.left_indent = Inches(0.4)
                p.runs[0].font.italic = True
            elif re.match(r'^[-*] ', stripped):
                _inline_paragraph(doc.add_paragraph(stripped[2:], style='List Bullet'))
            elif stripped == "":
                doc.add_paragraph()
            else:
                _inline_paragraph(doc.add_paragraph(stripped))

    def _inline_paragraph(para) -> None:
        """Apply bold/italic/code inline formatting to an existing paragraph."""
        if not para.runs:
            return
        raw = para.runs[0].text
        # python-docx Paragraph has no public clear(); remove existing runs.
        for run in list(para.runs):
            run_el = run._element
            run_el.getparent().remove(run_el)
        # Tokenise **bold**, *italic*, `code`
        tokens = re.split(r'(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)', raw)
        for tok in tokens:
            if tok.startswith('**') and tok.endswith('**'):
                r = para.add_run(tok[2:-2])
                r.bold = True
            elif tok.startswith('*') and tok.endswith('*'):
                r = para.add_run(tok[1:-1])
                r.italic = True
            elif tok.startswith('`') and tok.endswith('`'):
                r = para.add_run(tok[1:-1])
                r.font.name = 'Courier New'
                r.font.size = Pt(9)
            else:
                para.add_run(tok)

    if body.exec_summary:
        _add_markdown(body.exec_summary, "📋 Executive Summary")
        doc.add_page_break()

    if body.tech_summary:
        _add_markdown(body.tech_summary, "🔧 Technical Summary")
        if body.isso_summary:
            doc.add_page_break()

    if body.isso_summary:
        _add_markdown(body.isso_summary, "🔒 ISSO Compliance Brief")

    # Footer note
    doc.add_paragraph()
    footer_p = doc.add_paragraph()
    fr = footer_p.add_run(
        "Generated by Epyon Security Scanner  ·  AI-assisted — verify all findings before acting"
    )
    fr.font.size  = Pt(8)
    fr.font.color.rgb = RGBColor(0x88, 0x88, 0x88)
    fr.font.italic = True

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)

    date_slug = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename  = f"epyon-security-report-{date_slug}.docx"
    from fastapi.responses import Response as _Resp
    return _Resp(
        content=buf.read(),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/api/scans/{scan_id}/export/ssp-docx")
def export_scan_ssp_docx(scan_id: str, response: Response):
    """Export NIST SP 800-53 Control Evidence & Artifact Mapping Matrix as Word (.docx)."""
    api_main._sec_headers(response)
    if not api_main._SAFE_ID_RE.match(scan_id):
        raise HTTPException(400, "Invalid scan_id")
    scan_dirs = parsers.find_scan_dirs(api_main.EPYON_ROOT, days=35)
    matched = next((d for d in scan_dirs if d.name == scan_id), None)
    if not matched:
        raise HTTPException(404, "Scan not found")

    try:
        from docx import Document
        from docx.shared import Pt, RGBColor, Inches
        from docx.enum.text import WD_ALIGN_PARAGRAPH
    except ImportError:
        raise HTTPException(500, "python-docx is not installed. Run: pip install python-docx")

    import io
    from datetime import datetime, timezone

    matrix_data = parsers.parse_ssp_evidence_matrix(matched)
    controls = matrix_data.get("controls", [])

    doc = Document()
    for section in doc.sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    title_para = doc.add_heading("NIST SP 800-53 Control Evidence Matrix", level=0)
    title_para.runs[0].font.size = Pt(20)
    title_para.runs[0].font.color.rgb = RGBColor(0x0f, 0x17, 0x2a)

    meta = doc.add_paragraph()
    mr = meta.add_run(f"Scan ID: {scan_id}  |  Generated: {datetime.now(timezone.utc).strftime('%B %d, %Y')}  |  Confidential ATO Evidence Package")
    mr.font.size = Pt(9)
    mr.font.color.rgb = RGBColor(0x47, 0x55, 0x69)

    doc.add_paragraph()

    table = doc.add_table(rows=1, cols=5)
    table.style = 'Table Grid'
    hdr_cells = table.rows[0].cells
    headers = ['NIST Control', 'Control Name', 'Epyon Security Layer', 'Primary Evidence Artifact Path', 'SHA-256 Digest']
    for i, h in enumerate(headers):
        hdr_cells[i].text = h
        hdr_cells[i].paragraphs[0].runs[0].font.bold = True
        hdr_cells[i].paragraphs[0].runs[0].font.size = Pt(9)

    for c in controls:
        row_cells = table.add_row().cells
        row_cells[0].text = c.get("control_id", "")
        row_cells[1].text = c.get("control_name", "")
        row_cells[2].text = c.get("epyon_layer", "")
        row_cells[3].text = c.get("primary_artifact_path", "")
        row_cells[4].text = c.get("sha256_hash", "N/A")
        for cell in row_cells:
            cell.paragraphs[0].runs[0].font.size = Pt(8.5)

    doc.add_paragraph()
    doc.add_heading("Artifact Integrity Reference", level=1)
    for c in controls:
        p = doc.add_paragraph()
        p.add_run(f"{c.get('control_id')}: {c.get('control_name')}\n").bold = True
        p.add_run(f"• Layer: {c.get('epyon_layer')}\n")
        p.add_run(f"• Primary Artifact: {c.get('primary_artifact_path')}\n")
        p.add_run(f"• Format: {c.get('format')}\n")
        p.add_run(f"• SHA-256 Hash: {c.get('sha256_hash')}\n")
        p.add_run(f"• Summary: {c.get('summary')}\n")
        p.runs[0].font.size = Pt(9)

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)

    filename = f"ssp-ato-evidence-{scan_id}.docx"
    from fastapi.responses import Response as _Resp
    return _Resp(
        content=buf.read(),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
