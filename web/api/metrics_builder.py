"""Epyon Web — metrics_builder helpers."""
from __future__ import annotations

from datetime import datetime
from datetime import timezone
import logging
import threading
import time


from . import cache_state
from . import parse_cache
from . import parsers
from .app_trends import app_trend
from . import main as api_main


# ── Metrics ───────────────────────────────────────────────────

_metrics_lock = threading.Lock()


def _compute_metrics() -> dict:
    """Build the metrics payload. One build at a time; waiters reuse its result."""
    with _metrics_lock:
        if cache_state.metrics and (time.monotonic() - cache_state.metrics_ts) < api_main._METRICS_TTL:
            return cache_state.metrics
        started = time.monotonic()
        result = _build_metrics()
        parse_cache.flush()
        cache_state.metrics    = result
        cache_state.metrics_ts = time.monotonic()
        logging.getLogger("epyon.perf").info("metrics built in %.1fs", cache_state.metrics_ts - started)
        return result


def _freq_runs(scan_list: list) -> list[dict]:
    """Classify each scan as pr / nightly / other, and pass / fail by severity gate."""
    runs = []
    for s, _ in scan_list:
        ts = s.get("timestamp") or ""
        if not ts:
            continue
        ci = s.get("ci_source") or {}
        event = ci.get("event") or ""
        if event == "pull_request":
            kind = "pr"
        elif event == "schedule" or s.get("scan_type") == "nightly":
            kind = "nightly"
        else:
            kind = "other"
        result = {"fail": "fail", "pass": "pass"}.get(s.get("gate_status"), "unknown")
        runs.append({"date": ts[:10], "ts": ts, "kind": kind, "result": result})
    runs.sort(key=lambda r: r["ts"])
    return runs


def _build_metrics() -> dict:
    now = time.monotonic()
    scan_dirs = api_main._cached_find_scan_dirs(days=api_main._METRICS_DAYS)
    all_scans = [api_main._memo_load_scan(d) for d in scan_dirs]

    scan_points = sorted(
        [
            {
                "scan_id":   s["scan_id"],
                "target":    s["target"],
                "timestamp": s["timestamp"],
                "critical":  s["critical"],
                "high":      s["high"],
                "medium":    s["medium"],
                "low":       s["low"],
            }
            for s in all_scans if s.get("timestamp")
        ],
        key=lambda x: x["timestamp"],
    )

    by_target: dict[str, list] = {}
    for s, d in zip(all_scans, scan_dirs):
        by_target.setdefault(s["target"], []).append((s, d))

    # ── Monitored-app filter ──────────────────────────────────
    monitored = api_main._load_monitored_apps()
    if monitored:
        by_target = {k: v for k, v in by_target.items() if k in monitored}
        scan_points = [t for t in scan_points if t["target"] in monitored]
    metrics_filtered = bool(monitored)
    monitored_count  = len(monitored)

    # One point per day: the latest scan of each app that day, summed across apps.
    # Many scans per day (PR/push runs) would otherwise crowd out older history.
    latest_per_day: dict[str, dict[str, dict]] = {}
    for pt in scan_points:
        latest_per_day.setdefault(pt["timestamp"][:10], {})[pt["target"]] = pt
    trend = [
        {
            "scan_id":   "",
            "target":    f"{len(apps)} app{'s' if len(apps) != 1 else ''}",
            "timestamp": f"{day}T00:00:00Z",
            **{sev: sum(a[sev] for a in apps.values()) for sev in ("critical", "high", "medium", "low")},
        }
        for day, apps in sorted(latest_per_day.items())
    ]

    tool_counts:      dict[str, dict] = {}
    tool_app_counts:  dict[str, dict[str, int]] = {}
    total_with_fix    = 0
    total_without_fix = 0
    total_suppressed_instances = 0
    cve_counts:       dict[str, dict] = {}

    for _target, scan_list in by_target.items():
        scan_list.sort(key=lambda x: x[0].get("timestamp", ""), reverse=True)
        _, latest_dir = scan_list[0]
        total_suppressed_instances += parsers.count_suppressed_instances(latest_dir)
        findings = parsers.parse_scan_findings(latest_dir)
        if not findings:
            continue
        for sev in ("critical", "high", "medium", "low"):
            for f in findings.get(f"{sev}_findings", []):
                tool = f.get("tool") or "Unknown"
                if tool not in tool_counts:
                    tool_counts[tool] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
                tool_counts[tool][sev]    += 1
                tool_counts[tool]["total"] += 1
                tool_app_counts.setdefault(tool, {})
                tool_app_counts[tool][_target] = tool_app_counts[tool].get(_target, 0) + 1
                if f.get("fixed_version"):
                    total_with_fix += 1
                else:
                    total_without_fix += 1
                cve_id = f.get("id") or ""
                if cve_id.startswith("CVE-"):
                    ftype = (f.get("type") or "").lower()
                    ftool = (f.get("tool") or "").lower()
                    if ftype == "container_vulnerability" or "anchore" in ftool:
                        cve_source = "container"
                    else:
                        cve_source = "code"
                    if cve_id not in cve_counts:
                        cve_counts[cve_id] = {
                            "count":    0,
                            "severity": sev,
                            "title":    (f.get("title") or "")[:120],
                            "apps":     set(),
                            "sources":  set(),
                        }
                    cve_counts[cve_id]["count"] += 1
                    cve_counts[cve_id]["apps"].add(_target)
                    cve_counts[cve_id]["sources"].add(cve_source)

    top_cves = sorted(cve_counts.items(), key=lambda x: x[1]["count"], reverse=True)[:20]

    app_trends = {
        target: app_trend([sc for sc, _ in scan_list])
        for target, scan_list in by_target.items()
    }

    scan_frequency = {
        target: {
            "total": len(scan_list),
            "dates": sorted(
                s.get("timestamp", "")[:10]
                for s, _ in scan_list if s.get("timestamp")
            ),
            "runs": _freq_runs(scan_list),
        }
        for target, scan_list in by_target.items()
    }

    # ── Merges to main ─────────────────────────────────────────
    merge_dates_by_target: dict[str, list[str]] = {}
    for _target, scan_list in by_target.items():
        for s, _ in scan_list:
            ci = s.get("ci_source", {})
            if ci.get("event") in ("push", "workflow_dispatch") and ci.get("branch") in ("main", "master", "dev"):
                date = (s.get("timestamp") or "")[:10]
                if date:
                    merge_dates_by_target.setdefault(_target, []).append(date)

    merges_to_main = {
        target: {
            "total": len(dates),
            "dates": sorted(dates),
        }
        for target, dates in merge_dates_by_target.items()
    }
    total_merges_to_main = sum(len(d) for d in merge_dates_by_target.values())

    # ── SLA Compliance Rate ────────────────────────────────────
    # SLA thresholds (days): critical=7, high=30, medium=90, low=180
    SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
    sla_within:  dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    sla_breached: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    # ── Secret Detection Trend ─────────────────────────────────
    # Per-target, per-scan: count of TruffleHog findings over time (last 60 scans)
    secret_trend: list[dict] = []
    secret_trend_by_target: dict[str, list[dict]] = {}

    # ── Weighted Risk Score Trend ──────────────────────────────
    # Score = critical*10 + high*7 + medium*4 + low*1, per scan
    RISK_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1}
    risk_trend: list[dict] = []

    # ── Suppression Rate ───────────────────────────────────────
    total_suppressed = 0
    suppressed_by_sev: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    suppressed_by_tool: dict[str, int] = {}
    suppressed_by_target: dict[str, list[dict]] = {}

    # ── Recurrence + First-Time Fix Rate ──────────────────────
    # recurrence: fingerprints that were resolved but reappeared
    # first_time_fix: fingerprints resolved within 1 scan cycle of first appearance
    recurrence_count   = 0
    first_time_fixed   = 0
    total_resolved     = 0

    for _target, scan_list in by_target.items():
        eligible = [
            (s, d) for s, d in scan_list
            if s.get("scan_type") not in ("stig",)
        ]
        if not eligible:
            continue
        eligible_sorted = sorted(eligible, key=lambda x: x[0].get("timestamp", ""))

        # Secret trend for this target
        t_secret_trend: list[dict] = []
        for scan_meta, scan_dir in eligible_sorted:
            ts = (scan_meta.get("timestamp") or "")[:10]
            if not ts:
                continue
            # Risk score uses only scan_meta — compute before attempting findings parse
            s = scan_meta
            risk_trend.append({
                "date":     ts,
                "target":   _target,
                "score":    (s.get("critical", 0) * RISK_WEIGHTS["critical"]
                             + s.get("high",     0) * RISK_WEIGHTS["high"]
                             + s.get("medium",   0) * RISK_WEIGHTS["medium"]
                             + s.get("low",      0) * RISK_WEIGHTS["low"]),
                "critical": s.get("critical", 0),
                "high":     s.get("high",     0),
                "medium":   s.get("medium",   0),
                "low":      s.get("low",      0),
            })
            try:
                dg = api_main._scan_digest(scan_dir)
            except Exception:
                continue
            verified   = dg["verified"]
            unverified = dg["secrets"] - verified
            t_secret_trend.append({
                "date": ts, "target": _target,
                "verified": verified, "unverified": unverified,
                "total": dg["secrets"],
            })
        secret_trend.extend(t_secret_trend)
        if t_secret_trend:
            secret_trend_by_target[_target] = t_secret_trend

        # Suppression: union across all scans for target (latest scan may have empty file)
        seen_sup_keys: set[tuple] = set()
        target_suppressions: list[dict] = []
        for _, scan_dir in reversed(eligible_sorted):  # newest → oldest
            try:
                batch = api_main._memo_suppressed(scan_dir)
            except Exception:
                continue
            for sup in batch:
                key = (sup.get("type", ""), sup.get("value", ""))
                if key not in seen_sup_keys:
                    seen_sup_keys.add(key)
                    target_suppressions.append(sup)
        total_suppressed += len(target_suppressions)
        if target_suppressions:
            suppressed_by_target[_target] = [
                {
                    "value":       sup.get("value", ""),
                    "tool":        sup.get("tool", "Unknown"),
                    "type":        sup.get("type", ""),
                    "severity":    sup.get("severity", ""),
                    "reason":      sup.get("reason", ""),
                    "approved_by": sup.get("approved_by", ""),
                }
                for sup in target_suppressions
            ]
        for sup in target_suppressions:
            raw_sev = (sup.get("severity") or "").lower()
            if raw_sev in suppressed_by_sev:
                suppressed_by_sev[raw_sev] += 1
            tool_key = (sup.get("tool") or "Unknown")
            suppressed_by_tool[tool_key] = suppressed_by_tool.get(tool_key, 0) + 1

        if len(eligible_sorted) < 2:
            continue

        # Build per-scan fingerprint sets for recurrence + SLA + first-time-fix
        fp_first_seen: dict[str, tuple[str, str]] = {}  # fp -> (timestamp, sev)
        fp_resolved_at: dict[str, str] = {}             # fp -> resolved_scan_ts
        fp_ever_resolved: set[str]     = set()
        # Pending-resolution: fp disappeared last scan but we require one more
        # consecutive absence before counting it as a genuine fix (filters scanner noise).
        fp_pending_resolution: dict[str, str] = {}      # fp -> scan_ts when it first disappeared
        fp_last_present: dict[str, str] = {}            # fp -> last scan_ts it was still present
        prev_fps: set[str]             = set()
        prev_ts_str: str               = ""

        for scan_meta, scan_dir in eligible_sorted:
            ts = scan_meta.get("timestamp", "")
            if not ts:
                continue
            try:
                dg = api_main._scan_digest(scan_dir)
            except Exception:
                prev_fps = set()
                prev_ts_str = ts
                fp_pending_resolution.clear()
                continue
            curr_fps: set[str] = set()
            for fp, sev in dg["fps"].items():
                curr_fps.add(fp)
                if fp not in fp_first_seen:
                    fp_first_seen[fp] = (ts, sev)
                # Recurrence: was resolved before, now back
                if fp in fp_ever_resolved:
                    recurrence_count += 1
                    fp_ever_resolved.discard(fp)
                # Reappeared before confirmation — cancel the pending resolution
                fp_pending_resolution.pop(fp, None)

            # ── Two-scan confirmation: a finding must be absent from 2 consecutive
            # scans before it counts as resolved. Single-scan absences (scanner noise,
            # transient fetch failures, DB updates) are ignored. ──────────────────
            if prev_fps:
                disappeared_now = prev_fps - curr_fps

                # Confirm resolutions that were pending from the previous scan
                # (absent LAST scan AND still absent NOW → confirmed resolved)
                sla_seen_this_transition: set[str] = set()
                for fp, absent_since_ts in list(fp_pending_resolution.items()):
                    if fp not in curr_fps:  # still absent — confirmed
                        del fp_pending_resolution[fp]
                        if fp in fp_first_seen:
                            first_ts, sev = fp_first_seen[fp]
                            fp_ever_resolved.add(fp)
                            fp_resolved_at[fp] = absent_since_ts
                            total_resolved += 1
                            if fp_last_present.pop(fp, "") == first_ts:
                                first_time_fixed += 1
                            # SLA — deduplicate by CVE-ID::package (strip tool prefix)
                            fp_parts = fp.split('::', 2)
                            sla_key = f"{fp_parts[1]}::{fp_parts[2]}" if len(fp_parts) == 3 and fp_parts[1] else fp
                            if sla_key not in sla_seen_this_transition:
                                sla_seen_this_transition.add(sla_key)
                                try:
                                    first_dt = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
                                    res_dt   = datetime.fromisoformat(absent_since_ts.replace("Z", "+00:00"))
                                    if first_dt.tzinfo is None:
                                        first_dt = first_dt.replace(tzinfo=timezone.utc)
                                    if res_dt.tzinfo is None:
                                        res_dt = res_dt.replace(tzinfo=timezone.utc)
                                    days = (res_dt - first_dt).total_seconds() / 86400
                                    threshold = SLA_DAYS.get(sev, 180)
                                    if days <= threshold:
                                        sla_within[sev]   += 1
                                    else:
                                        sla_breached[sev] += 1
                                except ValueError:
                                    pass
                    # else: reappeared → already removed from pending_resolution above

                # Stage newly disappeared fingerprints as pending (not yet confirmed)
                for fp in disappeared_now:
                    if fp not in fp_ever_resolved and fp in fp_first_seen:
                        fp_pending_resolution[fp] = ts
                        fp_last_present[fp] = prev_ts_str

            prev_fps    = curr_fps
            prev_ts_str = ts

    # Aggregate SLA
    sla_by_sev = {}
    for sev in ("critical", "high", "medium", "low"):
        w = sla_within[sev]
        b = sla_breached[sev]
        total_sla = w + b
        sla_by_sev[sev] = {
            "within": w,
            "breached": b,
            "pct": round(w / total_sla * 100, 1) if total_sla > 0 else None,
            "sla_days": SLA_DAYS[sev],
        }
    sla_total_within  = sum(sla_within.values())
    sla_total_breached = sum(sla_breached.values())
    sla_total = sla_total_within + sla_total_breached
    sla_overall_pct = round(sla_total_within / sla_total * 100, 1) if sla_total > 0 else None

    # Aggregate risk trend (last 60 data points per target, sorted)
    by_target_trend: dict[str, list[dict]] = {}
    for pt in risk_trend:
        by_target_trend.setdefault(pt["target"], []).append(pt)

    risk_trend_sorted: list[dict] = []
    for target, pts in by_target_trend.items():
        pts_sorted = sorted(pts, key=lambda x: x["date"])[-60:]
        risk_trend_sorted.extend(pts_sorted)

    risk_trend_sorted.sort(key=lambda x: (x["target"], x["date"]))
    # Aggregate secret trend (last 60 total entries)
    secret_trend_sorted = sorted(secret_trend, key=lambda x: x["date"])[-60:]

    # Suppression rate vs fixed
    total_fixed_or_suppressed = total_resolved + total_suppressed
    suppression_rate_pct = (
        round(total_suppressed / total_fixed_or_suppressed * 100, 1)
        if total_fixed_or_suppressed > 0 else None
    )

    # Recurrence rate
    recurrence_rate_pct = (
        round(recurrence_count / total_resolved * 100, 1)
        if total_resolved > 0 else None
    )

    # First-time fix rate
    first_time_fix_pct = (
        round(first_time_fixed / total_resolved * 100, 1)
        if total_resolved > 0 else None
    )

    # ── MTTR (Mean Time to Remediate) + MTTD (Mean Time to Detect) ──────────────    # by_target lists are already sorted newest-first from the loop above
    all_remediation_days: list[float] = []
    all_remediation_days_by_sev: dict[str, list[float]] = {"critical": [], "high": [], "medium": [], "low": []}
    all_detection_days: list[float] = []
    all_detection_days_by_sev: dict[str, list[float]] = {"critical": [], "high": [], "medium": [], "low": []}
    target_mttr: dict[str, float] = {}
    # Per-target detailed metrics for app-level filtering
    metrics_by_target: dict[str, dict] = {}
    for _target, scan_list in by_target.items():
        # Only full and nightly scans carry consistent vulnerability data
        eligible = [
            (s, d) for s, d in scan_list
            if s.get("scan_type") not in ("stig",)
        ]
        if len(eligible) < 2:
            continue
        # eligible is newest-first; reverse to chronological order
        scans_to_check = list(reversed(eligible))  # oldest → newest

        # Build fingerprint -> first_seen_ts + severity mapping
        first_seen: dict[str, str] = {}
        first_seen_sev: dict[str, str] = {}
        known_fps: set[str] = set()
        prev_ts: str | None = None
        t_detection_days: list[float] = []
        t_detection_days_by_sev: dict[str, list[float]] = {"critical": [], "high": [], "medium": [], "low": []}
        for scan_meta, scan_dir in scans_to_check:
            ts = scan_meta.get("timestamp", "")
            if not ts:
                continue
            try:
                dg = api_main._scan_digest(scan_dir)
            except Exception:
                prev_ts = ts
                continue
            current_fp_sev: dict[str, str] = dg["fps"]
            current_fps: set[str] = set(current_fp_sev)
            for fp, sev in current_fp_sev.items():
                if fp not in first_seen:
                    first_seen[fp] = ts
                    first_seen_sev[fp] = sev
            # MTTD: record detection window for newly-appearing findings
            if prev_ts:
                try:
                    prev_dt = datetime.fromisoformat(prev_ts.replace("Z", "+00:00"))
                    curr_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if prev_dt.tzinfo is None:
                        prev_dt = prev_dt.replace(tzinfo=timezone.utc)
                    if curr_dt.tzinfo is None:
                        curr_dt = curr_dt.replace(tzinfo=timezone.utc)
                    detect_days = (curr_dt - prev_dt).total_seconds() / 86400
                    if detect_days >= 0:
                        for fp in (current_fps - known_fps):
                            sev = current_fp_sev.get(fp, "")
                            all_detection_days.append(detect_days)
                            t_detection_days.append(detect_days)
                            if sev in all_detection_days_by_sev:
                                all_detection_days_by_sev[sev].append(detect_days)
                            if sev in t_detection_days_by_sev:
                                t_detection_days_by_sev[sev].append(detect_days)
                except ValueError:
                    pass
            known_fps |= current_fps
            prev_ts = ts

        # Latest scan fingerprint set (scans_to_check[-1] is the newest)
        latest_meta, latest_dir = scans_to_check[-1]
        latest_ts = latest_meta.get("timestamp", "")
        if not latest_ts:
            continue
        latest_set: set[str] = set()
        try:
            latest_findings = parsers.parse_scan_findings(latest_dir)
        except Exception:
            continue
        for sev in ("critical", "high", "medium", "low"):
            for f in latest_findings.get(f"{sev}_findings", []):
                fp = f"{f.get('tool', '')}::{f.get('id', '')}::{f.get('package', '')}"
                if fp:
                    latest_set.add(fp)

        try:
            latest_dt = datetime.fromisoformat(latest_ts.replace("Z", "+00:00"))
            if latest_dt.tzinfo is None:
                latest_dt = latest_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

        target_days: list[float] = []
        t_remediation_days_by_sev: dict[str, list[float]] = {"critical": [], "high": [], "medium": [], "low": []}
        for fp, first_ts in first_seen.items():
            if fp not in latest_set:
                try:
                    first_dt = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
                    if first_dt.tzinfo is None:
                        first_dt = first_dt.replace(tzinfo=timezone.utc)
                    days = (latest_dt - first_dt).total_seconds() / 86400
                    if days >= 0:
                        all_remediation_days.append(days)
                        target_days.append(days)
                        sev = first_seen_sev.get(fp, "")
                        if sev in all_remediation_days_by_sev:
                            all_remediation_days_by_sev[sev].append(days)
                        if sev in t_remediation_days_by_sev:
                            t_remediation_days_by_sev[sev].append(days)
                except ValueError:
                    pass
        if target_days:
            target_mttr[_target] = round(sum(target_days) / len(target_days), 1)

        t_mttr = round(sum(target_days) / len(target_days), 1) if target_days else None
        t_mttd = round(sum(t_detection_days) / len(t_detection_days), 1) if t_detection_days else None
        metrics_by_target[_target] = {
            "mttr_days": t_mttr,
            "mttr_by_severity": {
                s: round(sum(v) / len(v), 1) if v else None
                for s, v in t_remediation_days_by_sev.items()
            },
            "mttd_days": t_mttd,
            "mttd_by_severity": {
                s: round(sum(v) / len(v), 1) if v else None
                for s, v in t_detection_days_by_sev.items()
            },
        }

    mttr_days = (
        round(sum(all_remediation_days) / len(all_remediation_days), 1)
        if all_remediation_days else None
    )
    mttr_by_severity = {
        sev: round(sum(days) / len(days), 1) if days else None
        for sev, days in all_remediation_days_by_sev.items()
    }
    mttd_days = (
        round(sum(all_detection_days) / len(all_detection_days), 1)
        if all_detection_days else None
    )
    mttd_by_severity = {
        sev: round(sum(days) / len(days), 1) if days else None
        for sev, days in all_detection_days_by_sev.items()
    }
    fastest_remediator = (
        min(target_mttr.items(), key=lambda x: x[1])
        if target_mttr else None
    )

    result = {
        "trend": trend,
        "by_tool": sorted(
            [
                {
                    "tool":     k,
                    "critical": v["critical"],
                    "high":     v["high"],
                    "medium":   v["medium"],
                    "low":      v["low"],
                    "total":    v["total"],
                    "top_app":  max(tool_app_counts.get(k, {"":0}).items(), key=lambda x: x[1])[0],
                }
                for k, v in tool_counts.items()
            ],
            key=lambda x: -x["total"],
        ),
        "fix_rate": {"with_fix": total_with_fix, "without_fix": total_without_fix},
        "mttr_days": mttr_days,
        "mttr_by_severity": mttr_by_severity,
        "mttd_days": mttd_days,
        "mttd_by_severity": mttd_by_severity,
        "metrics_by_target": metrics_by_target,
        "fastest_remediator": {"target": fastest_remediator[0], "mttr_days": fastest_remediator[1]} if fastest_remediator else None,
        "top_cves": [
            {
                "cve_id":   k,
                "count":    v["count"],
                "severity": v["severity"],
                "title":    v["title"],
                "apps":     sorted(v["apps"]),
                "sources":  sorted(v["sources"]),
            }
            for k, v in top_cves
        ],
        "scan_frequency": scan_frequency,
        "app_trends": app_trends,
        "merges_to_main": merges_to_main,
        "window_days":         api_main._METRICS_DAYS,
        "total_merges_to_main": total_merges_to_main,
        "metrics_filtered": metrics_filtered,
        "monitored_count":  monitored_count,
        # ── New metrics ──────────────────────────────────────
        "sla_compliance": {
            "overall_pct":     sla_overall_pct,
            "total_within":    sla_total_within,
            "total_breached":  sla_total_breached,
            "by_severity":     sla_by_sev,
        },
        "risk_trend":            risk_trend_sorted,
        "secret_trend":          secret_trend_sorted,
        "secret_trend_by_target": secret_trend_by_target,
        "suppression": {
            "total":       total_suppressed,
            "by_severity": suppressed_by_sev,
            "by_tool":     suppressed_by_tool,
            "by_target":   suppressed_by_target,
            "rate_pct":    suppression_rate_pct,
        },
        "accepted_risk_pct": (
            round(total_suppressed_instances /
                  (total_with_fix + total_without_fix + total_suppressed_instances) * 100, 1)
            if (total_with_fix + total_without_fix + total_suppressed_instances) > 0 else None
        ),
        "recurrence_rate_pct":    recurrence_rate_pct,
        "first_time_fix_pct":     first_time_fix_pct,
        "total_resolved":         total_resolved,
    }

    return result
