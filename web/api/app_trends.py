"""Per-application improvement/decline status from scan history."""
from __future__ import annotations

from typing import Any, Dict, List

# Same per-severity weights the Score Card applies to vulnerabilities.
RISK_WEIGHTS = {"critical": 15.0, "high": 5.0, "medium": 1.0, "low": 0.2}
STABLE_BAND_PCT = 10.0
MAX_POINTS = 30
# Quick scans skip layers and STIG-only scans have no vulnerability tools, so neither is a fair baseline.
TREND_SCAN_TYPES = frozenset({"full", "nightly"})


def risk_index(scan: Dict[str, Any]) -> float:
    return round(sum(float(scan.get(sev) or 0) * w for sev, w in RISK_WEIGHTS.items()), 1)


def _points(scans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One point per day (the day's latest scan), oldest first."""
    by_day: Dict[str, Dict[str, Any]] = {}
    for s in sorted(scans, key=lambda x: x.get("timestamp", "")):
        ts = s.get("timestamp") or ""
        if ts:
            by_day[ts[:10]] = s
    return [
        {"date": day, "risk_index": risk_index(s),
         **{sev: int(s.get(sev) or 0) for sev in RISK_WEIGHTS}}
        for day, s in sorted(by_day.items())
    ]


def app_trend(scans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Improving / Declining / Stable / Not enough data for one application.

    Only nightly and full scans count (they run the same vulnerability layers), so a quick or STIG-only
    scan is never read as an improvement or a decline.
    """
    same = [s for s in scans if s.get("timestamp") and s.get("scan_type") in TREND_SCAN_TYPES]
    if not same:
        return {"status": "Not enough data", "scans_compared": 0, "points": []}
    scan_type = "nightly/full"
    pts = _points(same)[-MAX_POINTS:]
    out: Dict[str, Any] = {"scan_type": scan_type, "scans_compared": len(pts), "points": pts}
    if len(pts) < 2:
        out["status"] = "Not enough data"
        return out
    first, prev, last = pts[0], pts[-2], pts[-1]
    delta = round(last["risk_index"] - first["risk_index"], 1)
    pct = None if first["risk_index"] == 0 else round(delta / first["risk_index"] * 100, 1)
    crit_high_delta = (last["critical"] + last["high"]) - (first["critical"] + first["high"])
    if crit_high_delta > 0 or (pct is None and delta > 0) or (pct is not None and pct >= STABLE_BAND_PCT):
        status = "Declining"
    elif crit_high_delta < 0 or (pct is not None and pct <= -STABLE_BAND_PCT):
        status = "Improving"
    else:
        status = "Stable"
    out.update({
        "status": status,
        "risk_index": last["risk_index"],
        "baseline_risk_index": first["risk_index"],
        "delta": delta,
        "delta_pct": pct,
        "since_previous": round(last["risk_index"] - prev["risk_index"], 1),
        "critical_high_delta": crit_high_delta,
        "from": first["date"],
        "to": last["date"],
    })
    return out
