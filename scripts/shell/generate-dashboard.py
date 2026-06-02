#!/usr/bin/env python3
"""
generate-dashboard.py — Epyon security dashboard generator.

Produces a self-contained HTML file that looks identical to the Epyon web UI
scan detail page.  The output embeds app.css + app.js from web/static/ plus the
scan data as a JSON blob.  No web server or internet connection is required to
view the result.

Usage:
    python3 generate-dashboard.py <scan_dir>
    python3 generate-dashboard.py <scan_dir> --output path/to/output.html

Environment:
    SCAN_DIR    Scan directory (alternative to positional arg)
    EPYON_ROOT  Path to the epyon workspace root (auto-detected when omitted)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# ── Import web-API parsers (for SBOM, API, network, pickle, modelcard) ────────
_PARSERS: object = None  # lazy import

def _get_parsers():
    global _PARSERS
    if _PARSERS is not None:
        return _PARSERS
    import importlib.util
    _here = Path(__file__).parent
    # Walk up to find web/api/parsers.py
    for root in [_here, _here.parent, _here.parent.parent]:
        parsers_path = root / "web" / "api" / "parsers.py"
        if parsers_path.exists():
            spec = importlib.util.spec_from_file_location("epyon_parsers", parsers_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _PARSERS = mod
            return mod
    return None


# ── Helpers ──────────────────────────────────────────────────────────────────

def _read_json(path: Path) -> dict | list | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _parse_suppressed_findings(scan_dir: Path) -> list[dict]:
    """Mirror of parsers.py::parse_suppressed_findings."""
    md_file = scan_dir / "suppressed-findings.md"
    if not md_file.exists():
        return []
    text = md_file.read_text(encoding="utf-8", errors="replace")
    results: list[dict] = []
    seen: set[tuple] = set()
    blocks = re.split(r"^## Suppressed:", text, flags=re.MULTILINE)
    for block in blocks[1:]:
        lines = block.strip().splitlines()
        record: dict = {"value": lines[0].strip() if lines else ""}
        for line in lines[1:]:
            m = re.match(r"-\s+\*\*(.+?)\*\*:\s*(.*)", line)
            if m:
                key = m.group(1).strip().lower().replace(" ", "_")
                record[key] = m.group(2).strip()
        dedup_key = (record.get("type", ""), record.get("value", ""))
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        results.append(record)
    return results


def _parse_stig(scan_dir: Path, scan_id: str) -> dict:
    """Return STIG aggregate fields matching the web UI API format."""
    stig_files = sorted(scan_dir.glob("stig-results-*.json"))
    if not stig_files:
        return {}

    stig_open = stig_pass = stig_na = stig_total = 0
    stig_reports: list[dict] = []
    any_valid = False

    app_slug = re.sub(
        r"[^a-z0-9]+", "-",
        re.sub(r"_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$", "", scan_id).lower()
    ).strip("-")

    for stig_file in stig_files:
        stig_results = _read_json(stig_file)
        if not stig_results or not isinstance(stig_results, dict):
            continue
        if "assessments" in stig_results:
            stig_results = stig_results["assessments"]
        if not stig_results:
            continue
        any_valid = True
        s_open  = sum(1 for v in stig_results.values() if v.get("status") == "Open")
        s_pass  = sum(1 for v in stig_results.values() if v.get("status") == "Not a Finding")
        s_na    = sum(1 for v in stig_results.values() if v.get("status") in ("Not Applicable", "Not Reviewed"))
        s_total = len(stig_results)
        stig_open  += s_open
        stig_pass  += s_pass
        stig_na    += s_na
        stig_total += s_total
        slug = stig_file.stem[len("stig-results-"):]
        stig_reports.append({
            "slug":  slug,
            "open":  s_open,
            "pass":  s_pass,
            "na":    s_na,
            "total": s_total,
        })

    if not any_valid:
        return {}

    return {
        "stig_open":    stig_open,
        "stig_pass":    stig_pass,
        "stig_na":      stig_na,
        "stig_total":   stig_total,
        "stig_reports": stig_reports,
    }


# ── Scan object builder ───────────────────────────────────────────────────────

def build_scan_object(scan_dir: Path) -> dict:
    """Build a scan data object that matches the web UI getScan() API response."""
    scan_id = scan_dir.name

    # ── security-findings-summary.json (canonical findings source) ────────────
    summary_raw  = _read_json(scan_dir / "security-findings-summary.json") or {}
    summary      = summary_raw.get("summary") or summary_raw

    # ── scan-metadata.json ────────────────────────────────────────────────────
    meta = _read_json(scan_dir / "scan-metadata.json") or {}

    # ── ci-metadata.json ─────────────────────────────────────────────────────
    ci_meta = _read_json(scan_dir / "ci-metadata.json") or {}

    # ── scan-manifest.json (fallback for user) ────────────────────────────────
    manifest    = _read_json(scan_dir / "scan-manifest.json") or {}
    manifest_meta = manifest.get("scan_metadata") or {}

    # ── Derive user ────────────────────────────────────────────────────────────
    user = (
        meta.get("scan_user")
        or ci_meta.get("actor")
        or manifest_meta.get("username")
        or ""
    )

    # ── Derive target name ────────────────────────────────────────────────────
    target = (
        meta.get("target_name")
        or manifest_meta.get("target_name")
        or scan_id.split("_")[0]
    )

    # ── Derive timestamp ──────────────────────────────────────────────────────
    timestamp = (
        meta.get("scan_timestamp")
        or summary.get("scan_timestamp")
        or ""
    )

    # ── Derive scan_type ──────────────────────────────────────────────────────
    scan_type = meta.get("scan_type", "full")

    # ── Counts ────────────────────────────────────────────────────────────────
    critical = summary.get("total_critical", 0)
    high     = summary.get("total_high", 0)
    medium   = summary.get("total_medium", 0)
    low      = summary.get("total_low", 0)

    # ── Findings ──────────────────────────────────────────────────────────────
    findings = {
        "critical_findings": summary_raw.get("critical_findings", []),
        "high_findings":     summary_raw.get("high_findings", []),
        "medium_findings":   summary_raw.get("medium_findings", []),
        "low_findings":      summary_raw.get("low_findings", []),
    }
    enrichment = summary_raw.get("enrichment")
    if enrichment:
        findings["enrichment"] = enrichment

    # ── Suppressed findings ───────────────────────────────────────────────────
    suppressed = _parse_suppressed_findings(scan_dir) or None

    # ── File statistics ───────────────────────────────────────────────────────
    file_statistics = meta.get("file_statistics") or {}

    # ── Source URL ────────────────────────────────────────────────────────────
    source_url = meta.get("source_url", "")

    # ── CI source ─────────────────────────────────────────────────────────────
    ci_source: dict | None = None
    if ci_meta.get("source") == "github":
        ci_source = {
            "source":   "github",
            "repo":     ci_meta.get("repo", ""),
            "branch":   ci_meta.get("branch", ""),
            "commit":   ci_meta.get("commit", ""),
            "workflow": ci_meta.get("workflow", ""),
            "event":    ci_meta.get("event", ""),
            "run_id":   ci_meta.get("run_id"),
        }

    # ── STIG ──────────────────────────────────────────────────────────────────
    stig = _parse_stig(scan_dir, scan_id)

    # ── Rich sections via web API parsers ────────────────────────────────────
    parsers = _get_parsers()
    sbom_data         = None
    api_data          = None
    network_discovery = None
    picklescan        = None
    modelcard         = None
    scorecard         = None
    if parsers:
        try: sbom_data         = parsers.load_sbom_packages(scan_dir)
        except Exception: pass
        try: api_data          = parsers.load_api_discovery(scan_dir)
        except Exception: pass
        try: network_discovery = parsers.parse_network_discovery_dir(scan_dir)
        except Exception: pass
        try: picklescan        = parsers.parse_picklescan_dir(scan_dir)
        except Exception: pass
        try: modelcard         = parsers.parse_modelcard_dir(scan_dir)
        except Exception: pass

    # ── Security scorecard (trl-assessment.json) ──────────────────────────────
    trl = _read_json(scan_dir / "trl-assessment.json")
    if trl and trl.get("trl_level"):
        scorecard = trl

    scan: dict = {
        "scan_id":         scan_id,
        "target":          target,
        "user":            user,
        "timestamp":       timestamp,
        "scan_type":       scan_type,
        "critical":        critical,
        "high":            high,
        "medium":          medium,
        "low":             low,
        "total":           critical + high + medium + low,
        "tools_analyzed":  summary.get("tools_analyzed", []),
        "findings":        findings,
        "has_dashboard":   False,  # we ARE the dashboard
        "source_url":      source_url,
    }
    if suppressed:
        scan["suppressed_findings"] = suppressed
    if file_statistics:
        scan["file_statistics"] = file_statistics
    if ci_source:
        scan["ci_source"] = ci_source
    if sbom_data and sbom_data.get("total"):
        scan["sbom"] = sbom_data
    if api_data and api_data.get("total"):
        scan["api_discovery"] = api_data
    if network_discovery:
        scan["network_discovery"] = network_discovery
    if picklescan:
        scan["picklescan"] = picklescan
    if modelcard:
        scan["modelcard"] = modelcard
    if scorecard:
        scan["scorecard"] = scorecard

    # ── Test Coverage ─────────────────────────────────────────────────────────
    coverage_data: dict | None = None
    _cov_summary = scan_dir / "coverage" / "coverage-summary.json"
    if _cov_summary.exists():
        _raw_cov = _read_json(_cov_summary)
        if _raw_cov and isinstance(_raw_cov, dict) and _raw_cov.get("status") not in ("not_detected",):
            coverage_data = {
                "percentage":       round(float(_raw_cov.get("percentage", 0)), 2),
                "language":         _raw_cov.get("language", "unknown"),
                "framework":        _raw_cov.get("framework", "unknown"),
                "lines_covered":    int(_raw_cov.get("lines_covered", 0)),
                "lines_total":      int(_raw_cov.get("lines_total", 0)),
                "branches_covered": int(_raw_cov.get("branches_covered", 0)),
                "branches_total":   int(_raw_cov.get("branches_total", 0)),
                "source":           "coverage-scan",
            }
    # Sonar fallback
    if coverage_data is None:
        _sonar_res = _read_json(scan_dir / "sonar" / "sonar-analysis-results.json")
        if _sonar_res and isinstance(_sonar_res, dict):
            _pct: float | None = None
            for _m in (_sonar_res.get("component") or {}).get("measures", []):
                if _m.get("metric") == "coverage":
                    try: _pct = round(float(_m["value"]), 2)
                    except (ValueError, TypeError): pass
                    break
            if _pct is None and "coverage" in _sonar_res:
                try: _pct = round(float(_sonar_res["coverage"]), 2)
                except (ValueError, TypeError): pass
            if _pct is not None:
                coverage_data = {"percentage": _pct, "framework": "sonarqube", "source": "sonarqube"}
    if coverage_data is not None:
        scan["test_coverage"] = coverage_data

    scan.update(stig)

    return scan


# ── HTML generation ───────────────────────────────────────────────────────────

_STATIC_OVERRIDES = """
/* ── Static dashboard overrides ── */
html, body { height: auto; overflow: auto; }
.sidebar, .topbar, .nav-footer { display: none !important; }
.main-content {
  margin-left: 0 !important;
  padding: 24px 32px !important;
  max-width: 1400px;
  margin: 0 auto !important;
}
"""


def _coverage_card_html(scan: dict) -> str:
    """Return an inline HTML coverage metric card, or empty string if no data."""
    cov = scan.get("test_coverage")
    if not cov:
        return ""
    pct = cov.get("percentage", 0)
    lang = cov.get("language", "")
    framework = cov.get("framework", "")
    lines_covered = cov.get("lines_covered", 0)
    lines_total = cov.get("lines_total", 0)
    source = cov.get("source", "")

    if pct >= 80:
        color = "#22c55e"   # green
        icon = "✅"
    elif pct >= 60:
        color = "#f59e0b"   # amber
        icon = "⚠️"
    else:
        color = "#ef4444"   # red
        icon = "❌"

    lines_html = ""
    if lines_total > 0:
        lines_html = f"<span style='font-size:0.78rem;color:#94a3b8;margin-left:8px'>{lines_covered}/{lines_total} lines</span>"

    source_label = ""
    if source == "sonarqube":
        source_label = "<span style='font-size:0.72rem;color:#64748b;margin-left:6px'>(via SonarQube)</span>"
    elif lang and lang != "unknown":
        fw_display = f"{lang}/{framework}" if framework and framework not in ("unknown", lang) else lang
        source_label = f"<span style='font-size:0.72rem;color:#64748b;margin-left:6px'>({fw_display})</span>"

    return f"""
<div style="
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 16px 20px;
  margin: 16px 0;
  display: flex;
  align-items: center;
  gap: 16px;
  font-family: inherit;
">
  <div style="font-size:1.4rem">{icon}</div>
  <div>
    <div style="font-size:0.8rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px">Test Coverage</div>
    <div style="font-size:1.6rem;font-weight:700;color:{color}">{pct:.1f}%{lines_html}</div>
    <div style="font-size:0.78rem;color:#64748b">Layer 16{source_label}</div>
  </div>
</div>"""


def generate_html(scan_dir: Path, epyon_root: Path, output_path: Path) -> None:
    scan      = build_scan_object(scan_dir)
    scan_id   = scan["scan_id"]
    scan_json = json.dumps(scan, ensure_ascii=False, separators=(",", ":"))

    css_file = epyon_root / "web" / "static" / "app.css"
    js_file  = epyon_root / "web" / "static" / "app.js"

    if not css_file.exists():
        print(f"Error: app.css not found at {css_file}", file=sys.stderr)
        sys.exit(1)
    if not js_file.exists():
        print(f"Error: app.js not found at {js_file}", file=sys.stderr)
        sys.exit(1)

    css = css_file.read_text(encoding="utf-8")
    js  = js_file.read_text(encoding="utf-8")

    coverage_card = _coverage_card_html(scan)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Scan \u2014 {scan_id}</title>
  <style>
{css}
{_STATIC_OVERRIDES}
  </style>
</head>
<body>
  <div class="main-content">
    {coverage_card}
    <div id="page"></div>
  </div>
  <script>window.__SCAN__ = {scan_json};</script>
  <script>
{js}
  </script>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    size_kb = output_path.stat().st_size // 1024
    print(f"  ✅ Dashboard written: {output_path} ({size_kb} KB)")


# ── Auto-detect epyon root ────────────────────────────────────────────────────

def _find_epyon_root(start: Path) -> Path:
    """Walk up from start until we find web/static/app.js."""
    candidate = start.resolve()
    while candidate != candidate.parent:
        if (candidate / "web" / "static" / "app.js").exists():
            return candidate
        candidate = candidate.parent
    print("Error: Could not find epyon root (looking for web/static/app.js).", file=sys.stderr)
    print("Set EPYON_ROOT or run from within the epyon workspace.", file=sys.stderr)
    sys.exit(1)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an Epyon web-UI-style security dashboard HTML file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "scan_dir", nargs="?",
        help="Path to the scan directory (or set $SCAN_DIR)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output HTML file path (default: <scan_dir>/consolidated-reports/dashboards/security-dashboard.html)",
    )
    parser.add_argument(
        "--epyon-root",
        help="Path to the epyon workspace root (auto-detected when omitted)",
    )
    args = parser.parse_args()

    # Resolve scan dir
    scan_dir_str = args.scan_dir or os.environ.get("SCAN_DIR")
    if not scan_dir_str:
        parser.print_help()
        sys.exit(1)

    scan_dir = Path(scan_dir_str).resolve()
    if not scan_dir.is_dir():
        print(f"Error: Not a directory: {scan_dir}", file=sys.stderr)
        sys.exit(1)

    # Resolve epyon root
    if args.epyon_root:
        epyon_root = Path(args.epyon_root).resolve()
    elif os.environ.get("EPYON_ROOT"):
        epyon_root = Path(os.environ["EPYON_ROOT"]).resolve()
    else:
        epyon_root = _find_epyon_root(scan_dir)

    # Resolve output path
    output_path = Path(args.output).resolve() if args.output else (
        scan_dir / "consolidated-reports" / "dashboards" / "security-dashboard.html"
    )

    print(f"  📊 Generating dashboard for: {scan_dir.name}")
    generate_html(scan_dir, epyon_root, output_path)


if __name__ == "__main__":
    main()
