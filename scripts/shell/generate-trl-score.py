#!/usr/bin/env python3
"""
generate-trl-score.py

Computes a Technical Readiness Level (TRL) score for a security scan based on
DoD/NASA TRL framework adapted for software. Reads existing scan outputs and
produces a trl-assessment.json file.

TRL Scale (1-9):
  TRL 1-3: Basic principles / concept / proof of concept
  TRL 4-6: Component validation / system prototype / prototype in environment
  TRL 7-9: System prototype in operational env / actual system / operational

For software:
  TRL 1-3: Code exists, basic functionality
  TRL 4-6: Security hardened, tested, documented
  TRL 7-9: Production-ready, compliant, low risk

Usage:
    generate-trl-score.py --scan-dir <path> [--output <path>] [--weights <config>]

Exit codes:
    0  - Success
    1  - Missing required files or bad arguments
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

# ── TRL Dimension Weights by Scan Type ────────────────────────────────────────
# Base weights for a standard web app / general software project
DEFAULT_WEIGHTS = {
    "security": 0.30,          # CVEs, secrets, malware
    "supply_chain": 0.20,      # SBOM, EOL, dependency health
    "code_quality": 0.15,      # SonarQube, IaC
    "compliance": 0.15,        # STIG, documentation
    "operational": 0.10,       # Helm, network, trend
    "mosa": 0.10,              # Modular Open Systems Approach
}

# ML model scan: emphasize AI-specific layers
ML_WEIGHTS = {
    "security": 0.35,          # Includes Picklescan, Garak
    "supply_chain": 0.15,
    "code_quality": 0.15,
    "compliance": 0.20,        # Model card, STIG
    "operational": 0.05,
    "mosa": 0.10,
}

# STIG-only scan: all weight on compliance
STIG_WEIGHTS = {
    "security": 0.25,
    "supply_chain": 0.15,
    "code_quality": 0.10,
    "compliance": 0.35,
    "operational": 0.05,
    "mosa": 0.10,
}

# Quick scan: emphasize fast-running tools
QUICK_WEIGHTS = {
    "security": 0.35,
    "supply_chain": 0.25,
    "code_quality": 0.15,
    "compliance": 0.10,
    "operational": 0.05,
    "mosa": 0.10,
}


# ── Evidence helpers ───────────────────────────────────────────────────────────
# Every score component is recorded as an evidence item so a reviewer can trace
# a number back to the tool output (path + SHA-256) and the findings behind it.

SCORING_VERSION = "2.0"
MAX_REFS = 25
SEV_KEYS = (
    ("critical_findings", "critical"),
    ("high_findings", "high"),
    ("medium_findings", "medium"),
    ("low_findings", "low"),
)


# ── Scan history ──────────────────────────────────────────────────────────────
# The Score Card describes the application, not a single run. Each artifact is read
# from the newest scan of the app that has it, so a quick scan never hides what the
# last full scan found and the score does not depend on the scan type.

_HISTORY: List[Path] = []


def set_history(scan_dir: Path) -> List[Path]:
    """Scans of this app up to and including scan_dir, newest first."""
    app = get_app_name_from_scan_dir(scan_dir)
    older = [d for d in find_all_app_scans(scan_dir, app) if d.name < scan_dir.name]
    _HISTORY[:] = [scan_dir] + sorted(older, key=lambda d: d.name, reverse=True)
    return list(_HISTORY)


def locate(scan_dir: Path, *rels: str) -> Path:
    """Newest existing copy of an artifact across scan history (else the current scan's path)."""
    for d in (_HISTORY or [scan_dir]):
        for rel in rels:
            if "*" in rel:
                hits = sorted(d.glob(rel), reverse=True)
                if hits:
                    return hits[0]
            elif (d / rel).exists():
                return d / rel
    return scan_dir / rels[0].replace("*", "missing")


def tool_family(name: Any) -> str:
    return str(name or "unknown").lower().split("-")[0]


def merge_findings(history: List[Path]) -> Optional[Dict[str, Any]]:
    """Combine consolidated findings across scans: each tool family comes from the newest scan that ran it."""
    merged: Dict[str, Any] = {key: [] for key, _ in SEV_KEYS}
    sources: Dict[str, str] = {}
    seen_any = False
    for d in history:
        data = load_json(d / "security-findings-summary.json")
        if not data:
            continue
        seen_any = True
        families = {tool_family(t) for t in data.get("summary", {}).get("tools_analyzed", [])}
        for key, _ in SEV_KEYS:
            for f in data.get(key, []):
                if isinstance(f, dict):
                    families.add(tool_family(f.get("tool")))
        for fam in sorted(families - set(sources)):
            sources[fam] = d.name
        for key, _ in SEV_KEYS:
            merged[key].extend(
                f for f in data.get(key, [])
                if isinstance(f, dict) and sources.get(tool_family(f.get("tool"))) == d.name)
    if not seen_any:
        return None
    merged["summary"] = {f"total_{sev}": len(merged[key]) for key, sev in SEV_KEYS}
    merged["tool_sources"] = sources
    return merged


def sha256_file(path: Path) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def make_evidence(
    scan_dir: Path,
    eid: str,
    kind: str,
    label: str,
    measured: Any = None,
    impact: Optional[float] = None,
    source: Optional[Path] = None,
    refs: Optional[List[str]] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    """Build one evidence item. kind: deduction | cap | bonus | component | info | missing."""
    item: Dict[str, Any] = {"id": eid, "kind": kind, "label": label}
    if measured is not None:
        item["measured"] = measured
    if impact is not None:
        item["impact"] = round(impact, 1)
    if source is not None and source.is_file():
        try:
            item["source"] = source.resolve().relative_to(scan_dir.resolve().parent).as_posix()
        except ValueError:
            item["source"] = source.name
        item["sha256"] = sha256_file(source)
        src_scan = item["source"].split("/")[0]
        if src_scan != scan_dir.name and item["sha256"]:
            extra = f"from earlier scan {src_scan}"
            note = f"{note}; {extra}" if note else extra
    if refs:
        item["refs"] = refs[:MAX_REFS]
        item["refs_total"] = len(refs)
    if note:
        item["note"] = note
    return item


def finding_ref(f: Dict[str, Any]) -> str:
    fid = f.get("vulnerability_id") or f.get("id") or f.get("rule_id") or f.get("check_id") or "finding"
    pkg = f.get("package_name") or f.get("package") or f.get("target") or ""
    tool = str(f.get("tool", ""))
    return f"{tool}:{fid}:{pkg}".rstrip(":")


def findings_by_severity(findings: Dict) -> Dict[str, List[Dict[str, Any]]]:
    return {sev: [f for f in findings.get(key, []) if isinstance(f, dict)] for key, sev in SEV_KEYS}


def is_sast(f: Dict[str, Any]) -> bool:
    return str(f.get("tool", "")).lower().startswith("semgrep")


def load_layer(scan_dir: Path, subdir: str, filename: str) -> "tuple[Path, Optional[Dict], List[Dict]]":
    """Load an ML layer result file (falls back to the legacy flat location)."""
    path = locate(scan_dir, f"{subdir}/{filename}", filename)
    data = load_json(path)
    items: List[Dict] = []
    if isinstance(data, dict):
        items = [f for f in data.get("findings", []) if isinstance(f, dict)]
    elif isinstance(data, list):
        items = [f for f in data if isinstance(f, dict)]
    return path, (data if isinstance(data, dict) else None), items


def sev_counts(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in items:
        sev = str(f.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


# ── Scoring Functions ──────────────────────────────────────────────────────────

def load_json(path: Path) -> Optional[Dict]:
    """Load JSON file; return None if missing or invalid."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def get_app_name_from_scan_dir(scan_dir: Path) -> str:
    """Extract app name from scan directory name (e.g., 'epyon_2026-05-26_12-00-00' → 'epyon')."""
    dir_name = scan_dir.name
    # Format: {app}_{date}_{time} or similar
    parts = dir_name.split("_")
    if len(parts) >= 1:
        return parts[0]
    return "unknown"


def find_all_app_scans(scan_dir: Path, app_name: str) -> List[Path]:
    """Find all scan directories for the same app, sorted by timestamp (newest first).
    
    Args:
        scan_dir: Current scan directory (e.g., /path/scans/epyon_2026-05-26_12-00-00)
        app_name: Application name
    
    Returns:
        List of scan directory Paths, sorted newest to oldest
    """
    scans_root = scan_dir.parent  # /path/scans/
    
    if not scans_root.exists() or not scans_root.is_dir():
        return [scan_dir]
    
    # Find all scan directories for this app
    pattern = f"{app_name}_*"
    all_scans = sorted(
        [d for d in scans_root.glob(pattern) if d.is_dir()],
        reverse=True  # Newest first
    )
    
    return all_scans if all_scans else [scan_dir]


def get_latest_stig_results(scan_dirs: List[Path]) -> Dict[str, Any]:
    """Get STIG results from the most recent scan with STIG data.

    Finds the most recent scan directory (newest to oldest) that has STIG results
    and returns metrics from that scan only, plus the review-quality signals the
    score card uses as evidence (human locks, confidence, evidence coverage).
    """
    for scan_dir in scan_dirs:
        stig_files = sorted(scan_dir.glob("stig-results-*.json"))
        if not stig_files:
            continue

        total_pass = 0
        total_applicable = 0
        cat1_pass = 0
        cat1_applicable = 0
        open_cat1: List[str] = []
        open_ids: List[str] = []
        human_locked: List[str] = []
        unsupported_pass: List[str] = []
        low_confidence: List[str] = []
        sources: List[Path] = []

        for stig_file in stig_files:
            stig_data = load_json(stig_file)
            if not stig_data:
                continue
            sources.append(stig_file)

            slug = stig_file.stem.replace("stig-results-", "")
            controls_file = scan_dir / f"stig-controls-{slug}.json"  # same scan as the results
            severity_map = {}
            if controls_file.exists():
                controls_data = load_json(controls_file)
                if controls_data and "controls" in controls_data:
                    for ctrl in controls_data["controls"]:
                        severity_map[ctrl["vuln_id"]] = ctrl.get("severity", "").lower()
                    sources.append(controls_file)

            findings = stig_data.get("findings", [])
            assessments = stig_data.get("assessments", {})

            for finding in findings:
                status = finding.get("status", "")
                severity = finding.get("severity", "")
                if status in ("Open", "NotAFinding", "Not a Finding"):
                    total_applicable += 1
                    if status in ("NotAFinding", "Not a Finding"):
                        total_pass += 1
                    if severity in ("high", "critical"):
                        cat1_applicable += 1
                        if status in ("NotAFinding", "Not a Finding"):
                            cat1_pass += 1

            for vuln_id, data in assessments.items():
                status = data.get("status", "")
                severity = severity_map.get(vuln_id, "")

                # "Not Reviewed" is a control that could not be confirmed from static
                # evidence; it is scored as Open (applicable, not passing), never as pass or N/A.
                if status in ("Open", "Not a Finding", "Not Applicable", "Not Reviewed"):
                    total_applicable += 1
                    if status == "Not a Finding":
                        total_pass += 1
                    elif status in ("Open", "Not Reviewed"):
                        open_ids.append(vuln_id)
                    if severity == "high":
                        cat1_applicable += 1
                        if status == "Not a Finding":
                            cat1_pass += 1
                        else:
                            open_cat1.append(vuln_id)

                if data.get("locked_by_human"):
                    human_locked.append(vuln_id)
                if status == "Not a Finding" and not data.get("locked_by_human"):
                    # A pass without written evidence cannot be credited in full.
                    if len(str(data.get("evidence", "")).strip()) < 20:
                        unsupported_pass.append(vuln_id)
                try:
                    conf = float(data.get("confidence", 100))
                except (TypeError, ValueError):
                    conf = 100.0
                if status in ("Not a Finding", "Not Applicable") and conf < 50:
                    low_confidence.append(vuln_id)

        result: Dict[str, Any] = {
            "pass_rate": None,
            "cat1_pass_rate": None,
            "files_assessed": len(stig_files),
            "latest_scan_with_stig": scan_dir.name,
            "latest_scan_dir": scan_dir,
            "sources": sources,
            "total_applicable": total_applicable,
            "total_pass": total_pass,
            "cat1_applicable": cat1_applicable,
            "open_ids": open_ids,
            "open_cat1": open_cat1,
            "human_locked": human_locked,
            "unsupported_pass": unsupported_pass,
            "low_confidence": low_confidence,
        }
        if total_applicable > 0:
            result["pass_rate"] = (total_pass / total_applicable) * 100.0
        if cat1_applicable > 0:
            result["cat1_pass_rate"] = (cat1_pass / cat1_applicable) * 100.0
        return result

    return {
        "pass_rate": None,
        "cat1_pass_rate": None,
        "files_assessed": 0,
        "latest_scan_with_stig": None,
        "latest_scan_dir": None,
        "sources": [],
        "total_applicable": 0,
        "total_pass": 0,
        "cat1_applicable": 0,
        "open_ids": [],
        "open_cat1": [],
        "human_locked": [],
        "unsupported_pass": [],
        "low_confidence": [],
    }


def aggregate_api_endpoints(scan_dirs: List[Path]) -> Dict[str, Any]:
    """Aggregate API endpoint discovery across multiple scan directories.
    
    Looks through all provided scan directories (newest to oldest) to find API endpoints.
    Returns the maximum number found across all scans.
    
    Args:
        scan_dirs: List of scan directory paths, sorted newest to oldest
    
    Returns:
        Dict with:
        - endpoint_count: Maximum endpoints found across all scans
        - scans_with_apis: Number of scans that had API discovery data
        - latest_scan_with_apis: Name of most recent scan with API endpoints
    """
    max_endpoints = 0
    scans_with_apis = 0
    latest_scan_with_apis = None
    
    for scan_dir in scan_dirs:
        # Try multiple possible locations for API discovery data
        api_locations = [
            scan_dir / "api-discovery" / "api-inventory.json",
            scan_dir / "api" / "api-discovery.json",
            scan_dir / "api" / "exports" / f"api-discovery-{scan_dir.name}.json",
            scan_dir / "api-discovery.json",
        ]
        
        for api_file in api_locations:
            if not api_file.exists():
                continue
            
            api_data = load_json(api_file)
            if not api_data:
                continue
            
            # Try multiple formats for endpoint count
            endpoint_count = 0
            
            # Format 1: Direct endpoints array (older format)
            if "endpoints" in api_data:
                endpoint_count = len(api_data["endpoints"])
            
            # Format 2: Summary with total_endpoints_discovered (current format)
            elif "summary" in api_data and "total_endpoints_discovered" in api_data["summary"]:
                endpoint_count = api_data["summary"]["total_endpoints_discovered"]
            
            # Format 3: Count routes from discovery_methods.code_routes (fallback)
            elif "discovery_methods" in api_data and "code_routes" in api_data["discovery_methods"]:
                routes = api_data["discovery_methods"]["code_routes"]
                endpoint_count = sum([
                    len(routes.get("python", [])),
                    len(routes.get("nodejs", [])),
                    len(routes.get("java", [])),
                ])
            
            if endpoint_count > 0:
                scans_with_apis += 1
                if latest_scan_with_apis is None:
                    latest_scan_with_apis = scan_dir.name
                if endpoint_count > max_endpoints:
                    max_endpoints = endpoint_count
                break  # Found API data in this scan, move to next scan
    
    return {
        "endpoint_count": max_endpoints,
        "scans_with_apis": scans_with_apis,
        "latest_scan_with_apis": latest_scan_with_apis,
    }


def _dimension(score: Optional[float], details: Dict[str, Any], evidence: List[Dict[str, Any]],
               applicable: bool = True) -> Dict[str, Any]:
    """A dimension is either scored from data that exists or marked not applicable (`applicable: false`, score 0, weight kept).

    Details never contain null values: anything that was not measured is left out.
    """
    clean = {k: v for k, v in details.items() if v is not None}
    return {
        "score": round(score, 1) if score is not None else 0,
        "max": 100,
        "applicable": applicable,
        "details": clean,
        "evidence": evidence,
    }


def score_security(scan_dir: Path, findings: Dict) -> Dict[str, Any]:
    """
    Security & Safety dimension (0-100).
    CVE severity, KEV, secrets, malware and the ML/AI layers (14/18/19/20).
    SAST (Semgrep) is scored under Code Quality so it is not counted twice.
    Hard caps: secrets > 0 → max 30; malware > 0 → max 20; dangerous model → max 40.
    """
    ev: List[Dict[str, Any]] = []
    by_sev = findings_by_severity(findings)
    summary = findings.get("summary", {})
    findings_file = locate(scan_dir, "security-findings-summary.json")

    counts: Dict[str, int] = {}
    refs: Dict[str, List[str]] = {}
    for sev, items in by_sev.items():
        non_sast = [f for f in items if not is_sast(f)]
        counts[sev] = len(non_sast) if items else int(summary.get(f"total_{sev}", 0) or 0)
        refs[sev] = [finding_ref(f) for f in non_sast]

    secret_findings = [f for sev in ("critical", "high") for f in by_sev[sev]
                       if str(f.get("tool", "")).lower() == "trufflehog"]
    has_secrets = len(secret_findings) > 0

    clamav_file = locate(scan_dir, "clamav/clamav-results.json")
    clamav_data = load_json(clamav_file)
    infected = 0
    if clamav_data:
        infected = clamav_data.get("summary", {}).get("infected_files", 0)
    has_malware = infected > 0

    pick_path, pick_data, pick_items = load_layer(scan_dir, "picklescan", "picklescan-results.json")
    dangerous = 0
    if pick_data:
        dangerous = int(pick_data.get("summary", {}).get("dangerous_imports", 0) or 0)
    pick_counts = sev_counts(pick_items)
    has_pickle_issues = dangerous > 0 or pick_counts["critical"] + pick_counts["high"] > 0

    garak_file = locate(scan_dir, "garak/garak-results.json")
    garak_data = load_json(garak_file)
    garak_pass_rate = 100.0
    if garak_data and isinstance(garak_data, dict) and "probes" in garak_data:
        probes = garak_data["probes"]
        if isinstance(probes, list):
            total_attempts = sum(p.get("attempts", 0) for p in probes if isinstance(p, dict))
            passed = sum(p.get("passed", 0) for p in probes if isinstance(p, dict))
            if total_attempts > 0:
                garak_pass_rate = (passed / total_attempts) * 100.0

    base_score = 100.0
    for sev, per in (("critical", 15), ("high", 5), ("medium", 1), ("low", 0.2)):
        impact = -counts[sev] * per
        base_score += impact
        if counts[sev]:
            ev.append(make_evidence(
                scan_dir, f"sec-cve-{sev}", "deduction",
                f"{counts[sev]} {sev} vulnerabilities (excluding SAST) at {per} pt each",
                counts[sev], impact, findings_file, refs[sev]))

    # Known-exploited vulnerabilities are weighted extra on top of their severity.
    kev = [f for sev in ("critical", "high", "medium", "low") for f in by_sev[sev]
           if f.get("cisa_kev") in (True, "true", "True", "Yes", "yes", 1)]
    if kev:
        impact = -min(30, 10 * len(kev))
        base_score += impact
        ev.append(make_evidence(
            scan_dir, "sec-kev", "deduction",
            f"{len(kev)} CISA Known Exploited Vulnerabilities (10 pts each, max 30)",
            len(kev), impact, findings_file, [finding_ref(f) for f in kev]))

    # ML/AI layers — each capped at 25 pts so one noisy layer cannot zero the dimension.
    ml_details: Dict[str, Any] = {}
    layers = [("ml-picklescan", "Layer 14 model file analysis", pick_path, pick_items)]
    for eid, label, sub, fname in (
        ("ml-provenance", "Layer 18 model provenance", "model-provenance", "model-provenance-results.json"),
        ("ml-inference", "Layer 19 inference environment", "inference-security", "inference-security-results.json"),
        ("ml-runtime", "Layer 20 ML runtime behaviour", "ml-runtime", "ml-runtime-analysis-results.json"),
    ):
        lpath, _, litems = load_layer(scan_dir, sub, fname)
        layers.append((eid, label, lpath, litems))
    provenance_path = layers[1][2]
    provenance_critical = False
    for eid, label, path, items in layers:
        if not items:
            continue
        c = sev_counts(items)
        ml_details[eid] = c
        impact = -min(25, c["critical"] * 10 + c["high"] * 5 + c["medium"] * 1)
        if eid == "ml-provenance" and c["critical"] > 0:
            provenance_critical = True
        if impact:
            base_score += impact
            ev.append(make_evidence(
                scan_dir, f"sec-{eid}", "deduction",
                f"{label}: {c['critical']} critical / {c['high']} high / {c['medium']} medium findings",
                c, impact, path,
                [f"{f.get('type', 'finding')}:{f.get('file', '')}" for f in items
                 if str(f.get("severity", "")).lower() in ("critical", "high", "medium")]))
    if base_score < 0:
        ev.append(make_evidence(scan_dir, "sec-floor", "info",
                                f"Deductions total {base_score - 100:.1f} pts; score is floored at 0",
                                round(base_score, 1), None))
    base_score = max(0, base_score)

    if has_secrets:
        base_score = min(base_score, 30)
        ev.append(make_evidence(scan_dir, "sec-cap-secrets", "cap",
                                f"{len(secret_findings)} leaked secret(s) cap Security at 30", len(secret_findings),
                                30, findings_file, [finding_ref(f) for f in secret_findings]))
    if has_malware:
        base_score = min(base_score, 20)
        ev.append(make_evidence(scan_dir, "sec-cap-malware", "cap",
                                f"{infected} infected file(s) cap Security at 20", infected, 20, clamav_file))
    if has_pickle_issues:
        base_score = min(base_score, 40)
        ev.append(make_evidence(scan_dir, "sec-cap-model", "cap",
                                "Dangerous model-file content caps Security at 40",
                                max(dangerous, pick_counts["critical"] + pick_counts["high"]), 40, pick_path))
    if provenance_critical:
        base_score = min(base_score, 40)
        ev.append(make_evidence(scan_dir, "sec-cap-provenance", "cap",
                                "Critical model provenance finding caps Security at 40", True, 40,
                                provenance_path))
    if garak_pass_rate < 80.0:
        base_score = min(base_score, 50)
        ev.append(make_evidence(scan_dir, "sec-cap-garak", "cap",
                                f"Garak pass rate {garak_pass_rate:.1f}% (<80%) caps Security at 50",
                                round(garak_pass_rate, 1), 50, garak_file))

    sources = findings.get("tool_sources") or {}
    if sources:
        ev.append(make_evidence(
            scan_dir, "sec-coverage", "info",
            "Findings merged across scan history; each tool comes from its newest run",
            len(sources), 0, None, [f"{fam} ← {scan}" for fam, scan in sorted(sources.items())]))
    if not [e for e in ev if e["kind"] != "info"]:
        ev.append(make_evidence(scan_dir, "sec-clean", "info",
                                "No vulnerabilities, secrets, malware or ML findings were recorded",
                                0, 0, findings_file))

    return _dimension(base_score, {
        "critical_cve": counts["critical"],
        "high_cve": counts["high"],
        "medium_cve": counts["medium"],
        "low_cve": counts["low"],
        "kev_count": len(kev),
        "has_secrets": has_secrets,
        "has_malware": has_malware,
        "pickle_issues": has_pickle_issues,
        "garak_pass_rate": round(garak_pass_rate, 1) if garak_data else None,
        "ml_layer_findings": ml_details,
    }, ev)


def score_supply_chain(scan_dir: Path, findings: Dict) -> Dict[str, Any]:
    """
    Supply Chain Integrity dimension (0-100).
    SBOM completeness, EOL components, vulnerability density, patchable debt
    (high/critical findings that already have a fix) and typosquatted models.
    """
    ev: List[Dict[str, Any]] = []
    sbom_file = locate(scan_dir, "sbom/filesystem.cyclonedx.json", "sbom/filesystem-cyclonedx.json")
    sbom_data = load_json(sbom_file)
    sbom_exists = sbom_data is not None
    component_count = 0
    if sbom_data and "components" in sbom_data:
        component_count = len(sbom_data["components"])

    xeol_file = locate(scan_dir, "xeol/xeol-results.json", "xeol/*xeol*results.json")
    xeol_data = load_json(xeol_file)
    eol_count = 0
    critical_eol = 0
    eol_refs: List[str] = []
    crit_eol_refs: List[str] = []
    if xeol_data and "matches" in xeol_data:
        eol_count = len(xeol_data["matches"])
        for match in xeol_data["matches"]:
            name = (match.get("artifact") or {}).get("name", "component")
            eol_refs.append(str(name))
            cycle_info = match.get("cycle", {})
            if cycle_info.get("eol", False) and cycle_info.get("support", True) is False:
                critical_eol += 1
                crit_eol_refs.append(str(name))

    summary = findings.get("summary", {})
    total_cve = summary.get("total_critical", 0) + summary.get("total_high", 0) + summary.get("total_medium", 0)
    vuln_ratio = (total_cve / component_count) if component_count > 0 else 0.0

    by_sev = findings_by_severity(findings)
    patchable = [f for sev in ("critical", "high") for f in by_sev[sev]
                 if not is_sast(f) and str(f.get("fix_available", "")).lower() in ("yes", "true")
                 and str(f.get("tool", "")).lower() != "trufflehog"]

    prov_path, _, prov_items = load_layer(scan_dir, "model-provenance", "model-provenance-results.json")
    typosquats = [f for f in prov_items if "typosquat" in str(f.get("type", "")).lower()]

    findings_file = locate(scan_dir, "security-findings-summary.json")
    base_score = 100.0
    if not sbom_exists:
        ev.append(make_evidence(scan_dir, "sc-no-sbom", "missing",
                                "No SBOM in any scan of this application — Supply Chain was not scanned and scores 0"))
        return _dimension(None, {}, ev, applicable=False)
    else:
        ev.append(make_evidence(scan_dir, "sc-sbom", "info",
                                f"SBOM present with {component_count} components", component_count, 0, sbom_file))
        if critical_eol:
            impact = -critical_eol * 20
            base_score += impact
            ev.append(make_evidence(scan_dir, "sc-eol-critical", "deduction",
                                    f"{critical_eol} end-of-support components (20 pts each)",
                                    critical_eol, impact, xeol_file, crit_eol_refs))
        if eol_count:
            impact = -eol_count * 5
            base_score += impact
            ev.append(make_evidence(scan_dir, "sc-eol", "deduction",
                                    f"{eol_count} EOL components (5 pts each)", eol_count, impact, xeol_file, eol_refs))
        if vuln_ratio:
            impact = -vuln_ratio * 10
            base_score += impact
            ev.append(make_evidence(scan_dir, "sc-density", "deduction",
                                    f"{total_cve} CVEs across {component_count} components "
                                    f"(density {vuln_ratio:.2f} × 10)", round(vuln_ratio, 2), impact, findings_file))
        if patchable:
            impact = -min(20, len(patchable) * 2)
            base_score += impact
            ev.append(make_evidence(scan_dir, "sc-patchable", "deduction",
                                    f"{len(patchable)} critical/high findings already have a fixed version "
                                    f"(2 pts each, max 20)", len(patchable), impact, findings_file,
                                    [finding_ref(f) for f in patchable]))
        if typosquats:
            impact = -min(30, len(typosquats) * 10)
            base_score += impact
            ev.append(make_evidence(scan_dir, "sc-typosquat", "deduction",
                                    f"{len(typosquats)} possible typosquatted model(s) (10 pts each, max 30)",
                                    len(typosquats), impact, prov_path,
                                    [str(f.get("file", "")) for f in typosquats]))
        base_score = max(0, base_score)

    return _dimension(base_score, {
        "sbom_exists": sbom_exists,
        "component_count": component_count,
        "eol_components": eol_count,
        "critical_eol": critical_eol,
        "vuln_ratio": round(vuln_ratio, 2),
        "patchable_high_critical": len(patchable),
        "typosquatted_models": len(typosquats),
    }, ev)


def score_code_quality(scan_dir: Path, findings: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Code Quality dimension (0-100).
    Weighted average of the quality tools that actually ran: SonarQube gate (40),
    Checkov IaC pass rate (30) and Semgrep SAST findings (30). Tools that did not
    run are listed as missing evidence and their weight is redistributed, so a
    scan is neither rewarded nor punished for tools outside its scan mode.
    """
    ev: List[Dict[str, Any]] = []
    components: List["tuple[float, float]"] = []  # (weight, score)

    sonar_file = locate(scan_dir, "sonar/quality-gate.json")
    sonar_data = load_json(sonar_file)
    sonar_pass = None
    sonar_debt_ratio = 0.0
    if sonar_data:
        sonar_pass = sonar_data.get("projectStatus", {}).get("status") == "OK"
        for condition in sonar_data.get("projectStatus", {}).get("conditions", []):
            if condition.get("metricKey") == "sqale_debt_ratio":
                sonar_debt_ratio = float(condition.get("actualValue", "0"))
        sonar_score = (100.0 if sonar_pass else 50.0) - sonar_debt_ratio * 2
        sonar_score = max(0.0, min(100.0, sonar_score))
        components.append((40, sonar_score))
        ev.append(make_evidence(scan_dir, "cq-sonar", "component",
                                f"SonarQube quality gate {'passed' if sonar_pass else 'failed'}, "
                                f"debt ratio {sonar_debt_ratio:.1f}%", round(sonar_score, 1), None,
                                sonar_file, note="weight 40"))
    else:
        ev.append(make_evidence(scan_dir, "cq-sonar-missing", "missing",
                                "SonarQube has not run — no evidence either way", None, None, sonar_file))

    checkov_file = locate(scan_dir, "checkov/checkov-results.json", "checkov/results.json")
    checkov_data = load_json(checkov_file)
    # Checkov writes one report per framework (a list) or a single report (a dict)
    reports = checkov_data if isinstance(checkov_data, list) else [checkov_data] if checkov_data else []
    summaries = [r["summary"] for r in reports if isinstance(r, dict) and isinstance(r.get("summary"), dict)]
    checkov_pass_rate = 100.0
    if summaries:
        passed = sum(int(x.get("passed", 0)) for x in summaries)
        failed = sum(int(x.get("failed", 0)) for x in summaries)
        total = passed + failed
        if total > 0:
            checkov_pass_rate = (passed / total) * 100.0
        components.append((30, checkov_pass_rate))
        ev.append(make_evidence(scan_dir, "cq-checkov", "component",
                                f"Checkov IaC: {passed} passed / {failed} failed checks",
                                round(checkov_pass_rate, 1), None, checkov_file, note="weight 30"))
    else:
        ev.append(make_evidence(scan_dir, "cq-checkov-missing", "missing",
                                "Checkov has not run — no evidence either way", None, None, checkov_file))

    semgrep_file = locate(scan_dir, "semgrep/semgrep-results.json")
    findings_file = locate(scan_dir, "security-findings-summary.json")
    sast = []
    if findings:
        sast = [f for sev, items in findings_by_severity(findings).items() for f in items if is_sast(f)]
    sast_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in sast:
        sev = str(f.get("severity", "")).lower()
        if sev in sast_counts:
            sast_counts[sev] += 1
    semgrep_ran = semgrep_file.exists() or bool(sast)
    sast_score = None
    if semgrep_ran:
        sast_score = max(0.0, 100.0 - sast_counts["critical"] * 15 - sast_counts["high"] * 5
                         - sast_counts["medium"] * 1 - sast_counts["low"] * 0.2)
        components.append((30, sast_score))
        ev.append(make_evidence(scan_dir, "cq-semgrep", "component",
                                f"Semgrep SAST: {sast_counts['critical']} critical / {sast_counts['high']} high / "
                                f"{sast_counts['medium']} medium / {sast_counts['low']} low",
                                round(sast_score, 1), None,
                                semgrep_file if semgrep_file.exists() else findings_file,
                                [finding_ref(f) for f in sast if str(f.get("severity", "")).lower() in ("critical", "high")],
                                note="weight 30"))
    else:
        ev.append(make_evidence(scan_dir, "cq-semgrep-missing", "missing",
                                "Semgrep has not run — no evidence either way", None, None, semgrep_file))

    total_weight = sum(w for w, _ in components)
    if not total_weight:
        return _dimension(None, {}, ev, applicable=False)
    base_score = sum(w * s for w, s in components) / total_weight

    return _dimension(base_score, {
        "sonar_quality_gate": sonar_pass,
        "sonar_debt_ratio": round(sonar_debt_ratio, 1) if sonar_data else None,
        "checkov_pass_rate": round(checkov_pass_rate, 1) if checkov_data else None,
        "sast_findings": sast_counts if semgrep_ran else None,
        "tools_scored": len(components),
    }, ev)


def score_compliance(scan_dir: Path) -> Dict[str, Any]:
    """
    Compliance & Documentation dimension (0-100).
    STIG compliance % (70) with CAT I weighting and an evidence-quality penalty,
    model card completeness (20) and API documentation (10).

    STIG data is taken from the most recent scan with STIG results; API data is
    aggregated across all historical scans since API discovery may not run every time.
    """
    ev: List[Dict[str, Any]] = []
    app_name = get_app_name_from_scan_dir(scan_dir)
    all_scans = find_all_app_scans(scan_dir, app_name)

    stig_agg = get_latest_stig_results(all_scans)
    stig_pass_rate = stig_agg["pass_rate"]
    stig_cat1_pass = stig_agg["cat1_pass_rate"]
    stig_files_count = stig_agg["files_assessed"]
    stig_src = stig_agg["sources"][0] if stig_agg["sources"] else None

    api_agg = aggregate_api_endpoints(all_scans)
    api_documented = api_agg["endpoint_count"]
    scans_with_apis = api_agg["scans_with_apis"]

    modelcard_file = locate(scan_dir, "modelcard/modelcard-results.json")
    modelcard_data = load_json(modelcard_file)
    modelcard_score = None
    if modelcard_data:
        modelcard_score = modelcard_data.get("completeness_score")
        if modelcard_score is None:
            passed = modelcard_data.get("passed", 0)
            failed = modelcard_data.get("failed", 0)
            total = passed + failed
            if total > 0:
                modelcard_score = (passed / total) * 100.0

    unsupported = stig_agg["unsupported_pass"]
    components: List["tuple[float, float]"] = []  # (weight, score)
    if stig_pass_rate is not None:
        stig_score = stig_pass_rate
        ev.append(make_evidence(
            scan_dir, "comp-stig", "component",
            f"STIG pass rate {stig_pass_rate:.1f}% ({stig_agg['total_pass']} of "
            f"{stig_agg['total_applicable']} applicable controls), weight 70",
            round(stig_pass_rate, 1), None, stig_src,
            stig_agg["open_ids"], note=f"from {stig_agg['latest_scan_with_stig']}"))
        if stig_cat1_pass is not None and stig_cat1_pass < 100:
            impact = -(100 - stig_cat1_pass) * 0.15 / 0.7
            stig_score += impact
            ev.append(make_evidence(
                scan_dir, "comp-cat1", "deduction",
                f"CAT I pass rate {stig_cat1_pass:.1f}% — {len(stig_agg['open_cat1'])} open CAT I control(s)",
                round(stig_cat1_pass, 1), impact, stig_src, stig_agg["open_cat1"]))
        if unsupported and stig_agg["total_pass"]:
            impact = -10.0 * len(unsupported) / stig_agg["total_pass"]
            stig_score += impact
            ev.append(make_evidence(
                scan_dir, "comp-unsupported", "deduction",
                f"{len(unsupported)} 'Not a Finding' control(s) have no written evidence "
                f"(up to 10 pts, proportional)", len(unsupported), impact, stig_src, unsupported))
        if stig_agg["human_locked"]:
            ev.append(make_evidence(
                scan_dir, "comp-human", "info",
                f"{len(stig_agg['human_locked'])} control(s) were reviewed and locked by a human",
                len(stig_agg["human_locked"]), 0, stig_src, stig_agg["human_locked"]))
        if stig_agg["low_confidence"]:
            ev.append(make_evidence(
                scan_dir, "comp-lowconf", "info",
                f"{len(stig_agg['low_confidence'])} passing control(s) have confidence below 50",
                len(stig_agg["low_confidence"]), 0, stig_src, stig_agg["low_confidence"]))
        components.append((70, max(0.0, min(100.0, stig_score))))
    else:
        components.append((70, 0.0))
        ev.append(make_evidence(scan_dir, "comp-no-stig", "missing",
                                "No STIG assessment in any scan of this application — scored 0 (weight 70)",
                                0, -70.0))

    if modelcard_score is not None:
        components.append((20, float(modelcard_score)))
        ev.append(make_evidence(scan_dir, "comp-modelcard", "component",
                                f"Model card completeness {modelcard_score:.1f}%, weight 20",
                                round(modelcard_score, 1), None, modelcard_file))

    if api_documented > 0:
        components.append((10, 100.0))
        ev.append(make_evidence(scan_dir, "comp-api", "component",
                                f"{api_documented} API endpoints documented across {scans_with_apis} scan(s), weight 10",
                                api_documented))

    total_weight = sum(w for w, _ in components)
    if not total_weight:
        return _dimension(None, {}, ev, applicable=False)
    base_score = sum(w * sc for w, sc in components) / total_weight

    return _dimension(base_score, {
        "stig_pass_rate": round(stig_pass_rate, 1) if stig_pass_rate is not None else None,
        "stig_cat1_pass_rate": round(stig_cat1_pass, 1) if stig_cat1_pass is not None else None,
        "stig_files_assessed": stig_files_count,
        "stig_latest_scan": stig_agg["latest_scan_with_stig"],
        "stig_open_controls": len(stig_agg["open_ids"]),
        "stig_human_locked": len(stig_agg["human_locked"]),
        "stig_unsupported_passes": len(unsupported),
        "modelcard_completeness": round(modelcard_score, 1) if modelcard_score else None,
        "api_endpoints_found": api_documented,
        "api_scans_aggregated": scans_with_apis,
        "api_latest_scan": api_agg["latest_scan_with_apis"],
    }, ev)


def _crit_high_total(merged: Optional[Dict[str, Any]]) -> Optional[int]:
    if not merged:
        return None
    s = merged.get("summary", {})
    return int(s.get("total_critical", 0) or 0) * 5 + int(s.get("total_high", 0) or 0)


def score_operational(scan_dir: Path, findings: Dict, metadata: Dict) -> Dict[str, Any]:
    """
    Operational Readiness dimension (0-100).
    Helm chart validity, network exposure and the real scan-to-scan trend
    (critical*5 + high compared with the previous scan of the same app).
    """
    ev: List[Dict[str, Any]] = []
    helm_file = locate(scan_dir, "helm/helm-results.json")
    helm_data = load_json(helm_file)
    helm_valid = None
    if helm_data:
        helm_valid = bool(helm_data.get("build_success")) or helm_data.get("status") == "success"

    network_file = locate(scan_dir, "network/network-discovery.json", "network-discovery/network-inventory.json")
    network_data = load_json(network_file)
    unexpected: List[str] = []
    # Only ports confirmed open by an active scan count; statically declared service ports are not exposure.
    open_ports = []
    if network_data and "open_ports" in network_data:
        open_ports = [p.get("port", 0) for p in network_data["open_ports"]]
    elif network_data and (network_data.get("summary") or {}).get("active_scan_run"):
        open_ports = list(network_data["summary"].get("unique_ports", []))
    standard_ports = {80, 443, 22, 3000, 8080, 8443}
    unexpected = [str(p) for p in open_ports if p not in standard_ports]
    unexpected_ports = len(unexpected)

    trend_direction = "stable"
    prev_name = None
    current = _crit_high_total(findings)
    previous = None
    # Compare like with like: the application's merged view as of the previous scan.
    if len(_HISTORY) > 1:
        previous = _crit_high_total(merge_findings(_HISTORY[1:]))
        if previous is not None:
            prev_name = _HISTORY[1].name
    if current is not None and previous is not None:
        if current > previous:
            trend_direction = "degrading"
        elif current < previous:
            trend_direction = "improving"

    base_score = 100.0
    if helm_valid is False:
        base_score -= 30
        ev.append(make_evidence(scan_dir, "op-helm", "deduction", "Helm chart failed to build",
                                False, -30, helm_file))
    elif helm_valid is None:
        ev.append(make_evidence(scan_dir, "op-helm-missing", "missing",
                                "Helm has not run — no evidence either way"))
    else:
        ev.append(make_evidence(scan_dir, "op-helm", "info", "Helm chart built successfully", True, 0, helm_file))

    if unexpected_ports:
        impact = -unexpected_ports * 10
        base_score += impact
        ev.append(make_evidence(scan_dir, "op-ports", "deduction",
                                f"{unexpected_ports} non-standard open port(s) (10 pts each)",
                                unexpected_ports, impact, network_file, unexpected))

    if trend_direction == "degrading":
        base_score -= 20
    elif trend_direction == "improving":
        base_score += 10
    if prev_name:
        ev.append(make_evidence(
            scan_dir, "op-trend", "bonus" if trend_direction == "improving" else
            ("deduction" if trend_direction == "degrading" else "info"),
            f"Trend {trend_direction}: critical×5+high is {current} now vs {previous} in {prev_name}",
            trend_direction, {"improving": 10, "degrading": -20}.get(trend_direction, 0),
            locate(scan_dir, "security-findings-summary.json")))
    else:
        ev.append(make_evidence(scan_dir, "op-trend-none", "missing",
                                "No earlier scan of this app to compare — no trend available"))

    if helm_valid is None and network_data is None and not prev_name:
        return _dimension(None, {}, ev, applicable=False)
    base_score = max(0, min(100, base_score))
    return _dimension(base_score, {
        "helm_valid": helm_valid,
        "unexpected_network_ports": unexpected_ports if network_data is not None else None,
        "trend_direction": trend_direction if prev_name else None,
        "trend_compared_to": prev_name,
    }, ev)


def score_mosa(scan_dir: Path, findings: Dict, metadata: Dict) -> Dict[str, Any]:
    """
    MOSA (Modular Open Systems Approach) dimension (0-100).
    Evaluates modularity, open standards, interoperability, portability, vendor independence.
    """
    ev: List[Dict[str, Any]] = []
    base_score = 100.0

    sbom_file = locate(scan_dir, "sbom/filesystem.cyclonedx.json", "sbom/filesystem-cyclonedx.json")
    has_sbom_standard = sbom_file.exists()

    api_result = aggregate_api_endpoints([scan_dir])
    api_count = api_result.get("endpoint_count", 0)
    has_openapi = api_count > 0

    helm_file = locate(scan_dir, "helm/helm-results.json")
    helm_data = load_json(helm_file)
    has_helm = helm_data is not None and (
        helm_data.get("chart_valid") is True or helm_data.get("status") == "success"
        or bool(helm_data.get("build_success")))

    dockerfile_present = any((d / "Dockerfile").exists() for d in (_HISTORY or [scan_dir])) or metadata.get("has_dockerfile", False)

    sbom_data = load_json(sbom_file)
    open_source_ratio = 0.0
    proprietary_count = 0
    if sbom_data and "components" in sbom_data:
        total_components = len(sbom_data["components"])
        if total_components > 0:
            for comp in sbom_data["components"]:
                licenses = comp.get("licenses", [])
                has_oss_license = any(
                    lic.get("license", {}).get("id", "").lower() in [
                        "mit", "apache-2.0", "bsd-3-clause", "gpl-3.0", "lgpl-3.0", "isc", "mpl-2.0"
                    ] for lic in licenses if isinstance(lic, dict)
                )
                if not has_oss_license and licenses:
                    proprietary_count += 1
            open_source_ratio = (total_components - proprietary_count) / total_components

    def check(eid: str, ok: bool, label: str, penalty: float, source: Optional[Path] = None) -> None:
        nonlocal base_score
        if ok:
            ev.append(make_evidence(scan_dir, eid, "info", label + " — present", True, 0, source))
        else:
            base_score -= penalty
            ev.append(make_evidence(scan_dir, eid, "deduction", label + " — absent", False, -penalty, source))

    check("mosa-sbom", has_sbom_standard, "Standard CycloneDX SBOM", 25, sbom_file)
    if helm_data is not None:
        check("mosa-helm", has_helm, "Valid Helm chart (modular deployment)", 15, helm_file)
    else:
        ev.append(make_evidence(scan_dir, "mosa-helm-missing", "missing", "Helm has not run — no evidence either way"))
    check("mosa-docker", dockerfile_present, "Dockerfile (portable packaging)", 15)
    check("mosa-api", has_openapi, f"Documented API endpoints ({api_count})", 10)

    if open_source_ratio < 0.5:
        base_score -= 20
        ev.append(make_evidence(scan_dir, "mosa-oss", "deduction",
                                f"Open-source ratio {open_source_ratio * 100:.0f}% (<50%)",
                                round(open_source_ratio * 100, 1), -20, sbom_file))
    elif open_source_ratio < 0.8:
        base_score -= 10
        ev.append(make_evidence(scan_dir, "mosa-oss", "deduction",
                                f"Open-source ratio {open_source_ratio * 100:.0f}% (<80%)",
                                round(open_source_ratio * 100, 1), -10, sbom_file))
    else:
        ev.append(make_evidence(scan_dir, "mosa-oss", "info",
                                f"Open-source ratio {open_source_ratio * 100:.0f}%",
                                round(open_source_ratio * 100, 1), 0, sbom_file))

    if not has_sbom_standard:
        return _dimension(None, {}, ev, applicable=False)
    base_score = max(0, base_score)
    return _dimension(base_score, {
        "has_sbom_standard": has_sbom_standard,
        "has_helm_chart": has_helm if helm_data is not None else None,
        "has_dockerfile": dockerfile_present,
        "has_openapi_spec": has_openapi,
        "api_endpoint_count": api_count,
        "open_source_ratio": round(open_source_ratio * 100, 1),
        "proprietary_components": proprietary_count,
    }, ev)


def calculate_trl(dimension_scores: Dict[str, Dict], weights: Dict[str, float]) -> int:
    """
    Map weighted dimension scores (0-100) to TRL level (1-9).
    
    Mapping:
      90-100 → TRL 9 (Operational, production-ready)
      80-89  → TRL 8 (System complete, qualified)
      70-79  → TRL 7 (System prototype in operational env)
      60-69  → TRL 6 (System prototype in relevant env)
      50-59  → TRL 5 (Component validation in relevant env)
      40-49  → TRL 4 (Component validation in lab)
      30-39  → TRL 3 (Proof of concept)
      20-29  → TRL 2 (Technology concept formulated)
      0-19   → TRL 1 (Basic principles observed)
    """
    weighted_score = 0.0
    for dimension, weight in weights.items():
        dim = dimension_scores.get(dimension, {})
        weighted_score += dim.get("score", 0) * weight
    
    # Map to TRL
    if weighted_score >= 90:
        return 9
    elif weighted_score >= 80:
        return 8
    elif weighted_score >= 70:
        return 7
    elif weighted_score >= 60:
        return 6
    elif weighted_score >= 50:
        return 5
    elif weighted_score >= 40:
        return 4
    elif weighted_score >= 30:
        return 3
    elif weighted_score >= 20:
        return 2
    else:
        return 1


def get_blockers(dimension_scores: Dict[str, Dict]) -> List[str]:
    """Identify critical blockers that cap TRL advancement."""
    blockers = []
    
    sec = dimension_scores["security"]["details"]
    if sec.get("has_secrets"):
        blockers.append("CRITICAL: Secret/credential leaks detected (TruffleHog)")
    if sec.get("has_malware"):
        blockers.append("CRITICAL: Malware detected (ClamAV)")
    if sec.get("critical_cve", 0) > 0:
        blockers.append(f"CRITICAL: {sec['critical_cve']} critical CVE(s) present")
    if sec.get("kev_count", 0) > 0:
        blockers.append(f"CRITICAL: {sec['kev_count']} CISA Known Exploited Vulnerabilit(y/ies) present")
    if sec.get("pickle_issues"):
        blockers.append("CRITICAL: Dangerous content detected in model files (Layer 14)")
    
    sc = dimension_scores["supply_chain"]["details"]
    if sc.get("critical_eol", 0) > 0:
        blockers.append(f"HIGH: {sc['critical_eol']} critical EOL component(s)")
    
    comp = dimension_scores["compliance"]["details"]
    stig_rate = comp.get("stig_pass_rate")
    if stig_rate is not None and stig_rate < 70:
        blockers.append(f"COMPLIANCE: STIG compliance below 70% ({stig_rate}%)")
    if comp.get("stig_unsupported_passes", 0) > 0:
        blockers.append(f"COMPLIANCE: {comp['stig_unsupported_passes']} 'Not a Finding' STIG control(s) lack written evidence")
    
    return blockers


def main():
    parser = argparse.ArgumentParser(description="Generate TRL assessment from Epyon scan outputs")
    parser.add_argument("--scan-dir", required=True, help="Path to scan directory")
    parser.add_argument("--output", help="Output JSON file (default: <scan-dir>/trl-assessment.json)")
    parser.add_argument("--weights", choices=["default", "ml", "stig", "quick"], default="auto",
                        help="Weight profile (auto detects from scan-metadata.json)")
    args = parser.parse_args()
    
    scan_dir = Path(args.scan_dir)
    if not scan_dir.is_dir():
        print(f"ERROR: Scan directory not found: {scan_dir}", file=sys.stderr)
        return 1
    
    # The Score Card describes the application, so every input comes from the
    # newest scan of the app that has it — not only from this scan.
    history = set_history(scan_dir)
    findings = merge_findings(history)
    metadata_file = None
    for name in ["scan-metadata.json", "scan-meta.json", "ci-metadata.json"]:
        candidate = locate(scan_dir, name)
        if candidate.exists():
            metadata_file = candidate
            break
    metadata = (load_json(metadata_file) if metadata_file else None) or {}
    metadata.setdefault("scan_id", scan_dir.name)

    if not findings:
        print("ERROR: no security-findings-summary.json found in any scan of this application", file=sys.stderr)
        return 1

    scan_type = metadata.get("scan_type", "full")
    # Weights never depend on the scan type; --weights remains an explicit override.
    weight_map = {"default": DEFAULT_WEIGHTS, "ml": ML_WEIGHTS, "stig": STIG_WEIGHTS, "quick": QUICK_WEIGHTS}
    weight_profile = "default" if args.weights == "auto" else args.weights
    weights = weight_map[weight_profile]

    # Score each dimension
    print(f"Computing TRL for scan: {metadata.get('scan_id', 'unknown')}")
    print(f"Scans considered: {len(history)} → weight profile: {weight_profile}")
    
    dimension_scores = {
        "security": score_security(scan_dir, findings),
        "supply_chain": score_supply_chain(scan_dir, findings),
        "code_quality": score_code_quality(scan_dir, findings),
        "compliance": score_compliance(scan_dir),
        "operational": score_operational(scan_dir, findings, metadata),
        "mosa": score_mosa(scan_dir, findings, metadata),
    }
    
    # Dimensions with no data score 0 and keep their weight: not scanning must never help the score.
    not_scored = [d for d, v in dimension_scores.items() if not v.get("applicable", True)]

    trl_level = calculate_trl(dimension_scores, weights)
    
    # Calculate weighted overall score
    weighted_score = sum(
        dimension_scores[dim]["score"] * weight
        for dim, weight in weights.items()
    )
    
    # Identify blockers
    blockers = get_blockers(dimension_scores)
    
    # Evidence manifest: every source artifact the score relied on, with its hash.
    manifest: Dict[str, str] = {}
    for dim in dimension_scores.values():
        for item in dim.get("evidence", []):
            if item.get("source") and item.get("sha256"):
                manifest[item["source"]] = item["sha256"]

    # Build output
    output = {
        "scoring_version": SCORING_VERSION,
        "evidence_manifest": [{"path": k, "sha256": v} for k, v in sorted(manifest.items())],
        "trl_level": trl_level,
        "trl_description": f"TRL {trl_level}/9",
        "weighted_score": round(weighted_score, 1),
        "weight_profile": weight_profile,
        "weights": weights,
        "not_scored": not_scored,
        "dimension_scores": dimension_scores,
        "blockers": blockers,
        "scan_metadata": {k: metadata[k] for k in ("scan_id", "scan_type", "scan_timestamp") if metadata.get(k) is not None},
        "generated_at": findings.get("enrichment", {}).get("enriched_at") or metadata.get("scan_timestamp") or scan_dir.name,
    }
    
    # Write output
    output_file = Path(args.output) if args.output else scan_dir / "trl-assessment.json"
    output_file.write_text(json.dumps(output, indent=2), encoding="utf-8")
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"TRL ASSESSMENT SUMMARY")
    print(f"{'='*60}")
    print(f"TRL Level: {trl_level}/9 (weighted score: {weighted_score:.1f}/100)")
    print(f"\nDimension Scores:")
    for dim, data in dimension_scores.items():
        weight = weights[dim]
        print(f"  {dim:20s}: {data['score']:5.1f}/100 (weight: {weight:.0%})")
    
    if blockers:
        print(f"\n⚠️  BLOCKERS ({len(blockers)}):")
        for blocker in blockers:
            print(f"  • {blocker}")
    else:
        print(f"\n✅ No critical blockers identified")
    
    print(f"\nOutput written to: {output_file}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
