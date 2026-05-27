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


def aggregate_stig_results(scan_dirs: List[Path]) -> Dict[str, Any]:
    """Aggregate STIG results across multiple scan directories.
    
    Looks through all provided scan directories (newest to oldest) to find STIG results.
    Uses the most recent STIG data available, not just from the current scan.
    
    Args:
        scan_dirs: List of scan directory paths, sorted newest to oldest
    
    Returns:
        Dict with aggregated STIG metrics:
        - pass_rate: Overall pass rate across all controls
        - cat1_pass_rate: Category I (high severity) pass rate
        - files_assessed: Number of STIG files found
        - scans_with_stigs: Number of scans that had STIG results
        - latest_scan_with_stig: Name of most recent scan with STIG data
    """
    total_pass = 0
    total_applicable = 0
    cat1_pass = 0
    cat1_applicable = 0
    scans_with_stigs = 0
    latest_scan_with_stig = None
    all_stig_files = []
    
    for scan_dir in scan_dirs:
        stig_files = list(scan_dir.glob("stig-results-*.json"))
        if not stig_files:
            continue
        
        scans_with_stigs += 1
        if latest_scan_with_stig is None:
            latest_scan_with_stig = scan_dir.name
        
        for stig_file in stig_files:
            all_stig_files.append(stig_file)
            stig_data = load_json(stig_file)
            if not stig_data:
                continue
            
            # Load severity mapping from controls file
            slug = stig_file.stem.replace("stig-results-", "")
            controls_file = scan_dir / f"stig-controls-{slug}.json"
            severity_map = {}
            if controls_file.exists():
                controls_data = load_json(controls_file)
                if controls_data and "controls" in controls_data:
                    for ctrl in controls_data["controls"]:
                        severity_map[ctrl["vuln_id"]] = ctrl.get("severity", "").lower()
            
            # Handle both old format (findings array) and new format (assessments dict)
            findings = stig_data.get("findings", [])
            assessments = stig_data.get("assessments", {})
            
            # Process old format
            for finding in findings:
                status = finding.get("status", "")
                severity = finding.get("severity", "")
                if status in ("Open", "NotAFinding", "Not a Finding"):
                    total_applicable += 1
                    if status in ("NotAFinding", "Not a Finding"):
                        total_pass += 1
                    
                    if severity in ("high", "critical"):  # Cat I
                        cat1_applicable += 1
                        if status in ("NotAFinding", "Not a Finding"):
                            cat1_pass += 1
            
            # Process new format (assessments dict from AI) - lookup severity from controls
            for vuln_id, data in assessments.items():
                status = data.get("status", "")
                severity = severity_map.get(vuln_id, "")
                
                if status in ("Open", "Not a Finding", "Not Applicable"):
                    total_applicable += 1
                    if status == "Not a Finding":
                        total_pass += 1
                    
                    # Cat I = high severity controls
                    if severity == "high":
                        cat1_applicable += 1
                        if status == "Not a Finding":
                            cat1_pass += 1
    
    result = {
        "pass_rate": None,
        "cat1_pass_rate": None,
        "files_assessed": len(all_stig_files),
        "scans_with_stigs": scans_with_stigs,
        "latest_scan_with_stig": latest_scan_with_stig,
    }
    
    if total_applicable > 0:
        result["pass_rate"] = (total_pass / total_applicable) * 100.0
    if cat1_applicable > 0:
        result["cat1_pass_rate"] = (cat1_pass / cat1_applicable) * 100.0
    
    return result


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


def score_security(scan_dir: Path, findings: Dict) -> Dict[str, Any]:
    """
    Security & Safety dimension (0-100).
    Hard caps: secrets > 0 → max 30; malware > 0 → max 20; critical CVE > threshold → cap
    """
    summary = findings.get("summary", {})
    critical = summary.get("total_critical", 0)
    high = summary.get("total_high", 0)
    medium = summary.get("total_medium", 0)
    low = summary.get("total_low", 0)
    
    # Check for secrets (TruffleHog)
    secret_findings = [f for f in findings.get("critical_findings", []) + findings.get("high_findings", [])
                       if f.get("tool", "").lower() == "trufflehog"]
    has_secrets = len(secret_findings) > 0
    
    # Check for malware (ClamAV results)
    clamav_file = scan_dir / "clamav" / "clamav-results.json"
    clamav_data = load_json(clamav_file)
    has_malware = False
    if clamav_data:
        infected = clamav_data.get("summary", {}).get("infected_files", 0)
        has_malware = infected > 0
    
    # Check Picklescan (ML models)
    picklescan_file = scan_dir / "picklescan-results.json"
    picklescan_data = load_json(picklescan_file)
    has_pickle_issues = False
    if picklescan_data:
        dangerous = picklescan_data.get("summary", {}).get("dangerous_imports", 0)
        has_pickle_issues = dangerous > 0
    
    # Check Garak (LLM safety)
    garak_file = scan_dir / "garak" / "garak-results.json"
    garak_data = load_json(garak_file)
    garak_pass_rate = 100.0
    if garak_data and isinstance(garak_data, dict) and "probes" in garak_data:
        probes = garak_data["probes"]
        if isinstance(probes, list):
            total_attempts = sum(p.get("attempts", 0) for p in probes if isinstance(p, dict))
            passed = sum(p.get("passed", 0) for p in probes if isinstance(p, dict))
            if total_attempts > 0:
                garak_pass_rate = (passed / total_attempts) * 100.0
    
    # Base score from CVE counts (penalize heavily for critical/high)
    base_score = 100.0
    base_score -= critical * 15  # Each critical CVE: -15 pts
    base_score -= high * 5       # Each high CVE: -5 pts
    base_score -= medium * 1     # Each medium CVE: -1 pt
    base_score -= low * 0.2      # Each low CVE: -0.2 pt
    base_score = max(0, base_score)
    
    # Apply hard caps
    if has_secrets:
        base_score = min(base_score, 30)
    if has_malware:
        base_score = min(base_score, 20)
    if has_pickle_issues:
        base_score = min(base_score, 40)
    if garak_pass_rate < 80.0:
        base_score = min(base_score, 50)
    
    return {
        "score": round(base_score, 1),
        "max": 100,
        "details": {
            "critical_cve": critical,
            "high_cve": high,
            "medium_cve": medium,
            "low_cve": low,
            "has_secrets": has_secrets,
            "has_malware": has_malware,
            "pickle_issues": has_pickle_issues,
            "garak_pass_rate": round(garak_pass_rate, 1) if garak_data else None,
        }
    }


def score_supply_chain(scan_dir: Path, findings: Dict) -> Dict[str, Any]:
    """
    Supply Chain Integrity dimension (0-100).
    Checks SBOM completeness, EOL components, dependency vuln ratio.
    """
    # SBOM completeness (try both naming conventions)
    sbom_file = scan_dir / "sbom" / "filesystem.cyclonedx.json"
    if not sbom_file.exists():
        sbom_file = scan_dir / "sbom" / "filesystem-cyclonedx.json"
    sbom_data = load_json(sbom_file)
    sbom_exists = sbom_data is not None
    component_count = 0
    if sbom_data and "components" in sbom_data:
        component_count = len(sbom_data["components"])
    
    # EOL components (Xeol)
    xeol_file = scan_dir / "xeol" / "xeol-results.json"
    xeol_data = load_json(xeol_file)
    eol_count = 0
    critical_eol = 0
    if xeol_data and "matches" in xeol_data:
        eol_count = len(xeol_data["matches"])
        for match in xeol_data["matches"]:
            cycle_info = match.get("cycle", {})
            if cycle_info.get("eol", False) and cycle_info.get("support", True) is False:
                critical_eol += 1
    
    # Dependency vulnerability ratio (CVEs per component)
    summary = findings.get("summary", {})
    total_cve = summary.get("total_critical", 0) + summary.get("total_high", 0) + summary.get("total_medium", 0)
    vuln_ratio = (total_cve / component_count) if component_count > 0 else 0.0
    
    base_score = 100.0
    if not sbom_exists:
        base_score = 0
    else:
        base_score -= critical_eol * 20  # Each critical EOL: -20 pts
        base_score -= eol_count * 5      # Each EOL component: -5 pts
        base_score -= vuln_ratio * 10    # Penalty for vuln density
        base_score = max(0, base_score)
    
    return {
        "score": round(base_score, 1),
        "max": 100,
        "details": {
            "sbom_exists": sbom_exists,
            "component_count": component_count,
            "eol_components": eol_count,
            "critical_eol": critical_eol,
            "vuln_ratio": round(vuln_ratio, 2),
        }
    }


def score_code_quality(scan_dir: Path) -> Dict[str, Any]:
    """
    Code Quality dimension (0-100).
    SonarQube quality gate + IaC security (Checkov).
    """
    # SonarQube gate (if ran)
    sonar_file = scan_dir / "sonar" / "quality-gate.json"
    sonar_data = load_json(sonar_file)
    sonar_pass = None
    sonar_debt_ratio = 0.0
    if sonar_data:
        sonar_pass = sonar_data.get("projectStatus", {}).get("status") == "OK"
        for condition in sonar_data.get("projectStatus", {}).get("conditions", []):
            if condition.get("metricKey") == "sqale_debt_ratio":
                sonar_debt_ratio = float(condition.get("actualValue", "0"))
    
    # Checkov IaC scan
    checkov_file = scan_dir / "checkov" / "results.json"
    checkov_data = load_json(checkov_file)
    checkov_pass_rate = 100.0
    if checkov_data and "summary" in checkov_data:
        passed = checkov_data["summary"].get("passed", 0)
        failed = checkov_data["summary"].get("failed", 0)
        total = passed + failed
        if total > 0:
            checkov_pass_rate = (passed / total) * 100.0
    
    # Calculate score based on what actually ran
    # SonarQube contributes 60% of quality score
    sonar_score = 0.0
    if sonar_pass is True:
        sonar_score = 60.0 - (sonar_debt_ratio * 1.2)  # Technical debt penalty
    elif sonar_pass is False:
        sonar_score = 30.0 - (sonar_debt_ratio * 1.2)  # Failed but ran
    # else: sonar_pass is None → 0 points (didn't run = no evidence)
    
    # Checkov contributes 40%
    checkov_score = 0.0
    if checkov_data and "summary" in checkov_data:
        checkov_score = checkov_pass_rate * 0.4
    # else: Checkov didn't run → 0 points
    
    base_score = sonar_score + checkov_score
    base_score = max(0, min(100, base_score))
    
    return {
        "score": round(base_score, 1),
        "max": 100,
        "details": {
            "sonar_quality_gate": sonar_pass,
            "sonar_debt_ratio": round(sonar_debt_ratio, 1) if sonar_data else None,
            "checkov_pass_rate": round(checkov_pass_rate, 1) if checkov_data else None,
        }
    }


def score_compliance(scan_dir: Path) -> Dict[str, Any]:
    """
    Compliance & Documentation dimension (0-100).
    STIG compliance % + model card completeness + API documentation.
    
    STIG and API data are aggregated across ALL historical scans for this app,
    not just the current scan, since these layers aren't run every time.
    """
    # Get app name and find all historical scans
    app_name = get_app_name_from_scan_dir(scan_dir)
    all_scans = find_all_app_scans(scan_dir, app_name)
    
    # Aggregate STIG results across all scans
    stig_agg = aggregate_stig_results(all_scans)
    stig_pass_rate = stig_agg["pass_rate"]
    stig_cat1_pass = stig_agg["cat1_pass_rate"]
    stig_files_count = stig_agg["files_assessed"]
    scans_with_stigs = stig_agg["scans_with_stigs"]
    
    # Aggregate API endpoints across all scans
    api_agg = aggregate_api_endpoints(all_scans)
    api_documented = api_agg["endpoint_count"]
    scans_with_apis = api_agg["scans_with_apis"]
    
    # Model card completeness (current scan only - specific to ML models)
    modelcard_file = scan_dir / "modelcard" / "modelcard-results.json"
    modelcard_data = load_json(modelcard_file)
    modelcard_score = None
    if modelcard_data:
        # Check for explicit completeness_score field first
        modelcard_score = modelcard_data.get("completeness_score")
        # If not present, calculate from passed/failed counts
        if modelcard_score is None:
            passed = modelcard_data.get("passed", 0)
            failed = modelcard_data.get("failed", 0)
            total = passed + failed
            if total > 0:
                modelcard_score = (passed / total) * 100.0
    
    base_score = 100.0
    
    # STIG contributes 70% (if ever ran)
    if stig_pass_rate is not None:
        base_score = stig_pass_rate * 0.7
        # Extra penalty for Cat I failures
        if stig_cat1_pass is not None and stig_cat1_pass < 100:
            base_score -= (100 - stig_cat1_pass) * 0.15
    else:
        base_score -= 30  # Penalty for no STIG assessment ever
    
    # Model card contributes 20% (if applicable)
    if modelcard_score is not None:
        base_score += modelcard_score * 0.2
    
    # API docs contribute 10%
    if api_documented > 0:
        base_score += 10
    
    base_score = max(0, min(100, base_score))
    
    return {
        "score": round(base_score, 1),
        "max": 100,
        "details": {
            "stig_pass_rate": round(stig_pass_rate, 1) if stig_pass_rate is not None else None,
            "stig_cat1_pass_rate": round(stig_cat1_pass, 1) if stig_cat1_pass is not None else None,
            "stig_files_assessed": stig_files_count,
            "stig_scans_aggregated": scans_with_stigs,
            "stig_latest_scan": stig_agg["latest_scan_with_stig"],
            "modelcard_completeness": round(modelcard_score, 1) if modelcard_score else None,
            "api_endpoints_found": api_documented,
            "api_scans_aggregated": scans_with_apis,
            "api_latest_scan": api_agg["latest_scan_with_apis"],
        }
    }


def score_operational(scan_dir: Path, findings: Dict, metadata: Dict) -> Dict[str, Any]:
    """
    Operational Readiness dimension (0-100).
    Helm chart validity + network exposure + scan trend direction.
    """
    # Helm chart validity
    helm_file = scan_dir / "helm" / "helm-results.json"
    helm_data = load_json(helm_file)
    helm_valid = None
    if helm_data:
        helm_valid = helm_data.get("build_success", False)
    
    # Network exposure
    network_file = scan_dir / "network-discovery" / "network-inventory.json"
    network_data = load_json(network_file)
    unexpected_ports = 0
    if network_data and "open_ports" in network_data:
        # Consider any non-standard ports as unexpected (simplified heuristic)
        standard_ports = {80, 443, 22, 3000, 8080, 8443}
        for port_info in network_data["open_ports"]:
            port = port_info.get("port", 0)
            if port not in standard_ports:
                unexpected_ports += 1
    
    # Scan trend (improvement vs. prior scan) - placeholder for now
    # Would need scan-history.json integration
    trend_direction = "stable"  # "improving" | "stable" | "degrading"
    
    base_score = 100.0
    
    if helm_valid is False:
        base_score -= 30
    elif helm_valid is None:
        base_score -= 10  # Not applicable penalty
    
    base_score -= unexpected_ports * 10  # Each unexpected port: -10 pts
    
    if trend_direction == "degrading":
        base_score -= 20
    elif trend_direction == "improving":
        base_score += 10
    
    base_score = max(0, min(100, base_score))
    
    return {
        "score": round(base_score, 1),
        "max": 100,
        "details": {
            "helm_valid": helm_valid,
            "unexpected_network_ports": unexpected_ports,
            "trend_direction": trend_direction,
        }
    }

def score_mosa(scan_dir: Path, findings: Dict, metadata: Dict) -> Dict[str, Any]:
    """
    MOSA (Modular Open Systems Approach) dimension (0-100).
    Evaluates modularity, open standards, interoperability, portability, vendor independence.
    """
    base_score = 100.0
    
    # Open Standards: SBOM (CycloneDX), OpenAPI specs, container standards
    sbom_file = scan_dir / "sbom" / "filesystem.cyclonedx.json"
    if not sbom_file.exists():
        sbom_file = scan_dir / "sbom" / "filesystem-cyclonedx.json"
    has_sbom_standard = sbom_file.exists()
    
    api_discovery_file = scan_dir / "api-discovery" / "openapi-specs.json"
    has_openapi = api_discovery_file.exists()
    
    # Modularity: Helm charts indicate modular deployment
    helm_file = scan_dir / "helm" / "helm-results.json"
    helm_data = load_json(helm_file)
    has_helm = helm_data is not None and helm_data.get("chart_valid") is True
    
    # Portability: Dockerfile/containerization
    dockerfile_present = (scan_dir / "Dockerfile").exists() or metadata.get("has_dockerfile", False)
    
    # Vendor Independence: Open source ratio
    sbom_data = load_json(sbom_file)
    open_source_ratio = 0.0
    proprietary_count = 0
    if sbom_data and "components" in sbom_data:
        total_components = len(sbom_data["components"])
        if total_components > 0:
            for comp in sbom_data["components"]:
                licenses = comp.get("licenses", [])
                # Check if component has recognizable open source license
                has_oss_license = any(
                    lic.get("license", {}).get("id", "").lower() in [
                        "mit", "apache-2.0", "bsd-3-clause", "gpl-3.0", "lgpl-3.0", "isc", "mpl-2.0"
                    ] for lic in licenses if isinstance(lic, dict)
                )
                if not has_oss_license and licenses:  # Has license but not OSS
                    proprietary_count += 1
            open_source_ratio = (total_components - proprietary_count) / total_components
    
    # Interoperability: Standard APIs, documented interfaces
    api_count = 0
    if has_openapi:
        api_data = load_json(api_discovery_file)
        if api_data and "endpoints" in api_data:
            api_count = len(api_data["endpoints"])
    
    # Scoring
    if not has_sbom_standard:
        base_score -= 25  # No standard SBOM format
    
    if not has_helm:
        base_score -= 15  # No modular deployment pattern
    
    if not dockerfile_present:
        base_score -= 15  # Not containerized/portable
    
    if not has_openapi:
        base_score -= 10  # No API documentation
    
    if open_source_ratio < 0.5:
        base_score -= 20  # High proprietary dependency
    elif open_source_ratio < 0.8:
        base_score -= 10  # Moderate proprietary dependency
    
    base_score = max(0, base_score)
    
    return {
        "score": round(base_score, 1),
        "max": 100,
        "details": {
            "has_sbom_standard": has_sbom_standard,
            "has_helm_chart": has_helm,
            "has_dockerfile": dockerfile_present,
            "has_openapi_spec": has_openapi,
            "api_endpoint_count": api_count,
            "open_source_ratio": round(open_source_ratio * 100, 1),
            "proprietary_components": proprietary_count,
        }
    }

def score_mosa(scan_dir: Path, findings: Dict, metadata: Dict) -> Dict[str, Any]:
    """
    MOSA (Modular Open Systems Approach) dimension (0-100).
    Evaluates modularity, open standards, interoperability, portability, vendor independence.
    """
    base_score = 100.0
    
    # Open Standards: SBOM (CycloneDX), OpenAPI specs, container standards
    sbom_file = scan_dir / "sbom" / "filesystem.cyclonedx.json"
    if not sbom_file.exists():
        sbom_file = scan_dir / "sbom" / "filesystem-cyclonedx.json"
    has_sbom_standard = sbom_file.exists()
    
    api_discovery_file = scan_dir / "api-discovery" / "openapi-specs.json"
    has_openapi = api_discovery_file.exists()
    
    # Modularity: Helm charts indicate modular deployment
    helm_file = scan_dir / "helm" / "helm-results.json"
    helm_data = load_json(helm_file)
    has_helm = helm_data is not None and helm_data.get("chart_valid") is True
    
    # Portability: Dockerfile/containerization
    dockerfile_present = (scan_dir / "Dockerfile").exists() or metadata.get("has_dockerfile", False)
    
    # Vendor Independence: Open source ratio
    sbom_data = load_json(sbom_file)
    open_source_ratio = 0.0
    proprietary_count = 0
    if sbom_data and "components" in sbom_data:
        total_components = len(sbom_data["components"])
        if total_components > 0:
            for comp in sbom_data["components"]:
                licenses = comp.get("licenses", [])
                # Check if component has recognizable open source license
                has_oss_license = any(
                    lic.get("license", {}).get("id", "").lower() in [
                        "mit", "apache-2.0", "bsd-3-clause", "gpl-3.0", "lgpl-3.0", "isc", "mpl-2.0"
                    ] for lic in licenses if isinstance(lic, dict)
                )
                if not has_oss_license and licenses:  # Has license but not OSS
                    proprietary_count += 1
            open_source_ratio = (total_components - proprietary_count) / total_components
    
    # Interoperability: Standard APIs, documented interfaces
    api_count = 0
    if has_openapi:
        api_data = load_json(api_discovery_file)
        if api_data and "endpoints" in api_data:
            api_count = len(api_data["endpoints"])
    
    # Scoring
    if not has_sbom_standard:
        base_score -= 25  # No standard SBOM format
    
    if not has_helm:
        base_score -= 15  # No modular deployment pattern
    
    if not dockerfile_present:
        base_score -= 15  # Not containerized/portable
    
    if not has_openapi:
        base_score -= 10  # No API documentation
    
    if open_source_ratio < 0.5:
        base_score -= 20  # High proprietary dependency
    elif open_source_ratio < 0.8:
        base_score -= 10  # Moderate proprietary dependency
    
    base_score = max(0, base_score)
    
    return {
        "score": round(base_score, 1),
        "max": 100,
        "details": {
            "has_sbom_standard": has_sbom_standard,
            "has_helm_chart": has_helm,
            "has_dockerfile": dockerfile_present,
            "has_openapi_spec": has_openapi,
            "api_endpoint_count": api_count,
            "open_source_ratio": round(open_source_ratio * 100, 1),
            "proprietary_components": proprietary_count,
        }
    }


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
        score = dimension_scores.get(dimension, {}).get("score", 0)
        weighted_score += score * weight
    
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
    
    sc = dimension_scores["supply_chain"]["details"]
    if not sc.get("sbom_exists"):
        blockers.append("BLOCKER: No SBOM present")
    if sc.get("critical_eol", 0) > 0:
        blockers.append(f"HIGH: {sc['critical_eol']} critical EOL component(s)")
    
    comp = dimension_scores["compliance"]["details"]
    stig_rate = comp.get("stig_pass_rate")
    if stig_rate is not None and stig_rate < 70:
        blockers.append(f"COMPLIANCE: STIG compliance below 70% ({stig_rate}%)")
    
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
    
    # Load required inputs
    findings_file = scan_dir / "security-findings-summary.json"
    
    # Check for metadata file (multiple naming conventions across versions)
    metadata_file = None
    for name in ["scan-metadata.json", "scan-meta.json", "ci-metadata.json"]:
        candidate = scan_dir / name
        if candidate.exists():
            metadata_file = candidate
            break
    
    findings = load_json(findings_file)
    metadata = load_json(metadata_file) if metadata_file else None
    
    if not findings:
        print(f"ERROR: security-findings-summary.json not found or invalid", file=sys.stderr)
        return 1
    if not metadata:
        print(f"ERROR: No metadata file found (tried scan-metadata.json, scan-meta.json, ci-metadata.json)", file=sys.stderr)
        return 1
    
    # Select weight profile
    scan_type = metadata.get("scan_type", "full")
    if args.weights == "auto":
        if scan_type in ("local_model", "huggingface"):
            weights = ML_WEIGHTS
            weight_profile = "ml"
        elif scan_type == "stig":
            weights = STIG_WEIGHTS
            weight_profile = "stig"
        elif scan_type == "quick":
            weights = QUICK_WEIGHTS
            weight_profile = "quick"
        else:
            weights = DEFAULT_WEIGHTS
            weight_profile = "default"
    else:
        weight_map = {"default": DEFAULT_WEIGHTS, "ml": ML_WEIGHTS, "stig": STIG_WEIGHTS, "quick": QUICK_WEIGHTS}
        weights = weight_map[args.weights]
        weight_profile = args.weights
    
    # Score each dimension
    print(f"Computing TRL for scan: {metadata.get('scan_id', 'unknown')}")
    print(f"Scan type: {scan_type} → weight profile: {weight_profile}")
    
    dimension_scores = {
        "security": score_security(scan_dir, findings),
        "supply_chain": score_supply_chain(scan_dir, findings),
        "code_quality": score_code_quality(scan_dir),
        "compliance": score_compliance(scan_dir),
        "operational": score_operational(scan_dir, findings, metadata),
        "mosa": score_mosa(scan_dir, findings, metadata),
    }
    
    # Calculate TRL
    trl_level = calculate_trl(dimension_scores, weights)
    
    # Calculate weighted overall score
    weighted_score = sum(
        dimension_scores[dim]["score"] * weight
        for dim, weight in weights.items()
    )
    
    # Identify blockers
    blockers = get_blockers(dimension_scores)
    
    # Build output
    output = {
        "trl_level": trl_level,
        "trl_description": f"TRL {trl_level}/9",
        "weighted_score": round(weighted_score, 1),
        "weight_profile": weight_profile,
        "weights": weights,
        "dimension_scores": dimension_scores,
        "blockers": blockers,
        "scan_metadata": {
            "scan_id": metadata.get("scan_id"),
            "scan_type": metadata.get("scan_type"),
            "scan_timestamp": metadata.get("scan_timestamp"),
        },
        "generated_at": findings.get("enrichment", {}).get("enriched_at") or metadata.get("scan_timestamp"),
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
