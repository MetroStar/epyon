"""
Scan tool output parsers for Epyon Web.
Reads raw tool JSON/log files from a scan directory and returns normalised findings.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

# ── Severity normalisation ────────────────────────────────────

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

def norm_sev(s: str | None) -> str:
    if not s:
        return "unknown"
    l = s.lower()
    if l == "critical":
        return "critical"
    if l == "high":
        return "high"
    if l in ("medium", "moderate"):
        return "medium"
    if l in ("low", "negligible", "info"):
        return "low"
    return "unknown"


def _determine_cve_source(data_source: str, namespace: str) -> str:
    """Determine the CVE database source from Grype/Anchore metadata."""
    data_source = data_source.lower()
    namespace = namespace.lower()
    
    # GitHub Security Advisory
    if "github" in data_source or "ghsa" in namespace:
        return "GHSA"
    
    # NVD (National Vulnerability Database)
    if "nvd" in data_source or "nvd.nist.gov" in data_source:
        return "NVD"
    
    # Alpine SecDB
    if "alpine" in namespace or "alpine" in data_source:
        return "Alpine"
    
    # Debian
    if "debian" in namespace or "debian" in data_source:
        return "Debian"
    
    # Ubuntu
    if "ubuntu" in namespace or "ubuntu" in data_source:
        return "Ubuntu"
    
    # RHEL / Red Hat
    if "rhel" in namespace or "redhat" in namespace or "rhel" in data_source:
        return "RHEL"
    
    # Default to Grype DB if we can't determine specific source
    return "Grype"


# ── Directory/path helpers ────────────────────────────────────

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TIME_RE = re.compile(r"^\d{2}-\d{2}-\d{2}$")


def parse_dir_name(name: str) -> dict:
    parts = name.split("_")
    if len(parts) >= 3:
        time_part = parts[-1]
        date_part = parts[-2]
        if _DATE_RE.match(date_part) and _TIME_RE.match(time_part):
            ts = f"{date_part}T{time_part.replace('-', ':')}"
            if len(parts) == 3:
                return {"target": parts[0], "user": "", "timestamp": ts}
            user   = parts[-3]
            target = "_".join(parts[:-3])
            return {"target": target, "user": user, "timestamp": ts}
    return {"target": name, "user": "", "timestamp": ""}


def find_scan_dirs(epyon_root: Path, days: int = 0) -> list[Path]:
    """
    Find all scan directories within epyon_root.
    
    Args:
        epyon_root: Root directory of the Epyon installation
        days: If > 0, only return scans from the last N days (based on directory name timestamp)
    
    Returns:
        List of Path objects for scan directories, sorted by name (chronological)
    """
    search = [
        epyon_root / "scans",
        epyon_root / "baseline" / "scans",
        epyon_root / "scripts" / "scans",
    ]
    
    # Calculate cutoff date if filtering by days
    cutoff_date = None
    if days > 0:
        from datetime import datetime, timedelta, timezone
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_date = cutoff_dt.strftime("%Y-%m-%d")
    
    dirs: list[Path] = []
    for base in search:
        if not base.exists():
            continue
        try:
            entries = sorted(base.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.name.startswith("."):
                continue
            try:
                if not entry.is_dir():
                    continue
                # Ensure it's inside epyon_root (path traversal guard)
                entry.resolve().relative_to(epyon_root.resolve())
                
                # Filter by date if requested
                if cutoff_date:
                    parsed = parse_dir_name(entry.name)
                    scan_date = parsed.get("timestamp", "")[:10]  # YYYY-MM-DD
                    if scan_date and scan_date < cutoff_date:
                        continue  # Skip scans older than cutoff
                
                dirs.append(entry)
            except (OSError, ValueError):
                continue
    return dirs


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _json_files_in(directory: Path, skip_symlinks: bool = True) -> list[Path]:
    if not directory.exists():
        return []
    try:
        return [
            f for f in sorted(directory.iterdir())
            if f.suffix == ".json"
            and "statistics" not in f.name
            and (not skip_symlinks or not f.is_symlink())
            and f.is_file()
        ]
    except OSError:
        return []


# ── Per-tool parsers ──────────────────────────────────────────

def parse_trivy_dir(scan_dir: Path) -> list[dict]:
    findings = []
    for file in _json_files_in(scan_dir / "trivy"):
        raw = _read_json(file)
        if not raw or not raw.get("SchemaVersion"):
            continue
        for result in raw.get("Results", []):
            for v in result.get("Vulnerabilities") or []:
                # For Trivy, we default to "Trivy" since it doesn't expose source metadata
                findings.append({
                    "tool": "Trivy",
                    "id": v.get("VulnerabilityID", ""),
                    "severity": norm_sev(v.get("Severity")),
                    "package": v.get("PkgName", ""),
                    "version": v.get("InstalledVersion", ""),
                    "fixed_version": v.get("FixedVersion", ""),
                    "title": v.get("Title") or v.get("Description", ""),
                    "description": v.get("Description", ""),
                    "target": result.get("Target", ""),
                    "references": (v.get("References") or [])[:3],
                    "cve_source": "Trivy",
                })
    return findings


def parse_grype_dir(scan_dir: Path) -> list[dict]:
    findings = []
    for file in _json_files_in(scan_dir / "grype"):
        raw = _read_json(file)
        if not raw or not isinstance(raw.get("matches"), list):
            continue
        for m in raw["matches"]:
            vuln = m.get("vulnerability", {})
            art  = m.get("artifact", {})
            locs = art.get("locations") or []
            fix_vers = (vuln.get("fix") or {}).get("versions") or []
            
            # Determine CVE source from dataSource and namespace
            data_source = vuln.get("dataSource", "")
            namespace = vuln.get("namespace", "")
            cve_source = _determine_cve_source(data_source, namespace)
            
            findings.append({
                "tool": "Grype",
                "id": vuln.get("id", ""),
                "severity": norm_sev(vuln.get("severity")),
                "package": art.get("name", ""),
                "version": art.get("version", ""),
                "fixed_version": fix_vers[0] if fix_vers else "",
                "title": vuln.get("description", ""),
                "description": vuln.get("description", ""),
                "target": locs[0].get("path", "") if locs else "",
                "references": (vuln.get("urls") or [])[:3],
                "cve_source": cve_source,
            })
    return findings


def parse_trufflehog_dir(scan_dir: Path) -> list[dict]:
    findings = []
    directory = scan_dir / "trufflehog"
    if not directory.exists():
        return findings
    scan_id = scan_dir.name
    for file in directory.iterdir():
        if not file.name.endswith(".json"):
            continue
        if file.name.startswith(f"{scan_id}_"):
            continue
        try:
            for line in file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Handle both single objects and arrays
                if isinstance(obj, list):
                    objects = obj
                else:
                    objects = [obj]
                
                for item in objects:
                    if not isinstance(item, dict) or not item.get("DetectorName"):
                        continue
                    meta = (item.get("SourceMetadata") or {}).get("Data") or {}
                    fs_data = meta.get("Filesystem") or meta.get("Git") or {}
                    verified = bool(item.get("Verified"))
                    file_path = fs_data.get("file") or fs_data.get("path", "")
                    
                    # Strip /workspace/ prefix added by Docker volume mount
                    if file_path.startswith("/workspace/"):
                        file_path = file_path[len("/workspace/"):]
                    
                    line_num = fs_data.get("line", "")
                    
                    # Build location string with file path and line number
                    location = file_path
                    if file_path and line_num:
                        location = f"{file_path}#L{line_num}"
                    
                    findings.append({
                        "tool": "TruffleHog",
                        "id": item.get("DetectorName", "SECRET"),
                        "severity": "critical" if verified else "high",
                        "package": item.get("DetectorName", ""),
                        "version": "",
                        "fixed_version": "",
                        "title": f"{'Verified' if verified else 'Unverified'} secret: {item.get('DetectorName', '')}",
                        "description": (
                            f"Detector: {item.get('DetectorName', '')}. "
                            f"File: {file_path}. "
                            f"Line: {line_num or '?'}"
                        ),
                        "target": file_path,
                        "location": location,
                        "line":   line_num,
                        "references": [],
                    })
        except OSError:
            continue
    return findings


def parse_checkov_dir(scan_dir: Path) -> list[dict]:
    findings = []
    directory = scan_dir / "checkov"
    if not directory.exists():
        return findings

    scan_id = scan_dir.name
    candidates: list[Path] = []

    try:
        entries = list(directory.iterdir())
    except OSError:
        return findings

    for entry in entries:
        if entry.name.startswith(f"{scan_id}_"):
            continue
        try:
            entry.stat()
        except OSError:
            continue
        if entry.is_dir() and entry.name.endswith(".json"):
            inner = entry / "results_json.json"
            if inner.exists():
                candidates.append(inner)
        elif entry.is_file() and entry.name.endswith(".json") and "statistics" not in entry.name:
            candidates.append(entry)

    for file in candidates:
        raw = _read_json(file)
        if not isinstance(raw, list):
            continue
        for section in raw:
            for check in (section.get("results") or {}).get("failed_checks") or []:
                raw_sev = check.get("severity") or (
                    (check.get("check_result") or {}).get("severity")
                )
                sev = norm_sev(raw_sev)
                if sev == "unknown":
                    sev = "medium"
                line_range = check.get("file_line_range") or []
                file_path = check.get("file_path", "")
                resource = check.get("resource", "")
                
                # Build location string with file path and line range
                location = file_path
                if line_range:
                    if len(line_range) == 2:
                        location = f"{file_path}#L{line_range[0]}-L{line_range[1]}"
                    elif len(line_range) == 1:
                        location = f"{file_path}#L{line_range[0]}"
                
                # Build description with check name and resource context
                check_name = check.get("check_name") or check.get("check_id", "")
                description = check_name
                if resource:
                    description = f"{check_name} — Resource: {resource}"
                if file_path and line_range:
                    line_range_str = '-'.join(str(x) for x in line_range)
                    description = f"{check_name} — {file_path}:{line_range_str}"
                    if resource:
                        description = f"{check_name} — Resource: {resource} in {file_path}:{line_range_str}"
                
                findings.append({
                    "tool": "Checkov",
                    "id": check.get("check_id", ""),
                    "severity": sev,
                    "package": file_path,
                    "version": "",
                    "fixed_version": "",
                    "title": check_name,
                    "description": description,
                    "target": file_path,
                    "location": location,
                    "resource": resource,
                    "file_line_range": line_range,
                    "references": [check["guideline"]] if check.get("guideline") else [],
                })
    return findings


def parse_clamav_dir(scan_dir: Path) -> list[dict]:
    findings = []
    directory = scan_dir / "clamav"
    if not directory.exists():
        return findings

    log_content = ""
    for candidate in ["clamav-detailed.log", "scan.log"]:
        f = directory / candidate
        if f.exists():
            try:
                log_content = f.read_text(encoding="utf-8", errors="replace")
                break
            except OSError:
                pass

    found_re = re.compile(r"^(.+?):\s+(.+?)\s+FOUND\s*$", re.MULTILINE)
    for m in found_re.finditer(log_content):
        file_path = m.group(1).strip()
        sig       = m.group(2).strip()
        findings.append({
            "tool": "ClamAV",
            "id": sig,
            "severity": "critical",
            "package": os.path.basename(file_path),
            "version": "",
            "fixed_version": "",
            "title": f"Malware detected: {sig}",
            "description": f"File: {file_path}  Signature: {sig}",
            "target": file_path,
            "references": [],
        })
    return findings


def parse_anchore_dir(scan_dir: Path) -> list[dict]:
    findings = []
    anchore_dir = scan_dir / "anchore"
    files: list[Path] = []

    fs_file = anchore_dir / "anchore-filesystem-results.json"
    if fs_file.exists():
        files.append(fs_file)

    images_dir = anchore_dir / "images"
    if images_dir.exists():
        files.extend(_json_files_in(images_dir))

    for file in files:
        raw = _read_json(file)
        if not raw:
            continue
        for m in raw.get("matches") or []:
            vuln = m.get("vulnerability", {})
            art  = m.get("artifact", {})
            locs = art.get("locations") or []
            fix_vers = (vuln.get("fix") or {}).get("versions") or []
            
            # Determine CVE source from dataSource and namespace
            data_source = vuln.get("dataSource", "")
            namespace = vuln.get("namespace", "")
            cve_source = _determine_cve_source(data_source, namespace)
            
            findings.append({
                "tool": "Anchore",
                "id": vuln.get("id", ""),
                "severity": (vuln.get("severity") or "unknown").lower(),
                "package": art.get("name", ""),
                "version": art.get("version", ""),
                "fixed_version": fix_vers[0] if fix_vers else "",
                "title": vuln.get("description") or vuln.get("id", ""),
                "description": vuln.get("description", ""),
                "target": locs[0].get("path", "") if locs else "",
                "references": vuln.get("urls") or [],
                "cve_source": cve_source,
            })
    return findings


def parse_xeol_dir(scan_dir: Path) -> list[dict]:
    findings = []
    for file in _json_files_in(scan_dir / "xeol"):
        raw = _read_json(file)
        if not raw:
            continue
        for m in raw.get("matches") or []:
            pkg  = m.get("artifact") or m.get("package") or {}
            eol  = m.get("eol") or {}
            locs = pkg.get("locations") or []
            eol_date = eol.get("eolDate", "")
            findings.append({
                "tool": "Xeol",
                "id": f"EOL:{eol_date}" if eol_date else "EOL",
                "severity": "high",
                "package": pkg.get("name", ""),
                "version": pkg.get("version", ""),
                "fixed_version": "",
                "title": f"End-of-life: {pkg.get('name', '')}@{pkg.get('version', '')}",
                "description": (
                    f"{pkg.get('name', '')}@{pkg.get('version', '')} reached end-of-life"
                    + (f" on {eol_date}" if eol_date else "")
                ),
                "target": locs[0].get("path", "") if locs else "",
                "references": [],
            })
    return findings


def parse_pip_audit_dir(scan_dir: Path) -> list[dict]:
    """Parse pip-audit direct dependency scan results.
    
    Reads pip-audit-consolidated-results.json which contains scan_results
    with vulnerability findings for Python dependencies.
    """
    findings = []
    pip_audit_dir = scan_dir / "pip-audit"
    if not pip_audit_dir.exists():
        return findings
    
    consolidated = pip_audit_dir / "pip-audit-consolidated-results.json"
    if not consolidated.exists():
        return findings
    
    raw = _read_json(consolidated)
    if not raw:
        return findings
    
    for scan_result in raw.get("scan_results") or []:
        file_path = scan_result.get("file", "")
        results = scan_result.get("results") or []
        
        for vuln in results:
            # pip-audit provides: id, name, v (version), description, fix_versions, published, advisory
            fix_versions = vuln.get("fix_versions") or []
            # Infer severity: if fix available -> medium, else -> high
            severity = "medium" if fix_versions else "high"
            
            findings.append({
                "tool": "pip-audit",
                "id": vuln.get("id", ""),
                "severity": severity,
                "package": vuln.get("name", ""),
                "version": vuln.get("v", ""),
                "fixed_version": fix_versions[0] if fix_versions else "",
                "title": vuln.get("id", ""),
                "description": vuln.get("description", ""),
                "target": file_path,
                "references": [vuln.get("advisory")] if vuln.get("advisory") else [],
                "cve_source": "OSV",
            })
    
    return findings


def parse_safety_dir(scan_dir: Path) -> list[dict]:
    """Parse Safety Python vulnerability scan results.
    
    Reads safety-consolidated-results.json which contains scan_results
    with vulnerability findings from Safety's vulnerability database.
    """
    findings = []
    safety_dir = scan_dir / "safety"
    if not safety_dir.exists():
        return findings
    
    consolidated = safety_dir / "safety-consolidated-results.json"
    if not consolidated.exists():
        return findings
    
    raw = _read_json(consolidated)
    if not raw:
        return findings
    
    for scan_result in raw.get("scan_results") or []:
        file_path = scan_result.get("file", "")
        results = scan_result.get("results") or []
        
        for vuln in results:
            # Safety provides: advisory_id/id, package, installed_version, safe_version, severity, advisory
            severity = (vuln.get("severity") or "medium").lower()
            safe_version = vuln.get("safe_version") or ""
            
            findings.append({
                "tool": "safety",
                "id": vuln.get("advisory_id") or vuln.get("id", ""),
                "severity": severity,
                "package": vuln.get("package", ""),
                "version": vuln.get("installed_version", ""),
                "fixed_version": safe_version,
                "title": vuln.get("advisory_id") or vuln.get("id", ""),
                "description": vuln.get("advisory", ""),
                "target": file_path,
                "references": [],
                "cve_source": "Safety DB",
            })
    
    return findings


def parse_network_discovery_dir(scan_dir: Path) -> dict | None:
    """Return normalized network-discovery data, or None if not present."""
    result_file = scan_dir / "network" / "network-discovery.json"
    if not result_file.exists():
        return None
    raw = _read_json(result_file)
    if not raw or not isinstance(raw, dict):
        return None
    summary = raw.get("summary") or {}
    sd      = raw.get("static_discovery") or {}
    active  = raw.get("active_scan") or {}

    # Flatten docker-compose service/port entries into a simple list
    compose_ports: list[dict] = []
    for compose_file in (sd.get("docker_compose") or []):
        for svc in (compose_file.get("services") or []):
            for p in (svc.get("ports") or []):
                compose_ports.append({
                    "file":    compose_file.get("file", ""),
                    "service": svc.get("name", ""),
                    "port":    p.get("container_port"),
                    "mapping": p.get("mapping", ""),
                })

    # Flatten dockerfile EXPOSE entries
    dockerfile_ports: list[dict] = []
    for df in (sd.get("dockerfiles") or []):
        for p in (df.get("ports") or []):
            dockerfile_ports.append({
                "file": df.get("file", ""),
                "port": p.get("port") or p,
            })

    # Kubernetes / Helm ports
    k8s_ports: list[dict] = []
    for obj in (sd.get("kubernetes") or []):
        for p in (obj.get("ports") or []):
            k8s_ports.append({"file": obj.get("file", ""), "port": p.get("port") or p})
    for chart in (sd.get("helm_charts") or []):
        for p in (chart.get("ports") or []):
            k8s_ports.append({"file": chart.get("file", ""), "port": p.get("port") or p})

    # App config / .env ports
    config_ports: list[dict] = []
    for cfg in list(sd.get("app_configs") or []) + list(sd.get("env_files") or []):
        for p in (cfg.get("ports") or []):
            config_ports.append({"file": cfg.get("file", ""), "port": p.get("port") or p})

    return {
        "total_ports":    summary.get("total_ports_discovered", 0),
        "unique_ports":   summary.get("unique_ports", []),
        "protocols":      summary.get("protocols", []),
        "services":       summary.get("inferred_services", []),
        "static_sources": summary.get("static_sources_found", 0),
        "active_scan_run": summary.get("active_scan_run", False),
        "compose_ports":   compose_ports,
        "dockerfile_ports": dockerfile_ports,
        "k8s_ports":       k8s_ports,
        "config_ports":    config_ports,
        "active_results":  active,
    }


def parse_picklescan_dir(scan_dir: Path) -> list[dict]:
    """Parse Layer 14 (Enhanced) - Comprehensive Model File Analysis.
    
    Returns normalized findings list from picklescan-results.json.
    Supports multi-format detection: pickle, pytorch, onnx, tensorflow, config.
    """
    result_file = scan_dir / "picklescan" / "picklescan-results.json"
    if not result_file.exists():
        return []
    raw = _read_json(result_file)
    if not raw or not isinstance(raw, dict):
        return []
    
    findings = []
    for finding in raw.get("findings", []):
        findings.append({
            "tool": "picklescan",
            "id": f"picklescan_{finding.get('type', 'unknown')}_{finding.get('file', 'unknown')}",
            "type": finding.get("type", "unknown"),
            "severity": norm_sev(finding.get("severity")),
            "file": finding.get("file", ""),
            "description": finding.get("description", ""),
            "evidence": finding.get("evidence", ""),
            "target": finding.get("file", ""),
        })
    return findings


def parse_coverage_dir(scan_dir: Path) -> dict | None:
    """Return normalized test coverage data from coverage/coverage-summary.json,
    or extract coverage % from sonar/sonar-analysis-results.json as a fallback.
    Returns None when no coverage data is available.
    """
    summary_file = scan_dir / "coverage" / "coverage-summary.json"
    if summary_file.exists():
        data = _read_json(summary_file)
        if data and isinstance(data, dict) and data.get("status") not in ("not_detected", None):
            return {
                "percentage":        round(float(data.get("percentage", 0)), 2),
                "language":          data.get("language", "unknown"),
                "framework":         data.get("framework", "unknown"),
                "lines_covered":     int(data.get("lines_covered", 0)),
                "lines_total":       int(data.get("lines_total", 0)),
                "branches_covered":  int(data.get("branches_covered", 0)),
                "branches_total":    int(data.get("branches_total", 0)),
                "status":            data.get("status", "success"),
                "timestamp":         data.get("timestamp", ""),
                "source":            "coverage-scan",
            }

    # Fallback: SonarQube metrics
    sonar_results = _read_json(scan_dir / "sonar" / "sonar-analysis-results.json")
    if sonar_results and isinstance(sonar_results, dict):
        pct: float | None = None
        measures = (sonar_results.get("component") or {}).get("measures", [])
        for m in measures:
            if m.get("metric") == "coverage":
                try:
                    pct = round(float(m["value"]), 2)
                except (KeyError, ValueError, TypeError):
                    pass
                break
        # Flat format produced by older run-sonar-analysis.sh versions
        if pct is None and "coverage" in sonar_results:
            try:
                pct = round(float(sonar_results["coverage"]), 2)
            except (ValueError, TypeError):
                pass
        if pct is not None:
            return {
                "percentage": pct,
                "language":   "unknown",
                "framework":  "sonarqube",
                "source":     "sonarqube",
            }

    return None


def parse_modelcard_dir(scan_dir: Path) -> dict | None:
    """Return the normalized model card compliance result dict, or None if not present."""
    result_file = scan_dir / "modelcard" / "modelcard-results.json"
    if not result_file.exists():
        return None
    raw = _read_json(result_file)
    if not raw or not isinstance(raw, dict):
        return None
    return {
        "status":       raw.get("status", "unknown"),
        "file_checked": raw.get("file_checked"),
        "passed":       raw.get("passed", 0),
        "failed":       raw.get("failed", 0),
        "warnings":     raw.get("warnings", 0),
        "findings":     raw.get("findings", []),
        "generated_at": raw.get("generated_at", ""),
    }


def parse_model_provenance_dir(scan_dir: Path) -> list[dict]:
    """Parse Layer 18 - Model Provenance & Threat Intelligence.
    
    Returns normalized findings list from model-provenance-results.json.
    Validates model signatures, author reputation, and threat intelligence.
    """
    result_file = scan_dir / "model-provenance" / "model-provenance-results.json"
    if not result_file.exists():
        return []
    raw = _read_json(result_file)
    if not raw or not isinstance(raw, dict):
        return []
    
    findings = []
    for finding in raw.get("findings", []):
        findings.append({
            "tool": "model-provenance",
            "id": f"provenance_{finding.get('type', 'unknown')}_{finding.get('file', 'unknown')}",
            "type": finding.get("type", "unknown"),
            "severity": norm_sev(finding.get("severity")),
            "file": finding.get("file", ""),
            "description": finding.get("description", ""),
            "evidence": finding.get("evidence", ""),
            "target": finding.get("file", ""),
        })
    return findings


def parse_inference_security_dir(scan_dir: Path) -> list[dict]:
    """Parse Layer 19 - Inference Environment Security.
    
    Returns normalized findings list from inference-security-results.json.
    Analyzes Dockerfile, docker-compose, and Kubernetes manifests for misconfigurations.
    """
    result_file = scan_dir / "inference-security" / "inference-security-results.json"
    if not result_file.exists():
        return []
    raw = _read_json(result_file)
    if not raw or not isinstance(raw, dict):
        return []
    
    findings = []
    for finding in raw.get("findings", []):
        findings.append({
            "tool": "inference-security",
            "id": f"inference_{finding.get('type', 'unknown')}_{finding.get('file', 'unknown')}",
            "type": finding.get("type", "unknown"),
            "severity": norm_sev(finding.get("severity")),
            "file": finding.get("file", ""),
            "description": finding.get("description", ""),
            "evidence": finding.get("evidence", ""),
            "target": finding.get("file", ""),
        })
    return findings


def parse_ml_runtime_dir(scan_dir: Path) -> list[dict]:
    """Parse Layer 20 - ML Runtime Behavioral Analysis.
    
    Returns normalized findings list from ml-runtime-analysis-results.json.
    Detects malicious runtime behavior via sandboxed model execution.
    """
    result_file = scan_dir / "ml-runtime" / "ml-runtime-analysis-results.json"
    if not result_file.exists():
        return []
    raw = _read_json(result_file)
    if not raw or not isinstance(raw, dict):
        return []
    
    findings = []
    for finding in raw.get("findings", []):
        findings.append({
            "tool": "ml-runtime",
            "id": f"runtime_{finding.get('type', 'unknown')}_{finding.get('file', 'unknown')}",
            "type": finding.get("type", "unknown"),
            "severity": norm_sev(finding.get("severity")),
            "file": finding.get("file", ""),
            "description": finding.get("description", ""),
            "evidence": finding.get("evidence", ""),
            "target": finding.get("file", ""),
        })
    return findings


def parse_mobile_code_dir(scan_dir: Path) -> list[dict]:
    """Parse Layer 17 mobile code detection results from mobile-code-results.json.
    
    Returns a list of mobile code findings with approval status.
    Each finding includes:
      - type: mobile code type (javascript_web, java_applet, flash, etc.)
      - file: path to file containing mobile code
      - line: line number (0 for file-level detections)
      - description: human-readable description
      - risk_level: critical/high/medium/low
      - category: DoD mobile code category (Category 1A, 1B, 2, etc.)
      - approval_status: approved/requires_approval/unapproved
      - requires_authorization: boolean flag
      - evidence: code snippet or file signature
    """
    mobile_code_file = scan_dir / "mobile-code-results.json"
    if not mobile_code_file.exists():
        return []
    
    try:
        with open(mobile_code_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []
    
    findings = []
    for raw_finding in data.get("findings", []):
        # Map risk level to severity (for consistency with other tools)
        risk_level = raw_finding.get("risk_level", "medium")
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }
        severity = severity_map.get(risk_level, "medium")
        
        finding = {
            "id": f"mobile_code_{raw_finding.get('type', 'unknown')}_{raw_finding.get('line', 0)}",
            "tool": "mobile-code",
            "type": raw_finding.get("type", "unknown"),
            "severity": severity,
            "risk_level": risk_level,
            "category": raw_finding.get("category", "Unknown"),
            "file": raw_finding.get("file", ""),
            "line": raw_finding.get("line", 0),
            "description": raw_finding.get("description", ""),
            "evidence": raw_finding.get("evidence", ""),
            "approval_status": raw_finding.get("approval_status", "unapproved"),
            "requires_authorization": raw_finding.get("requires_authorization", True),
            "match_type": raw_finding.get("match_type", ""),
        }
        
        # Add extension-specific fields if present
        if "extension_name" in raw_finding:
            finding["extension_name"] = raw_finding["extension_name"]
            finding["extension_version"] = raw_finding.get("extension_version", "")
        
        findings.append(finding)
    
    return findings


def count_suppressed_instances(scan_dir: Path) -> int:
    """Count raw suppression instances in suppressed-findings.md (one per rule firing, not deduplicated)."""
    md_file = scan_dir / "suppressed-findings.md"
    if not md_file.exists():
        return 0
    count = 0
    with md_file.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("## Suppressed:"):
                count += 1
    return count


def parse_build_evidence(scan_dir: Path) -> dict:
    """Parse container image build, SLSA provenance, and image signature evidence."""
    build_dir = scan_dir / "build"
    summary_file = build_dir / "build-summary.json"
    digest_file = build_dir / "image-digest.txt"
    manifest_file = build_dir / "oci-manifest.json"
    provenance_file = scan_dir / "provenance.json"
    sig_file = scan_dir / "image.sig"

    build_info = None
    if summary_file.exists():
        try:
            with open(summary_file, "r", encoding="utf-8") as f:
                build_info = json.load(f)
        except Exception:
            pass

    digest = None
    if digest_file.exists():
        try:
            digest = digest_file.read_text(encoding="utf-8").strip()
        except Exception:
            pass

    has_manifest = manifest_file.exists()
    
    provenance_info = None
    if provenance_file.exists():
        try:
            with open(provenance_file, "r", encoding="utf-8") as f:
                provenance_info = json.load(f)
        except Exception:
            pass

    sig_info = None
    if sig_file.exists():
        try:
            with open(sig_file, "r", encoding="utf-8") as f:
                sig_info = json.load(f)
        except Exception:
            pass

    return {
        "build": build_info,
        "digest": digest,
        "has_manifest": has_manifest,
        "provenance": provenance_info,
        "signature": sig_info,
        "artifacts": {
            "image_digest": digest is not None,
            "oci_manifest": has_manifest,
            "dockerfile": (build_dir / "Dockerfile").exists(),
            "build_log": (build_dir / "build.log").exists(),
            "slsa_provenance": provenance_file.exists(),
            "image_signature": sig_file.exists(),
            "sbom": (scan_dir / "sbom").is_dir(),
            "vuln_scans": (
                (scan_dir / "grype").is_dir()
                or (scan_dir / "trivy").is_dir()
                or (scan_dir / "clamav").is_dir()
            ),
            "scan_manifest": (scan_dir / "scan-manifest.json").exists(),
            "suppression_audit": (scan_dir / "suppressed-findings.md").exists(),
            "vex_justification": (scan_dir / "grype" / "vex-applied-results.json").exists(),
        }
    }


def parse_ssp_evidence_matrix(scan_dir: Path) -> dict:
    """Map scan evidence artifacts to NIST SP 800-53 / FedRAMP controls for SSP/ATO documentation."""
    scan_id = scan_dir.name
    manifest_data = _read_json(scan_dir / "scan-manifest.json") or {}
    file_hashes = manifest_data.get("file_hashes") or {}

    def _get_hash(rel_path: str) -> str | None:
        if rel_path in file_hashes:
            return file_hashes[rel_path]
        target_file = scan_dir / rel_path
        if target_file.is_file():
            try:
                import hashlib
                h = hashlib.sha256(target_file.read_bytes()).hexdigest()
                return f"sha256:{h}"
            except Exception:
                pass
        return None

    def _check_artifact(rel_path: str) -> tuple[bool, str | None]:
        p = scan_dir / rel_path
        exists = p.exists()
        h = _get_hash(rel_path) if exists else None
        return exists, h

    controls = []

    # CM-2 Baseline Configuration
    c_docker_exists, c_docker_hash = _check_artifact("build/Dockerfile")
    c_meta_exists, c_meta_hash = _check_artifact("scan-metadata.json")
    controls.append({
        "control_id": "CM-2",
        "control_name": "Baseline Configuration",
        "epyon_layer": "Phase 0 (Container Build & Config Metadata)",
        "primary_artifact_path": "build/Dockerfile" if c_docker_exists else "scan-metadata.json",
        "format": "Container Instructions / JSON",
        "status": "captured" if (c_docker_exists or c_meta_exists) else "not_captured",
        "sha256_hash": c_docker_hash or c_meta_hash or "N/A",
        "summary": "Dockerfile instructions & target scan metadata"
    })

    # CM-6 Configuration Settings
    c_checkov_exists, c_checkov_hash = _check_artifact("checkov/checkov-results.json")
    c_inf_exists, c_inf_hash = _check_artifact("inference-security/inference-security-results.json")
    controls.append({
        "control_id": "CM-6",
        "control_name": "Configuration Settings",
        "epyon_layer": "Layer 6 (Checkov IaC) & Layer 19 (Inference Security)",
        "primary_artifact_path": "checkov/checkov-results.json" if c_checkov_exists else "inference-security/inference-security-results.json",
        "format": "IaC / Container Security JSON",
        "status": "captured" if (c_checkov_exists or c_inf_exists) else "not_captured",
        "sha256_hash": c_checkov_hash or c_inf_hash or "N/A",
        "summary": "Infrastructure & container security misconfigurations"
    })

    # CM-8 Information System Component Inventory
    c_sbom_exists, c_sbom_hash = _check_artifact("sbom/filesystem.cyclonedx.json")
    if not c_sbom_exists:
        c_sbom_exists, c_sbom_hash = _check_artifact("sbom/filesystem.json")
    controls.append({
        "control_id": "CM-8",
        "control_name": "Information System Component Inventory",
        "epyon_layer": "Layer 1 (Syft SBOM Generation)",
        "primary_artifact_path": "sbom/filesystem.cyclonedx.json" if (scan_dir / "sbom/filesystem.cyclonedx.json").exists() else "sbom/filesystem.json",
        "format": "CycloneDX / SPDX JSON",
        "status": "captured" if c_sbom_exists else "not_captured",
        "sha256_hash": c_sbom_hash or "N/A",
        "summary": "Software Bill of Materials (packages, versions, purls)"
    })

    # SI-2 Flaw Remediation / Vulnerability Management
    c_grype_exists, c_grype_hash = _check_artifact("grype/grype-sbom-results.json")
    c_trivy_exists, c_trivy_hash = _check_artifact("trivy/trivy-results.json")
    c_summary_exists, c_summary_hash = _check_artifact("security-findings-summary.json")
    controls.append({
        "control_id": "SI-2",
        "control_name": "Flaw Remediation & Vulnerability Scanning",
        "epyon_layer": "Layer 7 (Trivy), Layer 8 (Grype), Layer 8.5 (pip-audit)",
        "primary_artifact_path": "security-findings-summary.json" if c_summary_exists else "grype/grype-sbom-results.json",
        "format": "Deduplicated Vulnerability JSON",
        "status": "captured" if (c_grype_exists or c_trivy_exists or c_summary_exists) else "not_captured",
        "sha256_hash": c_summary_hash or c_grype_hash or c_trivy_hash or "N/A",
        "summary": "Deduplicated CVE vulnerability findings & severity counts"
    })

    # SI-3 Malicious Code Protection
    c_clam_exists, c_clam_hash = _check_artifact("clamav/clamav-results.json")
    c_pickle_exists, c_pickle_hash = _check_artifact("picklescan-results.json")
    controls.append({
        "control_id": "SI-3",
        "control_name": "Malicious Code Protection",
        "epyon_layer": "Layer 4 (ClamAV) & Layer 14 (Picklescan Model Scanner)",
        "primary_artifact_path": "clamav/clamav-results.json" if c_clam_exists else "picklescan-results.json",
        "format": "Malware & Serialized Code Audit JSON",
        "status": "captured" if (c_clam_exists or c_pickle_exists) else "not_captured",
        "sha256_hash": c_clam_hash or c_pickle_hash or "N/A",
        "summary": "Antivirus malware scans & deserialization safety analysis"
    })

    # SI-7 Software, Firmware, and Information Integrity
    c_man_exists, c_man_hash = _check_artifact("scan-manifest.json")
    c_prov_exists, c_prov_hash = _check_artifact("provenance.jsonl")
    c_sig_exists, c_sig_hash = _check_artifact("image.sig")
    controls.append({
        "control_id": "SI-7",
        "control_name": "Software & Information Integrity",
        "epyon_layer": "Cryptographic Scan Manifest, SLSA Provenance & Cosign",
        "primary_artifact_path": "scan-manifest.json",
        "format": "SHA-256 Manifest / SLSA v1.0 / Cosign Signature",
        "status": "captured" if c_man_exists else "not_captured",
        "sha256_hash": c_man_hash or "N/A",
        "summary": "Cryptographic scan manifest, SLSA provenance & image signatures"
    })

    # CA-2 / CA-7 Security Control Assessments & Continuous Monitoring
    stig_files = list(scan_dir.glob("stig-results-*.json"))
    c_stig_exists = len(stig_files) > 0
    c_stig_path = stig_files[0].relative_to(scan_dir).as_posix() if c_stig_exists else "stig-results-app.json"
    c_stig_hash = _get_hash(c_stig_path) if c_stig_exists else None
    controls.append({
        "control_id": "CA-2",
        "control_name": "Security Control Assessments & STIG Compliance",
        "epyon_layer": "Layer 13 (DISA STIG Compliance Engine)",
        "primary_artifact_path": c_stig_path,
        "format": "DISA STIG JSON / CKLB Checklist / Markdown",
        "status": "captured" if c_stig_exists else "not_captured",
        "sha256_hash": c_stig_hash or "N/A",
        "summary": "AI-evaluated STIG controls & evidence timeline"
    })

    # IA-2 / IA-5 Identification, Authentication & Secrets
    c_truffle_exists, c_truffle_hash = _check_artifact("trufflehog/filesystem-results.json")
    controls.append({
        "control_id": "IA-5",
        "control_name": "Authenticator & Secret Management",
        "epyon_layer": "Layer 2 (TruffleHog Secret Detection)",
        "primary_artifact_path": "trufflehog/filesystem-results.json",
        "format": "High-Entropy Key & Credential JSON",
        "status": "captured" if c_truffle_exists else "not_captured",
        "sha256_hash": c_truffle_hash or "N/A",
        "summary": "High-entropy secrets, API keys, and credential scans"
    })

    # SA-11 / PL-2 Developer Security Testing & Risk Acceptance
    c_supp_exists, c_supp_hash = _check_artifact("suppressed-findings.md")
    controls.append({
        "control_id": "SA-11",
        "control_name": "Developer Security Testing & Risk Acceptance",
        "epyon_layer": "Suppression Engine & Severity Gate Audit",
        "primary_artifact_path": "suppressed-findings.md",
        "format": "Auditor Justification & Expiration Markdown Log",
        "status": "captured" if c_supp_exists else "not_captured",
        "sha256_hash": c_supp_hash or "N/A",
        "summary": "Documented risk acceptances, approvals, and expiration dates"
    })

    # RA-3 / RA-5 Risk Assessment & Vulnerability Monitoring
    c_trl_exists, c_trl_hash = _check_artifact("trl-assessment.json")
    controls.append({
        "control_id": "RA-3",
        "control_name": "Risk Assessment & Security Score Card",
        "epyon_layer": "Security Score Card (TRL Assessment)",
        "primary_artifact_path": "trl-assessment.json",
        "format": "Weighted TRL 1–9 Score JSON",
        "status": "captured" if c_trl_exists else "not_captured",
        "sha256_hash": c_trl_hash or "N/A",
        "summary": "6-dimensional weighted security posture score & TRL mapping"
    })

    return {
        "scan_id": scan_id,
        "timestamp": manifest_data.get("generated_at") or "",
        "manifest_version": manifest_data.get("manifest_version", "1.0"),
        "controls": controls
    }


def generate_ssp_evidence_markdown(matrix_data: dict) -> str:
    """Generate a clean Markdown table mapping NIST SP 800-53 controls to artifact paths for SSP/ATO docs."""
    scan_id = matrix_data.get("scan_id", "scan")
    timestamp = matrix_data.get("timestamp", "")
    controls = matrix_data.get("controls", [])

    md = []
    md.append(f"# System Security Plan (SSP) & ATO Control Evidence Matrix")
    md.append(f"**Scan ID:** `{scan_id}`  |  **Generated:** `{timestamp}`  |  **Orchestrator:** Epyon Security Platform\n")
    md.append("This document maps NIST SP 800-53 / FedRAMP security controls to cryptographic evidence artifacts generated by Epyon for ATO/cATO submissions.\n")
    md.append("| NIST 800-53 Control | Control Name | Epyon Security Layer | Primary Evidence Artifact Path | Pipeline Status | SHA-256 Digest |")
    md.append("|---------------------|--------------|----------------------|--------------------------------|-----------------|----------------|")

    for c in controls:
        status_str = "✅ Captured" if c["status"] == "captured" else "ℹ️ Optional / Skipped"
        hash_str = f"`{c['sha256_hash'][:16]}...`" if c["sha256_hash"] and c["sha256_hash"] != "N/A" else "N/A"
        md.append(f"| **{c['control_id']}** | {c['control_name']} | {c['epyon_layer']} | `{c['primary_artifact_path']}` | {status_str} | {hash_str} |")

    md.append("\n## Artifact Path Integrity Reference\n")
    for c in controls:
        md.append(f"### {c['control_id']}: {c['control_name']}")
        md.append(f"- **Epyon Layer:** {c['epyon_layer']}")
        md.append(f"- **Primary Artifact:** `{c['primary_artifact_path']}`")
        md.append(f"- **Format / Spec:** {c['format']}")
        md.append(f"- **Cryptographic SHA-256 Hash:** `{c['sha256_hash']}`")
        md.append(f"- **Evidence Summary:** {c['summary']}\n")

    return "\n".join(md)


def parse_suppressed_findings(scan_dir: Path) -> list[dict]:
    """Parse suppressed-findings.md and/or .epyon-ignore.yml into structured suppression records."""
    results = []
    seen: set[tuple] = set()

    # 1. Parse suppressed-findings.md if present
    md_file = scan_dir / "suppressed-findings.md"
    if md_file.exists():
        text = md_file.read_text(encoding="utf-8", errors="replace")
        blocks = re.split(r"^## Suppressed:", text, flags=re.MULTILINE)
        for block in blocks[1:]:  # skip preamble
            lines = block.strip().splitlines()
            record: dict = {"value": lines[0].strip() if lines else ""}
            for line in lines[1:]:
                m = re.match(r"-\s+\*\*(.+?)\*\*:\s*(.*)", line)
                if m:
                    key = m.group(1).strip().lower().replace(" ", "_")
                    record[key] = m.group(2).strip()
            dedup_key = (record.get("type", "").lower(), record.get("value", "").lower())
            if dedup_key not in seen:
                seen.add(dedup_key)
                results.append(record)

    # 2. Also check .epyon-ignore.yml files and temporary cache
    from datetime import datetime
    ignore_files = [
        scan_dir / ".epyon-ignore.yml",
        scan_dir.parent / ".epyon-ignore.yml",
        scan_dir.parent.parent / ".epyon-ignore.yml",
        Path("/tmp/epyon-ignore-cache.json"),
    ]

    for yml_file in ignore_files:
        if yml_file.exists():
            try:
                if yml_file.suffix == ".json":
                    data = json.loads(yml_file.read_text(encoding="utf-8"))
                    ignores = data.get("ignores", [])
                else:
                    import yaml
                    data = yaml.safe_load(yml_file.read_text(encoding="utf-8")) or {}
                    ignores = data.get("ignores", [])

                current_date = datetime.now()
                for rule in ignores:
                    t = (rule.get("type") or "").strip().lower()
                    v = (rule.get("value") or "").strip()
                    if not v:
                        continue

                    # Check expiration
                    expires_str = rule.get("expires") or ""
                    is_expired = rule.get("expired", False)
                    if expires_str and not is_expired:
                        try:
                            exp_dt = datetime.strptime(str(expires_str).strip(), "%Y-%m-%d")
                            if current_date > exp_dt:
                                is_expired = True
                        except Exception:
                            pass

                    if is_expired:
                        continue

                    dedup_key = (t, v.lower())
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        results.append({
                            "type": t,
                            "value": v,
                            "reason": rule.get("reason", ""),
                            "approved_by": rule.get("approved_by", ""),
                            "expires": str(expires_str),
                            "paths": rule.get("paths", [])
                        })
            except Exception:
                pass

    return results


def _is_finding_suppressed(finding: dict, suppressions: list[dict]) -> bool:
    """Check if a finding matches any suppression rule.
    
    Matching logic:
    - tool: matches finding["tool"]
    - cve / ghsa / vulnerability: matches finding["id"]
    - package: matches finding["package"]@finding["version"] or finding["package"]
    - path / file: matches finding["file"] or finding["target"]
    - secret-detector / secret: matches TruffleHog detector ID
    - iac: matches Checkov check ID
    """
    if not suppressions:
        return False

    import fnmatch

    finding_id = (finding.get("id") or "").strip().lower()
    finding_tool = (finding.get("tool") or "").strip().lower()
    pkg_name = (finding.get("package") or "").strip().lower()
    pkg_ver = (finding.get("version") or "").strip().lower()
    file_path = (finding.get("file") or finding.get("target") or "").strip()

    for suppression in suppressions:
        supp_type = (suppression.get("type") or "").strip().lower()
        supp_value = (suppression.get("value") or "").strip().lower()

        if not supp_value:
            continue

        # 1. Tool-level suppression
        if supp_type == "tool":
            if supp_value in ("*", finding_tool):
                return True
            continue

        # 2. Package suppression (e.g., netty-handler@4.1.136.Final or netty-handler)
        if supp_type == "package":
            if "@" in supp_value:
                supp_pkg, supp_ver = supp_value.split("@", 1)
                if pkg_name == supp_pkg and (not supp_ver or pkg_ver == supp_ver):
                    return True
            else:
                if pkg_name == supp_value:
                    return True
            continue

        # 3. Path / File suppression (glob matching)
        if supp_type in ("path", "file"):
            clean_path = file_path.replace("/workspace/", "").lstrip("/")
            if fnmatch.fnmatch(clean_path.lower(), supp_value) or fnmatch.fnmatch(file_path.lower(), supp_value):
                return True
            continue

        # 4. Secret detector suppression
        if supp_type in ("secret-detector", "secret", "detector"):
            if finding_tool == "trufflehog" and (supp_value in ("*", finding_id)):
                paths = suppression.get("paths") or []
                if paths:
                    clean_path = file_path.replace("/workspace/", "").lstrip("/")
                    if any(fnmatch.fnmatch(clean_path.lower(), p.lower()) for p in paths):
                        return True
                else:
                    return True
            continue

        # 5. CVE / GHSA / Vulnerability ID suppression
        if supp_type in ("cve", "vulnerability", "ghsa") or not supp_type:
            if supp_value in ("*", finding_id):
                return True
            if "*" in supp_value:
                pattern = supp_value.replace("*", ".*").replace("?", ".")
                try:
                    if re.match(f"^{pattern}$", finding_id):
                        return True
                except re.error:
                    pass

        # 6. Fallback matching against package name or package@version
        if supp_value in (pkg_name, f"{pkg_name}@{pkg_ver}"):
            return True

    return False


def _filter_suppressed_findings(findings_dict: dict, suppressions: list[dict]) -> dict:
    """Mark suppressed findings and update summary counts.
    
    Instead of removing suppressed findings, this function marks them with
    suppressed=True and updates the summary to show both total and suppressed counts.
    
    Args:
        findings_dict: Dict with critical_findings, high_findings, etc.
        suppressions: List of suppression records from parse_suppressed_findings()
    
    Returns:
        Updated findings dict with suppressed flags and summary counts
    """
    if not suppressions:
        return findings_dict
    
    result = findings_dict.copy()
    suppressed_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for sev in ("critical", "high", "medium", "low"):
        key = f"{sev}_findings"
        findings = result.get(key, [])
        
        # Mark suppressed findings
        for finding in findings:
            if _is_finding_suppressed(finding, suppressions):
                finding["suppressed"] = True
                suppressed_counts[sev] += 1
            else:
                finding["suppressed"] = False
    
    # Update summary to include suppressed counts
    if "summary" not in result:
        result["summary"] = {}
    
    result["summary"].update({
        "total_critical": len(result.get("critical_findings", [])),
        "total_high":     len(result.get("high_findings", [])),
        "total_medium":   len(result.get("medium_findings", [])),
        "total_low":      len(result.get("low_findings", [])),
        "suppressed_critical": suppressed_counts["critical"],
        "suppressed_high":     suppressed_counts["high"],
        "suppressed_medium":   suppressed_counts["medium"],
        "suppressed_low":      suppressed_counts["low"],
        "total_suppressed":    sum(suppressed_counts.values()),
    })
    
    return result


# ── Aggregate ─────────────────────────────────────────────────

def load_sbom_packages(scan_dir: Path) -> dict:
    """Read SBOM package data from syft-json (filesystem.json), falling back to
    CycloneDX only if syft-json is absent. Returns total count, type breakdown,
    and the package list (capped at 2000 for API response size)."""
    sbom_dir = scan_dir / "sbom"
    if not sbom_dir.is_dir():
        return {"total": 0, "by_type": {}, "packages": []}

    best_file: Path | None = None
    best_count = 0
    fmt = ""

    # Prefer syft-json (ecosystem types like npm/python/terraform are preserved)
    for f in sbom_dir.glob("*.json"):
        if "cyclonedx" in f.name or "summary" in f.name:
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        count = len(data.get("artifacts") or [])
        if count > best_count:
            best_count = count
            best_file = f
            fmt = "syft"

    # Fall back to CycloneDX if no syft-json found
    if best_count == 0:
        for f in sbom_dir.glob("*.cyclonedx.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            count = len(data.get("components") or [])
            if count > best_count:
                best_count = count
                best_file = f
                fmt = "cyclonedx"

    if best_file is None or best_count == 0:
        return {"total": 0, "by_type": {}, "packages": []}

    data = json.loads(best_file.read_text(encoding="utf-8"))

    if fmt == "syft":
        artifacts = data.get("artifacts") or []
        # Scan root reported by syft — used to resolve ambiguous paths
        _scan_root = ((data.get("source") or {}).get("metadata") or {}).get("path", "")

        def _real_path(raw: str) -> str:
            """Map synthetic temp filenames back to the original source files."""
            import re as _re, os as _os
            if raw.endswith("requirements-conda-env.txt"):
                d = _os.path.dirname(raw)
                for ext in ("environment.yaml", "environment.yml"):
                    candidate = _os.path.join(d, ext)
                    if _os.path.isfile(candidate):
                        return candidate
                return _os.path.join(d, "environment.yaml")  # fallback label
            p = _re.sub(r"requirements-pyproject\.txt$", "pyproject.toml", raw)
            if p != raw:
                return p
            # Syft normalises requirements.lock (pip format) paths to
            # requirements.txt.  If the scan root is still accessible and no
            # real requirements.txt exists there, map to requirements.lock.
            if raw.endswith("requirements.txt") and _scan_root:
                abs_txt = _os.path.join(_scan_root, raw.lstrip("/"))
                if not _os.path.isfile(abs_txt):
                    lock_candidate = abs_txt[:-len("requirements.txt")] + "requirements.lock"
                    if _os.path.isfile(lock_candidate):
                        return raw[:-len("requirements.txt")] + "requirements.lock"
            return raw

        packages = [
            {
                "name":     a.get("name", ""),
                "version":  a.get("version", ""),
                "type":     a.get("type", "unknown"),
                "language": a.get("language", ""),
                "purl":     a.get("purl", ""),
                "path":     _real_path((a.get("locations") or [{}])[0].get("path") or ""),
                "licenses": [
                    (lic.get("value") or lic.get("spdxExpression") or "")
                    for lic in (a.get("licenses") or [])
                    if isinstance(lic, dict)
                ],
            }
            for a in artifacts
        ]
    else:
        components = [c for c in (data.get("components") or []) if c.get("type") != "file"]
        packages = [
            {
                "name":     c.get("name", ""),
                "version":  c.get("version", ""),
                "type":     c.get("type", "library"),
                "language": "",
                "purl":     c.get("purl", ""),
                "path":     "",
                "licenses": [
                    (lic.get("license", {}).get("id") or lic.get("license", {}).get("name") or "")
                    for lic in (c.get("licenses") or [])
                    if isinstance(lic, dict)
                ],
            }
            for c in components
        ]

    by_type: dict[str, int] = {}
    for p in packages:
        by_type[p["type"]] = by_type.get(p["type"], 0) + 1

    packages.sort(key=lambda p: p["name"].lower())

    return {
        "total":    len(packages),
        "by_type":  by_type,
        "packages": packages[:2000],
    }


def parse_scan_findings(scan_dir: Path) -> dict:
    """Parse security findings for vulnerability management and Jira sync.
    
    NOTE: ML/AI security findings (layers 14, 17, 18, 19, 20) are intentionally
    excluded from this function. They are parsed separately and displayed in the
    ML/AI Security card, and are NOT synced to Jira as vulnerability findings.
    
    NOTE: Infrastructure misconfiguration and secret detection findings (Layer 6: Checkov,
    Layer 2: TruffleHog) are excluded from this function. They are parsed separately via
    parse_misconfiguration_findings() and displayed in the Misconfigurations card.
    """
    all_findings = (
        parse_trivy_dir(scan_dir)
        + parse_grype_dir(scan_dir)
        + parse_anchore_dir(scan_dir)
        + parse_pip_audit_dir(scan_dir)
        + parse_safety_dir(scan_dir)
        # TruffleHog and Checkov excluded - see parse_misconfiguration_findings() below
        + parse_clamav_dir(scan_dir)
        + parse_xeol_dir(scan_dir)
        + parse_sonarqube_dir(scan_dir)
        # ML/AI security findings excluded - see parse_ml_findings() above
    )

    by_tool = set(f["tool"] for f in all_findings)
    by_sev: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}
    for f in all_findings:
        s = f["severity"] if f["severity"] != "unknown" else "low"
        by_sev.setdefault(s, []).append(f)

    findings_dict = {
        "summary": {
            "total_critical": len(by_sev["critical"]),
            "total_high":     len(by_sev["high"]),
            "total_medium":   len(by_sev["medium"]),
            "total_low":      len(by_sev["low"]),
            "tools_analyzed": sorted(by_tool),
        },
        "critical_findings": by_sev["critical"],
        "high_findings":     by_sev["high"],
        "medium_findings":   by_sev["medium"],
        "low_findings":      by_sev["low"],
    }
    
    # Filter out suppressed findings
    suppressions = parse_suppressed_findings(scan_dir)
    if suppressions:
        findings_dict = _filter_suppressed_findings(findings_dict, suppressions)
    
    return findings_dict


def parse_ml_findings(scan_dir: Path) -> dict:
    """Parse ML/AI security findings separately from vulnerability findings.
    
    These findings are displayed in the ML/AI Security card and are NOT
    synced to Jira as vulnerability findings. They represent ML-specific
    security concerns like malicious model code, supply chain attacks,
    container misconfigurations, and runtime behavioral issues.
    
    Returns:
        dict with ML findings categorized by severity and tool
    """
    all_ml_findings = (
        parse_mobile_code_dir(scan_dir)
        + parse_picklescan_dir(scan_dir)
        + parse_model_provenance_dir(scan_dir)
        + parse_inference_security_dir(scan_dir)
        + parse_ml_runtime_dir(scan_dir)
    )
    
    by_tool = set(f["tool"] for f in all_ml_findings)
    by_sev: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}
    for f in all_ml_findings:
        s = f["severity"] if f["severity"] != "unknown" else "low"
        by_sev.setdefault(s, []).append(f)
    
    return {
        "summary": {
            "total_critical": len(by_sev["critical"]),
            "total_high":     len(by_sev["high"]),
            "total_medium":   len(by_sev["medium"]),
            "total_low":      len(by_sev["low"]),
            "tools_analyzed": sorted(by_tool),
        },
        "critical_findings": by_sev["critical"],
        "high_findings":     by_sev["high"],
        "medium_findings":   by_sev["medium"],
        "low_findings":      by_sev["low"],
    }


def parse_misconfiguration_findings(scan_dir: Path) -> dict:
    """Parse infrastructure, configuration misconfigurations, and secrets separately from vulnerability findings.
    
    These findings are displayed in the Misconfigurations card and represent
    IaC security issues, secret leaks, container misconfigurations, and policy violations
    detected by Checkov, TruffleHog, and similar tools. They are NOT treated as CVE vulnerabilities.
    
    Returns:
        dict with misconfiguration findings categorized by severity and tool
    """
    all_misconfig_findings = (
        parse_checkov_dir(scan_dir)
        + parse_trufflehog_dir(scan_dir)
    )
    
    by_tool = set(f["tool"] for f in all_misconfig_findings)
    by_sev: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}
    for f in all_misconfig_findings:
        s = f["severity"] if f["severity"] != "unknown" else "low"
        by_sev.setdefault(s, []).append(f)
    
    return {
        "summary": {
            "total_critical": len(by_sev["critical"]),
            "total_high":     len(by_sev["high"]),
            "total_medium":   len(by_sev["medium"]),
            "total_low":      len(by_sev["low"]),
            "tools_analyzed": sorted(by_tool),
        },
        "critical_findings": by_sev["critical"],
        "high_findings":     by_sev["high"],
        "medium_findings":   by_sev["medium"],
        "low_findings":      by_sev["low"],
    }


def parse_sonarqube_dir(scan_dir: Path) -> list[dict]:
    """Layer 3 — SonarQube / SonarCloud code quality issues.

    Reads ``scan_dir/sonar/sonar-issues.json`` produced by run-sonar-analysis.sh.
    The file is either the raw SonarQube API response
    ``{issues: [{key, rule, severity, component, line, message, ...}]}``
    or a plain list of the same objects.
    """
    issues_file = scan_dir / "sonar" / "sonar-issues.json"
    if not issues_file.exists():
        return []
    try:
        raw = json.loads(issues_file.read_text())
        if isinstance(raw, dict):
            issues = raw.get("issues", [])
        elif isinstance(raw, list):
            issues = raw
        else:
            return []
    except Exception:
        return []

    _sonar_sev_map = {
        "BLOCKER":  "critical",
        "CRITICAL": "critical",
        "MAJOR":    "high",
        "MINOR":    "medium",
        "INFO":     "low",
    }

    findings: list[dict] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        raw_sev  = (issue.get("severity") or "").upper()
        severity = _sonar_sev_map.get(raw_sev, "low")
        component = issue.get("component") or issue.get("path") or ""
        line      = issue.get("line") or issue.get("textRange", {}).get("startLine")
        location  = f"{component}:{line}" if line else component
        
        # Build GitHub-style location anchor if line number is available
        github_location = component
        if component and line:
            github_location = f"{component}#L{line}"
        
        rule      = issue.get("rule") or issue.get("ruleId") or "—"
        message   = issue.get("message") or issue.get("primaryMessage") or rule
        findings.append({
            "tool":     "SonarQube",
            "type":     "code_quality",
            "severity": severity,
            "id":       rule,
            "title":    message[:200],
            "package":  "",
            "version":  "",
            "fixed_version": "",
            "target":   location[:200],
            "location": github_location[:200],
            "line":     line,
            "references": [],
        })
    return findings


def load_enriched_findings(scan_dir: Path) -> dict | None:
    """Return findings from ``security-findings-summary.json`` (enriched with CISA KEV / NVD data).

    Field names are normalised to match the web format used by the SPA:
      vulnerability_id  → id
      package_name      → package
      package_version   → version
      fix_versions[0]   → fixed_version
    CISA KEV, nvd_url, nvd_cvss_v3_score, nvd_cvss_v3_severity are preserved.
    
    NOTE: Checkov findings are filtered out and handled separately via parse_misconfiguration_findings().
    Returns None when the file is absent or cannot be parsed.
    """
    summary_file = scan_dir / "security-findings-summary.json"
    if not summary_file.exists():
        return None
    try:
        raw = json.loads(summary_file.read_text())
    except Exception:
        return None
    if not isinstance(raw, dict):
        return None

    def _norm(findings: list) -> list:
        out = []
        for f in (findings or []):
            if not isinstance(f, dict):
                continue
            # Skip Checkov and TruffleHog findings - they belong in misconfigurations, not vulnerabilities
            tool_name = (f.get("tool") or "").lower()
            if tool_name in ("checkov", "trufflehog"):
                continue
            fix_versions = f.get("fix_versions") or []
            out.append({
                "tool":              f.get("tool", ""),
                "type":              f.get("type", ""),
                "severity":          (f.get("severity") or "unknown").lower(),
                "id":                f.get("vulnerability_id") or f.get("id") or "—",
                "title":             (f.get("description") or f.get("title") or "")[:200],
                "package":           f.get("package_name") or f.get("package") or "",
                "version":           f.get("package_version") or f.get("version") or "",
                "fixed_version":     fix_versions[0] if fix_versions else f.get("fixed_version", ""),
                "target":            f.get("target") or f.get("file_path") or "",
                "line":              f.get("line_number") or f.get("line") or "",
                "references":        f.get("nvd_references") or f.get("references") or [],
                # Enrichment fields
                "cisa_kev":          bool(f.get("cisa_kev", False)),
                "nvd_url":           f.get("nvd_url") or "",
                "nvd_cvss_v3_score": f.get("nvd_cvss_v3_score"),
                "nvd_cvss_v3_severity": f.get("nvd_cvss_v3_severity") or "",
            })
        return out

    summary = raw.get("summary") or {}
    enrichment = raw.get("enrichment") or {}
    
    # Normalize and filter findings (Checkov excluded)
    critical = _norm(raw.get("critical_findings", []))
    high = _norm(raw.get("high_findings", []))
    medium = _norm(raw.get("medium_findings", []))
    low = _norm(raw.get("low_findings", []))
    
    # Recalculate counts after filtering
    tools_analyzed = summary.get("tools_analyzed", [])
    # Remove Checkov and TruffleHog from tools list if present
    tools_analyzed = [t for t in tools_analyzed if t.lower() not in ("checkov", "trufflehog")]

    findings_dict = {
        "summary": {
            "total_critical": len(critical),
            "total_high":     len(high),
            "total_medium":   len(medium),
            "total_low":      len(low),
            "tools_analyzed": tools_analyzed,
        },
        "critical_findings": critical,
        "high_findings":     high,
        "medium_findings":   medium,
        "low_findings":      low,
        "enrichment":        enrichment,
    }
    
    # Filter out suppressed findings
    suppressions = parse_suppressed_findings(scan_dir)
    if suppressions:
        findings_dict = _filter_suppressed_findings(findings_dict, suppressions)
    
    return findings_dict


def parse_enrichment_summary(scan_dir: Path) -> dict | None:
    """Return the ``enrichment`` block from ``security-findings-summary.json`` or None."""
    summary_file = scan_dir / "security-findings-summary.json"
    if not summary_file.exists():
        return None
    try:
        raw = json.loads(summary_file.read_text())
        enrichment = raw.get("enrichment") if isinstance(raw, dict) else None
        if enrichment and isinstance(enrichment, dict) and enrichment:
            return enrichment
    except Exception:
        pass
    return None


def load_api_discovery(scan_dir: Path) -> dict | None:
    """Parse API discovery data from a scan directory.
    
    Returns dict with:
    - endpoints: List of discovered API endpoints
    - total: Total count of endpoints
    - by_method: Dict of method counts (GET, POST, etc.)
    - by_framework: Dict of framework counts (FastAPI, Express, etc.)
    - summary: Raw summary dict from the discovery file
    """
    # Try multiple possible locations
    api_locations = [
        scan_dir / "api" / "exports" / f"api-discovery-{scan_dir.name}.json",
        scan_dir / "api" / "api-discovery.json",
        scan_dir / "api-discovery" / "api-inventory.json",
        scan_dir / "api-discovery.json",
    ]
    
    for api_file in api_locations:
        if not api_file.exists():
            continue
        
        try:
            data = json.loads(api_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        
        # Handle different formats
        endpoints = []
        summary = data.get("summary", {})
        
        # Format 1: Direct endpoints array (older format)
        if "endpoints" in data and isinstance(data["endpoints"], list):
            endpoints = data["endpoints"]
        
        # Format 2: discovery_methods.code_routes (current format)
        elif "discovery_methods" in data and "code_routes" in data["discovery_methods"]:
            routes = data["discovery_methods"]["code_routes"]
            for lang in ["python", "nodejs", "java"]:
                lang_routes = routes.get(lang, [])
                if isinstance(lang_routes, list):
                    endpoints.extend(lang_routes)
        
        if not endpoints and not summary:
            continue
        
        # Count by method and framework
        by_method = {}
        by_framework = {}
        for ep in endpoints:
            if isinstance(ep, dict):
                method = ep.get("method", "UNKNOWN")
                by_method[method] = by_method.get(method, 0) + 1
                
                framework = ep.get("framework", "Unknown")
                by_framework[framework] = by_framework.get(framework, 0) + 1
        
        return {
            "endpoints": endpoints,
            "total": len(endpoints),
            "by_method": by_method,
            "by_framework": by_framework,
            "summary": summary,
        }
    
    return None


def load_scan(scan_dir: Path, epyon_root: Path) -> dict:
    scan_id = scan_dir.name
    parsed  = parse_dir_name(scan_id)

    data: dict = {
        "scan_id":       scan_id,
        "target":        parsed["target"],
        "user":          parsed["user"],
        "timestamp":     parsed["timestamp"],
        "scan_type":     "full",
        "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0,
        "tools_analyzed": [],
        "has_dashboard":  False,
        "dashboard_url":  None,
        "location":       str(scan_dir.parent.relative_to(epyon_root)),
    }

    meta = _read_json(scan_dir / "scan-metadata.json")
    if meta:
        data["scan_type"]        = meta.get("scan_type", "full")
        data["target"]           = meta.get("target_name") or parsed["target"]
        data["timestamp"]        = meta.get("scan_timestamp") or parsed["timestamp"]
        data["target_directory"] = meta.get("target_directory", "")
        data["source_url"]       = meta.get("source_url", "")
        data["file_statistics"]  = meta.get("file_statistics") or {}
        if meta.get("scan_user"):
            data["user"] = meta["scan_user"]

    # Resolve user from scan-manifest.json if still unknown
    if not data["user"]:
        manifest = _read_json(scan_dir / "scan-manifest.json")
        if manifest:
            data["user"] = (manifest.get("scan_metadata") or {}).get("username", "")

    # Infer scan_type from directory contents only when scan-metadata.json did not
    # supply it (meta is falsy or had no scan_type key).
    if not meta or not meta.get("scan_type"):
        # Infer scan_type from other files present in the scan directory
        vuln_dirs = {"grype", "trivy", "checkov", "sbom", "anchore", "xeol"}
        has_vuln = any((scan_dir / d).is_dir() for d in vuln_dirs)
        has_stig = bool(list(scan_dir.glob("stig-results-*.json")))
        if has_stig:
            # STIG-only scans have stig results but typically no vuln tool outputs
            data["scan_type"] = "stig" if not has_vuln else "nightly"
        elif (scan_dir / "picklescan").is_dir() or (scan_dir / "modelcard").is_dir():
            # Could be a local_model scan or a full scan with model weight files present;
            # default to local_model only if no standard vuln tool dirs exist
            all_vuln_dirs = vuln_dirs | {"trufflehog"}
            data["scan_type"] = "full" if any((scan_dir / d).is_dir() for d in all_vuln_dirs) else "local_model"
        else:
            # Check ci-metadata.json: scheduled GitHub Actions runs are nightly scans
            ci_meta_early = _read_json(scan_dir / "ci-metadata.json")
            if ci_meta_early and ci_meta_early.get("event") == "schedule" and has_vuln:
                data["scan_type"] = "nightly"

    # Prefer the pre-built summary file (one small JSON read — cheap).
    # Only fall back to full raw tool-output parsing when the summary is absent
    # (e.g. scan still in-progress or very old scan predating the summary step).
    # NOTE: Summary file counts include suppressed findings, so we must filter.
    summary_file = _read_json(scan_dir / "security-findings-summary.json")
    if summary_file:
        # Load and filter the enriched findings to get accurate counts
        filtered_findings = load_enriched_findings(scan_dir)
        if filtered_findings and filtered_findings.get("summary"):
            s = filtered_findings["summary"]
            data["critical"]       = s.get("total_critical", 0)
            data["high"]           = s.get("total_high", 0)
            data["medium"]         = s.get("total_medium", 0)
            data["low"]            = s.get("total_low", 0)
            data["total"]          = data["critical"] + data["high"] + data["medium"] + data["low"]
            data["tools_analyzed"] = s.get("tools_analyzed", [])
        else:
            # Fallback: use raw summary counts (no filtering applied)
            s = summary_file.get("summary") or summary_file
            data["critical"]       = s.get("total_critical", 0)
            data["high"]           = s.get("total_high", 0)
            data["medium"]         = s.get("total_medium", 0)
            data["low"]            = s.get("total_low", 0)
            data["total"]          = data["critical"] + data["high"] + data["medium"] + data["low"]
            data["tools_analyzed"] = s.get("tools_analyzed", [])
    else:
        raw_findings = parse_scan_findings(scan_dir)
        if raw_findings["summary"]["tools_analyzed"]:
            s = raw_findings["summary"]
            data["critical"]       = s["total_critical"]
            data["high"]           = s["total_high"]
            data["medium"]         = s["total_medium"]
            data["low"]            = s["total_low"]
            data["total"]          = data["critical"] + data["high"] + data["medium"] + data["low"]
            data["tools_analyzed"] = s["tools_analyzed"]

    dashboard = (
        scan_dir / "consolidated-reports" / "dashboards" / "security-dashboard.html"
    )
    if dashboard.exists():
        data["has_dashboard"] = True
        data["dashboard_url"] = f"/api/scans/{scan_id}/dashboard"

    ci_meta = _read_json(scan_dir / "ci-metadata.json")
    if ci_meta and ci_meta.get("source") == "github":
        data["ci_source"] = {
            "source":   "github",
            "repo":     ci_meta.get("repo", ""),
            "branch":   ci_meta.get("branch", ""),
            "commit":   ci_meta.get("commit", ""),
            "workflow": ci_meta.get("workflow", ""),
            "event":    ci_meta.get("event", ""),
            "run_id":   ci_meta.get("run_id"),
        }

    # Epyon STIG outputs are at the top level of scan_dir — aggregate ALL stig-results files
    stig_files = sorted(scan_dir.glob("stig-results-*.json"))
    if stig_files:
        stig_open = stig_pass = stig_na = stig_nr = stig_total = 0
        any_valid = False
        stig_reports: list[dict] = []
        for stig_file in stig_files:
            stig_results = _read_json(stig_file)
            if not stig_results or not isinstance(stig_results, dict):
                continue
            # Support both new wrapped format {assessments: {...}, token_usage: {...}}
            # and old flat format {vuln_id: {status, evidence}, ...}
            token_usage = {}
            if "assessments" in stig_results:
                token_usage  = stig_results.get("token_usage", {})
                stig_results = stig_results["assessments"]
            if not stig_results:
                continue
            any_valid = True
            s_open  = sum(1 for v in stig_results.values() if v.get("status") == "Open")
            s_pass  = sum(1 for v in stig_results.values() if v.get("status") == "Not a Finding")
            s_na    = sum(1 for v in stig_results.values() if v.get("status") == "Not Applicable")
            s_nr    = sum(1 for v in stig_results.values() if v.get("status") == "Not Reviewed")
            s_total = len(stig_results)
            stig_open  += s_open
            stig_pass  += s_pass
            stig_na    += s_na
            stig_nr    += s_nr
            stig_total += s_total
            # Derive the slug from the filename: stig-results-{slug}.json
            slug = stig_file.stem[len("stig-results-"):]
            # Derive the app slug from scan_id (pattern: {app_name}_{YYYY-MM-DD}_{HH-MM-SS})
            app_slug = re.sub(r"[^a-z0-9]+", "-", re.sub(r"_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$", "", scan_id).lower()).strip("-")
            md_file   = scan_dir / f"findings-{app_slug}-{slug}.md"
            cklb_file = scan_dir / f"findings-{app_slug}-{slug}.cklb"
            stig_reports.append({
                "slug":         slug,
                "open":         s_open,
                "pass":         s_pass,
                "na":           s_na,
                "nr":           s_nr,
                "total":        s_total,
                "has_md":       md_file.exists(),
                "has_cklb":     cklb_file.exists(),
                "md_url":       f"/api/scans/{scan_id}/stig-findings/{app_slug}-{slug}.md"   if md_file.exists()   else None,
                "cklb_url":     f"/api/scans/{scan_id}/stig-findings/{app_slug}-{slug}.cklb" if cklb_file.exists() else None,
                "token_usage":  token_usage,
            })
        if any_valid:
            data["stig_open"]    = stig_open
            data["stig_pass"]    = stig_pass
            data["stig_na"]      = stig_na
            data["stig_nr"]      = stig_nr
            data["stig_total"]   = stig_total
            data["stig_reports"] = stig_reports
            # Derive app slug from scan_id for primary findings filename
            _app_slug = re.sub(r"[^a-z0-9]+", "-", re.sub(r"_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$", "", scan_id).lower()).strip("-")
            _primary_md   = scan_dir / f"findings-{_app_slug}.md"
            _primary_cklb = scan_dir / f"findings-{_app_slug}.cklb"
            if _primary_md.exists():
                data["has_stig_report"] = True
                data["stig_report_url"] = f"/api/scans/{scan_id}/stig-findings-md"
            if _primary_cklb.exists():
                data["has_stig_cklb"] = True
                data["stig_cklb_url"] = f"/api/scans/{scan_id}/stig-findings-cklb"

    # ── Layer 14 — Comprehensive Model File Analysis (Enhanced Picklescan) ─────
    picklescan_data = parse_picklescan_dir(scan_dir)
    if picklescan_data:
        data["picklescan"] = picklescan_data

    # ── Layer 15 — Model Card Compliance ────────────────────────────────────
    modelcard_data = parse_modelcard_dir(scan_dir)
    if modelcard_data is not None:
        data["modelcard"] = modelcard_data

    # ── Layer 18 — Model Provenance & Threat Intelligence ───────────────────
    model_provenance_data = parse_model_provenance_dir(scan_dir)
    if model_provenance_data:
        data["model_provenance"] = model_provenance_data

    # ── Layer 19 — Inference Environment Security ───────────────────────────
    inference_security_data = parse_inference_security_dir(scan_dir)
    if inference_security_data:
        data["inference_security"] = inference_security_data

    # ── Layer 20 — ML Runtime Behavioral Analysis (Opt-in) ──────────────────
    ml_runtime_data = parse_ml_runtime_dir(scan_dir)
    if ml_runtime_data:
        data["ml_runtime"] = ml_runtime_data

    # ── Layer 16 — Network Discovery (PPSM) ─────────────────────────────────
    network_data = parse_network_discovery_dir(scan_dir)
    if network_data is not None:
        data["network_discovery"] = network_data

    # ── Test Coverage ────────────────────────────────────────────────────────
    coverage_data = parse_coverage_dir(scan_dir)
    if coverage_data is not None:
        data["test_coverage"] = coverage_data

    # ── Suppressed findings ──────────────────────────────────────────────────
    suppressed = parse_suppressed_findings(scan_dir)
    if suppressed:
        data["suppressed_findings"] = suppressed

    # ── Container Build & Supply Chain Evidence ──────────────────────────────
    data["build_evidence"] = parse_build_evidence(scan_dir)

    # ── Enrichment summary (CISA KEV / NVD totals) ───────────────────────────
    enrichment = parse_enrichment_summary(scan_dir)
    if enrichment:
        data["enrichment"] = enrichment

    return data


def get_status(scan: dict) -> str:
    if not scan or not scan.get("scan_id"):
        return "unknown"
    for sev in ("critical", "high", "medium", "low"):
        if scan.get(sev, 0) > 0:
            return sev
    return "clean"
