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


def find_scan_dirs(epyon_root: Path) -> list[Path]:
    search = [
        epyon_root / "scans",
        epyon_root / "baseline" / "scans",
        epyon_root / "scripts" / "scans",
    ]
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
                if not obj.get("DetectorName"):
                    continue
                meta = (obj.get("SourceMetadata") or {}).get("Data") or {}
                fs_data = meta.get("Filesystem") or meta.get("Git") or {}
                verified = bool(obj.get("Verified"))
                findings.append({
                    "tool": "TruffleHog",
                    "id": obj.get("DetectorName", "SECRET"),
                    "severity": "critical" if verified else "high",
                    "package": obj.get("DetectorName", ""),
                    "version": "",
                    "fixed_version": "",
                    "title": f"{'Verified' if verified else 'Unverified'} secret: {obj.get('DetectorName', '')}",
                    "description": (
                        f"Detector: {obj.get('DetectorName', '')}. "
                        f"File: {fs_data.get('file') or fs_data.get('path', 'unknown')}. "
                        f"Line: {fs_data.get('line', '?')}"
                    ),
                    "target": fs_data.get("file") or fs_data.get("path", ""),
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
                findings.append({
                    "tool": "Checkov",
                    "id": check.get("check_id", ""),
                    "severity": sev,
                    "package": check.get("file_path", ""),
                    "version": "",
                    "fixed_version": "",
                    "title": check.get("check_name") or check.get("check_id", ""),
                    "description": (
                        f"{check.get('check_name', '')} — "
                        f"{check.get('file_path', '')}:{'-'.join(str(x) for x in line_range)}"
                    ),
                    "target": check.get("file_path", ""),
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


def parse_picklescan_dir(scan_dir: Path) -> dict | None:
    """Return the normalized picklescan result dict, or None if not present."""
    result_file = scan_dir / "picklescan" / "picklescan-results.json"
    if not result_file.exists():
        return None
    raw = _read_json(result_file)
    if not raw or not isinstance(raw, dict):
        return None
    return {
        "status":        raw.get("status", "unknown"),
        "file_count":    raw.get("file_count", 0),
        "flagged_count": raw.get("flagged_count", 0),
        "infected_files": raw.get("infected_files", []),
        "findings":      raw.get("findings", []),
        "generated_at":  raw.get("generated_at", ""),
    }


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


# ── Aggregate ─────────────────────────────────────────────────

def parse_scan_findings(scan_dir: Path) -> dict:
    all_findings = (
        parse_trivy_dir(scan_dir)
        + parse_grype_dir(scan_dir)
        + parse_anchore_dir(scan_dir)
        + parse_trufflehog_dir(scan_dir)
        + parse_checkov_dir(scan_dir)
        + parse_clamav_dir(scan_dir)
        + parse_xeol_dir(scan_dir)
    )

    by_tool = set(f["tool"] for f in all_findings)
    by_sev: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}
    for f in all_findings:
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
        data["file_statistics"]  = meta.get("file_statistics") or {}
    else:
        # Infer scan_type from other files present in the scan directory
        if list(scan_dir.glob("stig-results-*.json")):
            # STIG-only scans have stig results but typically no vuln tool outputs
            vuln_dirs = {"grype", "trivy", "checkov", "sbom", "anchore", "xeol"}
            has_vuln = any((scan_dir / d).is_dir() for d in vuln_dirs)
            data["scan_type"] = "stig" if not has_vuln else "nightly"
        elif (scan_dir / "picklescan").is_dir() or (scan_dir / "modelcard").is_dir():
            data["scan_type"] = "huggingface"

    raw_findings = parse_scan_findings(scan_dir)
    has_raw = len(raw_findings["summary"]["tools_analyzed"]) > 0

    if has_raw:
        s = raw_findings["summary"]
        data["critical"]       = s["total_critical"]
        data["high"]           = s["total_high"]
        data["medium"]         = s["total_medium"]
        data["low"]            = s["total_low"]
        data["total"]          = data["critical"] + data["high"] + data["medium"] + data["low"]
        data["tools_analyzed"] = s["tools_analyzed"]
    else:
        fallback = _read_json(scan_dir / "security-findings-summary.json")
        if fallback:
            s = fallback.get("summary") or fallback
            data["critical"]       = s.get("total_critical", 0)
            data["high"]           = s.get("total_high", 0)
            data["medium"]         = s.get("total_medium", 0)
            data["low"]            = s.get("total_low", 0)
            data["total"]          = data["critical"] + data["high"] + data["medium"] + data["low"]
            data["tools_analyzed"] = s.get("tools_analyzed", [])

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
        stig_open = stig_pass = stig_na = stig_total = 0
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
            s_na    = sum(1 for v in stig_results.values() if v.get("status") in ("Not Applicable", "Not Reviewed"))
            s_total = len(stig_results)
            stig_open  += s_open
            stig_pass  += s_pass
            stig_na    += s_na
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
                "total":        s_total,
                "has_md":       md_file.exists(),
                "has_cklb":     cklb_file.exists(),
                "md_url":       f"/api/scans/{scan_id}/stig-findings/{slug}.md"   if md_file.exists()   else None,
                "cklb_url":     f"/api/scans/{scan_id}/stig-findings/{slug}.cklb" if cklb_file.exists() else None,
                "token_usage":  token_usage,
            })
        if any_valid:
            data["stig_open"]    = stig_open
            data["stig_pass"]    = stig_pass
            data["stig_na"]      = stig_na
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

    # ── Layer 14 — Picklescan ────────────────────────────────────────────────
    picklescan_data = parse_picklescan_dir(scan_dir)
    if picklescan_data is not None:
        data["picklescan"] = picklescan_data

    # ── Layer 15 — Model Card Compliance ────────────────────────────────────
    modelcard_data = parse_modelcard_dir(scan_dir)
    if modelcard_data is not None:
        data["modelcard"] = modelcard_data

    return data


def get_status(scan: dict) -> str:
    if not scan or not scan.get("scan_id"):
        return "unknown"
    for sev in ("critical", "high", "medium", "low"):
        if scan.get(sev, 0) > 0:
            return sev
    return "clean"
