#!/usr/bin/env python3
"""
run-mobile-code-scan.py — Layer 17: Mobile Code Detection

Scans target repositories for mobile code that requires authorization and monitoring
per DoD mobile code policy and STIG requirements (APSC-DV-002870, APSC-DV-003300).

Detects:
  • JavaScript/TypeScript in web contexts
  • Java applets (.class, .jar files)
  • Flash files (.swf, .fla)
  • ActiveX controls (IE-specific patterns)
  • VBScript files
  • Browser extensions (Chrome/Firefox manifests)
  • Downloadable executables served via web
  • Mobile agents and Java WebStart

Output: mobile-code-results.json with findings categorized by risk level
"""
import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple

# Mobile code patterns and signatures
MOBILE_CODE_PATTERNS = {
    "inline_javascript": {
        "description": "Inline JavaScript (unsigned)",
        "risk_level": "critical",
        "category": "Category 1A",
        "patterns": [
            r"<script[^>]*>(?!<\s*/\s*script)",  # Inline scripts (not empty tags)
            r"on\w+=[\"']",  # Event handlers
        ],
        "file_extensions": [".html", ".htm", ".jsp", ".php", ".aspx", ".erb"],
    },
    "external_javascript": {
        "description": "External JavaScript",
        "risk_level": "high",
        "category": "Category 1B",
        "patterns": [
            r"<script[^>]*src=",  # External scripts
            r"\.js[\"']",  # JS file references (in script tags or links)
        ],
        "file_extensions": [".html", ".htm", ".jsp", ".php", ".aspx", ".erb"],
    },
    "java_applet": {
        "description": "Java Applets",
        "risk_level": "critical",
        "category": "Category 1A",
        "patterns": [
            r"<applet[^>]*>",
            r"<object[^>]*classid.*java",
            r"\.class[\"']",
        ],
        "file_extensions": [".html", ".htm", ".jsp"],
        "file_types": [".class", ".jar"],
    },
    "flash": {
        "description": "Adobe Flash/Shockwave",
        "risk_level": "critical",
        "category": "Category 1A",
        "patterns": [
            r"<object[^>]*application/x-shockwave-flash",
            r"<embed[^>]*\.swf",
            r"\.swf[\"']",
        ],
        "file_extensions": [".html", ".htm"],
        "file_types": [".swf", ".fla"],
    },
    "activex": {
        "description": "ActiveX Controls",
        "risk_level": "critical",
        "category": "Category 1A",
        "patterns": [
            r"<object[^>]*classid=",
            r"new\s+ActiveXObject",
            r"\.cab[\"']",
        ],
        "file_extensions": [".html", ".htm", ".asp", ".aspx"],
        "file_types": [".ocx", ".cab"],
    },
    "vbscript": {
        "description": "VBScript",
        "risk_level": "critical",
        "category": "Category 1A",
        "patterns": [
            r"<script[^>]*type=[\"']text/vbscript",
            r"language=[\"']VBScript",
        ],
        "file_extensions": [".html", ".htm", ".asp", ".vbs"],
        "file_types": [".vbs"],
    },
    "browser_extension": {
        "description": "Browser Extensions",
        "risk_level": "medium",
        "category": "Category 2",
        "indicators": ["manifest.json", "background.js", "content_scripts"],
        "file_patterns": ["manifest.json", "background.js", "popup.html"],
    },
    "java_webstart": {
        "description": "Java WebStart (JNLP)",
        "risk_level": "high",
        "category": "Category 1B",
        "file_types": [".jnlp"],
        "patterns": [r"<jnlp[^>]*>"],
        "file_extensions": [".jnlp", ".html", ".htm"],
    },
    "downloadable_executable": {
        "description": "Downloadable Executables",
        "risk_level": "medium",
        "category": "Category 2",
        "patterns": [
            r"href=[\"'][^\"']*\.exe[\"']",
            r"href=[\"'][^\"']*\.msi[\"']",
            r"href=[\"'][^\"']*\.dll[\"']",
            r"download.*\.exe",
        ],
        "file_extensions": [".html", ".htm", ".jsp", ".php", ".aspx"],
        "file_types": [".exe", ".msi", ".dll", ".so", ".dylib"],
    },
}


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Layer 17: Mobile Code Detection Scanner")
    parser.add_argument("--target", required=True, help="Path to target repository")
    parser.add_argument("--scan-dir", required=True, help="Path to scan output directory")
    parser.add_argument("--app-name", required=True, help="Application name")
    parser.add_argument("--policy-file", help="Path to mobile code policy file (optional)")
    return parser.parse_args()


def is_binary_file(file_path: Path) -> bool:
    """Check if a file is binary."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(8192)
            if b"\0" in chunk:
                return True
            # Check for high proportion of non-text bytes
            text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
            non_text = sum(1 for byte in chunk if byte not in text_chars)
            return non_text / len(chunk) > 0.3 if chunk else False
    except Exception:
        return True


def scan_file_for_patterns(file_path: Path, mobile_code_type: str, config: Dict) -> List[Dict]:
    """Scan a single file for mobile code patterns."""
    findings = []
    
    # Check if file is relevant to this mobile code type
    # File must match either file_extensions (for pattern scanning) OR file_types (for file detection)
    matches_extension = "file_extensions" not in config or file_path.suffix in config["file_extensions"]
    matches_type = "file_types" in config and file_path.suffix in config["file_types"]
    
    if not matches_extension and not matches_type:
        return findings
    
    # Check for file type matches (e.g., .swf, .jar files themselves)
    if matches_type:
        findings.append({
            "type": mobile_code_type,
            "file": str(file_path),
            "line": 0,
            "description": config["description"],
            "risk_level": config["risk_level"],
            "category": config["category"],
            "evidence": f"Mobile code file detected: {file_path.name}",
            "match_type": "file_type",
        })
        return findings
    
    # Skip binary files for pattern matching
    if is_binary_file(file_path):
        return findings
    
    # Scan for patterns in text files (only if file matches file_extensions)
    if matches_extension and "patterns" in config:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                for line_num, line in enumerate(lines, 1):
                    for pattern in config["patterns"]:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append({
                                "type": mobile_code_type,
                                "file": str(file_path),
                                "line": line_num,
                                "description": config["description"],
                                "risk_level": config["risk_level"],
                                "category": config["category"],
                                "evidence": line.strip()[:200],
                                "pattern": pattern,
                                "match_type": "pattern",
                            })
        except Exception as e:
            print(f"⚠️  Error scanning {file_path}: {e}", file=sys.stderr)
    
    return findings


def detect_browser_extension(target_dir: Path) -> Tuple[List[Dict], Dict]:
    """Detect browser extensions by looking for manifest.json.
    
    Returns:
        Tuple of (findings_list, diagnostics_dict) where diagnostics contains:
        - manifests_found: count of manifest.json files
        - manifests_parsed: count successfully parsed
        - manifests_malformed: count of parse failures
        - malformed_files: list of file paths that failed to parse
    """
    findings = []
    diagnostics = {
        "manifests_found": 0,
        "manifests_parsed": 0,
        "manifests_malformed": 0,
        "malformed_files": [],
    }
    
    for manifest_path in target_dir.rglob("manifest.json"):
        diagnostics["manifests_found"] += 1
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            
            diagnostics["manifests_parsed"] += 1
                
            # Check for browser extension indicators
            if any(key in manifest for key in ["browser_action", "page_action", "content_scripts", "background"]):
                findings.append({
                    "type": "browser_extension",
                    "file": str(manifest_path),
                    "line": 0,
                    "description": "Browser Extension",
                    "risk_level": "medium",
                    "category": "Category 2",
                    "evidence": f"Extension: {manifest.get('name', 'Unknown')} v{manifest.get('version', '?')}",
                    "match_type": "manifest",
                    "extension_name": manifest.get("name"),
                    "extension_version": manifest.get("version"),
                })
        except Exception as e:
            diagnostics["manifests_malformed"] += 1
            diagnostics["malformed_files"].append(str(manifest_path))
            print(f"⚠️  Error parsing manifest {manifest_path}: {e}", file=sys.stderr)
    
    return findings, diagnostics


def load_policy(policy_file: Path = None) -> Tuple[Dict[str, Any], str]:
    """Load mobile code policy if it exists.
    
    Returns:
        Tuple of (policy_dict, status) where status is one of:
        - "loaded" (policy file found and parsed successfully)
        - "default" (no policy file, using default)
        - "failed" (policy file exists but failed to parse)
    """
    if policy_file and policy_file.exists():
        try:
            with open(policy_file, "r", encoding="utf-8") as f:
                policy = json.load(f)
            return policy, "loaded"
        except Exception as e:
            print(f"⚠️  Could not load policy file: {e}", file=sys.stderr)
            # Fall through to default policy
    
    # Default policy: all mobile code requires approval
    default_policy = {
        "approved_types": [],
        "approved_files": [],
        "approval_required": True,
    }
    
    status = "failed" if (policy_file and policy_file.exists()) else "default"
    return default_policy, status


def check_approval_status(finding: Dict, policy: Dict) -> str:
    """Check if a mobile code finding is approved per policy."""
    mobile_code_type = finding["type"]
    file_path = finding["file"]
    
    # Check if type is approved
    if mobile_code_type in policy.get("approved_types", []):
        return "approved"
    
    # Check if specific file is approved
    for approved_file in policy.get("approved_files", []):
        if approved_file in file_path:
            return "approved"
    
    # Check if approval is required
    if policy.get("approval_required", True):
        return "requires_approval"
    
    return "unapproved"


def scan_target_directory(target_dir: Path, policy: Dict) -> Tuple[List[Dict], Dict]:
    """Scan target directory for all mobile code types.
    
    Returns:
        Tuple of (findings_list, diagnostics_dict) where diagnostics contains:
        - files_considered: total files encountered
        - files_scanned: files actually scanned
        - files_skipped_by_extension: count
        - files_skipped_by_ignore_rules: count
        - files_skipped_is_directory: count
        - files_unreadable: count
        - unreadable_files: list of file paths that couldn't be read
        - pattern_matches_before_dedup: count of raw pattern matches
        - scan_errors: list of error messages
    """
    all_findings = []
    diagnostics = {
        "files_considered": 0,
        "files_scanned": 0,
        "files_skipped_by_extension": 0,
        "files_skipped_by_ignore_rules": 0,
        "files_skipped_is_directory": 0,
        "files_unreadable": 0,
        "unreadable_files": [],
        "pattern_matches_before_dedup": 0,
        "scan_errors": [],
    }
    
    # Ignored directory patterns
    IGNORE_PATTERNS = ["node_modules", "vendor", ".git", "__pycache__", "venv", ".venv",
                       "dist", "build", "__py", "coverage", ".pytest_cache", "egg-info"]
    
    print(f"🔍 Scanning {target_dir} for mobile code...")
    
    # Detect browser extensions first (special case)
    extension_findings, ext_diag = detect_browser_extension(target_dir)
    all_findings.extend(extension_findings)
    # Merge browser extension diagnostics
    diagnostics.update(ext_diag)
    
    # Scan for other mobile code types
    for mobile_code_type, config in MOBILE_CODE_PATTERNS.items():
        if mobile_code_type == "browser_extension":
            continue  # Already handled
        
        print(f"   Checking for {config['description']}...")
        
        # Determine which files to scan
        scan_extensions = set(config.get("file_extensions", []) + config.get("file_types", []))
        
        for file_path in target_dir.rglob("*"):
            diagnostics["files_considered"] += 1
            
            if not file_path.is_file():
                diagnostics["files_skipped_is_directory"] += 1
                continue
            
            # Skip common ignore patterns
            if any(part.startswith(".") for part in file_path.parts):
                diagnostics["files_skipped_by_ignore_rules"] += 1
                continue
            if any(part in IGNORE_PATTERNS for part in file_path.parts):
                diagnostics["files_skipped_by_ignore_rules"] += 1
                continue
            
            # Check if file matches target extensions
            if scan_extensions and file_path.suffix not in scan_extensions:
                diagnostics["files_skipped_by_extension"] += 1
                continue
            
            # Attempt to scan file
            try:
                findings = scan_file_for_patterns(file_path, mobile_code_type, config)
                diagnostics["pattern_matches_before_dedup"] += len(findings)
                all_findings.extend(findings)
                diagnostics["files_scanned"] += 1
            except PermissionError:
                diagnostics["files_unreadable"] += 1
                diagnostics["unreadable_files"].append(str(file_path))
                diagnostics["scan_errors"].append(f"Permission denied: {file_path}")
            except UnicodeDecodeError:
                # Binary file or encoding issue — skip silently
                diagnostics["files_skipped_by_extension"] += 1
            except Exception as e:
                diagnostics["files_unreadable"] += 1
                diagnostics["unreadable_files"].append(str(file_path))
                diagnostics["scan_errors"].append(f"Error scanning {file_path}: {str(e)}")
    
    # Deduplicate findings based on (file, line, type)
    findings_before_dedup = len(all_findings)
    seen_keys: Set[Tuple[str, int, str]] = set()
    deduplicated_findings = []
    
    for finding in all_findings:
        key = (finding["file"], finding["line"], finding["type"])
        if key not in seen_keys:
            seen_keys.add(key)
            deduplicated_findings.append(finding)
    
    all_findings = deduplicated_findings
    findings_after_dedup = len(all_findings)
    diagnostics["findings_after_dedup"] = findings_after_dedup
    diagnostics["deduplication_ratio"] = round(
        (findings_before_dedup - findings_after_dedup) / findings_before_dedup
        if findings_before_dedup > 0 else 0, 2
    )
    
    # Apply policy approval status to all findings
    for finding in all_findings:
        finding["approval_status"] = check_approval_status(finding, policy)
        finding["requires_authorization"] = finding["approval_status"] == "requires_approval"
    
    return all_findings, diagnostics


def generate_summary(findings: List[Dict]) -> Dict[str, Any]:
    """Generate summary statistics for mobile code findings."""
    summary = {
        "total_findings": len(findings),
        "by_risk_level": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "by_category": {},
        "by_type": {},
        "by_approval_status": {
            "approved": 0,
            "requires_approval": 0,
            "unapproved": 0,
        },
        "unique_files": len(set(f["file"] for f in findings)),
        "unauthorized_count": 0,
    }
    
    for finding in findings:
        # Risk level
        risk = finding.get("risk_level", "low")
        summary["by_risk_level"][risk] = summary["by_risk_level"].get(risk, 0) + 1
        
        # Category
        category = finding.get("category", "Unknown")
        summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
        
        # Type
        mobile_type = finding.get("type", "unknown")
        summary["by_type"][mobile_type] = summary["by_type"].get(mobile_type, 0) + 1
        
        # Approval status
        approval = finding.get("approval_status", "unapproved")
        summary["by_approval_status"][approval] = summary["by_approval_status"].get(approval, 0) + 1
        
        # Count unauthorized
        if finding.get("requires_authorization", False):
            summary["unauthorized_count"] += 1
    
    return summary


def write_results(output_file: Path, findings: List[Dict], summary: Dict, scan_metadata: Dict):
    """Write scan results to JSON file."""
    output = {
        "scan_metadata": scan_metadata,
        "summary": summary,
        "findings": findings,
        "policy_enforced": True,
        "compliance_notes": {
            "APSC-DV-002870": "Unsigned Category 1A mobile code detection",
            "APSC-DV-003300": "Uncategorized/emerging mobile code detection",
        },
    }
    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    
    print(f"✅ Mobile code scan results written to {output_file}")


def main():
    """Main execution function."""
    scan_start_time = time.time()
    args = parse_args()
    
    target_dir = Path(args.target).resolve()
    scan_dir = Path(args.scan_dir).resolve()
    output_file = scan_dir / "mobile-code-results.json"
    
    # Load policy if provided
    policy_file = Path(args.policy_file) if args.policy_file else None
    policy, policy_status = load_policy(policy_file)
    
    print("=" * 70)
    print("Layer 17: Mobile Code Detection Scanner")
    print("=" * 70)
    print(f"Target:    {target_dir}")
    print(f"Scan Dir:  {scan_dir}")
    print(f"App Name:  {args.app_name}")
    print(f"Policy:    {policy_status.capitalize()} {'(default: all require approval)' if policy_status == 'default' else ''}")
    print("=" * 70)
    
    if not target_dir.exists():
        print(f"❌ Error: Target directory does not exist: {target_dir}", file=sys.stderr)
        return 1
    
    # Run scan
    findings, scan_diagnostics = scan_target_directory(target_dir, policy)
    scan_duration = time.time() - scan_start_time
    
    summary = generate_summary(findings)
    
    # Scan metadata with comprehensive diagnostics
    scan_metadata = {
        "target": str(target_dir),
        "app_name": args.app_name,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "scanner_version": f"1.0.0+{datetime.now(timezone.utc).strftime('%Y%m%d')}",  # Version with date
        "layer": 17,
        "layer_name": "Mobile Code Detection",
        "scan_duration_seconds": round(scan_duration, 2),
        "policy_file": str(policy_file) if policy_file else None,
        "policy_status": policy_status,
        "diagnostics": {
            **scan_diagnostics,
            "pattern_types_checked": len([k for k in MOBILE_CODE_PATTERNS.keys() if k != "browser_extension"]),
            "findings_after_dedup": len(findings),
            "deduplication_ratio": round(
                1 - (len(findings) / scan_diagnostics["pattern_matches_before_dedup"])
                if scan_diagnostics["pattern_matches_before_dedup"] > 0 else 0,
                3
            ),
        },
    }
    
    # Write results
    write_results(output_file, findings, summary, scan_metadata)
    
    # Print summary
    print("\n" + "=" * 70)
    print("SCAN SUMMARY")
    print("=" * 70)
    print(f"Total Findings:         {summary['total_findings']}")
    print(f"Unique Files:           {summary['unique_files']}")
    print(f"Requires Authorization: {summary['unauthorized_count']}")
    print(f"\nScan Duration:          {scan_duration:.2f} seconds")
    print(f"Files Scanned:          {scan_diagnostics['files_scanned']}")
    print(f"Files Skipped:          {scan_diagnostics['files_skipped_by_extension'] + scan_diagnostics['files_skipped_by_ignore_rules']}")
    print(f"  By extension:         {scan_diagnostics['files_skipped_by_extension']}")
    print(f"  By ignore rules:      {scan_diagnostics['files_skipped_by_ignore_rules']}")
    print(f"Files Unreadable:       {scan_diagnostics['files_unreadable']}")
    
    print("\nBy Risk Level:")
    for level in ["critical", "high", "medium", "low"]:
        count = summary["by_risk_level"].get(level, 0)
        if count > 0:
            print(f"  {level.upper():10s}: {count}")
    
    print("\nBy Approval Status:")
    for status, count in summary["by_approval_status"].items():
        if count > 0:
            print(f"  {status:20s}: {count}")
    
    if summary["by_type"]:
        print("\nDetected Mobile Code Types:")
        for mobile_type, count in summary["by_type"].items():
            type_desc = MOBILE_CODE_PATTERNS.get(mobile_type, {}).get("description", mobile_type)
            print(f"  {type_desc:30s}: {count}")
    
    if scan_diagnostics.get("manifests_malformed", 0) > 0:
        print(f"\n⚠️  Warning: {scan_diagnostics['manifests_malformed']} malformed manifest.json files")
    
    if scan_diagnostics.get("scan_errors"):
        print(f"\n⚠️  Warning: {len(scan_diagnostics['scan_errors'])} scan errors occurred")
    
    print("=" * 70)
    
    # Exit with error if unauthorized mobile code found
    if summary["unauthorized_count"] > 0:
        print(f"\n⚠️  WARNING: Found {summary['unauthorized_count']} mobile code instances requiring authorization")
        return 0  # Don't fail scan, just report
    else:
        print("\n✅ No unauthorized mobile code detected")
        return 0


if __name__ == "__main__":
    sys.exit(main())
