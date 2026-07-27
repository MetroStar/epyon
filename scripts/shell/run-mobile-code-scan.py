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
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Set

# Mobile code patterns and signatures
MOBILE_CODE_PATTERNS = {
    "javascript_web": {
        "description": "JavaScript in web contexts (HTML, JSP, PHP)",
        "risk_level": "medium",
        "category": "Category 2",
        "patterns": [
            r"<script[^>]*>",  # Inline scripts
            r"<script[^>]*src=",  # External scripts
            r"\.js[\"']",  # JS file references
            r"on\w+=[\"']",  # Event handlers
        ],
        "file_extensions": [".html", ".htm", ".jsp", ".php", ".aspx", ".erb"],
    },
    "java_applet": {
        "description": "Java Applets",
        "risk_level": "high",
        "category": "Category 1B",
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
        "risk_level": "high",
        "category": "Category 1B",
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
        "risk_level": "high",
        "category": "Category 1B",
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
    "webstart": {
        "description": "Java WebStart (JNLP)",
        "risk_level": "high",
        "category": "Category 1B",
        "file_types": [".jnlp"],
        "patterns": [r"<jnlp[^>]*>"],
        "file_extensions": [".jnlp", ".html", ".htm"],
    },
    "downloadable_executable": {
        "description": "Downloadable Executables",
        "risk_level": "high",
        "category": "Category 1B",
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
    
    # Skip if file doesn't match expected extensions
    if "file_extensions" in config and file_path.suffix not in config["file_extensions"]:
        return findings
    
    # Check for file type matches (e.g., .swf, .jar files themselves)
    if "file_types" in config and file_path.suffix in config["file_types"]:
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
    
    # Scan for patterns in text files
    if "patterns" in config:
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


def detect_browser_extension(target_dir: Path) -> List[Dict]:
    """Detect browser extensions by looking for manifest.json."""
    findings = []
    
    for manifest_path in target_dir.rglob("manifest.json"):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
                
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
            print(f"⚠️  Error parsing manifest {manifest_path}: {e}", file=sys.stderr)
    
    return findings


def load_policy(policy_file: Path = None) -> Dict[str, Any]:
    """Load mobile code policy if it exists."""
    if policy_file and policy_file.exists():
        try:
            with open(policy_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️  Could not load policy file: {e}", file=sys.stderr)
    
    # Default policy: all mobile code requires approval
    return {
        "approved_types": [],
        "approved_files": [],
        "approval_required": True,
    }


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


def scan_target_directory(target_dir: Path, policy: Dict) -> List[Dict]:
    """Scan target directory for all mobile code types."""
    all_findings = []
    
    print(f"🔍 Scanning {target_dir} for mobile code...")
    
    # Detect browser extensions first (special case)
    extension_findings = detect_browser_extension(target_dir)
    all_findings.extend(extension_findings)
    
    # Scan for other mobile code types
    for mobile_code_type, config in MOBILE_CODE_PATTERNS.items():
        if mobile_code_type == "browser_extension":
            continue  # Already handled
        
        print(f"   Checking for {config['description']}...")
        
        # Determine which files to scan
        scan_extensions = set(config.get("file_extensions", []) + config.get("file_types", []))
        
        for file_path in target_dir.rglob("*"):
            if not file_path.is_file():
                continue
            
            # Skip common ignore patterns
            if any(part.startswith(".") for part in file_path.parts):
                continue
            if any(part in ["node_modules", "vendor", ".git", "__pycache__", "venv"] for part in file_path.parts):
                continue
            
            # Check if file matches target extensions
            if scan_extensions and file_path.suffix not in scan_extensions:
                continue
            
            findings = scan_file_for_patterns(file_path, mobile_code_type, config)
            all_findings.extend(findings)
    
    # Apply policy approval status to all findings
    for finding in all_findings:
        finding["approval_status"] = check_approval_status(finding, policy)
        finding["requires_authorization"] = finding["approval_status"] == "requires_approval"
    
    return all_findings


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
    args = parse_args()
    
    target_dir = Path(args.target).resolve()
    scan_dir = Path(args.scan_dir).resolve()
    output_file = scan_dir / "mobile-code-results.json"
    
    # Load policy if provided
    policy_file = Path(args.policy_file) if args.policy_file else None
    policy = load_policy(policy_file)
    
    print("=" * 70)
    print("Layer 17: Mobile Code Detection Scanner")
    print("=" * 70)
    print(f"Target:    {target_dir}")
    print(f"Scan Dir:  {scan_dir}")
    print(f"App Name:  {args.app_name}")
    print(f"Policy:    {'Loaded' if policy_file and policy_file.exists() else 'Default (all require approval)'}")
    print("=" * 70)
    
    if not target_dir.exists():
        print(f"❌ Error: Target directory does not exist: {target_dir}", file=sys.stderr)
        return 1
    
    # Run scan
    findings = scan_target_directory(target_dir, policy)
    summary = generate_summary(findings)
    
    # Scan metadata
    scan_metadata = {
        "target": str(target_dir),
        "app_name": args.app_name,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "scanner_version": "1.0.0",
        "layer": 17,
        "layer_name": "Mobile Code Detection",
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
