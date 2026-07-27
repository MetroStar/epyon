#!/usr/bin/env python3
"""
Mobile Code Scanner Validation Test

Runs the mobile code scanner against known test fixtures and validates:
- True positives (correctly detected mobile code)
- True negatives (correctly ignored legitimate code)
- False positives (incorrectly flagged legitimate code)
- False negatives (missed mobile code)
- Precision, recall, and F1 score
"""
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set

# Expected findings by fixture file
EXPECTED_FINDINGS = {
    # Category 1A - Critical Risk (unsigned/inline)
    "category-1a/inline-js-malicious.html": [
        {"type": "inline_javascript", "risk_level": "critical"}
    ],
    "category-1a/java-applet-unsigned.html": [
        {"type": "java_applet", "risk_level": "critical"}
    ],
    "category-1a/flash-embed.html": [
        {"type": "flash", "risk_level": "critical"}
    ],
    "category-1a/activex-object.html": [
        {"type": "activex", "risk_level": "critical"},
        {"type": "vbscript", "risk_level": "critical"}
    ],
    
    # Category 1B - High Risk (external/signed)
    "category-1b/external-js-cdn.html": [
        {"type": "external_javascript", "risk_level": "high"}
    ],
    "category-1b/signed-java-webstart.jnlp": [
        {"type": "java_webstart", "risk_level": "high"}
    ],
    
    # Category 2 - Medium Risk (controlled)
    "category-2/browser-extension/manifest.json": [
        {"type": "browser_extension", "risk_level": "medium"}
    ],
    "category-2/downloadable-executable.html": [
        {"type": "downloadable_executable", "risk_level": "medium"}
    ],
    
    # Legitimate - should have NO findings
    "legitimate/static-html.html": [],
    "legitimate/json-data.json": [],
    
    # Ignored - should have NO findings (even though it contains suspicious code)
    "ignored/node_modules/package/malicious.js": [],
}


def run_scanner(target_dir: Path, scan_dir: Path) -> Dict:
    """Run the mobile code scanner and return parsed results."""
    # Navigate up from tests/ to epyon root
    scanner_script = Path(__file__).parent.parent / "scripts" / "shell" / "run-mobile-code-scan.py"
    
    if not scanner_script.exists():
        print(f"Scanner script not found at: {scanner_script}", file=sys.stderr)
        return {"findings": []}
    
    cmd = [
        "python3",
        str(scanner_script),
        "--target", str(target_dir),
        "--scan-dir", str(scan_dir),
        "--app-name", "mobile-code-test",
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Scanner failed: {result.stderr}", file=sys.stderr)
        return {"findings": []}
    
    results_file = scan_dir / "mobile-code-results.json"
    if not results_file.exists():
        return {"findings": []}
    
    return json.loads(results_file.read_text())


def normalize_finding(finding: Dict) -> tuple:
    """Normalize a finding to a comparable tuple."""
    return (
        finding.get("type", ""),
        finding.get("risk_level", ""),
        Path(finding.get("file", "")).as_posix(),  # Normalize path separators
    )


def validate_results(scan_results: Dict, test_dir: Path) -> Dict:
    """Validate scanner results against expected findings."""
    findings_by_file: Dict[str, List[Dict]] = {}
    
    # Group actual findings by file (relative to test dir)
    for finding in scan_results.get("findings", []):
        file_path = Path(finding["file"])
        try:
            rel_path = file_path.relative_to(test_dir).as_posix()
        except ValueError:
            # File not under test dir
            continue
        findings_by_file.setdefault(rel_path, []).append(finding)
    
    # Calculate metrics
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0
    
    errors = []
    
    # Check each expected file
    for expected_file, expected_list in EXPECTED_FINDINGS.items():
        actual_list = findings_by_file.get(expected_file, [])
        
        # Normalize findings for comparison
        expected_set = {(f["type"], f["risk_level"]) for f in expected_list}
        actual_set = {(f.get("type"), f.get("risk_level")) for f in actual_list}
        
        # True positives: correctly detected expected findings
        tp = len(expected_set & actual_set)
        true_positives += tp
        
        # False negatives: missed expected findings
        fn = len(expected_set - actual_set)
        false_negatives += fn
        if fn > 0:
            errors.append(f"FALSE NEGATIVE: {expected_file} — missed {expected_set - actual_set}")
        
        # False positives: unexpected findings
        fp = len(actual_set - expected_set)
        false_positives += fp
        if fp > 0:
            errors.append(f"FALSE POSITIVE: {expected_file} — unexpected {actual_set - expected_set}")
        
        # True negatives: correctly ignored legitimate code
        if len(expected_list) == 0 and len(actual_list) == 0:
            true_negatives += 1
    
    # Check for findings in unexpected files (not in EXPECTED_FINDINGS)
    unexpected_files = set(findings_by_file.keys()) - set(EXPECTED_FINDINGS.keys())
    for unexpected_file in unexpected_files:
        false_positives += len(findings_by_file[unexpected_file])
        errors.append(f"FALSE POSITIVE: {unexpected_file} — file not in test corpus")
    
    # Calculate precision, recall, F1
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1_score, 3),
        "errors": errors,
        "total_expected_findings": sum(len(v) for v in EXPECTED_FINDINGS.values()),
        "total_actual_findings": len(scan_results.get("findings", [])),
    }


def main():
    test_dir = Path(__file__).parent / "fixtures" / "mobile-code"
    scan_dir = Path(__file__).parent / "tmp" / "mobile-code-validation-scan"
    scan_dir.mkdir(parents=True, exist_ok=True)
    
    print("Running mobile code scanner against test fixtures...")
    scan_results = run_scanner(test_dir, scan_dir)
    
    print(f"Scanner found {len(scan_results.get('findings', []))} findings")
    print("\nValidating results...")
    
    metrics = validate_results(scan_results, test_dir)
    
    print("\n" + "="*60)
    print("MOBILE CODE SCANNER VALIDATION RESULTS")
    print("="*60)
    print(f"True Positives:  {metrics['true_positives']}")
    print(f"False Positives: {metrics['false_positives']}")
    print(f"False Negatives: {metrics['false_negatives']}")
    print(f"True Negatives:  {metrics['true_negatives']}")
    print(f"\nPrecision: {metrics['precision']:.1%}")
    print(f"Recall:    {metrics['recall']:.1%}")
    print(f"F1 Score:  {metrics['f1_score']:.3f}")
    print(f"\nExpected Findings: {metrics['total_expected_findings']}")
    print(f"Actual Findings:   {metrics['total_actual_findings']}")
    
    if metrics["errors"]:
        print("\n" + "="*60)
        print("ERRORS:")
        print("="*60)
        for error in metrics["errors"]:
            print(f"  • {error}")
    
    # Success criteria: F1 score >= 0.9 (90%)
    if metrics["f1_score"] >= 0.9:
        print("\n✓ PASS: Mobile code scanner validation successful")
        return 0
    else:
        print("\n✗ FAIL: Mobile code scanner validation failed (F1 < 0.9)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
