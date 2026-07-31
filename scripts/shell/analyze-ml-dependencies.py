#!/usr/bin/env python3
"""
ML-aware pip-audit analysis helper.
Enhances pip-audit results with ML-specific intelligence:
- ML package detection
- Typosquatting checks for popular ML packages
- CVE severity highlighting for ML frameworks
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Common ML/AI frameworks and libraries
ML_PACKAGES = {
    'torch', 'pytorch', 'torchvision', 'torchaudio',  # PyTorch ecosystem
    'tensorflow', 'tensorflow-gpu', 'tf', 'keras',  # TensorFlow ecosystem
    'transformers', 'tokenizers', 'datasets', 'accelerate',  # Hugging Face
    'scikit-learn', 'sklearn',  # scikit-learn
    'numpy', 'scipy', 'pandas',  # Core data science
    'matplotlib', 'seaborn', 'plotly',  # Visualization
    'jupyter', 'notebook', 'jupyterlab',  # Notebooks
    'jax', 'jaxlib', 'flax',  # JAX ecosystem
    'onnx', 'onnxruntime',  # ONNX
    'xgboost', 'lightgbm', 'catboost',  # Gradient boosting
    'opencv-python', 'cv2', 'pillow', 'pil',  # Computer vision
    'nltk', 'spacy', 'gensim',  # NLP
    'mlflow', 'wandb', 'tensorboard',  # Experiment tracking
    'fastai', 'timm',  # High-level frameworks
    'optuna', 'ray',  # Hyperparameter tuning
    'safetensors',  # Safe model serialization
}

# Typosquatting targets (most popular ML packages)
TYPOSQUAT_TARGETS = [
    'torch', 'tensorflow', 'transformers', 'numpy', 'scipy', 'pandas',
    'scikit-learn', 'keras', 'opencv-python', 'matplotlib',
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # j+1 instead of j since previous_row and current_row are one character longer
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def is_ml_package(package_name: str) -> bool:
    """Check if a package is a known ML/AI framework."""
    name_lower = package_name.lower()
    return any(ml_pkg in name_lower for ml_pkg in ML_PACKAGES)


def check_typosquatting(package_name: str) -> Tuple[bool, str, int]:
    """
    Check if a package name is a potential typosquat of popular ML packages.
    
    Returns:
        (is_typosquat, target_package, distance)
    """
    name_lower = package_name.lower()
    
    for target in TYPOSQUAT_TARGETS:
        distance = levenshtein_distance(name_lower, target)
        
        # Distance 1-2 is suspicious (but exclude exact matches)
        if 0 < distance < 2:
            return True, target, distance
    
    return False, "", 0


def analyze_pip_audit_results(results_file: Path, output_file: Path) -> Dict:
    """
    Analyze pip-audit results and add ML-specific intelligence.
    
    Args:
        results_file: Path to pip-audit consolidated results JSON
        output_file: Path to write ML-enhanced results JSON
    
    Returns:
        Enhanced results dictionary
    """
    try:
        with open(results_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading pip-audit results: {e}", file=sys.stderr)
        return {}
    
    # ML-specific findings
    ml_findings = {
        'ml_packages_found': [],
        'ml_vulnerabilities': [],
        'typosquat_warnings': [],
        'high_severity_ml_cves': [],
    }
    
    all_packages_seen: Set[str] = set()
    
    # Analyze each scan result
    for scan_result in data.get('scan_results', []):
        source_file = scan_result.get('file', 'unknown')
        vulnerabilities = scan_result.get('results', [])
        
        for vuln in vulnerabilities:
            package_name = vuln.get('name', '')
            if not package_name:
                continue
            
            all_packages_seen.add(package_name)
            
            # Check if this is an ML package
            if is_ml_package(package_name):
                if package_name not in [p['name'] for p in ml_findings['ml_packages_found']]:
                    ml_findings['ml_packages_found'].append({
                        'name': package_name,
                        'source': source_file
                    })
                
                # This is a vulnerability in an ML package
                ml_vuln = {
                    'package': package_name,
                    'version': vuln.get('version', 'unknown'),
                    'id': vuln.get('id', 'unknown'),
                    'source_file': source_file,
                    'fix_versions': vuln.get('fix_versions', []),
                }
                
                # Add severity if available
                if 'aliases' in vuln:
                    ml_vuln['cve_ids'] = [alias for alias in vuln['aliases'] if alias.startswith('CVE-')]
                
                ml_findings['ml_vulnerabilities'].append(ml_vuln)
                
                # Check severity (high/critical CVEs in ML packages are especially concerning)
                # pip-audit doesn't always provide severity, but we can check for GHSA/CVE
                if vuln.get('id', '').startswith('GHSA-') or any(
                    alias.startswith('CVE-') for alias in vuln.get('aliases', [])
                ):
                    ml_findings['high_severity_ml_cves'].append({
                        'package': package_name,
                        'id': vuln.get('id', 'unknown'),
                        'description': vuln.get('description', 'No description available')[:200],
                        'source_file': source_file,
                    })
    
    # Check for typosquatting across all packages seen
    for package_name in all_packages_seen:
        is_typosquat, target, distance = check_typosquatting(package_name)
        if is_typosquat:
            ml_findings['typosquat_warnings'].append({
                'package': package_name,
                'suspected_target': target,
                'levenshtein_distance': distance,
                'severity': 'critical',  # Typosquatting is always critical
                'recommendation': f'Verify this is not a typosquat of "{target}". Check package source and maintainer.'
            })
    
    # Add ML findings to the data
    enhanced_data = data.copy()
    enhanced_data['ml_specific_findings'] = ml_findings
    enhanced_data['ml_packages_detected'] = len(ml_findings['ml_packages_found'])
    enhanced_data['ml_vulnerabilities_count'] = len(ml_findings['ml_vulnerabilities'])
    enhanced_data['typosquat_warnings_count'] = len(ml_findings['typosquat_warnings'])
    
    # Write enhanced results
    try:
        with open(output_file, 'w') as f:
            json.dump(enhanced_data, f, indent=2)
        print(f"ML-enhanced results written to: {output_file}")
    except Exception as e:
        print(f"Error writing enhanced results: {e}", file=sys.stderr)
        return {}
    
    return ml_findings


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <pip-audit-results.json> <output-file.json>", file=sys.stderr)
        sys.exit(1)
    
    results_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])
    
    if not results_file.exists():
        print(f"Error: Results file not found: {results_file}", file=sys.stderr)
        sys.exit(1)
    
    ml_findings = analyze_pip_audit_results(results_file, output_file)
    
    # Print summary
    print("\n=== ML-Specific Analysis Summary ===")
    print(f"ML packages detected: {len(ml_findings['ml_packages_found'])}")
    if ml_findings['ml_packages_found']:
        print("  Packages:", ', '.join([p['name'] for p in ml_findings['ml_packages_found']]))
    
    print(f"ML vulnerabilities: {len(ml_findings['ml_vulnerabilities'])}")
    print(f"High-severity ML CVEs: {len(ml_findings['high_severity_ml_cves'])}")
    
    print(f"Typosquat warnings: {len(ml_findings['typosquat_warnings'])}")
    if ml_findings['typosquat_warnings']:
        for warning in ml_findings['typosquat_warnings']:
            print(f"  ⚠️  {warning['package']} (distance {warning['levenshtein_distance']} from {warning['suspected_target']})")
    
    # Exit with error code if critical issues found
    if ml_findings['typosquat_warnings']:
        sys.exit(2)  # Typosquat detected (critical)
    elif ml_findings['high_severity_ml_cves']:
        sys.exit(1)  # High severity ML CVEs found
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
