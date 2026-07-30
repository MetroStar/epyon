#!/usr/bin/env python3
"""
Enhanced Layer 14 — Comprehensive Model File Analysis
Scans ML model files for security threats across multiple serialization formats:
- Pickle exploits (via picklescan library + custom checks)
- PyTorch JIT graph manipulation
- ONNX operator injection
- TensorFlow SavedModel malicious ops
- Suspicious imports and obfuscated payloads

Usage:
    python3 run-picklescan.py --target /path/to/repo --scan-dir /path/to/output --app-name myapp [--formats pickle,pytorch,onnx,tf]
"""

import argparse
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Set, Tuple

# File extensions by format
PICKLE_EXTENSIONS = {'.pkl', '.pickle', '.pt', '.pth', '.bin', '.ckpt', '.npy', '.npz', '.joblib', '.h5', '.hdf5'}
PYTORCH_EXTENSIONS = {'.pt', '.pth', '.ckpt'}
ONNX_EXTENSIONS = {'.onnx'}
TF_EXTENSIONS = {'.pb'}
CONFIG_EXTENSIONS = {'.json'}

# Dangerous imports that should not appear in model files
DANGEROUS_IMPORTS = {
    'subprocess', 'os.system', 'os.exec', 'os.spawn', 'os.popen',
    'socket', 'urllib', 'requests', 'http.client',
    'eval', 'exec', 'compile', '__import__',
    'ctypes', 'cffi',
    'multiprocessing', 'threading.Thread',
    'pickle.loads', 'pickle.load', 'pickle.Unpickler',
    'yaml.load', 'yaml.unsafe_load',
    'marshal.loads',
    'shelve.open',
    'dill.loads',
}

# Obfuscation patterns (base64, hex strings)
OBFUSCATION_PATTERNS = [
    re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),  # Base64
    re.compile(r'0x[0-9a-fA-F]{20,}'),         # Long hex strings
    re.compile(r'\\x[0-9a-fA-F]{2}' * 10),     # Hex escape sequences
]


class ModelExploitScanner:
    """Comprehensive scanner for ML model security threats."""
    
    def __init__(self, target_dir: Path, formats: Set[str] = None):
        self.target_dir = target_dir
        self.formats = formats or {'pickle', 'pytorch', 'onnx', 'tf', 'config'}
        self.findings: List[Dict] = []
        self.stats = {
            'total_files': 0,
            'pickle_files': 0,
            'pytorch_files': 0,
            'onnx_files': 0,
            'tf_files': 0,
            'config_files': 0,
            'flagged_count': 0,
        }
    
    def scan(self) -> Dict:
        """Run comprehensive scan across all supported formats."""
        print(f"[INFO] Scanning {self.target_dir} for model security threats...")
        
        # Scan pickle files with picklescan library
        if 'pickle' in self.formats:
            self._scan_pickle_files()
        
        # Scan PyTorch files for JIT exploits
        if 'pytorch' in self.formats:
            self._scan_pytorch_files()
        
        # Scan ONNX files for operator injection
        if 'onnx' in self.formats:
            self._scan_onnx_files()
        
        # Scan TensorFlow SavedModel files
        if 'tf' in self.formats:
            self._scan_tf_files()
        
        # Scan config files for suspicious patterns
        if 'config' in self.formats:
            self._scan_config_files()
        
        return self._generate_report()
    
    def _scan_pickle_files(self):
        """Scan pickle files using picklescan library + custom checks."""
        try:
            import picklescan.scanner
        except ImportError:
            print("[WARN] picklescan library not available — skipping pickle scan", file=sys.stderr)
            return
        
        for pickle_file in self._find_files(PICKLE_EXTENSIONS):
            self.stats['pickle_files'] += 1
            self.stats['total_files'] += 1
            
            try:
                # Use picklescan library for basic checks
                scanner = picklescan.scanner.Scanner()
                result = scanner.scan(str(pickle_file))
                
                if result and result.get('issues'):
                    for issue in result['issues']:
                        self.findings.append({
                            'type': 'pickle_exploit',
                            'file': str(pickle_file.relative_to(self.target_dir)),
                            'severity': 'critical',
                            'description': f"Malicious pickle opcode detected: {issue.get('code', 'unknown')}",
                            'evidence': issue.get('message', ''),
                            'match_type': 'picklescan_library',
                            'format': 'pickle',
                        })
                        self.stats['flagged_count'] += 1
                
                # Additional custom checks for suspicious content
                self._check_file_for_imports(pickle_file, 'pickle')
                
            except Exception as e:
                print(f"[WARN] Error scanning pickle file {pickle_file}: {e}", file=sys.stderr)
    
    def _scan_pytorch_files(self):
        """Scan PyTorch model files for JIT graph manipulation exploits."""
        for pt_file in self._find_files(PYTORCH_EXTENSIONS):
            self.stats['pytorch_files'] += 1
            self.stats['total_files'] += 1
            
            try:
                # PyTorch files are often ZIP archives containing model weights + code
                if zipfile.is_zipfile(pt_file):
                    with zipfile.ZipFile(pt_file, 'r') as zf:
                        # Check for Python code in the archive
                        for name in zf.namelist():
                            if name.endswith('.py'):
                                code_content = zf.read(name).decode('utf-8', errors='ignore')
                                dangerous = self._find_dangerous_imports(code_content)
                                if dangerous:
                                    self.findings.append({
                                        'type': 'pytorch_jit_exploit',
                                        'file': str(pt_file.relative_to(self.target_dir)),
                                        'severity': 'critical',
                                        'description': f"PyTorch model contains embedded Python code with dangerous imports",
                                        'evidence': f"File: {name}, Imports: {', '.join(dangerous)}",
                                        'match_type': 'embedded_code',
                                        'format': 'pytorch',
                                    })
                                    self.stats['flagged_count'] += 1
                            
                            # Check for suspicious file names
                            if any(pattern in name.lower() for pattern in ['eval', 'exec', 'system', 'shell']):
                                self.findings.append({
                                    'type': 'pytorch_suspicious_file',
                                    'file': str(pt_file.relative_to(self.target_dir)),
                                    'severity': 'high',
                                    'description': f"PyTorch model contains suspicious file name in archive",
                                    'evidence': f"Suspicious file: {name}",
                                    'match_type': 'suspicious_filename',
                                    'format': 'pytorch',
                                })
                                self.stats['flagged_count'] += 1
                
                # Check for suspicious imports in the file content
                self._check_file_for_imports(pt_file, 'pytorch')
                
            except Exception as e:
                print(f"[WARN] Error scanning PyTorch file {pt_file}: {e}", file=sys.stderr)
    
    def _scan_onnx_files(self):
        """Scan ONNX model files for operator injection attacks."""
        for onnx_file in self._find_files(ONNX_EXTENSIONS):
            self.stats['onnx_files'] += 1
            self.stats['total_files'] += 1
            
            try:
                # Read ONNX file (protobuf format)
                with open(onnx_file, 'rb') as f:
                    content = f.read()
                
                # Look for suspicious operator names in the binary
                suspicious_ops = ['PyOp', 'PythonOp', 'CustomOp', 'Exec', 'System']
                for op in suspicious_ops:
                    if op.encode('utf-8') in content or op.encode('utf-16') in content:
                        self.findings.append({
                            'type': 'onnx_operator_injection',
                            'file': str(onnx_file.relative_to(self.target_dir)),
                            'severity': 'high',
                            'description': f"ONNX model contains suspicious custom operator: {op}",
                            'evidence': f"Operator name found in model file: {op}",
                            'match_type': 'custom_operator',
                            'format': 'onnx',
                        })
                        self.stats['flagged_count'] += 1
                
                # Check for obfuscated payloads
                obfuscation = self._check_obfuscation(content)
                if obfuscation:
                    self.findings.append({
                        'type': 'onnx_obfuscation',
                        'file': str(onnx_file.relative_to(self.target_dir)),
                        'severity': 'medium',
                        'description': f"ONNX model contains obfuscated data",
                        'evidence': f"Obfuscation pattern: {obfuscation}",
                        'match_type': 'obfuscation',
                        'format': 'onnx',
                    })
                    self.stats['flagged_count'] += 1
                
            except Exception as e:
                print(f"[WARN] Error scanning ONNX file {onnx_file}: {e}", file=sys.stderr)
    
    def _scan_tf_files(self):
        """Scan TensorFlow SavedModel files for malicious operations."""
        for tf_file in self._find_files(TF_EXTENSIONS):
            self.stats['tf_files'] += 1
            self.stats['total_files'] += 1
            
            try:
                # TensorFlow SavedModel uses protobuf
                with open(tf_file, 'rb') as f:
                    content = f.read()
                
                # Look for suspicious TensorFlow ops
                suspicious_ops = ['PyFunc', 'PyFuncStateless', 'EagerPyFunc', 'system', 'exec']
                for op in suspicious_ops:
                    if op.encode('utf-8') in content:
                        self.findings.append({
                            'type': 'tf_malicious_op',
                            'file': str(tf_file.relative_to(self.target_dir)),
                            'severity': 'critical' if 'Func' in op else 'high',
                            'description': f"TensorFlow SavedModel contains suspicious operation: {op}",
                            'evidence': f"Operation found in graph: {op}",
                            'match_type': 'suspicious_op',
                            'format': 'tensorflow',
                        })
                        self.stats['flagged_count'] += 1
                
            except Exception as e:
                print(f"[WARN] Error scanning TensorFlow file {tf_file}: {e}", file=sys.stderr)
    
    def _scan_config_files(self):
        """Scan configuration files (config.json, etc.) for suspicious patterns."""
        config_patterns = [
            'config.json',
            'model_config.json',
            'trainer_config.json',
            '*.index.json',
        ]
        
        for pattern in config_patterns:
            for config_file in self.target_dir.rglob(pattern):
                if config_file.is_file():
                    self.stats['config_files'] += 1
                    self.stats['total_files'] += 1
                    
                    try:
                        with open(config_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        # Check for suspicious imports in config
                        dangerous = self._find_dangerous_imports(content)
                        if dangerous:
                            self.findings.append({
                                'type': 'config_dangerous_import',
                                'file': str(config_file.relative_to(self.target_dir)),
                                'severity': 'high',
                                'description': f"Model config contains dangerous imports or code execution patterns",
                                'evidence': f"Imports: {', '.join(dangerous)}",
                                'match_type': 'config_import',
                                'format': 'config',
                            })
                            self.stats['flagged_count'] += 1
                        
                        # Check for obfuscation
                        obfuscation = self._check_obfuscation(content.encode('utf-8'))
                        if obfuscation:
                            self.findings.append({
                                'type': 'config_obfuscation',
                                'file': str(config_file.relative_to(self.target_dir)),
                                'severity': 'medium',
                                'description': f"Model config contains obfuscated data",
                                'evidence': f"Obfuscation pattern: {obfuscation}",
                                'match_type': 'obfuscation',
                                'format': 'config',
                            })
                            self.stats['flagged_count'] += 1
                        
                    except Exception as e:
                        print(f"[WARN] Error scanning config file {config_file}: {e}", file=sys.stderr)
    
    def _find_files(self, extensions: Set[str]) -> List[Path]:
        """Find all files with given extensions in target directory."""
        found = []
        for ext in extensions:
            found.extend(self.target_dir.rglob(f'*{ext}'))
        return [f for f in found if f.is_file()]
    
    def _check_file_for_imports(self, file_path: Path, format: str):
        """Check a file for dangerous imports (binary scan)."""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Convert to text for pattern matching (ignore decode errors)
            text_content = content.decode('utf-8', errors='ignore')
            
            dangerous = self._find_dangerous_imports(text_content)
            if dangerous:
                self.findings.append({
                    'type': 'dangerous_import',
                    'file': str(file_path.relative_to(self.target_dir)),
                    'severity': 'critical',
                    'description': f"Model file contains dangerous imports",
                    'evidence': f"Imports: {', '.join(dangerous)}",
                    'match_type': 'import_scan',
                    'format': format,
                })
                self.stats['flagged_count'] += 1
        except Exception as e:
            pass  # Silently skip unreadable files
    
    def _find_dangerous_imports(self, content: str) -> Set[str]:
        """Find dangerous imports in text content."""
        found = set()
        for dangerous in DANGEROUS_IMPORTS:
            if dangerous in content:
                found.add(dangerous)
        return found
    
    def _check_obfuscation(self, content: bytes) -> str:
        """Check for obfuscation patterns in content."""
        text_content = content.decode('utf-8', errors='ignore')
        
        for pattern in OBFUSCATION_PATTERNS:
            matches = pattern.findall(text_content)
            if matches:
                # Return description of first match
                if len(matches[0]) > 40:
                    return f"base64-like string (length: {len(matches[0])})"
                elif matches[0].startswith('0x'):
                    return f"long hex string (length: {len(matches[0])})"
                else:
                    return f"hex escape sequence (length: {len(matches[0])})"
        return ""
    
    def _generate_report(self) -> Dict:
        """Generate final scan report."""
        return {
            'tool': 'picklescan',
            'version': '2.0-enhanced',
            'status': 'completed',
            'scan_id': os.environ.get('SCAN_ID', 'unknown'),
            'target': str(self.target_dir),
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'statistics': self.stats,
            'formats_scanned': list(self.formats),
            'findings': self.findings,
            'summary': {
                'total_files_scanned': self.stats['total_files'],
                'flagged_files': self.stats['flagged_count'],
                'critical_findings': len([f for f in self.findings if f['severity'] == 'critical']),
                'high_findings': len([f for f in self.findings if f['severity'] == 'high']),
                'medium_findings': len([f for f in self.findings if f['severity'] == 'medium']),
            }
        }


def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Layer 14 — Comprehensive Model File Analysis'
    )
    parser.add_argument('--target', required=True, help='Target directory to scan')
    parser.add_argument('--scan-dir', required=True, help='Output directory for results')
    parser.add_argument('--app-name', required=True, help='Application name')
    parser.add_argument(
        '--formats',
        default='pickle,pytorch,onnx,tf,config',
        help='Comma-separated list of formats to scan (default: all)'
    )
    
    args = parser.parse_args()
    
    target_dir = Path(args.target).resolve()
    scan_dir = Path(args.scan_dir).resolve()
    formats = set(args.formats.split(','))
    
    if not target_dir.exists():
        print(f"[ERROR] Target directory does not exist: {target_dir}", file=sys.stderr)
        sys.exit(1)
    
    scan_dir.mkdir(parents=True, exist_ok=True)
    
    # Run scan
    scanner = ModelExploitScanner(target_dir, formats)
    report = scanner.scan()
    
    # Write results
    output_file = scan_dir / 'picklescan-results.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[INFO] Scan complete. Results written to: {output_file}")
    print(f"[INFO] Total files scanned: {report['statistics']['total_files']}")
    print(f"[INFO] Flagged files: {report['statistics']['flagged_count']}")
    print(f"[INFO] Critical findings: {report['summary']['critical_findings']}")
    print(f"[INFO] High findings: {report['summary']['high_findings']}")
    print(f"[INFO] Medium findings: {report['summary']['medium_findings']}")
    
    # Exit with error code if critical/high findings
    if report['summary']['critical_findings'] > 0 or report['summary']['high_findings'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
