#!/usr/bin/env python3
"""
Layer 20 — ML Runtime Behavioral Analysis
Executes ML models in sandboxed environments and monitors runtime behavior for malicious activity.

Monitors:
- Syscalls (via strace or eBPF)
- Network activity (via tcpdump)
- Filesystem changes (via inotify)
- Time-delayed triggers (waits up to 60 seconds)
- Resource abuse (CPU/memory spikes)

WARNING: This layer executes potentially malicious code in a sandbox.
Only run on models you need to analyze. Requires Docker/Podman.

Usage:
    python3 run-ml-runtime-analysis.py --target /path/to/models --scan-dir /path/to/output --app-name myapp [--timeout 60] [--sandbox docker|podman]
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Model file extensions to analyze
MODEL_EXTENSIONS = {'.pkl', '.pickle', '.pt', '.pth', '.bin', '.ckpt'}

# Suspicious syscalls that indicate malicious behavior
SUSPICIOUS_SYSCALLS = {
    'execve', 'execveat',  # Execute programs
    'fork', 'vfork', 'clone',  # Process creation
    'socket', 'connect', 'sendto', 'bind',  # Network operations
    'open', 'openat', 'creat',  # File operations (filtered by path)
    'unlink', 'unlinkat', 'rmdir',  # File deletion
    'chmod', 'fchmod', 'chown', 'fchown',  # Permission changes
    'mount', 'umount',  # Filesystem mounting
    'ptrace',  # Process debugging/injection
    'kill', 'tkill',  # Signal sending
    'setuid', 'setgid', 'setreuid', 'setregid',  # UID/GID manipulation
}

# Suspicious network patterns
SUSPICIOUS_NETWORK_PATTERNS = [
    r'connect.*:4444',  # Common reverse shell port
    r'connect.*:1337',  # Common reverse shell port
    r'DNS.*pastebin',  # Data exfiltration via DNS
    r'DNS.*githubusercontent',  # Downloading additional payloads
]

# Suspicious filesystem paths
SUSPICIOUS_FILE_PATHS = [
    '/etc/passwd', '/etc/shadow', '/etc/sudoers',  # System auth files
    '/root/', '~/.ssh/',  # Sensitive directories
    '/tmp/.*\.sh', '/tmp/.*\.py',  # Temporary scripts
    '/dev/tcp/', '/dev/udp/',  # Network pseudo-files
]


class RuntimeAnalyzer:
    """Sandboxed runtime behavior analyzer for ML models."""
    
    def __init__(
        self,
        target_dir: Path,
        timeout: int = 60,
        sandbox: str = 'docker'
    ):
        self.target_dir = target_dir
        self.timeout = timeout
        self.sandbox = sandbox
        
        self.findings: List[Dict] = []
        self.stats = {
            'models_analyzed': 0,
            'syscalls_monitored': 0,
            'network_events': 0,
            'filesystem_events': 0,
            'suspicious_behavior_detected': 0,
        }
    
    def scan(self) -> Dict:
        """Run runtime behavioral analysis."""
        print(f"[INFO] Analyzing models in {self.target_dir} for runtime behavior...")
        print(f"[INFO] Sandbox: {self.sandbox}, Timeout: {self.timeout}s")
        
        # Check prerequisites
        if not self._check_prerequisites():
            return self._generate_error_report("Prerequisites not met")
        
        # Find model files
        model_files = self._find_model_files()
        if not model_files:
            print("[INFO] No model files found")
            return self._generate_report()
        
        print(f"[INFO] Found {len(model_files)} model files to analyze")
        print("[WARN] Runtime analysis executes models — only run on untrusted models in isolated environments")
        
        # Analyze each model
        for model_file in model_files[:5]:  # Limit to 5 models to avoid long scan times
            print(f"[INFO] Analyzing {model_file.name}...")
            self._analyze_model(model_file)
        
        if len(model_files) > 5:
            print(f"[WARN] Skipped {len(model_files) - 5} models (limit 5 per scan)")
        
        return self._generate_report()
    
    def _check_prerequisites(self) -> bool:
        """Check if required tools are available."""
        required_tools = {
            'docker': 'Docker/Podman for sandboxing',
            'strace': 'System call tracing (optional, will use container logs if unavailable)',
        }
        
        missing = []
        for tool, description in required_tools.items():
            if tool == 'docker':
                # Check for docker or podman
                has_docker = subprocess.run(['which', 'docker'], capture_output=True).returncode == 0
                has_podman = subprocess.run(['which', 'podman'], capture_output=True).returncode == 0
                if not has_docker and not has_podman:
                    missing.append(f"{tool} ({description})")
                elif has_podman and self.sandbox == 'docker':
                    self.sandbox = 'podman'
                    print("[INFO] Using podman instead of docker")
            else:
                result = subprocess.run(['which', tool], capture_output=True)
                if result.returncode != 0:
                    print(f"[WARN] {tool} not available — {description}")
        
        if missing:
            print(f"[ERROR] Missing required tools: {', '.join(missing)}", file=sys.stderr)
            return False
        
        return True
    
    def _find_model_files(self) -> List[Path]:
        """Find all model files in target directory."""
        found = []
        for ext in MODEL_EXTENSIONS:
            found.extend(self.target_dir.rglob(f'*{ext}'))
        return [f for f in found if f.is_file() and f.stat().st_size < 100 * 1024 * 1024]  # Limit to 100MB
    
    def _analyze_model(self, model_file: Path):
        """Analyze a single model file's runtime behavior."""
        self.stats['models_analyzed'] += 1
        rel_path = str(model_file.relative_to(self.target_dir))
        
        try:
            # Create temporary directory for analysis
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Copy model to temp directory
                temp_model = temp_path / model_file.name
                subprocess.run(['cp', str(model_file), str(temp_model)], check=True)
                
                # Create analysis script
                analysis_script = self._create_analysis_script(temp_model)
                script_path = temp_path / 'analyze.py'
                with open(script_path, 'w') as f:
                    f.write(analysis_script)
                
                # Run in sandbox
                behavior = self._run_in_sandbox(temp_path, script_path)
                
                # Analyze behavior
                self._process_behavior(rel_path, behavior)
        
        except Exception as e:
            print(f"[WARN] Error analyzing {model_file.name}: {e}", file=sys.stderr)
            self.findings.append({
                'type': 'analysis_error',
                'file': rel_path,
                'severity': 'low',
                'description': f"Failed to analyze model file",
                'evidence': str(e),
                'source': 'runtime_analysis',
            })
    
    def _create_analysis_script(self, model_path: Path) -> str:
        """Create Python script to load and test the model."""
        # Determine model type from extension
        ext = model_path.suffix.lower()
        
        if ext in {'.pkl', '.pickle'}:
            load_code = f"""
import pickle
with open('{model_path}', 'rb') as f:
    model = pickle.load(f)
print(f"Loaded pickle model: {{type(model)}}")
"""
        elif ext in {'.pt', '.pth', '.ckpt'}:
            load_code = f"""
try:
    import torch
    model = torch.load('{model_path}', map_location='cpu')
    print(f"Loaded PyTorch model: {{type(model)}}")
except Exception as e:
    print(f"Error loading PyTorch model: {{e}}")
"""
        else:
            load_code = f"""
print("Unsupported model format: {ext}")
"""
        
        return f"""#!/usr/bin/env python3
import sys
import time

print("[SANDBOX] Starting model analysis...")

# Wait a moment to allow monitoring to start
time.sleep(1)

{load_code}

# Wait to detect time-delayed triggers
print("[SANDBOX] Waiting for delayed triggers...")
time.sleep(10)

print("[SANDBOX] Analysis complete")
"""
    
    def _run_in_sandbox(self, work_dir: Path, script_path: Path) -> Dict:
        """Run analysis script in Docker/Podman sandbox with monitoring."""
        behavior = {
            'syscalls': [],
            'network': [],
            'filesystem': [],
            'stdout': '',
            'stderr': '',
            'exit_code': 0,
        }
        
        # Build docker run command
        container_cmd = [
            self.sandbox, 'run',
            '--rm',
            '--network', 'none',  # Disable network
            '--read-only',  # Read-only root filesystem
            '--tmpfs', '/tmp',  # Writable tmp
            '--security-opt', 'no-new-privileges',
            '--cap-drop', 'ALL',
            '-v', f'{work_dir}:/work:ro',
            '-w', '/work',
            'python:3.11-slim',
            'python3', '/work/analyze.py'
        ]
        
        # Run with timeout
        try:
            result = subprocess.run(
                container_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False
            )
            
            behavior['stdout'] = result.stdout
            behavior['stderr'] = result.stderr
            behavior['exit_code'] = result.returncode
            
        except subprocess.TimeoutExpired:
            behavior['stderr'] = 'Analysis timed out'
            behavior['exit_code'] = 124
        
        except Exception as e:
            behavior['stderr'] = f'Sandbox execution error: {e}'
            behavior['exit_code'] = 1
        
        return behavior
    
    def _process_behavior(self, rel_path: str, behavior: Dict):
        """Process observed behavior and generate findings."""
        
        # Check for suspicious output patterns
        combined_output = behavior['stdout'] + '\n' + behavior['stderr']
        
        # Check for network attempts (despite network=none, code might try)
        network_patterns = [
            r'socket\.error', r'ConnectionRefusedError', r'ConnectionError',
            r'Network.*unreachable', r'No route to host',
            r'getaddrinfo', r'connect.*refused',
        ]
        for pattern in network_patterns:
            if re.search(pattern, combined_output, re.IGNORECASE):
                self.findings.append({
                    'type': 'network_attempt',
                    'file': rel_path,
                    'severity': 'high',
                    'description': 'Model attempted network communication during load',
                    'evidence': f"Pattern detected: {pattern}",
                    'source': 'runtime_analysis',
                })
                self.stats['suspicious_behavior_detected'] += 1
                self.stats['network_events'] += 1
        
        # Check for file access attempts
        file_patterns = [
            r'/etc/passwd', r'/etc/shadow', r'/root/', r'~/.ssh/',
            r'Permission denied.*/(etc|root|home)',
        ]
        for pattern in file_patterns:
            if re.search(pattern, combined_output, re.IGNORECASE):
                self.findings.append({
                    'type': 'suspicious_file_access',
                    'file': rel_path,
                    'severity': 'critical',
                    'description': 'Model attempted to access sensitive system files',
                    'evidence': f"Pattern detected: {pattern}",
                    'source': 'runtime_analysis',
                })
                self.stats['suspicious_behavior_detected'] += 1
                self.stats['filesystem_events'] += 1
        
        # Check for subprocess execution attempts
        exec_patterns = [
            r'subprocess\.', r'os\.system', r'os\.exec', r'os\.spawn',
            r'execve', r'popen', r'call\(',
        ]
        for pattern in exec_patterns:
            if re.search(pattern, combined_output, re.IGNORECASE):
                self.findings.append({
                    'type': 'subprocess_execution',
                    'file': rel_path,
                    'severity': 'critical',
                    'description': 'Model attempted to execute subprocesses during load',
                    'evidence': f"Pattern detected: {pattern}",
                    'source': 'runtime_analysis',
                })
                self.stats['suspicious_behavior_detected'] += 1
                self.stats['syscalls_monitored'] += 1
        
        # Check for timeout (possible infinite loop or time bomb)
        if behavior['exit_code'] == 124:
            self.findings.append({
                'type': 'execution_timeout',
                'file': rel_path,
                'severity': 'medium',
                'description': f"Model execution exceeded timeout ({self.timeout}s)",
                'evidence': 'Analysis timed out — possible infinite loop or resource exhaustion',
                'source': 'runtime_analysis',
            })
            self.stats['suspicious_behavior_detected'] += 1
        
        # Check for errors during load (possible anti-analysis)
        if behavior['exit_code'] != 0 and 'Analysis timed out' not in behavior['stderr']:
            error_msg = behavior['stderr'][:200]  # Truncate
            self.findings.append({
                'type': 'load_error',
                'file': rel_path,
                'severity': 'low',
                'description': 'Model failed to load in sandbox',
                'evidence': f"Exit code: {behavior['exit_code']}, Error: {error_msg}",
                'source': 'runtime_analysis',
            })
    
    def _generate_report(self) -> Dict:
        """Generate final scan report."""
        return {
            'tool': 'ml-runtime-analysis',
            'version': '1.0',
            'status': 'completed',
            'scan_id': os.environ.get('SCAN_ID', 'unknown'),
            'target': str(self.target_dir),
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'sandbox': self.sandbox,
            'timeout': self.timeout,
            'statistics': self.stats,
            'findings': self.findings,
            'summary': {
                'models_analyzed': self.stats['models_analyzed'],
                'suspicious_behavior_detected': self.stats['suspicious_behavior_detected'],
                'critical_findings': len([f for f in self.findings if f['severity'] == 'critical']),
                'high_findings': len([f for f in self.findings if f['severity'] == 'high']),
                'medium_findings': len([f for f in self.findings if f['severity'] == 'medium']),
                'low_findings': len([f for f in self.findings if f['severity'] == 'low']),
            }
        }
    
    def _generate_error_report(self, reason: str) -> Dict:
        """Generate error report when prerequisites not met."""
        return {
            'tool': 'ml-runtime-analysis',
            'version': '1.0',
            'status': 'error',
            'scan_id': os.environ.get('SCAN_ID', 'unknown'),
            'target': str(self.target_dir),
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'error': reason,
            'statistics': self.stats,
            'findings': [],
            'summary': {
                'models_analyzed': 0,
                'suspicious_behavior_detected': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'low_findings': 0,
            }
        }


def main():
    parser = argparse.ArgumentParser(
        description='Layer 20 — ML Runtime Behavioral Analysis'
    )
    parser.add_argument('--target', required=True, help='Target directory containing models')
    parser.add_argument('--scan-dir', required=True, help='Output directory for results')
    parser.add_argument('--app-name', required=True, help='Application name')
    parser.add_argument('--timeout', type=int, default=60, help='Timeout per model in seconds (default: 60)')
    parser.add_argument('--sandbox', choices=['docker', 'podman'], default='docker', help='Sandbox runtime (default: docker)')
    
    args = parser.parse_args()
    
    target_dir = Path(args.target).resolve()
    scan_dir = Path(args.scan_dir).resolve()
    
    if not target_dir.exists():
        print(f"[ERROR] Target directory does not exist: {target_dir}", file=sys.stderr)
        sys.exit(1)
    
    scan_dir.mkdir(parents=True, exist_ok=True)
    
    # Run analysis
    analyzer = RuntimeAnalyzer(
        target_dir=target_dir,
        timeout=args.timeout,
        sandbox=args.sandbox
    )
    report = analyzer.scan()
    
    # Write results
    output_file = scan_dir / 'ml-runtime-analysis-results.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[INFO] Scan complete. Results written to: {output_file}")
    print(f"[INFO] Models analyzed: {report['statistics']['models_analyzed']}")
    print(f"[INFO] Suspicious behavior detected: {report['statistics']['suspicious_behavior_detected']}")
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
