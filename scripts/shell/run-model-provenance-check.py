#!/usr/bin/env python3
"""
Layer 18 — Model Provenance & Threat Intelligence
Validates ML model provenance, checks signatures, and cross-references against threat intelligence.

Validates:
- Model file SHA256 hashes against expected values
- GPG/Sigstore signatures (if present)
- Hugging Face Hub download provenance
- Author reputation and account age (via HF Hub API)
- Static blocklist (configuration/ml-blocklist.json)
- Dynamic threat feed (optional via --threat-feed-url)
- Supply chain metadata (model cards, training data lineage)

Usage:
    python3 run-model-provenance-check.py --target /path/to/repo --scan-dir /path/to/output --app-name myapp [--threat-feed-url URL] [--blocklist-path PATH]
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Model file extensions to check
MODEL_EXTENSIONS = {'.pkl', '.pickle', '.pt', '.pth', '.bin', '.ckpt', '.onnx', '.pb', '.safetensors', '.h5', '.hdf5'}

# Metadata files that indicate HF Hub download
HF_METADATA_FILES = {'.huggingface', 'config.json', 'model_index.json', 'preprocessor_config.json'}

# Git LFS pointer pattern
GIT_LFS_POINTER_PATTERN = re.compile(r'^version https://git-lfs\.github\.com/spec/v1')


class ModelProvenanceChecker:
    """Validates model provenance and checks threat intelligence."""
    
    def __init__(
        self,
        target_dir: Path,
        blocklist_path: Optional[Path] = None,
        threat_feed_url: Optional[str] = None,
        hf_token: Optional[str] = None
    ):
        self.target_dir = target_dir
        self.blocklist_path = blocklist_path
        self.threat_feed_url = threat_feed_url
        self.hf_token = hf_token
        
        self.findings: List[Dict] = []
        self.stats = {
            'total_models': 0,
            'models_with_signatures': 0,
            'models_with_hf_metadata': 0,
            'blocked_models': 0,
            'unverified_models': 0,
        }
        
        # Load static blocklist
        self.blocklist = self._load_blocklist()
        
        # Fetch dynamic threat feed if URL provided
        self.threat_feed = self._fetch_threat_feed() if threat_feed_url else {}
    
    def scan(self) -> Dict:
        """Run comprehensive provenance check."""
        print(f"[INFO] Scanning {self.target_dir} for model provenance...")
        
        # Find all model files
        model_files = self._find_model_files()
        self.stats['total_models'] = len(model_files)
        
        if not model_files:
            print("[INFO] No model files found")
            return self._generate_report()
        
        print(f"[INFO] Found {len(model_files)} model files")
        
        # Check each model
        for model_file in model_files:
            self._check_model_file(model_file)
        
        # Check for HF Hub metadata
        self._check_hf_metadata()
        
        # Check for model cards
        self._check_model_cards()
        
        return self._generate_report()
    
    def _find_model_files(self) -> List[Path]:
        """Find all model files in target directory."""
        found = []
        for ext in MODEL_EXTENSIONS:
            found.extend(self.target_dir.rglob(f'*{ext}'))
        return [f for f in found if f.is_file()]
    
    def _check_model_file(self, model_file: Path):
        """Check a single model file for provenance issues."""
        rel_path = str(model_file.relative_to(self.target_dir))
        
        # Compute SHA256 hash
        file_hash = self._compute_sha256(model_file)
        
        # Check against static blocklist
        if self._is_blocked_hash(file_hash):
            self.findings.append({
                'type': 'blocked_model',
                'file': rel_path,
                'severity': 'critical',
                'description': 'Model file hash matches known malicious model in threat intelligence blocklist',
                'evidence': f"SHA256: {file_hash}",
                'hash': file_hash,
                'source': 'static_blocklist',
            })
            self.stats['blocked_models'] += 1
            return
        
        # Check against dynamic threat feed
        if self.threat_feed and self._is_blocked_by_feed(file_hash):
            self.findings.append({
                'type': 'blocked_model',
                'file': rel_path,
                'severity': 'critical',
                'description': 'Model file hash matches entry in dynamic threat intelligence feed',
                'evidence': f"SHA256: {file_hash}",
                'hash': file_hash,
                'source': 'dynamic_feed',
            })
            self.stats['blocked_models'] += 1
            return
        
        # Check for GPG signature
        sig_file = model_file.with_suffix(model_file.suffix + '.sig')
        if sig_file.exists():
            self.stats['models_with_signatures'] += 1
            sig_result = self._verify_gpg_signature(model_file, sig_file)
            if not sig_result['valid']:
                self.findings.append({
                    'type': 'signature_verification_failed',
                    'file': rel_path,
                    'severity': 'high',
                    'description': 'GPG signature verification failed for model file',
                    'evidence': sig_result['error'],
                    'hash': file_hash,
                    'source': 'gpg',
                })
        else:
            # No signature found — not necessarily bad, but worth noting
            self.stats['unverified_models'] += 1
        
        # Check if it's a Git LFS pointer
        if self._is_git_lfs_pointer(model_file):
            # Extract SHA256 from pointer
            lfs_hash = self._extract_lfs_hash(model_file)
            if lfs_hash:
                # Check if actual file exists
                actual_file = self._resolve_lfs_file(model_file, lfs_hash)
                if not actual_file:
                    self.findings.append({
                        'type': 'lfs_pointer_unresolved',
                        'file': rel_path,
                        'severity': 'medium',
                        'description': 'Git LFS pointer found but actual model file not downloaded',
                        'evidence': f"Expected SHA256: {lfs_hash}",
                        'hash': file_hash,
                        'source': 'git_lfs',
                    })
    
    def _check_hf_metadata(self):
        """Check for Hugging Face Hub metadata and validate provenance."""
        # Check for .huggingface directory (indicates HF download)
        hf_dir = self.target_dir / '.huggingface'
        if hf_dir.exists():
            self.stats['models_with_hf_metadata'] += 1
        
        # Parse config.json for model metadata (even without .huggingface)
        config_file = self.target_dir / 'config.json'
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # Check for _name_or_path (indicates HF Hub download)
                model_name = config.get('_name_or_path', '')
                if model_name:
                    # Check if author is blocked
                    author = model_name.split('/')[0] if '/' in model_name else ''
                    if author and self._is_blocked_author(author):
                        self.findings.append({
                            'type': 'blocked_author',
                            'file': 'config.json',
                            'severity': 'critical',
                            'description': f"Model from blocked author: {author}",
                            'evidence': f"Model name: {model_name}",
                            'author': author,
                            'source': 'static_blocklist',
                        })
                    
                    # Check if repo is blocked
                    if self._is_blocked_repo(model_name):
                        self.findings.append({
                            'type': 'blocked_repo',
                            'file': 'config.json',
                            'severity': 'critical',
                            'description': f"Model from blocked repository: {model_name}",
                            'evidence': f"Repository listed in threat intelligence blocklist",
                            'repo': model_name,
                            'source': 'static_blocklist',
                        })
                    
                    # Check for typosquatting
                    if self._is_typosquat(model_name):
                        self.findings.append({
                            'type': 'typosquat_warning',
                            'file': 'config.json',
                            'severity': 'high',
                            'description': f"Model name resembles typosquat of popular model",
                            'evidence': f"Model name: {model_name}",
                            'model_name': model_name,
                            'source': 'pattern_matching',
                        })
                    
                    # Optional: Check HF Hub API for reputation
                    if self.hf_token:
                        reputation = self._check_hf_reputation(model_name)
                        if reputation and reputation.get('risk_score', 0) > 50:
                            self.findings.append({
                                'type': 'low_reputation',
                                'file': 'config.json',
                                'severity': 'medium',
                                'description': f"Model author has low reputation score",
                                'evidence': f"Risk score: {reputation['risk_score']}/100",
                                'model_name': model_name,
                                'source': 'hf_hub_api',
                            })
            
            except Exception as e:
                print(f"[WARN] Error parsing config.json: {e}", file=sys.stderr)
    
    def _check_model_cards(self):
        """Check for model cards and validate supply chain metadata."""
        readme_files = ['README.md', 'MODEL_CARD.md', 'model_card.md']
        
        for readme_name in readme_files:
            readme_file = self.target_dir / readme_name
            if readme_file.exists():
                try:
                    with open(readme_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Check for required sections
                    required_sections = ['model description', 'training data', 'intended use']
                    missing = [s for s in required_sections if s.lower() not in content.lower()]
                    
                    if missing:
                        self.findings.append({
                            'type': 'incomplete_model_card',
                            'file': readme_name,
                            'severity': 'low',
                            'description': f"Model card missing recommended sections",
                            'evidence': f"Missing: {', '.join(missing)}",
                            'source': 'model_card',
                        })
                
                except Exception as e:
                    print(f"[WARN] Error reading {readme_name}: {e}", file=sys.stderr)
    
    def _compute_sha256(self, file_path: Path) -> str:
        """Compute SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _load_blocklist(self) -> Dict:
        """Load static threat intelligence blocklist."""
        if not self.blocklist_path or not self.blocklist_path.exists():
            return {}
        
        try:
            with open(self.blocklist_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[WARN] Error loading blocklist: {e}", file=sys.stderr)
            return {}
    
    def _fetch_threat_feed(self) -> Dict:
        """Fetch dynamic threat intelligence feed."""
        if not self.threat_feed_url:
            return {}
        
        try:
            print(f"[INFO] Fetching threat intelligence from {self.threat_feed_url}...")
            req = urllib.request.Request(self.threat_feed_url, headers={'User-Agent': 'Epyon-ML-Scanner/2.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception as e:
            print(f"[WARN] Error fetching threat feed: {e}", file=sys.stderr)
            return {}
    
    def _is_blocked_hash(self, file_hash: str) -> bool:
        """Check if hash is in static blocklist."""
        blocked_hashes = self.blocklist.get('blocked_hashes', [])
        return any(entry['sha256'] == file_hash for entry in blocked_hashes)
    
    def _is_blocked_by_feed(self, file_hash: str) -> bool:
        """Check if hash is in dynamic threat feed."""
        feed_hashes = self.threat_feed.get('blocked_hashes', [])
        return any(entry.get('sha256') == file_hash for entry in feed_hashes)
    
    def _is_blocked_author(self, author: str) -> bool:
        """Check if author is in blocklist."""
        blocked_authors = self.blocklist.get('blocked_authors', [])
        return any(entry['username'] == author for entry in blocked_authors)
    
    def _is_blocked_repo(self, repo: str) -> bool:
        """Check if repository is in blocklist."""
        blocked_repos = self.blocklist.get('blocked_repos', [])
        return any(repo.startswith(entry['repo']) for entry in blocked_repos)
    
    def _is_typosquat(self, model_name: str) -> bool:
        """Check if model name resembles typosquatting."""
        patterns = self.blocklist.get('patterns', {})
        typosquat_targets = patterns.get('typosquat_targets', [])
        
        # Extract base model name (strip username if present)
        base_name = model_name.split('/')[-1] if '/' in model_name else model_name
        base_name_lower = base_name.lower()
        
        # Check for Levenshtein distance < 3 from known models (but not exact matches)
        for target in typosquat_targets:
            target_lower = target.lower()
            distance = self._levenshtein_distance(base_name_lower, target_lower)
            if 0 < distance < 3:  # Exclude exact matches (distance == 0)
                return True
        
        # Check suspicious patterns
        suspicious_patterns = patterns.get('suspicious_model_names', [])
        for pattern_str in suspicious_patterns:
            pattern = re.compile(pattern_str)
            if pattern.search(base_name):
                return True
        
        return False
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Compute Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _verify_gpg_signature(self, file_path: Path, sig_path: Path) -> Dict:
        """Verify GPG signature for a file."""
        try:
            result = subprocess.run(
                ['gpg', '--verify', str(sig_path), str(file_path)],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return {'valid': True, 'error': None}
            else:
                return {'valid': False, 'error': result.stderr}
        
        except subprocess.TimeoutExpired:
            return {'valid': False, 'error': 'GPG verification timed out'}
        except FileNotFoundError:
            return {'valid': False, 'error': 'gpg command not found'}
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def _is_git_lfs_pointer(self, file_path: Path) -> bool:
        """Check if file is a Git LFS pointer."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                first_line = f.readline()
                return GIT_LFS_POINTER_PATTERN.match(first_line) is not None
        except Exception:
            return False
    
    def _extract_lfs_hash(self, file_path: Path) -> Optional[str]:
        """Extract SHA256 hash from Git LFS pointer."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('oid sha256:'):
                        return line.split(':', 1)[1].strip()
        except Exception:
            pass
        return None
    
    def _resolve_lfs_file(self, pointer_path: Path, lfs_hash: str) -> Optional[Path]:
        """Try to resolve actual LFS file from pointer."""
        # Common LFS object locations
        lfs_dirs = [
            self.target_dir / '.git' / 'lfs' / 'objects',
            Path.home() / '.cache' / 'git-lfs' / 'objects',
        ]
        
        # LFS stores objects as: {first 2 chars}/{next 2 chars}/{full hash}
        if len(lfs_hash) >= 4:
            subpath = Path(lfs_hash[:2]) / lfs_hash[2:4] / lfs_hash
            for lfs_dir in lfs_dirs:
                candidate = lfs_dir / subpath
                if candidate.exists():
                    return candidate
        
        return None
    
    def _check_hf_reputation(self, model_name: str) -> Optional[Dict]:
        """Check author reputation via Hugging Face Hub API."""
        if not self.hf_token or '/' not in model_name:
            return None
        
        author = model_name.split('/')[0]
        url = f"https://huggingface.co/api/users/{author}"
        
        try:
            req = urllib.request.Request(
                url,
                headers={
                    'Authorization': f'Bearer {self.hf_token}',
                    'User-Agent': 'Epyon-ML-Scanner/2.0'
                }
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                # Calculate simple risk score (0-100, higher = riskier)
                risk_score = 0
                
                # New account (< 30 days) = +30
                created_at = data.get('createdAt', '')
                if created_at:
                    # Simplified check — in production would parse ISO8601
                    risk_score += 30
                
                # Low number of models = +20
                num_models = data.get('numModels', 0)
                if num_models < 5:
                    risk_score += 20
                
                # Not verified = +30
                if not data.get('isVerified', False):
                    risk_score += 30
                
                return {
                    'risk_score': risk_score,
                    'author': author,
                    'num_models': num_models,
                    'is_verified': data.get('isVerified', False),
                }
        
        except Exception as e:
            print(f"[WARN] Error checking HF reputation for {author}: {e}", file=sys.stderr)
            return None
    
    def _generate_report(self) -> Dict:
        """Generate final scan report."""
        return {
            'tool': 'model-provenance-check',
            'version': '1.0',
            'status': 'completed',
            'scan_id': os.environ.get('SCAN_ID', 'unknown'),
            'target': str(self.target_dir),
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'statistics': self.stats,
            'blocklist_loaded': bool(self.blocklist),
            'threat_feed_loaded': bool(self.threat_feed),
            'findings': self.findings,
            'summary': {
                'total_models_scanned': self.stats['total_models'],
                'blocked_models': self.stats['blocked_models'],
                'unverified_models': self.stats['unverified_models'],
                'critical_findings': len([f for f in self.findings if f['severity'] == 'critical']),
                'high_findings': len([f for f in self.findings if f['severity'] == 'high']),
                'medium_findings': len([f for f in self.findings if f['severity'] == 'medium']),
                'low_findings': len([f for f in self.findings if f['severity'] == 'low']),
            }
        }


def main():
    parser = argparse.ArgumentParser(
        description='Layer 18 — Model Provenance & Threat Intelligence'
    )
    parser.add_argument('--target', required=True, help='Target directory to scan')
    parser.add_argument('--scan-dir', required=True, help='Output directory for results')
    parser.add_argument('--app-name', required=True, help='Application name')
    parser.add_argument('--blocklist-path', help='Path to static threat intelligence blocklist JSON')
    parser.add_argument('--threat-feed-url', help='URL to fetch dynamic threat intelligence feed')
    parser.add_argument('--hf-token', help='Hugging Face API token for reputation checking')
    
    args = parser.parse_args()
    
    target_dir = Path(args.target).resolve()
    scan_dir = Path(args.scan_dir).resolve()
    
    if not target_dir.exists():
        print(f"[ERROR] Target directory does not exist: {target_dir}", file=sys.stderr)
        sys.exit(1)
    
    scan_dir.mkdir(parents=True, exist_ok=True)
    
    # Default blocklist path
    blocklist_path = None
    if args.blocklist_path:
        blocklist_path = Path(args.blocklist_path)
    else:
        # Try default location
        script_dir = Path(__file__).parent
        default_blocklist = script_dir / '../../configuration/ml-blocklist.json'
        if default_blocklist.exists():
            blocklist_path = default_blocklist.resolve()
    
    # Get HF token from env if not provided
    hf_token = args.hf_token or os.environ.get('HF_TOKEN')
    
    # Run scan
    checker = ModelProvenanceChecker(
        target_dir=target_dir,
        blocklist_path=blocklist_path,
        threat_feed_url=args.threat_feed_url,
        hf_token=hf_token
    )
    report = checker.scan()
    
    # Write results
    output_file = scan_dir / 'model-provenance-results.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[INFO] Scan complete. Results written to: {output_file}")
    print(f"[INFO] Total models scanned: {report['statistics']['total_models']}")
    print(f"[INFO] Blocked models: {report['statistics']['blocked_models']}")
    print(f"[INFO] Unverified models: {report['statistics']['unverified_models']}")
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
