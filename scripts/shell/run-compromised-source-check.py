#!/usr/bin/env python3
"""
Layer 21 — Compromised Source / Supply Chain Incident Detection

Cross-references a target repository against a registry of disclosed
artifact-repository / package-registry compromises (configuration/compromised-sources.json)
and flags any reference to a known-compromised host, with a best-effort
confidence rating based on whether the reference was modified inside the
confirmed incident window.

Background: attackers who gain administrative access to an artifact
repository (e.g. via an authentication bypass) can read or replace stored
artifacts. A repository reference alone does not prove tampering — the
scope of most incidents remains under investigation — so findings are
rated by confidence rather than treated as confirmed compromises.

Scans:
- Package manager configs (.npmrc, pip.conf/pip.ini, Pipfile, requirements.txt,
  pom.xml, Maven settings.xml, Gradle build files, NuGet.config, go.mod, Cargo.toml)
- Container/orchestration manifests (Dockerfile, docker-compose, Helm Chart.yaml/values.yaml)
- CycloneDX/SPDX SBOM external references (if a Layer 1 SBOM is present in --scan-dir)

Usage:
    python3 run-compromised-source-check.py --target /path/to/repo --scan-dir /path/to/output \
        --app-name myapp [--registry-path PATH]
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Config/manifest filenames worth inspecting for registry/repository references.
MANIFEST_FILENAMES = {
    '.npmrc', '.yarnrc', 'pip.conf', 'pip.ini', 'Pipfile', 'requirements.txt',
    'pom.xml', 'settings.xml', 'build.gradle', 'build.gradle.kts', 'NuGet.config',
    'go.mod', 'Cargo.toml', '.netrc', 'Chart.yaml', 'values.yaml',
}
MANIFEST_GLOBS = ('Dockerfile*', 'docker-compose*.yml', 'docker-compose*.yaml')

# SBOM file locations produced by Layer 1 (Syft), relative to --scan-dir.
SBOM_RELATIVE_PATHS = ('sbom',)


class CompromisedSourceChecker:
    """Scans a target repository for references to known-compromised artifact hosts."""

    def __init__(self, target_dir: Path, scan_dir: Path, registry_path: Optional[Path] = None):
        self.target_dir = target_dir
        self.scan_dir = scan_dir
        self.findings: List[Dict] = []
        self.exclude_patterns = self._load_exclude_patterns()
        self.stats = {
            'incidents_loaded': 0,
            'files_scanned': 0,
            'matches_found': 0,
            'high_confidence': 0,
            'medium_confidence': 0,
            'low_confidence': 0,
        }
        self.registry = self._load_registry(registry_path)
        self._is_git_repo = (self.target_dir / '.git').exists()

    # ── Config loading ──────────────────────────────────────────────────
    def _load_registry(self, registry_path: Optional[Path]) -> List[Dict]:
        if not registry_path or not registry_path.exists():
            print(f"[WARN] Compromised-source registry not found: {registry_path}", file=sys.stderr)
            return []
        try:
            with open(registry_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"[WARN] Failed to parse compromised-source registry: {e}", file=sys.stderr)
            return []
        incidents = [i for i in data.get('incidents', []) if i.get('status', 'open') != 'closed']
        self.stats['incidents_loaded'] = len(incidents)
        return incidents

    def _load_exclude_patterns(self) -> List[str]:
        """Load non-expired `type: path` glob rules from the target's
        .epyon-ignore.yml so a normal scan never flags deliberately-suppressed
        content (mirrors Layer 18's model-provenance convention)."""
        ignore_file = self.target_dir / '.epyon-ignore.yml'
        if not ignore_file.exists():
            return []
        try:
            import yaml
        except ImportError:
            return []
        try:
            with open(ignore_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            return []
        now = datetime.now()
        patterns = []
        for ig in data.get('ignores', []) or []:
            if ig.get('type') != 'path':
                continue
            expires = ig.get('expires')
            if expires:
                try:
                    if now > datetime.strptime(expires, '%Y-%m-%d'):
                        continue
                except Exception:
                    pass
            value = ig.get('value')
            if value:
                patterns.append(value)
        return patterns

    def _is_excluded(self, file_path: Path) -> bool:
        if not self.exclude_patterns:
            return False
        try:
            rel = file_path.relative_to(self.target_dir).as_posix()
        except ValueError:
            return False
        import fnmatch
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, pattern.rstrip('/*') + '/*'):
                return True
        return False

    # ── Scan ─────────────────────────────────────────────────────────────
    def scan(self) -> Dict:
        print(f"[INFO] Scanning {self.target_dir} for references to compromised artifact sources...")

        if not self.registry:
            print("[INFO] No compromised-source incidents loaded; nothing to check")
            return self._generate_report()

        for manifest_file in self._find_manifest_files():
            self._check_manifest_file(manifest_file)

        self._check_sboms()

        return self._generate_report()

    def _find_manifest_files(self) -> List[Path]:
        found: List[Path] = []
        for name in MANIFEST_FILENAMES:
            found.extend(self.target_dir.rglob(name))
        for pattern in MANIFEST_GLOBS:
            found.extend(self.target_dir.rglob(pattern))
        unique = sorted(set(f for f in found if f.is_file() and not self._is_excluded(f)))
        return unique

    def _all_hosts(self, incident: Dict) -> List[str]:
        hosts = [incident.get('host', '')]
        hosts.extend(incident.get('additional_hosts', []) or [])
        return [h for h in hosts if h]

    def _check_manifest_file(self, manifest_file: Path):
        rel_path = str(manifest_file.relative_to(self.target_dir))
        try:
            with open(manifest_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"[WARN] Could not read {rel_path}: {e}", file=sys.stderr)
            return
        self.stats['files_scanned'] += 1

        last_modified = self._git_last_modified(manifest_file)

        for incident in self.registry:
            for host in self._all_hosts(incident):
                host_lower = host.lower()
                for line_no, line in enumerate(lines, start=1):
                    if host_lower in line.lower():
                        self._record_match(
                            rel_path=rel_path, line_no=line_no, line=line.strip(),
                            host=host, incident=incident, last_modified=last_modified,
                        )

    def _git_last_modified(self, file_path: Path) -> Optional[str]:
        """Best-effort: last commit date (ISO8601) that touched this file."""
        if not self._is_git_repo:
            return None
        try:
            rel = file_path.relative_to(self.target_dir).as_posix()
            result = subprocess.run(
                ['git', '-C', str(self.target_dir), 'log', '-1', '--format=%cI', '--', rel],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout.strip()
            return output or None
        except Exception:
            return None

    def _confidence_for(self, incident: Dict, last_modified: Optional[str]) -> str:
        window_start = incident.get('window_start')
        window_end = incident.get('window_end')
        if not last_modified or not window_start or not window_end:
            return 'medium'
        try:
            modified_date = last_modified[:10]
            if window_start <= modified_date <= window_end:
                return 'high'
            return 'low'
        except Exception:
            return 'medium'

    def _record_match(self, rel_path: str, line_no: int, line: str, host: str,
                       incident: Dict, last_modified: Optional[str]):
        confidence = self._confidence_for(incident, last_modified)
        base_severity = incident.get('severity', 'medium')
        # Downgrade severity one notch when confidence is low (reference present
        # but outside the confirmed window / timing unknown).
        severity = base_severity if confidence in ('high', 'medium') else _downgrade(base_severity)

        evidence = line[:200]
        self.findings.append({
            'type': 'compromised_source_reference',
            'file': rel_path,
            'line': line_no,
            'host': host,
            'incident_id': incident.get('id'),
            'cve': incident.get('cve'),
            'severity': severity,
            'confidence': confidence,
            'description': (
                f"Reference to known-compromised artifact source '{host}' "
                f"({incident.get('cve', 'no CVE assigned')})"
            ),
            'evidence': evidence,
            'last_modified': last_modified,
            'window_start': incident.get('window_start'),
            'window_end': incident.get('window_end'),
            'advisory_url': incident.get('advisory_url'),
            'attack_path': incident.get('attack_path'),
            'controls': incident.get('controls', []),
            'remediation': incident.get('remediation', []),
            'source': 'manifest_scan',
        })
        self.stats['matches_found'] += 1
        self.stats[f'{confidence}_confidence'] += 1

    # ── SBOM cross-reference ─────────────────────────────────────────────
    def _check_sboms(self):
        for rel in SBOM_RELATIVE_PATHS:
            sbom_dir = self.scan_dir / rel
            if not sbom_dir.is_dir():
                continue
            for sbom_file in sbom_dir.glob('*.json'):
                self._check_sbom_file(sbom_file)

    def _check_sbom_file(self, sbom_file: Path):
        try:
            with open(sbom_file, 'r', encoding='utf-8') as f:
                sbom = json.load(f)
        except Exception:
            return

        try:
            sbom_rel_file = str(sbom_file.relative_to(self.scan_dir))
        except ValueError:
            sbom_rel_file = sbom_file.name

        text_blob = json.dumps(sbom)
        for incident in self.registry:
            for host in self._all_hosts(incident):
                if host.lower() in text_blob.lower():
                    self.findings.append({
                        'type': 'compromised_source_sbom_reference',
                        'file': sbom_rel_file,
                        'line': None,
                        'host': host,
                        'incident_id': incident.get('id'),
                        'cve': incident.get('cve'),
                        'severity': incident.get('severity', 'medium'),
                        'confidence': 'medium',
                        'description': (
                            f"SBOM contains a component or external reference pointing to "
                            f"known-compromised artifact source '{host}' ({incident.get('cve', 'no CVE assigned')})"
                        ),
                        'evidence': f"Matched in {sbom_file.name}",
                        'last_modified': None,
                        'window_start': incident.get('window_start'),
                        'window_end': incident.get('window_end'),
                        'advisory_url': incident.get('advisory_url'),
                        'attack_path': incident.get('attack_path'),
                        'controls': incident.get('controls', []),
                        'remediation': incident.get('remediation', []),
                        'source': 'sbom_scan',
                    })
                    self.stats['matches_found'] += 1
                    self.stats['medium_confidence'] += 1

    # ── Report ───────────────────────────────────────────────────────────
    def _generate_report(self) -> Dict:
        return {
            'tool': 'compromised-source-check',
            'version': '1.0',
            'status': 'completed',
            'scan_id': os.environ.get('SCAN_ID', 'unknown'),
            'target': str(self.target_dir),
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'statistics': self.stats,
            'registry_loaded': bool(self.registry),
            'findings': self.findings,
            'summary': {
                'critical_findings': len([f for f in self.findings if f['severity'] == 'critical']),
                'high_findings': len([f for f in self.findings if f['severity'] == 'high']),
                'medium_findings': len([f for f in self.findings if f['severity'] == 'medium']),
                'low_findings': len([f for f in self.findings if f['severity'] == 'low']),
            },
        }


def _downgrade(severity: str) -> str:
    order = ['critical', 'high', 'medium', 'low']
    try:
        idx = order.index(severity)
    except ValueError:
        return severity
    return order[min(idx + 1, len(order) - 1)]


def main():
    parser = argparse.ArgumentParser(
        description='Layer 21 — Compromised Source / Supply Chain Incident Detection'
    )
    parser.add_argument('--target', required=True, help='Target directory to scan')
    parser.add_argument('--scan-dir', required=True, help='Output directory for results')
    parser.add_argument('--app-name', required=True, help='Application name')
    parser.add_argument('--registry-path', help='Path to compromised-sources.json registry')

    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    scan_dir = Path(args.scan_dir).resolve()

    if not target_dir.exists():
        print(f"[ERROR] Target directory does not exist: {target_dir}", file=sys.stderr)
        sys.exit(1)

    scan_dir.mkdir(parents=True, exist_ok=True)

    registry_path = None
    if args.registry_path:
        registry_path = Path(args.registry_path)
    else:
        script_dir = Path(__file__).parent
        default_registry = script_dir / '../../configuration/compromised-sources.json'
        if default_registry.exists():
            registry_path = default_registry.resolve()

    checker = CompromisedSourceChecker(
        target_dir=target_dir, scan_dir=scan_dir, registry_path=registry_path,
    )
    report = checker.scan()

    output_file = scan_dir / 'compromised-source-results.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print(f"\n[INFO] Scan complete. Results written to: {output_file}")
    print(f"[INFO] Incidents loaded: {report['statistics']['incidents_loaded']}")
    print(f"[INFO] Files scanned: {report['statistics']['files_scanned']}")
    print(f"[INFO] Matches found: {report['statistics']['matches_found']}")
    print(f"[INFO] Critical findings: {report['summary']['critical_findings']}")
    print(f"[INFO] High findings: {report['summary']['high_findings']}")

    if report['summary']['critical_findings'] > 0 or report['summary']['high_findings'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
