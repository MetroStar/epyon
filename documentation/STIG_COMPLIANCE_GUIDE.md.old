# STIG Compliance Guide for Epyon

**Document Version**: 1.0  
**Last Updated**: February 6, 2026  
**Status**: Active

## Overview

This guide maps Epyon's security scanning capabilities to Security Technical Implementation Guide (STIG) controls. While Epyon does not provide automated STIG checklist generation (planned for future releases), it can provide critical evidence and validation for many STIG requirements.

## Important Notes

⚠️ **Limitations:**
- Epyon provides **evidence collection** and **technical validation**, not complete STIG compliance
- Manual review and documentation are still required for many controls
- STIG compliance requires organizational processes beyond technical scanning
- This guide covers common STIGs; specific applications may have additional requirements

✅ **Best Use:**
- Evidence collection for STIG control validation
- Continuous monitoring for security drift
- Technical validation before submission to security teams
- Automated security baseline enforcement

---

## STIG Control Mapping by Category

### 1. Application Security Development STIG (V5R3)

#### APSC-DV-000160: The application must protect the confidentiality and integrity of transmitted information.

**Epyon Tools:**
- **Checkov** - Validates TLS/SSL configurations in IaC
- **Trivy** - Scans for weak crypto libraries and configurations
- **TruffleHog** - Detects exposed certificates/keys

**Evidence Collection:**
```bash
# Run full scan
./scripts/shell/run-target-security-scan.sh "/path/to/app" full

# Check specific findings
grep -r "TLS\|SSL\|crypto" scans/*/checkov/
grep -r "certificate\|private.*key" scans/*/trufflehog/
```

**Report Location:**
- `scans/{scan_id}/checkov/checkov-results.json` - Look for TLS/SSL misconfigurations
- `scans/{scan_id}/trivy/trivy-results.json` - Search for crypto vulnerabilities
- `scans/{scan_id}/trufflehog/trufflehog-results.json` - Check for exposed credentials

---

#### APSC-DV-000500: The application must prevent non-privileged users from executing privileged functions.

**Epyon Tools:**
- **Checkov** - Validates RBAC configurations, privilege escalation
- **Trivy** - Scans for containers running as root
- **SonarQube** - Code analysis for authorization checks

**Evidence Collection:**
```bash
# Check for privilege escalation issues
grep -i "privilege\|root\|sudo\|setuid" scans/*/checkov/checkov-results.json
grep -i "USER root\|privileged" scans/*/trivy/trivy-results.json

# Review SonarQube security hotspots
cat scans/*/sonar/sonar-results.json | jq '.issues[] | select(.type=="SECURITY_HOTSPOT")'
```

**Dashboard View:**
- Open interactive dashboard: `./scripts/shell/open-latest-dashboard.sh`
- Filter by "High" severity → Look for privilege escalation findings

---

#### APSC-DV-000590: The application must not be vulnerable to SQL Injection.

**Epyon Tools:**
- **SonarQube** - SQL injection detection via code analysis
- **Checkov** - Database security configurations

**Evidence Collection:**
```bash
# Run SonarQube analysis
./scripts/shell/run-sonar-analysis.sh

# Search for SQL injection vulnerabilities
cat scans/*/sonar/sonar-results.json | jq '.issues[] | select(.rule | contains("sql"))'
```

**Manual Validation Required:**
- Dynamic testing with OWASP ZAP (not included in Epyon)
- Penetration testing results
- Code review of database queries

---

#### APSC-DV-001620: The application must not be subject to input handling vulnerabilities.

**Epyon Tools:**
- **SonarQube** - Input validation analysis
- **Grype/Trivy** - Known vulnerabilities in parsing libraries

**Evidence Collection:**
```bash
# Check for input handling issues in code
cat scans/*/sonar/sonar-results.json | jq '.issues[] | select(.rule | contains("input\|validation\|sanitiz"))'

# Check for vulnerable parsing libraries
cat scans/*/grype/grype-results.json | jq '.matches[] | select(.vulnerability.description | contains("input\|parse\|deserializ"))'
```

---

#### APSC-DV-002440: The application must protect the confidentiality and integrity of stored information.

**Epyon Tools:**
- **TruffleHog** - Detects secrets in code/configs
- **Checkov** - Validates encryption at rest configurations
- **ClamAV** - Malware detection that could compromise data

**Evidence Collection:**
```bash
# Check for exposed secrets
./scripts/shell/export-api-discovery.sh "scans/latest" json
cat scans/*/trufflehog/trufflehog-results.json | jq '.results[] | select(.verified==true)'

# Validate encryption configurations
grep -i "encrypt\|kms\|vault" scans/*/checkov/checkov-results.json
```

---

#### APSC-DV-002560: The application must protect audit information from unauthorized modification.

**Epyon Tools:**
- **Checkov** - Log storage and retention configurations
- **Trivy** - Container image file permissions

**Evidence Collection:**
```bash
# Check logging configurations
grep -i "log\|audit\|cloudwatch\|splunk" scans/*/checkov/checkov-results.json

# Verify file permissions in containers
grep -i "permission\|chmod\|chown" scans/*/trivy/trivy-results.json
```

---

#### APSC-DV-003235: The application must not be vulnerable to race conditions.

**Epyon Tools:**
- **SonarQube** - Concurrency bug detection
- **Code Coverage Analysis** - Identifies untested concurrent code

**Evidence Collection:**
```bash
# Search for concurrency issues
cat scans/*/sonar/sonar-results.json | jq '.issues[] | select(.rule | contains("concurrent\|thread\|race\|synchroniz"))'
```

**Manual Validation Required:**
- Stress testing and load testing results
- Concurrency testing documentation

---

### 2. Container Platform STIG (V2R1)

#### CNTR-K8-000150: The Kubernetes API server must have anonymous authentication disabled.

**Epyon Tools:**
- **Checkov** - Kubernetes security policy validation
- **Trivy** - Kubernetes manifest scanning

**Evidence Collection:**
```bash
# Check Kubernetes configurations
grep -i "anonymous\|authentication" scans/*/checkov/checkov-results.json
grep -i "anonymous" scans/*/trivy/trivy-results.json

# Review Helm chart security
cat scans/*/helm/helm-lint-results.txt
```

---

#### CNTR-K8-000380: Kubernetes Kubelet must deny hostname override.

**Epyon Tools:**
- **Checkov** - Kubelet configuration validation
- **Helm** - Chart security validation

**Evidence Collection:**
```bash
# Scan Helm charts and manifests
./scripts/shell/run-checkov-scan.sh filesystem

# Check for kubelet misconfigurations
grep -i "kubelet\|hostname-override" scans/*/checkov/checkov-results.json
```

---

#### CNTR-K8-001360: Kubernetes must separate user functionality.

**Epyon Tools:**
- **Checkov** - RBAC and namespace policies
- **Trivy** - Security context validation

**Evidence Collection:**
```bash
# Validate RBAC configurations
grep -i "rbac\|role\|namespace\|securitycontext" scans/*/checkov/checkov-results.json

# Check container security contexts
grep -i "securityContext\|runAsUser\|capabilities" scans/*/trivy/trivy-results.json
```

---

#### CNTR-K8-002010: Kubernetes must have a pod security policy set.

**Epyon Tools:**
- **Checkov** - Pod Security Policy validation
- **Trivy** - Pod security standards compliance

**Evidence Collection:**
```bash
# Check for PSP/PSS configurations
grep -i "podsecuritypolicy\|podsecurity\|psp\|pss" scans/*/checkov/checkov-results.json

# Review security dashboard for pod security issues
./scripts/shell/generate-security-dashboard.sh
```

---

### 3. Docker Enterprise STIG (V2R2)

#### DKER-EE-001010: All Docker Enterprise components must be compatible with Docker Enterprise.

**Epyon Tools:**
- **Trivy** - Image vulnerability scanning with version detection
- **SBOM** - Component inventory and version tracking

**Evidence Collection:**
```bash
# Generate SBOM for version tracking
./scripts/shell/run-sbom-scan.sh

# Export SBOM for compliance documentation
./scripts/shell/export-sbom.sh "scans/latest" json

# Review component versions
cat scans/*/sbom/sbom.json | jq '.components[] | {name, version}'
```

---

#### DKER-EE-002000: Only trusted container images must be used.

**Epyon Tools:**
- **Baseline Scanning** - DHI approved image validation
- **Trivy** - Image provenance and signature validation
- **Configuration** - Approved base images list

**Evidence Collection:**
```bash
# Run baseline scan against DHI images
./scripts/shell/run-baseline-scan.sh

# Compare against approved base images
cat configuration/approved-base-images.conf

# Generate comparison report
cat scans/*/baseline-comparison.json
```

---

#### DKER-EE-002140: Docker Enterprise images must be scanned for vulnerabilities.

**Epyon Tools:**
- **Grype** - Comprehensive vulnerability scanning
- **Trivy** - Container image CVE detection
- **Xeol** - End-of-life software detection

**Evidence Collection:**
```bash
# Full image security scan
./scripts/shell/run-target-security-scan.sh "/path/to/app" images

# Export vulnerability reports
cat scans/*/grype/grype-results.json | jq '.matches[] | {vulnerability: .vulnerability.id, severity: .vulnerability.severity}'
cat scans/*/trivy/trivy-results.json | jq '.Results[] | .Vulnerabilities[]?'

# Check for EOL software
cat scans/*/xeol/xeol-results.json
```

---

#### DKER-EE-005170: Secrets must not be stored in Docker Enterprise images.

**Epyon Tools:**
- **TruffleHog** - Secret detection in images and code
- **Checkov** - Secret management configuration validation

**Evidence Collection:**
```bash
# Scan for secrets
./scripts/shell/run-trufflehog-scan.sh filesystem

# Export secrets report
cat scans/*/trufflehog/trufflehog-results.json | jq '.results[] | select(.verified==true)'

# Check dashboard for secret findings
./scripts/shell/open-latest-dashboard.sh
# → Filter by "TruffleHog" in interactive dashboard
```

---

### 4. Application Security and Development STIG - DevSecOps (V2R1)

#### ASDV-DV-000010: The DevSecOps platform must scan all application code for security vulnerabilities.

**Epyon Tools:**
- **All 10 Security Layers** - Comprehensive scanning
- **Automated Orchestration** - Full pipeline execution

**Evidence Collection:**
```bash
# Run complete security scan
./scripts/shell/run-target-security-scan.sh "/path/to/app" full

# Generate consolidated dashboard
./scripts/shell/generate-security-dashboard.sh

# Export all results
./scripts/shell/export-api-discovery.sh "scans/latest" json
./scripts/shell/export-sbom.sh "scans/latest" json
```

**Dashboard Evidence:**
- Interactive dashboard shows all 10 layers: `./scripts/shell/open-latest-dashboard.sh`
- Consolidated JSON: `scans/{scan_id}/consolidated-reports/consolidated-security-report.json`

---

#### ASDV-DV-000030: The DevSecOps platform must scan all application dependencies for security vulnerabilities.

**Epyon Tools:**
- **Grype** - Dependency vulnerability scanning with SBOM
- **Trivy** - Package vulnerability detection
- **SBOM Generation** - Complete dependency inventory

**Evidence Collection:**
```bash
# Generate SBOM
./scripts/shell/run-sbom-scan.sh

# Scan dependencies
./scripts/shell/run-grype-scan.sh filesystem
./scripts/shell/run-trivy-scan.sh filesystem

# Export dependency report
./scripts/shell/export-sbom.sh "scans/latest" json
cat scans/*/sbom/sbom.json | jq '.components[] | select(.type=="library")'
```

---

#### ASDV-DV-000070: The DevSecOps platform must identify end-of-life software.

**Epyon Tools:**
- **Xeol** - EOL software detection
- **SBOM Analysis** - Version tracking

**Evidence Collection:**
```bash
# Run EOL detection
./scripts/shell/run-xeol-scan.sh filesystem

# Review EOL findings
cat scans/*/xeol/xeol-results.json | jq '.matches[] | {name: .artifact.name, version: .artifact.version, eolDate: .cycle.eolDate}'

# Check baseline for EOL software
./scripts/shell/run-baseline-scan.sh
```

---

#### ASDV-DV-000100: The DevSecOps platform must scan container images for security vulnerabilities.

**Epyon Tools:**
- **Trivy** - Multi-layer container scanning
- **Grype** - Container image CVE detection
- **Baseline Scanning** - DHI image comparison

**Evidence Collection:**
```bash
# Image-focused scan
./scripts/shell/run-target-security-scan.sh "/path/to/app" images

# Baseline comparison
./scripts/shell/run-baseline-scan.sh

# Review image scan results
cat scans/*/trivy/trivy-results.json | jq '.Results[] | select(.Type=="container")'
```

---

#### ASDV-DV-000220: The DevSecOps platform must scan for malware.

**Epyon Tools:**
- **ClamAV** - Antivirus and malware detection

**Evidence Collection:**
```bash
# Run malware scan
./scripts/shell/run-clamav-scan.sh

# Review clean status
cat scans/*/clamav/clamav-scan.log
grep "Infected files: 0" scans/*/clamav/clamav-scan.log
```

---

#### ASDV-DV-000320: The DevSecOps platform must enforce severity-based quality gates.

**Epyon Tools:**
- **Severity Gate Checker** - Automated quality gate enforcement
- **Dashboard** - Severity-based filtering and reporting

**Evidence Collection:**
```bash
# Check severity gate
./scripts/shell/check-severity-gate.sh "scans/latest"

# Configure thresholds (example)
CRITICAL_THRESHOLD=0 HIGH_THRESHOLD=5 ./scripts/shell/check-severity-gate.sh "scans/latest"

# Review severity breakdown in dashboard
./scripts/shell/open-latest-dashboard.sh
```

---

#### ASDV-DV-000500: The DevSecOps platform must provide automated remediation recommendations.

**Epyon Tools:**
- **Remediation Suggestions** - Automated fix recommendations

**Evidence Collection:**
```bash
# Generate remediation suggestions
./scripts/shell/generate-remediation-suggestions.sh

# Review recommendations
cat scans/*/consolidated-reports/remediation-suggestions.json
cat scans/*/consolidated-reports/remediation-suggestions.md
```

---

### 5. Red Hat OpenShift STIG (V2R1)

#### CNTR-OS-000010: OpenShift must use TLS 1.2 or greater for secure communication.

**Epyon Tools:**
- **Checkov** - TLS configuration validation
- **Trivy** - Weak crypto library detection

**Evidence Collection:**
```bash
# Check TLS configurations
grep -i "tls\|ssl\|cipher" scans/*/checkov/checkov-results.json

# Verify no weak crypto
cat scans/*/trivy/trivy-results.json | jq '.Results[] | .Vulnerabilities[]? | select(.Title | contains("TLS\|SSL\|crypto"))'
```

---

#### CNTR-OS-000390: OpenShift must prohibit the use of cached authenticators.

**Epyon Tools:**
- **Checkov** - Authentication configuration validation
- **TruffleHog** - Cached credential detection

**Evidence Collection:**
```bash
# Check authentication configurations
grep -i "auth\|cache\|token" scans/*/checkov/checkov-results.json

# Scan for cached credentials
cat scans/*/trufflehog/trufflehog-results.json | jq '.results[] | select(.raw | contains("token\|cache"))'
```

---

## Compliance Workflow

### Step 1: Run Full Security Scan

```bash
# Execute comprehensive scan
./scripts/shell/run-target-security-scan.sh "/path/to/application" full

# Include baseline validation for approved images
./scripts/shell/run-baseline-scan.sh
```

### Step 2: Generate Reports

```bash
# Create interactive dashboard
./scripts/shell/generate-security-dashboard.sh

# Generate remediation guidance
./scripts/shell/generate-remediation-suggestions.sh

# Export structured data
./scripts/shell/export-api-discovery.sh "scans/latest" json
./scripts/shell/export-sbom.sh "scans/latest" json
```

### Step 3: Review Findings by STIG Category

```bash
# Open interactive dashboard
./scripts/shell/open-latest-dashboard.sh

# Filter by:
# - Severity (Critical, High, Medium, Low)
# - Tool (Trivy, Grype, Checkov, etc.)
# - Category (Infrastructure, Vulnerabilities, Secrets, etc.)
```

### Step 4: Document Evidence

**Key Files for STIG Documentation:**

```
scans/{scan_id}/
├── consolidated-reports/
│   ├── consolidated-security-report.json    # Master report
│   ├── dashboards/security-dashboard.html   # Visual evidence
│   └── remediation-suggestions.md           # Fix guidance
├── trivy/trivy-results.json                 # Container security
├── grype/grype-results.json                 # Vulnerability scanning
├── checkov/checkov-results.json             # IaC security
├── trufflehog/trufflehog-results.json       # Secret detection
├── clamav/clamav-scan.log                   # Malware scan
├── xeol/xeol-results.json                   # EOL software
├── sbom/sbom.json                           # Component inventory
└── baseline-comparison.json                 # Approved image validation
```

### Step 5: Address Findings

```bash
# Generate fix recommendations
cat scans/*/consolidated-reports/remediation-suggestions.json | jq '.vulnerabilities[] | select(.severity=="CRITICAL")'

# Check severity gate compliance
./scripts/shell/check-severity-gate.sh "scans/latest"

# Re-scan after remediation
./scripts/shell/run-target-security-scan.sh "/path/to/application" full
```

---

## STIG Evidence Matrix

| STIG Control | Category | Epyon Tool(s) | Evidence Location | Automated/Manual |
|--------------|----------|---------------|-------------------|------------------|
| APSC-DV-000160 | TLS/Crypto | Checkov, Trivy, TruffleHog | checkov/, trivy/, trufflehog/ | Automated |
| APSC-DV-000500 | Privilege Escalation | Checkov, Trivy, SonarQube | checkov/, trivy/, sonar/ | Automated |
| APSC-DV-000590 | SQL Injection | SonarQube | sonar/ | Partial (code only) |
| APSC-DV-001620 | Input Validation | SonarQube, Grype | sonar/, grype/ | Automated |
| APSC-DV-002440 | Data Protection | TruffleHog, Checkov, ClamAV | trufflehog/, checkov/, clamav/ | Automated |
| APSC-DV-002560 | Audit Protection | Checkov, Trivy | checkov/, trivy/ | Automated |
| APSC-DV-003235 | Race Conditions | SonarQube | sonar/ | Manual review required |
| CNTR-K8-000150 | K8s Auth | Checkov, Trivy | checkov/, trivy/ | Automated |
| CNTR-K8-000380 | Kubelet Config | Checkov, Helm | checkov/, helm/ | Automated |
| CNTR-K8-001360 | User Separation | Checkov, Trivy | checkov/, trivy/ | Automated |
| CNTR-K8-002010 | Pod Security | Checkov, Trivy | checkov/, trivy/ | Automated |
| DKER-EE-001010 | Component Versions | Trivy, SBOM | trivy/, sbom/ | Automated |
| DKER-EE-002000 | Trusted Images | Baseline Scan, Trivy | baseline/, trivy/ | Automated |
| DKER-EE-002140 | Image Scanning | Grype, Trivy, Xeol | grype/, trivy/, xeol/ | Automated |
| DKER-EE-005170 | Secrets in Images | TruffleHog | trufflehog/ | Automated |
| ASDV-DV-000010 | Code Scanning | All Layers | consolidated-reports/ | Automated |
| ASDV-DV-000030 | Dependency Scanning | Grype, Trivy, SBOM | grype/, trivy/, sbom/ | Automated |
| ASDV-DV-000070 | EOL Detection | Xeol, SBOM | xeol/, sbom/ | Automated |
| ASDV-DV-000100 | Container Scanning | Trivy, Grype, Baseline | trivy/, grype/, baseline/ | Automated |
| ASDV-DV-000220 | Malware Scanning | ClamAV | clamav/ | Automated |
| ASDV-DV-000320 | Quality Gates | Severity Gate Checker | consolidated-reports/ | Automated |
| ASDV-DV-000500 | Remediation | Remediation Suggestions | remediation-suggestions.json | Automated |
| CNTR-OS-000010 | TLS Config | Checkov, Trivy | checkov/, trivy/ | Automated |
| CNTR-OS-000390 | Cached Auth | Checkov, TruffleHog | checkov/, trufflehog/ | Automated |

---

## Query Examples for Common STIG Requirements

### Find All Critical Vulnerabilities (ASDV-DV-000320)

```bash
# Critical findings across all tools
cat scans/*/consolidated-reports/consolidated-security-report.json | \
  jq '.findings[] | select(.severity=="CRITICAL")'

# Critical CVEs only
cat scans/*/grype/grype-results.json | \
  jq '.matches[] | select(.vulnerability.severity=="Critical")'
```

### Verify No Secrets in Code (DKER-EE-005170)

```bash
# Verified secrets (confirmed true positives)
cat scans/*/trufflehog/trufflehog-results.json | \
  jq '.results[] | select(.verified==true)'

# All secret detections
cat scans/*/trufflehog/trufflehog-results.json | \
  jq '.results[] | {detector: .detector_name, verified: .verified, file: .source_metadata.filename}'
```

### Check Infrastructure Security (CNTR-K8-001360)

```bash
# Checkov security findings
cat scans/*/checkov/checkov-results.json | \
  jq '.results.failed_checks[] | {check_id: .check_id, check_name: .check_name, severity: .severity}'

# Kubernetes-specific issues
grep -i "kubernetes\|k8s\|pod\|deployment" scans/*/checkov/checkov-results.json
```

### Validate Dependency Security (ASDV-DV-000030)

```bash
# All vulnerable dependencies
cat scans/*/grype/grype-results.json | \
  jq '.matches[] | {package: .artifact.name, version: .artifact.version, vulnerability: .vulnerability.id, severity: .vulnerability.severity}'

# Group by severity
cat scans/*/grype/grype-results.json | \
  jq '[.matches[] | .vulnerability.severity] | group_by(.) | map({severity: .[0], count: length})'
```

### Check for EOL Software (ASDV-DV-000070)

```bash
# All EOL components
cat scans/*/xeol/xeol-results.json | \
  jq '.matches[] | {name: .artifact.name, version: .artifact.version, eol_date: .cycle.eolDate}'

# Already EOL (past end date)
cat scans/*/xeol/xeol-results.json | \
  jq --arg today "$(date +%Y-%m-%d)" '.matches[] | select(.cycle.eolDate < $today)'
```

### Verify Clean Malware Scan (ASDV-DV-000220)

```bash
# Check for infections
grep "Infected files:" scans/*/clamav/clamav-scan.log

# Verify clean status (should return 0)
grep -c "Infected files: 0" scans/*/clamav/clamav-scan.log
```

---

## Automated Evidence Collection Script

Save this as `scripts/shell/collect-stig-evidence.sh`:

```bash
#!/bin/bash
# Collect STIG Evidence from Latest Scan

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCANS_DIR="$PROJECT_ROOT/scans"

# Find latest scan
LATEST_SCAN=$(ls -t "$SCANS_DIR" | head -1)
SCAN_DIR="$SCANS_DIR/$LATEST_SCAN"
OUTPUT_DIR="$SCAN_DIR/stig-evidence"

mkdir -p "$OUTPUT_DIR"

echo "🔍 Collecting STIG Evidence from: $LATEST_SCAN"

# 1. Critical Vulnerabilities (ASDV-DV-000320)
echo "📋 Extracting Critical Vulnerabilities..."
cat "$SCAN_DIR/grype/grype-results.json" | \
  jq '.matches[] | select(.vulnerability.severity=="Critical")' \
  > "$OUTPUT_DIR/critical-vulnerabilities.json" 2>/dev/null || echo "[]" > "$OUTPUT_DIR/critical-vulnerabilities.json"

# 2. Secrets Detection (DKER-EE-005170)
echo "🔐 Extracting Secrets Findings..."
cat "$SCAN_DIR/trufflehog/trufflehog-results.json" | \
  jq '.results[]' \
  > "$OUTPUT_DIR/secrets-detected.json" 2>/dev/null || echo "[]" > "$OUTPUT_DIR/secrets-detected.json"

# 3. Infrastructure Security (Multiple STIGs)
echo "🏗️  Extracting Infrastructure Findings..."
cat "$SCAN_DIR/checkov/checkov-results.json" | \
  jq '.results.failed_checks[]' \
  > "$OUTPUT_DIR/infrastructure-findings.json" 2>/dev/null || echo "[]" > "$OUTPUT_DIR/infrastructure-findings.json"

# 4. EOL Software (ASDV-DV-000070)
echo "⏰ Extracting EOL Components..."
cat "$SCAN_DIR/xeol/xeol-results.json" | \
  jq '.matches[]' \
  > "$OUTPUT_DIR/eol-software.json" 2>/dev/null || echo "[]" > "$OUTPUT_DIR/eol-software.json"

# 5. Malware Scan (ASDV-DV-000220)
echo "🦠 Extracting Malware Scan Results..."
cp "$SCAN_DIR/clamav/clamav-scan.log" "$OUTPUT_DIR/malware-scan.log" 2>/dev/null || echo "No ClamAV scan found" > "$OUTPUT_DIR/malware-scan.log"

# 6. Container Security (DKER-EE-002140)
echo "🐳 Extracting Container Findings..."
cat "$SCAN_DIR/trivy/trivy-results.json" | \
  jq '.Results[] | .Vulnerabilities[]?' \
  > "$OUTPUT_DIR/container-vulnerabilities.json" 2>/dev/null || echo "[]" > "$OUTPUT_DIR/container-vulnerabilities.json"

# 7. SBOM for Compliance (DKER-EE-001010)
echo "📦 Copying SBOM..."
cp "$SCAN_DIR/sbom/sbom.json" "$OUTPUT_DIR/sbom.json" 2>/dev/null || echo "{}" > "$OUTPUT_DIR/sbom.json"

# 8. Summary Report
echo "📊 Generating Summary..."
cat > "$OUTPUT_DIR/stig-evidence-summary.txt" <<EOF
STIG Evidence Collection Summary
=================================
Scan ID: $LATEST_SCAN
Collection Date: $(date)

Files Generated:
- critical-vulnerabilities.json    (ASDV-DV-000320)
- secrets-detected.json            (DKER-EE-005170)
- infrastructure-findings.json     (CNTR-K8-*, CNTR-OS-*)
- eol-software.json                (ASDV-DV-000070)
- malware-scan.log                 (ASDV-DV-000220)
- container-vulnerabilities.json   (DKER-EE-002140)
- sbom.json                        (DKER-EE-001010)

Statistics:
- Critical Vulnerabilities: $(cat "$OUTPUT_DIR/critical-vulnerabilities.json" | jq '. | length')
- Secrets Detected: $(cat "$OUTPUT_DIR/secrets-detected.json" | jq '. | length')
- Infrastructure Issues: $(cat "$OUTPUT_DIR/infrastructure-findings.json" | jq '. | length')
- EOL Components: $(cat "$OUTPUT_DIR/eol-software.json" | jq '. | length')
- Container Vulnerabilities: $(cat "$OUTPUT_DIR/container-vulnerabilities.json" | jq '. | length')
- Malware Infections: $(grep "Infected files:" "$OUTPUT_DIR/malware-scan.log" | awk '{print $3}')

Dashboard: file://$SCAN_DIR/consolidated-reports/dashboards/security-dashboard.html
EOF

echo "✅ STIG Evidence collected at: $OUTPUT_DIR"
cat "$OUTPUT_DIR/stig-evidence-summary.txt"
```

Make it executable:
```bash
chmod +x scripts/shell/collect-stig-evidence.sh
```

Usage:
```bash
# After running a scan, collect STIG evidence
./scripts/shell/collect-stig-evidence.sh
```

---

## Manual STIG Validation Still Required

Epyon **cannot** automatically validate the following (requires manual process):

### Process & Documentation Controls
- **Organizational policies** (e.g., security training, incident response plans)
- **Change management procedures** (e.g., approval workflows, documentation)
- **Personnel security** (e.g., background checks, access reviews)
- **Physical security** (e.g., facility access, hardware controls)

### Runtime & Dynamic Testing
- **Dynamic application security testing (DAST)** - penetration testing, fuzzing
- **Runtime behavioral analysis** - monitoring application behavior in production
- **Network security testing** - firewall rules, network segmentation validation
- **Authentication/authorization testing** - session management, access control validation

### Configuration Management
- **Production configurations** - Epyon scans code/images, not live deployments
- **Operational procedures** - backup schedules, patching processes, monitoring
- **Third-party service validation** - cloud provider configurations, SaaS security

### Compliance Documentation
- **POA&M creation** - requires manual risk assessment and remediation planning
- **Authority to Operate (ATO) packages** - requires security team review
- **Control implementation statements** - narrative descriptions for each STIG control

---

## Best Practices for STIG Compliance with Epyon

### 1. Establish Baseline Scans

```bash
# Scan approved baseline images
./scripts/shell/run-baseline-scan.sh

# Document baseline as "known good" state
cp scans/baseline_*/consolidated-reports/consolidated-security-report.json \
   documentation/stig-baseline-approved.json
```

### 2. Continuous Scanning Schedule

```bash
# Daily scans during development
0 9 * * * cd /path/to/epyon && ./scripts/shell/run-target-security-scan.sh "/path/to/app" full

# Weekly baseline validation
0 0 * * 0 cd /path/to/epyon && ./scripts/shell/run-baseline-scan.sh
```

### 3. Quality Gate Integration

```bash
# Fail builds on critical vulnerabilities
./scripts/shell/check-severity-gate.sh "scans/latest"
CRITICAL_THRESHOLD=0 HIGH_THRESHOLD=10 ./scripts/shell/check-severity-gate.sh "scans/latest"
```

### 4. Evidence Archival

```bash
# Archive scan results for compliance audit trail
SCAN_DATE=$(date +%Y-%m-%d)
tar -czf "stig-evidence-$SCAN_DATE.tar.gz" scans/*/stig-evidence/
```

### 5. Remediation Tracking

```bash
# Track fixes across scans
SCAN1="scans/app_2026-02-01"
SCAN2="scans/app_2026-02-06"

# Compare critical findings
diff <(cat $SCAN1/stig-evidence/critical-vulnerabilities.json | jq -r '.[].vulnerability.id' | sort) \
     <(cat $SCAN2/stig-evidence/critical-vulnerabilities.json | jq -r '.[].vulnerability.id' | sort)
```

---

## Future STIG Enhancements (Roadmap)

As noted in the main README, full STIG compliance features are planned for future releases:

- **Automated STIG Checklist Generation** - Direct mapping to STIG control IDs
- **POA&M Integration** - Track findings as POA&M items with remediation plans
- **RMF Support** - Risk Management Framework documentation and categorization
- **Control Traceability Matrix** - Map scan findings to specific STIG controls
- **Compliance Dashboards** - STIG-specific reporting with pass/fail by control
- **Evidence Package Export** - ATO-ready documentation bundles

---

## Additional Resources

### STIG References
- **DISA STIG Library**: https://public.cyber.mil/stigs/
- **Application Security Development STIG**: https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=app-security
- **Container Platform STIG**: https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=container-platform
- **DevSecOps STIG**: https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=application-security-devsecops

### Epyon Documentation
- **Security Review**: [SECURITY_REVIEW_AND_TEST_COVERAGE.md](./SECURITY_REVIEW_AND_TEST_COVERAGE.md)
- **Scan Architecture**: [SCAN_DIRECTORY_ARCHITECTURE.md](./SCAN_DIRECTORY_ARCHITECTURE.md)
- **Offline Setup**: [OFFLINE_AIR_GAPPED_SETUP.md](./OFFLINE_AIR_GAPPED_SETUP.md)

---

## Support

For questions about STIG compliance with Epyon:
1. Review the [Security Review](./SECURITY_REVIEW_AND_TEST_COVERAGE.md) for security architecture
2. Check scan results in the interactive dashboard: `./scripts/shell/open-latest-dashboard.sh`
3. Use the evidence collection script: `./scripts/shell/collect-stig-evidence.sh`

**Note**: This guide provides technical evidence collection only. Formal STIG compliance requires security team review, documentation, and ATO approval processes beyond the scope of automated scanning tools.

---

**Document History:**
- **v1.0** (Feb 6, 2026): Initial STIG compliance guide created with control mappings for Application Security Development STIG, Container Platform STIG, Docker Enterprise STIG, DevSecOps STIG, and Red Hat OpenShift STIG
