# Ten-Layer Security Architecture with SBOM Integration

## Overview
The comprehensive security architecture has been expanded from nine to ten layers with the addition of dedicated SBOM (Software Bill of Materials) generation. SBOMs provide crucial inventory visibility for all dependencies and components before vulnerability scanning.

## Updated Security Layer Architecture

### Layer 1: Secret Detection (Multi-Target)
- **Tool**: TruffleHog
- **Purpose**: Detect hardcoded secrets, API keys, passwords
- **Targets**: Filesystem, Container Images
- **Reports**: `trufflehog-reports/`

### Layer 2: Software Bill of Materials (SBOM) ⭐ NEW
- **Tool**: Syft (Anchore)
- **Purpose**: Generate comprehensive software inventory
- **Features**: Multi-format support (Node.js, Python, Go, Java, Rust)
- **Reports**: `sbom-reports/`
- **Output Types**: 
  - Filesystem SBOM
  - Language-specific SBOMs (detected automatically)
  - Combined summary report

### Layer 3: Code Quality Analysis
- **Tool**: SonarQube
- **Purpose**: Static code analysis, quality metrics
- **Reports**: `sonar-reports/`

### Layer 4: Malware Detection
- **Tool**: ClamAV
- **Purpose**: Antivirus scanning
- **Reports**: `clamav-reports/`

### Layer 5: Helm Chart Building
- **Tool**: Helm
- **Purpose**: Kubernetes deployment templates
- **Reports**: `helm-reports/`

### Layer 6: Infrastructure Security
- **Tool**: Checkov
- **Purpose**: Infrastructure as Code security scanning
- **Reports**: `checkov-reports/`

### Layer 7: Container Security (Multi-Target)
- **Tool**: Trivy
- **Purpose**: Container and filesystem security scanning
- **Targets**: Filesystem, Container Images, Base Images, Kubernetes
- **Reports**: `trivy-reports/`

### Layer 8: Anchore Security Analysis
- **Tool**: Anchore (Placeholder)
- **Purpose**: Container image analysis and policy enforcement
- **Reports**: `anchore-reports/`

### Layer 9: End-of-Life Detection
- **Tool**: Xeol
- **Purpose**: EOL software detection
- **Reports**: `xeol-reports/`

### Layer 10: Vulnerability Detection (Multi-Target)
- **Tool**: Grype
- **Purpose**: Vulnerability scanning and SBOM analysis
- **Targets**: Filesystem, Container Images, Base Images
- **Reports**: `grype-reports/`

## SBOM Integration Features

### Automatic Project Detection
The SBOM layer automatically detects project types and generates appropriate SBOMs:

- **Node.js**: `package.json` detection → Node.js SBOM
- **Python**: `requirements.txt`, `pyproject.toml`, `setup.py` → Python SBOM
- **Go**: `go.mod` → Go SBOM
- **Java**: `pom.xml`, `build.gradle` → Java SBOM
- **Rust**: `Cargo.toml` → Rust SBOM
- **Docker**: `Dockerfile` → Container preparation notes

### SBOM Output Files
All SBOM files follow the standardized naming convention:
```
{TargetName}_{username}_{YYYY-MM-DD_HH-MM-SS}_sbom-{type}.json
```

Example output:
- `myproject_rnelson_2025-11-16_12-45-30_sbom-filesystem.json`
- `myproject_rnelson_2025-11-16_12-45-30_sbom-nodejs.json`
- `myproject_rnelson_2025-11-16_12-45-30_sbom-summary.json`

### Implementation Details

#### Syft Integration
- **Primary**: Local Syft installation (if available)
- **Fallback**: Docker version (`anchore/syft:latest`)
- **Format**: JSON output with comprehensive artifact cataloging

#### Directory Structure
```
reports/
└── sbom-reports/
    ├── {SCAN_ID}_sbom-filesystem.json
    ├── {SCAN_ID}_sbom-nodejs.json
    ├── {SCAN_ID}_sbom-summary.json
    ├── {SCAN_ID}_sbom-scan.log
    ├── sbom-summary.json → latest summary
    └── sbom-scan.log → latest log
```

#### Summary Report
The SBOM summary includes:
- Scan metadata (ID, timestamp, target)
- List of all generated SBOM files
- Artifact counts per SBOM type
- Total artifact inventory count

## Usage Examples

### Quick Scan (includes SBOM)
```bash
./run-target-security-scan.sh /path/to/project quick
```

### Full Ten-Layer Scan
```bash
./run-target-security-scan.sh /path/to/project full
```

### Standalone SBOM Generation
```bash
./run-sbom-scan.sh /path/to/project
```

## Integration Benefits

1. **Inventory Before Analysis**: SBOM provides complete dependency inventory before vulnerability scanning
2. **Enhanced Reporting**: Combined SBOM + vulnerability data provides better context
3. **Compliance**: SBOM generation supports regulatory and supply chain security requirements
4. **Consistent Patterns**: Same directory structure and naming as all other security layers
5. **Multi-Project Support**: Automatically adapts to different project types

## File Updates

### Modified Scripts
- `run-target-security-scan.sh`: Updated to ten-layer architecture with SBOM as Layer 2
- Created `run-sbom-scan.sh`: Dedicated SBOM generation script

### Directory Structure
- Created `reports/sbom-reports/` directory
- Maintains consistent `../../reports/[tool]-reports/` pattern

This integration provides comprehensive software inventory capabilities while maintaining the established security architecture patterns and conventions.