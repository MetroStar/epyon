# Epyon Parser Functions Reference

Complete reference for all parsing functions in the Epyon security scanner.

---

## Table of Contents

- [Utility Functions](#utility-functions)
- [Per-Tool Parsers (Security Layers)](#per-tool-parsers-security-layers)
- [Special Feature Parsers](#special-feature-parsers)
- [Aggregate Parsers](#aggregate-parsers)
- [Shell Script Parsers](#shell-script-parsers)

---

## Utility Functions

### `norm_sev(s: str | None) -> str`
**Location:** [web/api/parsers.py:17](../web/api/parsers.py#L17)

**Purpose:** Normalizes severity strings to standard values.

**Parameters:**
- `s` (str | None): Raw severity string from tool output

**Returns:** `str` - One of: `"critical"`, `"high"`, `"medium"`, `"low"`, `"unknown"`

**Mapping:**
- `"critical"` → `"critical"`
- `"high"` → `"high"`
- `"medium"`, `"moderate"` → `"medium"`
- `"low"`, `"negligible"`, `"info"` → `"low"`
- Everything else → `"unknown"`

---

### `_determine_cve_source(data_source: str, namespace: str) -> str`
**Location:** [web/api/parsers.py:32](../web/api/parsers.py#L32)

**Purpose:** Determines the CVE database source from Grype/Anchore metadata.

**Parameters:**
- `data_source` (str): Data source field from vulnerability metadata
- `namespace` (str): Namespace field from vulnerability metadata

**Returns:** `str` - One of: `"GHSA"`, `"NVD"`, `"Alpine"`, `"Debian"`, `"Ubuntu"`, `"RHEL"`, `"Grype"`

**Detection Logic:**
- GitHub Security Advisory: `"github"` in data_source or `"ghsa"` in namespace
- NVD: `"nvd"` or `"nvd.nist.gov"` in data_source
- Alpine SecDB: `"alpine"` in namespace or data_source
- Debian: `"debian"` in namespace or data_source
- Ubuntu: `"ubuntu"` in namespace or data_source
- RHEL: `"rhel"` or `"redhat"` in namespace or data_source
- Default: `"Grype"`

---

### `parse_dir_name(name: str) -> dict`
**Location:** [web/api/parsers.py:71](../web/api/parsers.py#L71)

**Purpose:** Parses scan directory names to extract target, user, and timestamp.

**Parameters:**
- `name` (str): Scan directory name (format: `{target}_{user}_{YYYY-MM-DD}_{HH-MM-SS}`)

**Returns:** `dict` with keys:
```python
{
    "target": str,      # Target application name
    "user": str,        # Username (empty if not present)
    "timestamp": str    # ISO timestamp format (YYYY-MM-DDTHH:MM:SS)
}
```

**Examples:**
- `"myapp_2026-07-02_14-30-00"` → `{"target": "myapp", "user": "", "timestamp": "2026-07-02T14:30:00"}`
- `"myapp_rnelson_2026-07-02_14-30-00"` → `{"target": "myapp", "user": "rnelson", "timestamp": "2026-07-02T14:30:00"}`

---

### `find_scan_dirs(epyon_root: Path, days: int = 0) -> list[Path]`
**Location:** [web/api/parsers.py:86](../web/api/parsers.py#L86)

**Purpose:** Finds all scan directories within epyon_root, with optional date filtering.

**Parameters:**
- `epyon_root` (Path): Root directory of the Epyon installation
- `days` (int): If > 0, only return scans from the last N days (default: 0 = all scans)

**Returns:** `list[Path]` - List of Path objects for scan directories, sorted chronologically

**Search Locations:**
- `epyon_root/scans/`
- `epyon_root/baseline/scans/`
- `epyon_root/scripts/scans/`

**Security:** Includes path traversal guard to ensure results are within epyon_root.

---

### `_read_json(path: Path) -> Any`
**Location:** [web/api/parsers.py:140](../web/api/parsers.py#L140)

**Purpose:** Safely reads JSON files, returning None on any error.

**Parameters:**
- `path` (Path): Path to JSON file

**Returns:** `Any` - Parsed JSON data, or `None` if file doesn't exist or is invalid

---

### `_json_files_in(directory: Path, skip_symlinks: bool = True) -> list[Path]`
**Location:** [web/api/parsers.py:147](../web/api/parsers.py#L147)

**Purpose:** Lists JSON files in a directory, excluding statistics files.

**Parameters:**
- `directory` (Path): Directory to search
- `skip_symlinks` (bool): Skip symbolic links (default: True)

**Returns:** `list[Path]` - Sorted list of JSON file paths

**Exclusions:**
- Files containing "statistics" in name
- Symbolic links (if `skip_symlinks=True`)
- Non-files

---

## Per-Tool Parsers (Security Layers)

### `parse_trivy_dir(scan_dir: Path) -> list[dict]`
**Location:** [web/api/parsers.py:164](../web/api/parsers.py#L164)  
**Layer:** 7 - Container Security

**Purpose:** Parses Trivy container vulnerability scan results.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `trivy/` subdirectory

**Reads From:** `scan_dir/trivy/*.json`

**Returns:** `list[dict]` - List of vulnerability findings with structure:
```python
{
    "tool": "Trivy",
    "id": str,                # CVE ID (e.g., "CVE-2024-1234")
    "severity": str,          # Normalized severity
    "package": str,           # Package name
    "version": str,           # Installed version
    "fixed_version": str,     # Fixed version (empty if none)
    "title": str,             # Vulnerability title
    "description": str,       # Full description
    "target": str,            # Target file/image
    "references": list[str],  # Up to 3 reference URLs
    "cve_source": "Trivy"     # Always "Trivy"
}
```

---

### `parse_grype_dir(scan_dir: Path) -> list[dict]`
**Location:** [web/api/parsers.py:189](../web/api/parsers.py#L189)  
**Layer:** 8 - Vulnerability Scanning

**Purpose:** Parses Grype vulnerability scan results with CVE source detection.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `grype/` subdirectory

**Reads From:** `scan_dir/grype/*.json`

**Returns:** `list[dict]` - Same structure as Trivy, but with dynamic `cve_source`:
```python
{
    "tool": "Grype",
    "id": str,
    "severity": str,
    "package": str,
    "version": str,
    "fixed_version": str,
    "title": str,
    "description": str,
    "target": str,
    "references": list[str],
    "cve_source": str         # GHSA, NVD, Alpine, Debian, Ubuntu, RHEL, or Grype
}
```

---

### `parse_trufflehog_dir(scan_dir: Path) -> list[dict]`
**Location:** [web/api/parsers.py:222](../web/api/parsers.py#L222)  
**Layer:** 2 - Secret Detection

**Purpose:** Parses TruffleHog secret detection results.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `trufflehog/` subdirectory

**Reads From:** `scan_dir/trufflehog/*.json` (excludes files starting with scan_id)

**Returns:** `list[dict]` - Secret findings:
```python
{
    "tool": "TruffleHog",
    "id": str,                # Detector name (e.g., "AWS", "GitHub")
    "severity": str,          # "critical" if verified, else "high"
    "package": str,           # Detector name
    "version": "",
    "fixed_version": "",
    "title": str,             # "Verified/Unverified secret: {detector}"
    "description": str,       # Detector, file path, and line number
    "target": str,            # File path
    "location": str,          # File path with line anchor (e.g., "config.py#L42")
    "line": str,              # Line number
    "references": []
}
```

**Special Handling:** Supports both JSONL format and array of objects per file.

---

### `parse_checkov_dir(scan_dir: Path) -> list[dict]`
**Location:** [web/api/parsers.py:276](../web/api/parsers.py#L276)  
**Layer:** 6 - IaC Security

**Purpose:** Parses Checkov Infrastructure-as-Code security scan results.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `checkov/` subdirectory

**Reads From:** `scan_dir/checkov/*.json` and `scan_dir/checkov/*.json/results_json.json`

**Returns:** `list[dict]` - IaC policy violations:
```python
{
    "tool": "Checkov",
    "id": str,                # Check ID (e.g., "CKV_AWS_23")
    "severity": str,          # Normalized (defaults to "medium" if unknown)
    "package": str,           # File path
    "version": "",
    "fixed_version": "",
    "title": str,             # Check name
    "description": str,       # Check name + resource + file path with line range
    "target": str,            # File path
    "location": str,          # File path with line anchors (e.g., "file.tf#L10-L15")
    "resource": str,          # Resource identifier (e.g., "aws_s3_bucket.example")
    "file_line_range": list,  # [start_line, end_line] as integers
    "references": list[str]   # Guideline URL if present
}
```

**Location Format Examples:**
- Single line: `.github/workflows/deploy.yml#L42`
- Line range: `terraform/main.tf#L10-L15`
- No lines: `Dockerfile` (if line range not available)

---

### `parse_clamav_dir(scan_dir: Path) -> list[dict]`
**Location:** [web/api/parsers.py:335](../web/api/parsers.py#L335)  
**Layer:** 4 - Malware Detection

**Purpose:** Parses ClamAV malware scan logs.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `clamav/` subdirectory

**Reads From:** 
- `scan_dir/clamav/clamav-detailed.log` (preferred)
- `scan_dir/clamav/scan.log` (fallback)

**Returns:** `list[dict]` - Malware detections:
```python
{
    "tool": "ClamAV",
    "id": str,                # Malware signature
    "severity": "critical",   # Always critical
    "package": str,           # Filename
    "version": "",
    "fixed_version": "",
    "title": str,             # "Malware detected: {signature}"
    "description": str,       # File path and signature
    "target": str,            # Full file path
    "references": []
}
```

**Log Format:** Parses lines matching regex `^(.+?):\s+(.+?)\s+FOUND\s*$`

---

### `parse_anchore_dir(scan_dir: Path) -> list[dict]`
**Location:** [web/api/parsers.py:370](../web/api/parsers.py#L370)  
**Layer:** 10 - Container Analysis

**Purpose:** Parses Anchore container and filesystem vulnerability results.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `anchore/` subdirectory

**Reads From:**
- `scan_dir/anchore/anchore-filesystem-results.json`
- `scan_dir/anchore/images/*.json`

**Returns:** `list[dict]` - Same structure as Grype:
```python
{
    "tool": "Anchore",
    "id": str,
    "severity": str,
    "package": str,
    "version": str,
    "fixed_version": str,
    "title": str,
    "description": str,
    "target": str,
    "references": list[str],
    "cve_source": str         # GHSA, NVD, Alpine, Debian, Ubuntu, RHEL, or Grype
}
```

---

### `parse_xeol_dir(scan_dir: Path) -> list[dict]`
**Location:** [web/api/parsers.py:445](../web/api/parsers.py#L445)  
**Layer:** 9 - EOL Detection

**Purpose:** Parses Xeol end-of-life package detection results.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `xeol/` subdirectory

**Reads From:** `scan_dir/xeol/*.json`

**Returns:** `list[dict]` - EOL package findings:
```python
{
    "tool": "Xeol",
    "id": str,                # "EOL:YYYY-MM-DD" or "EOL"
    "severity": "high",       # Always high
    "package": str,           # Package name
    "version": str,           # Package version
    "fixed_version": "",
    "title": str,             # "End-of-life: {package}@{version}"
    "description": str,       # Package@version reached EOL [on date]
    "target": str,            # File path
    "references": []
}
```

---

### `parse_pip_audit_dir(scan_dir: Path) -> list[dict]`
**Location:** [web/api/parsers.py:474](../web/api/parsers.py#L474)  
**Layer:** 8.5 - Direct Dependency Scanning

**Purpose:** Parses pip-audit direct Python dependency vulnerability scan results. Complements SBOM-based scanners by checking Python dependencies directly against OSV database.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `pip-audit/` subdirectory

**Reads From:** `scan_dir/pip-audit/pip-audit-consolidated-results.json`

**Returns:** `list[dict]` - Python dependency vulnerabilities:
```python
{
    "tool": "pip-audit",
    "id": str,                # Vulnerability ID (e.g., "PYSEC-2024-1234")
    "severity": str,          # "medium" if fix available, else "high"
    "package": str,           # Package name
    "version": str,           # Installed version
    "fixed_version": str,     # First fixed version if available
    "title": str,             # Vulnerability ID
    "description": str,       # Vulnerability description
    "target": str,            # Dependency file path (requirements.txt, pyproject.toml, etc.)
    "references": list[str],  # Advisory URL if present
    "cve_source": "OSV"       # Always OSV
}
```

**Consolidated Format:** Reads `scan_results` array containing objects with `file` (dependency file path) and `results` (array of vulnerabilities) per scanned dependency file.

**Severity Logic:** pip-audit doesn't provide explicit severity, so it's inferred:
- Has fix available (`fix_versions` not empty) → `"medium"`
- No fix available → `"high"`

---

### `parse_safety_dir(scan_dir: Path) -> list[dict]`
**Location:** [web/api/parsers.py:520](../web/api/parsers.py#L520)  
**Layer:** 11.6 - Python Safety Check

**Purpose:** Parses Safety Python vulnerability scan results. Complements pip-audit by checking dependencies against Safety's vulnerability database (NVD + PyPI advisories).

**Parameters:**
- `scan_dir` (Path): Scan directory containing `safety/` subdirectory

**Reads From:** `scan_dir/safety/safety-consolidated-results.json`

**Returns:** `list[dict]` - Python dependency vulnerabilities:
```python
{
    "tool": "safety",
    "id": str,                # Advisory ID
    "severity": str,          # Severity from Safety DB (critical/high/medium/low)
    "package": str,           # Package name
    "version": str,           # Installed version
    "fixed_version": str,     # Safe version if available
    "title": str,             # Advisory ID
    "description": str,       # Advisory text
    "target": str,            # Dependency file path
    "references": [],
    "cve_source": "Safety DB"
}
```

**Consolidated Format:** Reads `scan_results` array containing objects with `file` (dependency file path) and `results` (array of vulnerabilities) per scanned dependency file.

---

### `parse_sonarqube_dir(scan_dir: Path) -> list[dict]`
**Location:** [web/api/parsers.py:521](../web/api/parsers.py#L521)  
**Layer:** 3 - Code Quality

**Purpose:** Parses SonarQube/SonarCloud code quality issues.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `sonar/` subdirectory

**Reads From:** `scan_dir/sonar/sonar-issues.json`

**Returns:** `list[dict]` - Code quality issues:
```python
{
    "tool": "SonarQube",
    "type": "code_quality",
    "severity": str,          # BLOCKER/CRITICAL→critical, MAJOR→high, MINOR→medium, INFO→low
    "id": str,                # Rule ID
    "title": str,             # Issue message (max 200 chars)
    "package": "",
    "version": "",
    "fixed_version": "",
    "target": str,            # component:line or just component
    "location": str,          # GitHub-style location (e.g., "src/main.py#L42")
    "line": int,              # Line number
    "references": []
}
```

**Severity Mapping:**
- `BLOCKER`, `CRITICAL` → `"critical"`
- `MAJOR` → `"high"`
- `MINOR` → `"medium"`
- `INFO` → `"low"`

---

## Special Feature Parsers

### `parse_network_discovery_dir(scan_dir: Path) -> dict | None`
**Location:** [web/api/parsers.py:443](../web/api/parsers.py#L443)  
**Layer:** 16 - Network Discovery (PPSM)

**Purpose:** Parses network/port discovery results from static analysis and active scanning.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `network/` subdirectory

**Reads From:** `scan_dir/network/network-discovery.json`

**Returns:** `dict | None`:
```python
{
    "total_ports": int,               # Total ports discovered
    "unique_ports": list[int],        # Unique port numbers
    "protocols": list[str],           # Protocols (tcp, udp)
    "services": list[str],            # Inferred services
    "static_sources": int,            # Number of static sources found
    "active_scan_run": bool,          # Whether active scan was performed
    "compose_ports": list[dict],      # Docker Compose port mappings
    "dockerfile_ports": list[dict],   # Dockerfile EXPOSE directives
    "k8s_ports": list[dict],          # Kubernetes/Helm port definitions
    "config_ports": list[dict],       # App config file ports
    "active_results": dict            # Raw active scan results
}
```

**Port Entry Structures:**
```python
# compose_ports
{"file": str, "service": str, "port": int, "mapping": str}

# dockerfile_ports, k8s_ports, config_ports
{"file": str, "port": int}
```

---

### `parse_picklescan_dir(scan_dir: Path) -> dict | None`
**Location:** [web/api/parsers.py:506](../web/api/parsers.py#L506)  
**Layer:** 14 - Pickle Safety

**Purpose:** Parses picklescan results for ML model weight file security.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `picklescan/` subdirectory

**Reads From:** `scan_dir/picklescan/picklescan-results.json`

**Returns:** `dict | None`:
```python
{
    "status": str,                  # "clean", "infected", or "unknown"
    "target": str,                  # Target directory scanned
    "file_count": int,              # Total weight files scanned
    "total_weight_files": int,      # Same as file_count
    "flagged_count": int,           # Number of flagged files
    "infected_files": list[str],    # List of infected file paths
    "weight_formats": list[str],    # Detected formats (pkl, pt, safetensors)
    "findings": list[dict],         # Detailed findings per file
    "generated_at": str             # ISO timestamp
}
```

---

### `parse_coverage_dir(scan_dir: Path) -> dict | None`
**Location:** [web/api/parsers.py:527](../web/api/parsers.py#L527)

**Purpose:** Parses test coverage data from coverage tools or SonarQube.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `coverage/` or `sonar/` subdirectory

**Reads From:**
1. `scan_dir/coverage/coverage-summary.json` (preferred)
2. `scan_dir/sonar/sonar-analysis-results.json` (fallback)

**Returns:** `dict | None`:
```python
# From coverage-summary.json
{
    "percentage": float,           # Coverage percentage (0-100)
    "language": str,               # Detected language
    "framework": str,              # Coverage framework (pytest-cov, jest, etc.)
    "lines_covered": int,          # Lines covered
    "lines_total": int,            # Total lines
    "branches_covered": int,       # Branches covered
    "branches_total": int,         # Total branches
    "status": str,                 # "success" or "not_detected"
    "timestamp": str,              # ISO timestamp
    "source": "coverage-scan"
}

# From SonarQube (fallback)
{
    "percentage": float,
    "language": "unknown",
    "framework": "sonarqube",
    "source": "sonarqube"
}
```

---

### `parse_modelcard_dir(scan_dir: Path) -> dict | None`
**Location:** [web/api/parsers.py:578](../web/api/parsers.py#L578)  
**Layer:** 15 - Model Card Compliance

**Purpose:** Parses AI/ML model card compliance check results.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `modelcard/` subdirectory

**Reads From:** `scan_dir/modelcard/modelcard-results.json`

**Returns:** `dict | None`:
```python
{
    "status": str,              # "compliant", "non_compliant", or "unknown"
    "file_checked": str,        # Path to model card file
    "passed": int,              # Number of checks passed
    "failed": int,              # Number of checks failed
    "warnings": int,            # Number of warnings
    "findings": list[dict],     # Detailed findings
    "generated_at": str         # ISO timestamp
}
```

---

### `count_suppressed_instances(scan_dir: Path) -> int`
**Location:** [web/api/parsers.py:597](../web/api/parsers.py#L597)

**Purpose:** Counts raw suppression instances in suppressed findings markdown (not deduplicated).

**Parameters:**
- `scan_dir` (Path): Scan directory

**Reads From:** `scan_dir/suppressed-findings.md`

**Returns:** `int` - Count of lines starting with `"## Suppressed:"`

---

### `parse_suppressed_findings(scan_dir: Path) -> list[dict]`
**Location:** [web/api/parsers.py:610](../web/api/parsers.py#L610)

**Purpose:** Parses suppressed findings markdown into structured records.

**Parameters:**
- `scan_dir` (Path): Scan directory

**Reads From:** `scan_dir/suppressed-findings.md`

**Returns:** `list[dict]` - Deduplicated suppression records:
```python
{
    "value": str,          # CVE ID, secret pattern, or finding identifier
    "type": str,           # "cve", "secret", "iac", etc.
    "reason": str,         # Suppression justification
    "expires": str,        # Expiration date (YYYY-MM-DD)
    "approved_by": str,    # Approver name/email
    "paths": list[str]     # Specific file paths (optional)
}
```

**Deduplication:** By `(type, value)` tuple to prevent duplicate rules.

---

### `parse_enrichment_summary(scan_dir: Path) -> dict | None`
**Location:** [web/api/parsers.py:916](../web/api/parsers.py#L916)

**Purpose:** Extracts enrichment metadata (CISA KEV / NVD) from findings summary.

**Parameters:**
- `scan_dir` (Path): Scan directory

**Reads From:** `scan_dir/security-findings-summary.json`

**Returns:** `dict | None` - Enrichment block:
```python
{
    "cisa_kev_count": int,           # Number of CISA KEV vulnerabilities
    "nvd_enriched_count": int,       # Number of NVD-enriched findings
    "enrichment_timestamp": str,     # When enrichment was performed
    "enrichment_sources": list[str]  # Sources used (CISA, NVD)
}
```

---

### `load_api_discovery(scan_dir: Path) -> dict | None`
**Location:** [web/api/parsers.py:931](../web/api/parsers.py#L931)  
**Layer:** 11 - API Discovery

**Purpose:** Parses discovered API endpoints from static code analysis.

**Parameters:**
- `scan_dir` (Path): Scan directory

**Reads From:** (tries multiple locations in order)
1. `scan_dir/api/exports/api-discovery-{scan_id}.json`
2. `scan_dir/api/api-discovery.json`
3. `scan_dir/api-discovery/api-inventory.json`
4. `scan_dir/api-discovery.json`

**Returns:** `dict | None`:
```python
{
    "endpoints": list[dict],        # List of endpoint objects
    "total": int,                   # Total endpoint count
    "by_method": dict[str, int],    # Count per HTTP method
    "by_framework": dict[str, int], # Count per framework
    "summary": dict                 # Raw summary from discovery file
}
```

**Endpoint Structure:**
```python
{
    "method": str,        # GET, POST, PUT, DELETE, etc.
    "path": str,          # API path/route
    "framework": str,     # FastAPI, Express, Flask, etc.
    "file": str,          # Source file path
    "line": int           # Line number
}
```

**Supported Formats:**
- Direct endpoints array (older format)
- `discovery_methods.code_routes` with language breakdown (current format)

---

## Aggregate Parsers

### `load_sbom_packages(scan_dir: Path) -> dict`
**Location:** [web/api/parsers.py:640](../web/api/parsers.py#L640)  
**Layer:** 1 - SBOM Generation

**Purpose:** Loads SBOM package data from Syft or CycloneDX formats.

**Parameters:**
- `scan_dir` (Path): Scan directory containing `sbom/` subdirectory

**Reads From:**
1. `scan_dir/sbom/*.json` (Syft format, preferred)
2. `scan_dir/sbom/*.cyclonedx.json` (CycloneDX fallback)

**Returns:** `dict`:
```python
{
    "total": int,              # Total package count
    "by_type": dict[str, int], # Count per package type
    "packages": list[dict]     # Package list (capped at 2000)
}
```

**Package Structure (Syft format):**
```python
{
    "name": str,           # Package name
    "version": str,        # Package version
    "type": str,           # npm, python, apk, deb, etc.
    "language": str,       # Programming language
    "purl": str,           # Package URL
    "path": str,           # File path (with synthetic name mapping)
    "licenses": list[str]  # SPDX license identifiers
}
```

**Path Mapping (Syft):**
- `requirements-pyproject.txt` → `pyproject.toml`
- `requirements-conda-env.txt` → `environment.yaml`
- `requirements.txt` → `requirements.lock` (if lock file exists and .txt doesn't)

---

### `parse_scan_findings(scan_dir: Path) -> dict`
**Location:** [web/api/parsers.py:983](../web/api/parsers.py#L983)

**Purpose:** Aggregates findings from all security tools and groups by severity.

**Parameters:**
- `scan_dir` (Path): Scan directory

**Calls:** All per-tool parsers (Trivy, Grype, Anchore, pip-audit, safety, TruffleHog, Checkov, ClamAV, Xeol, SonarQube)

**Returns:** `dict`:
```python
{
    "summary": {
        "total_critical": int,
        "total_high": int,
        "total_medium": int,
        "total_low": int,
        "tools_analyzed": list[str]  # Sorted list of tool names
    },
    "critical_findings": list[dict],
    "high_findings": list[dict],
    "medium_findings": list[dict],
    "low_findings": list[dict]
}
```

**Note:** Unknown severities are treated as low.

---

### `load_enriched_findings(scan_dir: Path) -> dict | None`
**Location:** [web/api/parsers.py:850](../web/api/parsers.py#L850)

**Purpose:** Loads pre-enriched findings with CISA KEV and NVD metadata.

**Parameters:**
- `scan_dir` (Path): Scan directory

**Reads From:** `scan_dir/security-findings-summary.json`

**Returns:** `dict | None` - Same structure as `parse_scan_findings()`, but with enriched fields:
```python
{
    "summary": {...},              # Same as parse_scan_findings
    "critical_findings": [...],    # Enhanced with enrichment fields
    "high_findings": [...],
    "medium_findings": [...],
    "low_findings": [...],
    "enrichment": dict             # Enrichment metadata
}
```

**Enhanced Finding Structure:**
```python
{
    # Standard fields
    "tool": str,
    "type": str,
    "severity": str,
    "id": str,
    "title": str,
    "package": str,
    "version": str,
    "fixed_version": str,
    "target": str,
    "line": str,
    "references": list[str],
    
    # Enrichment fields
    "cisa_kev": bool,                # Is this a CISA Known Exploited Vulnerability?
    "nvd_url": str,                  # NVD detail URL
    "nvd_cvss_v3_score": float,      # CVSS v3 base score (0-10)
    "nvd_cvss_v3_severity": str      # NVD severity rating
}
```

**Field Normalization:**
- `vulnerability_id` → `id`
- `package_name` → `package`
- `package_version` → `version`
- `fix_versions[0]` → `fixed_version`

---

### `load_scan(scan_dir: Path, epyon_root: Path) -> dict`
**Location:** [web/api/parsers.py:999](../web/api/parsers.py#L999)

**Purpose:** Main loader - assembles complete scan data from all sources.

**Parameters:**
- `scan_dir` (Path): Scan directory
- `epyon_root` (Path): Epyon installation root

**Reads From:**
- `scan_dir/scan-metadata.json`
- `scan_dir/scan-manifest.json`
- `scan_dir/security-findings-summary.json`
- `scan_dir/ci-metadata.json`
- `scan_dir/stig-results-*.json`
- All layer subdirectories

**Returns:** `dict` - Complete scan object:
```python
{
    # Basic metadata
    "scan_id": str,
    "target": str,
    "user": str,
    "timestamp": str,              # ISO format
    "scan_type": str,              # "quick", "nightly", "full", "stig", "local_model"
    "location": str,               # Relative path from epyon_root
    
    # Findings summary
    "critical": int,
    "high": int,
    "medium": int,
    "low": int,
    "total": int,
    "tools_analyzed": list[str],
    
    # Dashboard
    "has_dashboard": bool,
    "dashboard_url": str | None,
    
    # Optional metadata
    "target_directory": str,       # Original target path
    "source_url": str,             # Git URL if from CI
    "file_statistics": dict,       # File counts by extension
    
    # CI metadata (if from GitHub Actions)
    "ci_source": {
        "source": "github",
        "repo": str,
        "branch": str,
        "commit": str,
        "workflow": str,
        "event": str,
        "run_id": int
    },
    
    # STIG results (if present)
    "stig_open": int,
    "stig_pass": int,
    "stig_na": int,
    "stig_nr": int,
    "stig_total": int,
    "stig_reports": list[dict],    # Per-STIG breakdown
    "has_stig_report": bool,
    "stig_report_url": str,
    "has_stig_cklb": bool,
    "stig_cklb_url": str,
    
    # Layer-specific data (if present)
    "picklescan": dict,            # Layer 14
    "modelcard": dict,             # Layer 15
    "network_discovery": dict,     # Layer 16
    "test_coverage": dict,
    "suppressed_findings": list[dict],
    "enrichment": dict
}
```

**STIG Report Entry:**
```python
{
    "slug": str,                # STIG identifier
    "open": int,
    "pass": int,
    "na": int,
    "nr": int,
    "total": int,
    "has_md": bool,
    "has_cklb": bool,
    "md_url": str | None,
    "cklb_url": str | None,
    "token_usage": dict         # AI token usage stats
}
```

**Scan Type Inference:**
- Has STIG results but no vuln tools → `"stig"`
- Has picklescan/modelcard but no vuln tools → `"local_model"`
- Scheduled GitHub Actions run → `"nightly"`
- Otherwise uses `scan-metadata.json` or defaults to `"full"`

---

### `get_status(scan: dict) -> str`
**Location:** [web/api/parsers.py:1195](../web/api/parsers.py#L1195)

**Purpose:** Determines overall scan status from severity counts.

**Parameters:**
- `scan` (dict): Scan object from `load_scan()`

**Returns:** `str` - One of: `"critical"`, `"high"`, `"medium"`, `"low"`, `"clean"`, `"unknown"`

**Logic:** Returns the highest severity with count > 0, or `"clean"` if all counts are 0.

---

## Shell Script Parsers

### `parse_ignore_rules()`
**Location:** [scripts/shell/parse-epyon-ignore.sh:13](../scripts/shell/parse-epyon-ignore.sh#L13)

**Purpose:** Parses `.epyon-ignore.yml` suppression rules from target repository.

**Parameters:**
- `$1` (optional): Path to ignore file (defaults to `${TARGET_DIR}/.epyon-ignore.yml`)

**Reads From:** `.epyon-ignore.yml` in target repository

**Writes To:** `$IGNORE_CACHE` (default: `/tmp/epyon-ignore-cache.json`)

**Output Format:**
```json
{
  "ignores": [
    {
      "type": "cve",
      "value": "CVE-2024-1234",
      "reason": "False positive - not exploitable in our configuration",
      "expires": "2026-12-31",
      "approved_by": "security@example.com",
      "paths": ["src/legacy/"],
      "expired": false
    }
  ]
}
```

**Features:**
- Validates expiration dates against current date
- Requires PyYAML module (gracefully degrades if missing)
- Handles YAML parsing errors
- Deduplicates by `(type, value)`

**YAML Input Format:**
```yaml
ignores:
  - type: cve
    value: CVE-2024-1234
    reason: "Justification text"
    expires: 2026-12-31
    approved_by: security@example.com
    paths:
      - src/legacy/
```

---

### `parse_findings_file()`
**Location:** [scripts/shell/get-scan-metrics.sh:187](../scripts/shell/get-scan-metrics.sh#L187)

**Purpose:** Parses `security-findings-summary.json` into shell severity variables.

**Parameters:**
- `$1`: Path to `security-findings-summary.json`

**Sets Shell Variables:**
- `CRITICAL_COUNT`
- `HIGH_COUNT`
- `MEDIUM_COUNT`
- `LOW_COUNT`

**Used By:** `get-scan-metrics.sh` to extract severity counts for reporting.

---

## Parser Usage Patterns

### Web API Usage
```python
from pathlib import Path
from web.api.parsers import load_scan, parse_scan_findings

epyon_root = Path("/path/to/epyon")
scan_dir = epyon_root / "scans" / "myapp_2026-07-02_14-30-00"

# Load complete scan data (preferred)
scan_data = load_scan(scan_dir, epyon_root)

# Or load raw findings only
findings = parse_scan_findings(scan_dir)
```

### Shell Script Usage
```bash
source scripts/shell/parse-epyon-ignore.sh

# Parse ignore rules
TARGET_DIR="/path/to/target/repo"
IGNORE_CACHE="/tmp/epyon-ignore-cache.json"
parse_ignore_rules

# Use parsed rules
IGNORE_JSON=$(cat "$IGNORE_CACHE")
```

---

## Error Handling

All parsers follow these conventions:

1. **File Not Found:** Return empty list `[]` or `None` (never throw)
2. **Invalid JSON:** Return empty list `[]` or `None`
3. **Missing Keys:** Use `.get()` with defaults, never fail on missing data
4. **Type Mismatches:** Validate types, skip invalid entries
5. **Path Traversal:** Validate all paths are within expected directories

---

## Performance Considerations

1. **Lazy Loading:** Most parsers only called when needed by `load_scan()`
2. **Summary Priority:** `load_scan()` prefers pre-built `security-findings-summary.json` over raw parsing
3. **Package Cap:** `load_sbom_packages()` caps at 2000 packages for API response size
4. **Symlink Skipping:** `_json_files_in()` skips symlinks by default to avoid circular reads
5. **Sorted Iteration:** Directory listings are sorted for deterministic behavior

---

## Security Considerations

1. **Path Traversal Prevention:** All path operations validated against expected root
2. **No Arbitrary Code Execution:** Pure data parsing, no eval or exec
3. **UTF-8 Handling:** Explicit encoding with error handling
4. **Regex Safety:** All regex patterns are pre-compiled and tested
5. **Secret Protection:** Never log or echo file contents that may contain secrets

---

## Version History

- **2026-07-02:** Initial comprehensive reference created
- Parsers last updated: 2026-07-02 (per file timestamps)

---

**See Also:**
- [SCAN_MATRIX.md](SCAN_MATRIX.md) - Security layer details
- [SCAN_DIRECTORY_ARCHITECTURE.md](SCAN_DIRECTORY_ARCHITECTURE.md) - Directory structure
- [IGNORE_RULES_GUIDE.md](IGNORE_RULES_GUIDE.md) - Suppression rule syntax
