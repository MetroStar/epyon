# ML/AI Security Guide

**Comprehensive Guide to Machine Learning and Artificial Intelligence Security in Epyon**

---

## Table of Contents

- [Overview](#overview)
- [Threat Model](#threat-model)
- [ML Security Layers](#ml-security-layers)
  - [Layer 14: Comprehensive Model File Analysis](#layer-14-comprehensive-model-file-analysis)
  - [Layer 18: Model Provenance & Threat Intelligence](#layer-18-model-provenance--threat-intelligence)
  - [Layer 19: Inference Environment Security](#layer-19-inference-environment-security)
  - [Layer 20: ML Runtime Behavioral Analysis](#layer-20-ml-runtime-behavioral-analysis)
  - [Layer 8.5: ML-Aware Dependency Analysis](#layer-85-ml-aware-dependency-analysis)
  - [Layer 13: ML STIG Compliance](#layer-13-ml-stig-compliance)
- [Usage Examples](#usage-examples)
- [Best Practices](#best-practices)
- [Threat Intelligence](#threat-intelligence)
- [Performance Considerations](#performance-considerations)
- [Troubleshooting](#troubleshooting)

---

## Overview

Epyon provides **five integrated ML/AI security capabilities** designed to detect and mitigate supply chain attacks, malicious model exploits, and infrastructure misconfigurations in machine learning applications. These capabilities were developed in response to real-world attacks like the 2026 Hugging Face sandbox escape incident, where attackers used malicious pickle files and PyTorch JIT exploits to break out of execution sandboxes.

### What Makes ML Security Different?

Traditional application security focuses on vulnerabilities in source code, dependencies, and infrastructure. ML security adds three unique attack surfaces:

1. **Serialized Model Files**: Pickle, PyTorch, ONNX, and TensorFlow files can contain executable code that runs when the model loads
2. **Model Provenance**: Models downloaded from third-party repositories may be backdoored, poisoned, or typosquatted
3. **Inference Infrastructure**: ML workloads often run as privileged containers with GPU access, creating expanded attack surfaces

Epyon addresses all three surfaces with **four dedicated security layers** (14, 18, 19, 20) plus **two enhanced existing layers** (8.5, 13).

### Coverage Summary

| Layer | Capability | Attack Surface | Detection Method |
|-------|------------|----------------|------------------|
| **14** | Comprehensive Model File Analysis | Malicious model files | Static analysis of pickle/PyTorch/ONNX/TensorFlow formats |
| **18** | Model Provenance & Threat Intelligence | Supply chain compromise | Blocklist matching, typosquatting detection, signature verification |
| **19** | Inference Environment Security | Infrastructure misconfiguration | Static Dockerfile/K8s manifest analysis |
| **20** | ML Runtime Behavioral Analysis | Malicious runtime behavior | Sandboxed model loading with behavior monitoring |
| **8.5** | ML-Aware Dependency Analysis | Dependency vulnerabilities & typosquatting | Enhanced pip-audit with ML framework awareness |
| **13** | ML STIG Compliance | Policy compliance | AI-powered assessment of 15 ML-specific security controls |

---

## Threat Model

Epyon's ML security capabilities defend against the following attack vectors:

### 1. Malicious Model Exploits

**Attack**: Attacker embeds malicious code in a serialized model file (pickle, PyTorch checkpoint, ONNX model)

**Examples**:
- **Pickle arbitrary code execution**: Using `__reduce__` to call `os.system()`, `subprocess.Popen()`, or `socket.connect()`
- **PyTorch JIT exploits**: Malicious TorchScript code embedded in `.pt` files that executes on model load
- **ONNX operator injection**: Custom operators that perform network calls or file system access
- **TensorFlow SavedModel manipulation**: Malicious ops embedded in graph definitions

**Epyon Defense**: **Layer 14** scans all model files for dangerous imports, malicious opcodes, and obfuscation patterns

### 2. Supply Chain Attacks

**Attack**: Attacker compromises a model repository or publishes a malicious lookalike model

**Examples**:
- **Typosquatting**: Publishing `bert-base-uncased-v2` to trick users looking for `bert-base-uncased`
- **Account takeover**: Compromising a popular model author's account to push backdoored models
- **Dependency confusion**: Publishing malicious models with names similar to internal organizational models

**Epyon Defense**: **Layer 18** checks model hashes against blocklists, detects typosquatting via Levenshtein distance, verifies GPG signatures, and checks Hugging Face author reputation

### 3. Inference Infrastructure Exploits

**Attack**: Attacker escapes from an inference container to compromise the host or cluster

**Examples**:
- **Privileged containers**: Running inference as root with `--privileged` flag
- **Dangerous capabilities**: Containers with `CAP_SYS_ADMIN` or `CAP_SYS_MODULE` can load kernel modules
- **Read-write root filesystem**: Allows attackers to modify system binaries after initial compromise
- **No AppArmor/seccomp**: Disabling Linux security modules removes sandboxing protection

**Epyon Defense**: **Layer 19** scans Dockerfile, docker-compose.yml, and Kubernetes manifests for 25+ security misconfigurations

### 4. Malicious Runtime Behavior

**Attack**: Model performs unexpected actions when loaded (network calls, file access, subprocess execution)

**Examples**:
- **Data exfiltration**: Model connects to attacker-controlled server to leak sensitive training data or API keys
- **Cryptocurrency mining**: Model spawns background processes to mine cryptocurrency
- **Lateral movement**: Model scans internal network or attempts SSH connections to other hosts

**Epyon Defense**: **Layer 20** loads models in an isolated Docker/Podman sandbox with network disabled and monitors for suspicious behavior

### 5. Dependency Vulnerabilities

**Attack**: Exploiting known vulnerabilities in ML frameworks or typosquatted ML packages

**Examples**:
- **Known CVEs**: Using vulnerable TensorFlow, PyTorch, or transformers versions with public exploits
- **Typosquatted packages**: Installing `tensorfIow` (capital I) instead of `tensorflow`

**Epyon Defense**: **Layer 8.5** highlights ML package CVEs and detects typosquatting with Levenshtein distance < 3

---

## ML Security Layers

### Layer 14: Comprehensive Model File Analysis

**Tool**: `run-picklescan.py` (enhanced Python scanner)

**Purpose**: Detect malicious code embedded in serialized model files across five formats

**Formats Supported**:
- **Pickle** (`.pkl`, `.pickle`, `.pth`, `.bin`, `.ckpt`, `.npy`, `.npz`, `.joblib`) — Python serialization
- **PyTorch** (`.pt`, `.pth`) — PyTorch JIT TorchScript analysis
- **ONNX** (`.onnx`) — ONNX operator inspection
- **TensorFlow** (SavedModel directories, `.pb`, `.h5`, `.hdf5`) — TensorFlow graph analysis
- **Config files** (`.json`, `.yaml`, `.yml` in model directories) — Obfuscation detection

#### What It Detects

**Pickle Files**:
- Dangerous imports: `os.system`, `subprocess`, `socket`, `eval`, `exec`, `compile`, `__import__`, `ctypes`, `requests`, `urllib`, `shutil.rmtree`
- Malicious opcodes via `picklescan` library (when available)

**PyTorch Files**:
- JIT TorchScript code containing network/file/subprocess operations
- Suspicious function calls: `torch.jit.load`, `torch.serialization._legacy_load`

**ONNX Files**:
- Custom operators (any op outside standard ONNX spec)
- Network-related operators
- File I/O operators

**TensorFlow Files**:
- Malicious TensorFlow ops: `PyFunc`, `PyFuncStateless`
- Network/file/subprocess ops in graph definitions

**Config Files**:
- Base64 encoding (potential obfuscation)
- Hex escapes (`\x`)
- Unicode escapes (`\u`, `\U`)

#### Output Schema

```json
[
  {
    "file": "models/bert-malicious.pkl",
    "type": "dangerous_import",
    "severity": "critical",
    "description": "Dangerous import detected: subprocess",
    "evidence": "Found import of 'subprocess.Popen' at opcode offset 42",
    "recommendation": "Do not load this model. Review model source and re-download from trusted repository."
  }
]
```

#### Usage

```bash
# Scan all model formats
python3 scripts/shell/run-picklescan.py \
  --target /path/to/model-repo \
  --scan-dir scans/myapp_2026-07-30_10-00-00 \
  --app-name myapp \
  --formats pickle,pytorch,onnx,tensorflow,config

# Scan only pickle files
python3 scripts/shell/run-picklescan.py \
  --target /path/to/model-repo \
  --scan-dir scans/myapp_2026-07-30_10-00-00 \
  --app-name myapp \
  --formats pickle
```

**Auto-enabled in**: `nightly`, `full` scan modes  
**Manual control**: `RUN_PICKLESCAN=true/false` or `SKIP_PICKLESCAN=true`

---

### Layer 18: Model Provenance & Threat Intelligence

**Tool**: `run-model-provenance-check.py`

**Purpose**: Validate model authenticity and detect supply chain compromises

**Checks Performed**:

1. **Blocklist Matching** (`ml-blocklist.json`):
   - SHA256 hash against known malicious models
   - Author username against compromised accounts
   - Repository name against compromised repos
   - Model name against suspicious patterns (e.g., `.*cracked.*`, `.*nulled.*`)

2. **Typosquatting Detection**:
   - Levenshtein distance < 3 from popular models (bert-base-uncased, gpt2, llama, mistral, etc.)
   - Excludes exact matches (distance == 0)

3. **Signature Verification** (optional):
   - GPG signature validation for signed model files
   - Requires `.asc` signature file alongside model

4. **Hugging Face Metadata** (optional):
   - Checks for Hugging Face metadata directory (`.huggingface/`)
   - Validates `config.json` structure
   - Requires `HF_TOKEN` environment variable

5. **Author Reputation** (optional):
   - Queries Hugging Face Hub API for author stats
   - Flags newly created accounts or accounts with few models
   - Requires `HF_TOKEN` environment variable

6. **Model Card Compliance**:
   - Checks for README.md or model card
   - Validates documentation quality

#### Threat Intelligence Blocklist

The blocklist at `configuration/ml-blocklist.json` contains:

```json
{
  "version": "1.0.0",
  "last_updated": "2026-07-30T00:00:00Z",
  "blocked_hashes": [
    "sha256:abc123...",
    "sha256:def456..."
  ],
  "blocked_authors": [
    "malicious-user-2026",
    "compromised-account"
  ],
  "blocked_repos": [
    "org/backdoored-model"
  ],
  "patterns": {
    "suspicious_model_names": [
      ".*cracked.*",
      ".*free-premium.*",
      ".*unlocked.*",
      ".*nulled.*"
    ],
    "typosquat_targets": [
      "bert-base-uncased",
      "gpt2",
      "llama-2-7b",
      "mistral-7b-v0.1",
      "roberta-base",
      "t5-base",
      "vit-base-patch16-224"
    ]
  }
}
```

**Updating the Blocklist**:
1. Monitor security advisories from Hugging Face, NCSC, CISA
2. Add confirmed malicious hashes/authors/repos to blocklist
3. Commit and push to version control
4. Blocklist is read at scan time (no rebuild required)

#### Output Schema

```json
[
  {
    "file": "models/bert-base-uncased-v2.bin",
    "type": "typosquatting",
    "severity": "high",
    "description": "Potential typosquatting attack detected",
    "evidence": "Model name 'bert-base-uncased-v2' has Levenshtein distance 2 from known model 'bert-base-uncased'",
    "recommendation": "Verify this is the intended model. Check official repository for correct model name."
  }
]
```

#### Usage

```bash
# Basic provenance check
python3 scripts/shell/run-model-provenance-check.py \
  --target /path/to/model-repo \
  --scan-dir scans/myapp_2026-07-30_10-00-00 \
  --app-name myapp

# With custom blocklist and threat feed
python3 scripts/shell/run-model-provenance-check.py \
  --target /path/to/model-repo \
  --scan-dir scans/myapp_2026-07-30_10-00-00 \
  --app-name myapp \
  --blocklist-path /custom/blocklist.json \
  --threat-feed-url https://internal-security/ml-threats.json

# With Hugging Face integration
HF_TOKEN=hf_xxx python3 scripts/shell/run-model-provenance-check.py \
  --target /path/to/model-repo \
  --scan-dir scans/myapp_2026-07-30_10-00-00 \
  --app-name myapp \
  --hf-token $HF_TOKEN
```

**Auto-enabled in**: `nightly`, `full` scan modes  
**Manual control**: `RUN_MODEL_PROVENANCE=true/false` or `SKIP_MODEL_PROVENANCE=true`

---

### Layer 19: Inference Environment Security

**Tool**: `run-inference-security-scan.sh` (pure bash)

**Purpose**: Detect infrastructure misconfigurations in inference deployment files

**Files Scanned**:
- `Dockerfile`, `*.dockerfile`, `Dockerfile.*`
- `docker-compose.yml`, `docker-compose.*.yml`, `compose.yml`
- `*.yaml`, `*.yml` (Kubernetes manifests)

**Checks Performed**:

**Dockerfile Analysis** (10 checks):
- Root user execution (no `USER` directive or `USER root`)
- Missing `--chown` on `COPY` instructions
- Privileged ports < 1024 in `EXPOSE`
- Missing health check
- `apt-get update` without `&&` chaining (layer bloat)

**Docker Compose Analysis** (8 checks):
- `privileged: true` flag
- Dangerous capabilities: `ALL`, `SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`
- `security_opt: apparmor:unconfined`
- `security_opt: seccomp:unconfined`
- `/var/run/docker.sock` mounts (Docker socket exposure)
- No resource limits (`mem_limit`, `cpus`)

**Kubernetes Manifest Analysis** (15 checks):
- Missing `runAsNonRoot: true`
- Missing `runAsUser` (defaults to root)
- `privileged: true` in `securityContext`
- `allowPrivilegeEscalation: true`
- Missing `readOnlyRootFilesystem: true`
- Dangerous capabilities not dropped (`SYS_ADMIN`, `SYS_MODULE`, `NET_ADMIN`)
- `hostNetwork: true`
- `hostPID: true`
- `hostIPC: true`

#### Output Schema

```json
[
  {
    "file": "Dockerfile",
    "type": "dockerfile_root_user",
    "severity": "high",
    "description": "Container runs as root user",
    "evidence": "No USER directive found in Dockerfile",
    "recommendation": "Add 'USER nonroot' directive after installing dependencies"
  }
]
```

#### Usage

```bash
# Scan all deployment files
./scripts/shell/run-inference-security-scan.sh \
  /path/to/app \
  scans/myapp_2026-07-30_10-00-00 \
  myapp
```

**Auto-enabled in**: `nightly`, `full` scan modes  
**Manual control**: `RUN_INFERENCE_SECURITY=true/false` or `SKIP_INFERENCE_SECURITY=true`

---

### Layer 20: ML Runtime Behavioral Analysis

**Tool**: `run-ml-runtime-analysis.py`

**Purpose**: Detect malicious behavior by actually loading models in an isolated sandbox

**⚠️ WARNING**: This layer executes potentially malicious code in a sandbox. **Resource intensive and slow.** Opt-in only.

**How It Works**:

1. **Model Discovery**: Finds up to 5 model files (`.pkl`, `.pt`, `.onnx`, SavedModel dirs)
2. **Sandbox Creation**: Spins up Docker/Podman container with:
   - `--network none` (no network access)
   - `--read-only` (read-only root filesystem)
   - `--security-opt no-new-privileges`
   - `--cap-drop ALL` (no Linux capabilities)
   - 60-second timeout
3. **Behavior Monitoring**: Watches for:
   - Network connection attempts (socket creation, DNS queries)
   - File access outside model directory
   - Subprocess execution
   - Timeout (indicates infinite loop or resource exhaustion)
4. **Analysis**: Generates findings for any suspicious behavior

**Behavior Detection**:

```python
# Network attempts
"socket.gaierror"  # DNS lookup failed (no network)
"ConnectionRefused"
"Network is unreachable"

# File access
"PermissionError"  # Tried to write to read-only filesystem
"Read-only file system"

# Subprocess execution
"subprocess.Popen"
"os.system"

# Timeout
"Timeout" in stderr  # Model took >60s to load
```

#### Output Schema

```json
[
  {
    "file": "models/malicious.pkl",
    "type": "network_communication",
    "severity": "critical",
    "description": "Model attempted network communication during loading",
    "evidence": "socket.gaierror: [Errno -3] Temporary failure in name resolution",
    "recommendation": "Do not use this model. Network calls during model loading indicate malicious behavior."
  }
]
```

#### Usage

```bash
# Enable Layer 20 (requires Docker or Podman)
RUN_ML_RUNTIME=true python3 scripts/shell/run-ml-runtime-analysis.py \
  --target /path/to/model-repo \
  --scan-dir scans/myapp_2026-07-30_10-00-00 \
  --app-name myapp \
  --timeout 60 \
  --max-models 5
```

**Enabled in**: None (always opt-in)  
**Manual control**: `RUN_ML_RUNTIME=true` (required)

**Requirements**:
- Docker or Podman installed
- Python 3.11+ base image available
- Sufficient system resources (1 CPU, 2GB RAM per model)

**Performance Impact**:
- Scans 5 models max (configurable with `--max-models`)
- ~30-60 seconds per model
- Total time: 2.5-5 minutes for full scan

---

### Layer 8.5: ML-Aware Dependency Analysis

**Tool**: `analyze-ml-dependencies.py` (enhancement to existing pip-audit layer)

**Purpose**: Highlight ML framework vulnerabilities and detect typosquatted ML packages

**Enhancements Over Standard pip-audit**:

1. **ML Package Recognition**: Identifies 40+ ML/AI packages (tensorflow, torch, transformers, scikit-learn, etc.)
2. **Typosquatting Detection**: Checks dependency names against known ML packages with Levenshtein distance 1-2
3. **ML-Specific CVE Highlighting**: Flags high/critical CVEs in ML frameworks

**ML Packages Recognized**:
```python
{
    "tensorflow", "tensorflow-cpu", "tensorflow-gpu",
    "torch", "torchvision", "torchaudio",
    "transformers", "datasets", "tokenizers",
    "scikit-learn", "scipy", "numpy", "pandas",
    "keras", "opencv-python", "pillow",
    "xgboost", "lightgbm", "catboost",
    # ... 40+ total
}
```

**Typosquatting Targets**:
```python
[
    "tensorflow", "torch", "transformers",
    "scikit-learn", "numpy", "pandas",
    "opencv-python", "pillow", "scipy", "keras"
]
```

#### Output Schema

```json
{
  "ml_vulnerabilities": [
    {
      "name": "tensorflow",
      "version": "2.10.0",
      "id": "CVE-2023-XXXXX",
      "severity": "high",
      "description": "TensorFlow XLA compiler vulnerability"
    }
  ],
  "typosquat_warnings": [
    {
      "installed": "tensorfIow",
      "intended": "tensorflow",
      "distance": 1
    }
  ],
  "high_severity_ml_cves": 3
}
```

#### Usage

ML dependency analysis runs automatically as part of Layer 8.5 (pip-audit). No additional flags required.

```bash
# Layer 8.5 runs in quick/nightly/full modes by default
./epyon.sh /path/to/app

# Skip Layer 8.5
SKIP_PIP_AUDIT=true ./epyon.sh /path/to/app
```

**Auto-enabled in**: `quick`, `nightly`, `full` scan modes  
**Manual control**: `SKIP_PIP_AUDIT=true`

---

### Layer 13: ML STIG Compliance

**Tool**: `run-stig-assessment.py` (enhancement to existing STIG layer)

**Purpose**: Assess compliance with 15 ML-specific security controls

**ML Security Controls** (from `ML-Security-Checklist.json`):

**Model Security** (ML-001 to ML-004):
- ML-001: Pickle files scanned for dangerous imports
- ML-002: Model files scanned for obfuscation patterns
- ML-003: ONNX models scanned for malicious operators
- ML-004: PyTorch JIT code scanned for exploits

**Supply Chain Security** (ML-005 to ML-009):
- ML-005: Model hashes checked against blocklist
- ML-006: Model authors checked against blocklist
- ML-007: Model names checked for typosquatting
- ML-008: Model signatures verified (GPG)
- ML-009: Model cards present and complete

**Infrastructure Security** (ML-010 to ML-012):
- ML-010: Inference containers run as non-root
- ML-011: Kubernetes securityContext properly configured
- ML-012: Privileged mode disabled

**Runtime Security** (ML-013 to ML-015):
- ML-013: No network communication during model loading
- ML-014: No unauthorized file access during model loading
- ML-015: No subprocess execution during model loading

#### Assessment Logic

Each control is assessed based on findings from Layers 14, 18, 19, 20:

```python
# Example: ML-001 assessment
picklescan_findings = read_json("picklescan-results.json")
dangerous_imports = [f for f in picklescan_findings if f["type"] == "dangerous_import"]

if dangerous_imports:
    status = "Open"
    confidence = 95
    evidence = f"Found {len(dangerous_imports)} files with dangerous imports"
else:
    status = "Not a Finding"
    confidence = 90
    evidence = "No dangerous imports detected in pickle files"
```

**Freeze Logic**: Controls with `confidence >= 85` and status `Not a Finding` or `Not Applicable` are frozen and carried forward from previous scans without re-assessment.

#### Output

**JSON** (`stig-results-ml.json`):
```json
{
  "assessments": {
    "ML-001": {
      "status": "Open",
      "evidence": "Found 2 files with dangerous imports: subprocess, socket",
      "confidence": 95
    }
  },
  "token_usage": {
    "prompt_tokens": 1500,
    "completion_tokens": 500,
    "total_cost": 0.015
  }
}
```

**Markdown** (`findings-{app}-ml.md`): Human-readable report with evidence and recommendations

**CKLB** (`findings-{app}-ml.cklb`): DISA Checklist format for STIG Manager import

#### Usage

ML STIG controls are assessed automatically when `run_stig=true` in `full` or `stig` scan modes:

```bash
# Run full scan with STIG assessment
OPENAI_API_KEY=sk-xxx ./epyon.sh /path/to/app

# STIG-only mode (includes ML controls)
python3 scripts/shell/run-stig-assessment.py \
  --stigs-dir configuration/stigs \
  --target /path/to/app \
  --scan-dir scans/myapp_2026-07-30_10-00-00 \
  --app-name myapp
```

**Auto-enabled in**: `full` (with `run_stig=true`), `stig` scan modes  
**Manual control**: `RUN_STIG=true`  
**Requires**: `OPENAI_API_KEY` environment variable

---

## Usage Examples

### Example 1: Quick ML Security Check (Layers 14, 18, 8.5 only)

Scan a Hugging Face model repository for malicious files and supply chain issues:

```bash
# Clone model from Hugging Face
git clone https://huggingface.co/bert-base-uncased /tmp/bert-model

# Run quick scan (Layers 1, 2, 7, 8, 8.5 + 14, 18)
RUN_PICKLESCAN=true RUN_MODEL_PROVENANCE=true \
  ./epyon.sh /tmp/bert-model
```

**Expected Output**:
- Layer 14: Scans `.pkl`, `.bin` weight files for malicious opcodes
- Layer 18: Validates model hash, checks for typosquatting, verifies README
- Layer 8.5: Checks `requirements.txt` for ML CVEs and typosquatted packages

### Example 2: Full ML Security Audit (All Layers)

Comprehensive security audit of an ML inference service:

```bash
# Run full scan with all ML layers including runtime analysis
OPENAI_API_KEY=sk-xxx \
RUN_ML_RUNTIME=true \
  ./epyon.sh /path/to/ml-service --app-name ml-service
```

**Expected Output**:
- Layer 14: Multi-format model file analysis (pickle, PyTorch, ONNX, TensorFlow)
- Layer 18: Provenance validation, blocklist checks, typosquatting detection
- Layer 19: Dockerfile/K8s security analysis (privileged mode, root user, capabilities)
- Layer 20: Sandboxed model loading with behavior monitoring (network, files, subprocess)
- Layer 8.5: ML dependency CVE highlighting and typosquatting
- Layer 13: 15 ML STIG controls assessed with AI

### Example 3: CI/CD Integration (GitHub Actions)

Add ML security to your GitHub Actions workflow:

```yaml
# .github/workflows/ml-security-scan.yml
name: ML Security Scan
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 2 * * 0'  # Weekly Sunday 2am

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Epyon ML Security Scan
        uses: deptofdefense/epyon/.github/workflows/epyon-scan.yml@main
        with:
          target_directory: '.'
          app_name: ${{ github.event.repository.name }}
          scan_mode: full
          run_model_provenance: true
          run_inference_security: true
          # Layer 20 disabled in CI (too slow)
          run_ml_runtime: false
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          HF_TOKEN: ${{ secrets.HF_TOKEN }}
```

### Example 4: Kubernetes Deployment Security

Scan a Kubernetes manifest for inference security issues:

```bash
# Scan Kubernetes deployment files
./scripts/shell/run-inference-security-scan.sh \
  /path/to/k8s-manifests \
  scans/k8s-scan_$(date +%Y-%m-%d_%H-%M-%S) \
  k8s-inference

# Expected findings:
# - Missing runAsNonRoot: true
# - Missing readOnlyRootFilesystem: true
# - Dangerous capabilities not dropped
```

### Example 5: Updating the Threat Intelligence Blocklist

Add a newly discovered malicious model to the blocklist:

```bash
# Calculate SHA256 of malicious model
sha256sum malicious-model.bin
# Output: abc123def456... malicious-model.bin

# Edit blocklist
vim configuration/ml-blocklist.json

# Add hash to blocked_hashes array
{
  "version": "1.0.1",
  "last_updated": "2026-07-30T15:30:00Z",
  "blocked_hashes": [
    "sha256:abc123def456...",  # Added: malicious-model.bin from CVE-2026-XXXXX
    # ... existing entries
  ]
}

# Commit and push
git add configuration/ml-blocklist.json
git commit -m "chore: add CVE-2026-XXXXX malicious model hash to blocklist"
git push
```

---

## Best Practices

### 1. Defense in Depth

Run **multiple ML security layers** together for comprehensive coverage:

```bash
# Minimum recommended ML security stack
RUN_PICKLESCAN=true \
RUN_MODEL_PROVENANCE=true \
RUN_INFERENCE_SECURITY=true \
  ./epyon.sh /path/to/ml-app
```

**Why**: Each layer detects different attack vectors. Layer 14 catches malicious file content, Layer 18 catches supply chain compromises, Layer 19 catches infrastructure misconfigurations.

### 2. Use Layer 20 Sparingly

**DO**:
- Use Layer 20 for high-risk models (untrusted sources, newly discovered, suspicious provenance)
- Run Layer 20 in isolated CI environments with resource limits
- Set conservative timeouts (`--timeout 30`)

**DON'T**:
- Enable Layer 20 in every scan (too slow)
- Run Layer 20 on production infrastructure (security risk)
- Skip Layers 14/18 in favor of only Layer 20 (defense in depth)

### 3. Keep the Blocklist Updated

**Sources for Threat Intelligence**:
- [Hugging Face Security Advisories](https://huggingface.co/docs/hub/security)
- [NCSC AI Security Guidelines](https://www.ncsc.gov.uk/)
- [CISA Advisories](https://www.cisa.gov/cybersecurity-advisories)
- [MITRE ATT&CK for ML](https://attack.mitre.org/)
- Security mailing lists (oss-security, ML security forums)

**Update Frequency**: Review blocklist monthly or immediately after major incidents

### 4. Harden Inference Infrastructure

Follow the **principle of least privilege**:

```dockerfile
# Good Dockerfile example
FROM python:3.11-slim

# Create non-root user
RUN useradd -m -u 1000 mluser

# Install dependencies as root
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

# Switch to non-root user
USER mluser
WORKDIR /app

# Copy application files with correct ownership
COPY --chown=mluser:mluser . /app

# Run as non-root
CMD ["python", "serve.py"]
```

```yaml
# Good Kubernetes example
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ml-inference
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: inference
        image: myorg/ml-service:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
        resources:
          limits:
            memory: "2Gi"
            cpu: "1"
```

### 5. Verify Model Signatures

For critical models, require GPG signatures:

```bash
# Model author signs model
gpg --detach-sign --armor model.bin
# Creates model.bin.asc

# Epyon verifies signature automatically if .asc file present
RUN_MODEL_PROVENANCE=true ./epyon.sh /path/to/model

# Manual GPG verification
gpg --verify model.bin.asc model.bin
```

### 6. Monitor ML Dependencies

ML frameworks have frequent security updates. Pin versions but scan regularly:

```txt
# requirements.txt
tensorflow==2.15.0  # Pinned for reproducibility
torch==2.1.0
transformers==4.35.0
```

```bash
# Weekly dependency security scan
SKIP_PICKLESCAN=true \
SKIP_MODEL_PROVENANCE=true \
SKIP_INFERENCE_SECURITY=true \
  ./epyon.sh /path/to/ml-app  # Focus on Layer 8.5
```

### 7. Implement Model Validation Gates

Fail CI/CD on critical ML security findings:

```yaml
# GitHub Actions: Fail on ML critical findings
- name: Check ML Security Results
  run: |
    # Count critical findings from ML layers
    CRITICAL=$(jq '[.critical_findings[] | select(.tool | IN("picklescan", "model-provenance", "inference-security"))] | length' \
      scans/*/security-findings-summary.json)
    
    if [ "$CRITICAL" -gt 0 ]; then
      echo "::error::Found $CRITICAL critical ML security issues"
      exit 1
    fi
```

---

## Threat Intelligence

### Maintaining the Blocklist

The ML threat intelligence blocklist (`configuration/ml-blocklist.json`) should be maintained as a **living document**.

**Blocklist Structure**:

```json
{
  "version": "1.0.0",
  "last_updated": "2026-07-30T00:00:00Z",
  
  "blocked_hashes": [
    "sha256:abc123...",  // Full SHA256 hash of malicious model file
    "sha256:def456..."
  ],
  
  "blocked_authors": [
    "malicious-user-2026",  // HuggingFace username or email
    "compromised-account"
  ],
  
  "blocked_repos": [
    "org/backdoored-model",  // HuggingFace repo in org/name format
    "username/malicious-checkpoint"
  ],
  
  "patterns": {
    "suspicious_model_names": [
      ".*cracked.*",      // Regex: matches any model with "cracked" in name
      ".*free-premium.*", // Regex: common piracy indicators
      ".*unlocked.*",
      ".*nulled.*",
      ".*hacked.*"
    ],
    
    "typosquat_targets": [
      "bert-base-uncased",     // Popular models to protect
      "gpt2",
      "llama-2-7b",
      "mistral-7b-v0.1",
      "roberta-base",
      "t5-base",
      "vit-base-patch16-224"
    ]
  }
}
```

**Update Process**:

1. **Discovery**: Monitor security advisories, incident reports, and security mailing lists
2. **Verification**: Confirm malicious activity (don't add false positives)
3. **Documentation**: Comment why each entry was added (include CVE or incident reference)
4. **Update**: Edit `ml-blocklist.json`, increment version, update `last_updated`
5. **Test**: Run scan against known-good models to ensure no false positives
6. **Commit**: Git commit with descriptive message
7. **Distribute**: Push to central repository; all scans read latest blocklist

**Version Control**: Always commit blocklist updates to git. Historical versions help with incident response and forensics.

### Community Threat Feeds

Epyon supports remote threat feeds via `--threat-feed-url`:

```bash
# Use organization's internal threat feed
python3 scripts/shell/run-model-provenance-check.py \
  --target /path/to/model \
  --scan-dir scans/myapp_2026-07-30_10-00-00 \
  --app-name myapp \
  --threat-feed-url https://security.example.org/ml-threats.json
```

**Threat Feed Format**: Same JSON schema as `ml-blocklist.json`

**SSRF Protection**: Threat feed URLs are validated against private IP ranges. Only public URLs are allowed.

---

## Performance Considerations

### Layer 14: Comprehensive Model File Analysis

**Performance**: Fast (0.5-2 seconds per model file)

**Resource Usage**:
- CPU: Minimal (single-threaded Python)
- Memory: <100MB
- Disk: No temp files

**Optimization**:
- Scans only model files (not all files)
- Skips binary analysis if file extension doesn't match

**Bottlenecks**: Large model files (>2GB) may take 5-10 seconds to scan

### Layer 18: Model Provenance & Threat Intelligence

**Performance**: Fast (1-3 seconds per model)

**Resource Usage**:
- CPU: Minimal (hash computation, string matching)
- Memory: <50MB
- Network: Optional HuggingFace API calls (<1KB per model)

**Optimization**:
- Blocklist loaded once per scan (not per model)
- HuggingFace API calls cached for 1 hour

**Bottlenecks**: HuggingFace API rate limiting (60 req/hour without token, 5000 req/hour with `HF_TOKEN`)

### Layer 19: Inference Environment Security

**Performance**: Very fast (<1 second)

**Resource Usage**:
- CPU: Minimal (bash text parsing)
- Memory: <10MB
- Disk: No temp files

**Optimization**:
- Pure bash (no Python subprocess overhead)
- Regex-based (no external tools)

**Bottlenecks**: None (instant for typical projects)

### Layer 20: ML Runtime Behavioral Analysis

**Performance**: Slow (30-60 seconds per model)

**⚠️ Resource Usage**:
- CPU: 1 core per model (Docker container)
- Memory: 2GB per model (Python + ML framework)
- Disk: 500MB per model (container image)
- Network: None (isolated sandbox)

**Optimization**:
- Default limit: 5 models per scan (configurable with `--max-models`)
- Default timeout: 60 seconds (configurable with `--timeout`)
- Skips models >500MB (too large to safely load)

**Bottlenecks**: 
- Docker image pull (first run only): ~500MB download
- Model loading time: Varies by framework (PyTorch faster than TensorFlow)

**When to Use**:
- ✅ High-risk models from untrusted sources
- ✅ Weekly/monthly comprehensive audits
- ✅ Post-incident forensics
- ❌ Every CI/CD run (too slow)
- ❌ Production scans (security risk)

**Total Scan Time Estimates**:

| Layers Enabled | Small Project | Medium Project | Large ML Repo |
|----------------|---------------|----------------|---------------|
| 14 + 18 + 19   | 5 seconds     | 15 seconds     | 30 seconds    |
| 14 + 18 + 19 + 20 | 2.5 minutes | 5 minutes      | 6 minutes     |

---

## Troubleshooting

### "picklescan library not found"

**Symptom**: Layer 14 warnings about picklescan library

**Cause**: `picklescan` Python package not installed

**Solution**:
```bash
pip install picklescan
# Or install from requirements
pip install -r requirements.txt
```

**Note**: Layer 14 gracefully degrades — falls back to custom dangerous import detection if picklescan unavailable

---

### "No Docker/Podman found for Layer 20"

**Symptom**: Layer 20 fails with "Docker not found" error

**Cause**: Layer 20 requires Docker or Podman to create isolation sandbox

**Solution**:
```bash
# macOS
brew install docker

# Ubuntu/Debian
sudo apt-get install docker.io

# Verify Docker is running
docker ps
```

**Alternative**: Skip Layer 20 if Docker unavailable:
```bash
RUN_ML_RUNTIME=false ./epyon.sh /path/to/app
```

---

### "HuggingFace API rate limit exceeded"

**Symptom**: Layer 18 warnings about API rate limiting

**Cause**: HuggingFace API allows only 60 requests/hour without authentication

**Solution**:
```bash
# Create HF token at https://huggingface.co/settings/tokens
export HF_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxx

# Re-run scan with token
HF_TOKEN=$HF_TOKEN ./epyon.sh /path/to/app
```

**Note**: With `HF_TOKEN`, rate limit increases to 5000 req/hour

---

### "Layer 20 timeout on every model"

**Symptom**: All models time out after 60 seconds in Layer 20

**Cause**: Models are too large to load in default 60-second timeout

**Solution**:
```bash
# Increase timeout to 120 seconds
python3 scripts/shell/run-ml-runtime-analysis.py \
  --target /path/to/model \
  --scan-dir scans/myapp_2026-07-30_10-00-00 \
  --app-name myapp \
  --timeout 120
```

**Alternative**: Reduce number of models scanned:
```bash
# Scan only 2 largest models
python3 scripts/shell/run-ml-runtime-analysis.py \
  --target /path/to/model \
  --scan-dir scans/myapp_2026-07-30_10-00-00 \
  --app-name myapp \
  --max-models 2
```

---

### "False positive: Levenshtein distance flagging similar model names"

**Symptom**: Layer 18 flags legitimate model variants as typosquatting

**Cause**: Models with similar names to popular models (e.g., `bert-base-uncased-finetuned`)

**Solution**: This is expected behavior. Review the finding and verify the model source:

```bash
# Check model source in HuggingFace
# If legitimate variant, suppress with .epyon-ignore.yml:

suppressions:
  - type: finding_id
    value: "typosquatting"
    tool: model-provenance
    reason: "Legitimate finetuned variant of bert-base-uncased from trusted source"
    approved_by: security-team
    expires: "2027-07-30"
```

---

### "Layer 13 ML controls marked 'Not Reviewed'"

**Symptom**: All ML STIG controls show status "Not Reviewed"

**Cause**: `OPENAI_API_KEY` not set or invalid

**Solution**:
```bash
# Set OpenAI API key
export OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxx

# Re-run STIG assessment
python3 scripts/shell/run-stig-assessment.py \
  --stigs-dir configuration/stigs \
  --target /path/to/app \
  --scan-dir scans/myapp_2026-07-30_10-00-00 \
  --app-name myapp
```

**Alternative**: Use self-hosted LLM (requires additional configuration)

---

### "Layer 19 not detecting Kubernetes issues"

**Symptom**: Kubernetes manifests present but no findings from Layer 19

**Cause**: Manifest files not recognized (wrong extension or location)

**Solution**:
```bash
# Ensure manifests have .yaml or .yml extension
mv k8s-deployment.txt k8s-deployment.yaml

# Check file is detected
ls -la *.yaml *.yml

# Re-run scan
./scripts/shell/run-inference-security-scan.sh \
  /path/to/k8s \
  scans/k8s_2026-07-30_10-00-00 \
  k8s-app
```

**Supported Kubernetes Resources**:
- Deployment
- Pod
- StatefulSet
- DaemonSet
- Job
- CronJob

**Unsupported**: Custom Resources (CRDs) are not analyzed

---

For additional help, see:
- [STIG Compliance Guide](STIG_COMPLIANCE_GUIDE.md)
- [Scan Matrix](SCAN_MATRIX.md)
- [Webhook Integration Guide](WEBHOOK_INTEGRATION_GUIDE.md)
- [Main README](../README.md)
