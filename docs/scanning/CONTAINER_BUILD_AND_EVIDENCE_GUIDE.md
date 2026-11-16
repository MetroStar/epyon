# Container Image Building & Evidence-Based Scanning Guide

Epyon serves as a unified orchestration engine for security scanning, ATO compliance, and supply chain attestation.

## Overview

When building container images (Docker/OCI), a security-focused pipeline must collect both runtime image components and evidence artifacts needed for security audits, SLSA provenance, and ATO (Authority to Operate) verification.

### 10-of-10 Release & Evidence Artifact Matrix

| # | Artifact | Purpose / Description | Epyon Producer / Script | Output Location |
|---|----------|----------------------|-------------------------|-----------------|
| 1 | **Immutable Image Digest** | SHA-256 digest identifying exact image state | `run-build-scan.sh` | `build/image-digest.txt` |
| 2 | **OCI Manifest & Layers** | Config JSON + ordered layer diff digests | `run-build-scan.sh` | `build/oci-manifest.json` |
| 3 | **CycloneDX / SPDX SBOM** | Software Inventory (packages, licenses) | `run-sbom-scan.sh` | `sbom/filesystem.cyclonedx.json` |
| 4 | **Vulnerability Scan Results** | OS & app vulnerabilities | `run-grype-scan.sh`, `run-trivy-scan.sh` | `grype/`, `trivy/` |
| 5 | **SAST & Security Reports** | Code quality, secrets, IaC, malware | `run-sonar-analysis.sh`, `run-trufflehog-scan.sh`, `run-checkov-scan.sh`, `run-clamav-scan.sh` | `sonarqube/`, `trufflehog/`, `checkov/`, `clamav/` |
| 6 | **Unit / Integration Test Evidence** | Test coverage & XUnit reports | `run-sonar-analysis.sh` | `sonarqube/sonar-test-results.json` |
| 7 | **SLSA Provenance Attestation** | SLSA v1.0 in-toto build provenance | `generate-slsa-provenance.sh` | `provenance.jsonl` |
| 8 | **Cryptographic Image Signature** | Cosign / Notation signature record | `sign-image-cosign.sh` | `image.sig` |
| 9 | **Policy Gate Decision** | Quality gate pass/fail & suppressions | `check-severity-gate.sh` | `suppressed-findings.md` |
| 10 | **Build Logs & Audit Manifest** | Console logs + SHA-256 scan manifest | `generate-scan-manifest.sh` | `scan-manifest.json`, `build/build.log` |

---

## OCI Container Structure

```
Image index (multi-arch manifest list)
└── Image manifest
    ├── Image configuration (entrypoint, env vars, ports, user)
    └── Filesystem layers (read-only diffs)
```

---

## Phase 0: Image Build & Supply Chain Module

When `BUILD_ENABLED=true` or `--build-image` is supplied to `epyon.sh`, Epyon executes Phase 0 before running security scan layers:

1. **Build Container Image**: Uses `docker`, `podman`, or `buildah` to build the image from target `Dockerfile`.
2. **Extract Immutable Digest & Manifest**: Queries the image daemon/registry for `RepoDigests` and OCI manifest JSON.
3. **Generate SLSA Provenance**: Produces an in-toto predicate with source repository commit SHA, workflow ID, builder identity, and image digest.
4. **Sign Image (Optional)**: Uses Cosign (keyless OIDC or key-based) to attach a cryptographic signature.
5. **Trigger 20-Layer Scan**: Passes the newly built image directly into Grype, Trivy, Syft, Anchore, and Inference Security scanners.

### Dockerfile Discovery (Monorepos)

`run-build-scan.sh` locates the Dockerfile to build in this order:

1. **Explicit override** — `DOCKERFILE` env var or `-f`/`--dockerfile PATH` CLI flag (path is checked as given, then relative to the target directory). Use this to pin a specific Dockerfile when a repo has more than one (e.g. `ui/Dockerfile` in a monorepo with a frontend and backend).
2. **Target root** — `Dockerfile`, `dockerfile`, `Containerfile`, or `Dockerfile.production` directly under the target directory.
3. **Recursive discovery** — if no root-level Dockerfile exists, Epyon recursively searches the target directory (excluding `.git`, `node_modules`, and similar) and builds the first match alphabetically, printing a warning (and suggesting `--dockerfile`) if multiple candidates are found.

This mirrors the discovery logic Trivy/Anchore already use (`discover_dockerfile_base_images`) to find base images for baseline scanning, so the same Dockerfile that is scanned for `FROM` references is also the one actually built — a monorepo with only a nested Dockerfile (no root `Dockerfile`) previously fell back to a non-container scan and never had its real, patched image built or routed to Trivy/Anchore; those scanners would still find and scan the *raw upstream* base image referenced in the nested Dockerfile, reporting stale CVEs/EOL findings that the actual shipped image had already patched (e.g. via `apk upgrade`/`apt-get upgrade` layers).

A successful build now also records `"mode": "container_build"` in `build-summary.json`, which `run-epyon-scan-ci.sh` and `run-target-security-scan.sh` require in order to route the freshly built image into Grype/Trivy/Anchore as `PRIMARY_BASELINE_IMAGE` instead of falling back to scanning the raw base image from the Dockerfile.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BUILD_ENABLED` | `false` | Enable Phase 0 container image building |
| `IMAGE_NAME` | Target repo name | Name for built image |
| `IMAGE_TAG` | `git rev-parse --short HEAD` | Tag for built image |
| `DOCKERFILE` | *(auto-discovered)* | Dockerfile/Containerfile path to build, relative to the target repo (overrides auto-discovery); maps to the reusable workflow's `dockerfile_path` input |
| `COSIGN_KEY` | *(optional)* | Private key for Cosign image signing |

### CLI Usage

```bash
# Build image and run full 21-layer security scan
./epyon.sh --target /path/to/app --build-image --image-name myapp --image-tag v1.0.0

# Monorepo: pin the Dockerfile to build when more than one exists
./epyon.sh --target /path/to/app --build-image --dockerfile ui/Dockerfile
```
