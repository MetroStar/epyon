# Anchore Scanner Configuration Guide

## Overview

Epyon's Anchore/Grype scanner **automatically detects** container characteristics (OS, architecture, runtime) to prevent false positives. The scanner inspects Docker images before scanning and configures itself appropriately — no manual configuration required for most cases.

### Auto-Detection Features (v3.9.0+)

✅ **Architecture Detection**: Automatically detects ARM64/AMD64 and sets correct platform  
✅ **OS/Distro Detection**: Identifies Alpine/Debian/Ubuntu from image metadata  
✅ **Runtime Detection**: Detects Node.js/Python/Go/Java from environment variables and binaries  
✅ **Smart Exclusions**: Automatically excludes build-stage dependencies for single-runtime images  
✅ **GitHub Actions Compatible**: Works transparently in CI/CD without user intervention

## How Auto-Detection Works

When scanning container images, Epyon:

1. **Inspects image metadata** using `docker image inspect`
2. **Detects architecture** (arm64/amd64) and sets `--platform` flag
3. **Identifies base OS** from labels, image name, and history layers
4. **Probes runtime binaries** by checking env vars and running `which` commands
5. **Configures exclusions** based on detected runtime (e.g., Node.js-only → exclude Python/Go/Java)

All detection happens automatically in GitHub Actions workflows — users don't need to set env vars.

## Common False Positive Scenarios

### 1. OS Misidentification
**Symptom**: Scanner reports Debian vulnerabilities (libc6, perl-base, libsqlite3) in an Alpine Linux container.

**Cause**: Grype scans the build context or detects remnants from multi-stage builds, misidentifying the OS.

**Solution**: Use platform flags and enable distro detection logging.

### 2. Build-Stage Dependencies
**Symptom**: Python, Go, or Java vulnerabilities appear in a Node.js-only production image.

**Cause**: Build-stage dependencies (node-gyp, build tools) are scanned even though they're not in the final image.

**Solution**: Exclude build-stage package types from production scans.

### 3. Cross-Platform Scanning
**Symptom**: ARM64/aarch64 binaries show x86_64 vulnerabilities when scanned on Apple Silicon Macs.

**Cause**: Platform mismatch between scan host and target container.

**Solution**: Explicitly set the target platform.

## Configuration Options

**Note:** These environment variables are **optional overrides** for the auto-detection system. In most cases (especially GitHub Actions), you don't need to set them — the scanner configures itself automatically.

### Environment Variables (Manual Override)

| Variable | Values | Default | Purpose |
|----------|--------|---------|---------|
| `ANCHORE_PLATFORM` | `linux/amd64`<br>`linux/arm64`<br>`linux/aarch64` | Auto-detected from image | Override auto-detected platform architecture |
| `ANCHORE_EXCLUDE_TYPES` | `python,go,java,ruby`<br>(comma-separated) | Auto-configured | Override auto-detected runtime exclusions |
| `ANCHORE_SHOW_DISTRO` | `true` / `false` | `true` | Log detected OS/distro after each scan for debugging |
| `ANCHORE_SKIP_BUILD` | `true` / `false` | `false` | Skip `docker compose build`, pull images from registry instead |

### Usage Examples

#### Override auto-detection (rarely needed)
```bash
# Force specific platform (overrides auto-detection)
export ANCHORE_PLATFORM="linux/amd64"

# Manually specify exclusions (overrides runtime detection)
export ANCHORE_EXCLUDE_TYPES="python,go,java"

./epyon.sh --target /path/to/app --app-name myapp
```

#### Debug auto-detection behavior
```bash
# See what the scanner detects
export ANCHORE_SHOW_DISTRO="true"
./epyon.sh --target /path/to/app --app-name myapp

# Check logs
grep "Auto-detected\|Detected runtime" scans/*/anchore/anchore-scan.log
```

**Expected output:**
```
[2026-06-22 14:30:45] ℹ Auto-detected architecture: ARM64
[2026-06-22 14:30:45] ℹ Detected base OS: alpine
[2026-06-22 14:30:45] ℹ Detected runtime: Node.js
[2026-06-22 14:30:45] 🔧 Auto-excluding build-stage deps: python,go,java,ruby (Node.js-only runtime)
[2026-06-22 14:30:46] ℹ Detected OS: alpine 3.21.5
```

## Remediation Workflows

### Step 1: Verify Auto-Detection (v3.9.0+)

**In most cases, you don't need to configure anything.** The scanner automatically detects your image characteristics.

Run a scan and check the logs:
```bash
./epyon.sh --target /path/to/app --app-name myapp --scan-mode quick

# Check auto-detection logs
grep "Auto-detected\|Detected runtime\|Auto-excluding" scans/myapp_*/anchore/anchore-scan.log
```

**Expected output for Alpine Node.js image:**
```
ℹ Auto-detected architecture: ARM64
ℹ Detected base OS: alpine
ℹ Detected runtime: Node.js
🔧 Auto-excluding build-stage deps: python,go,java,ruby (Node.js-only runtime)
ℹ Detected OS: alpine 3.21.5
```

✅ If you see these logs, auto-detection is working — false positives should be eliminated automatically.

### Step 2: Manual Override (If Needed)

Only use manual overrides if auto-detection fails or you have special requirements:

```bash
# Force specific configuration (overrides auto-detection)
export ANCHORE_PLATFORM="linux/arm64"
export ANCHORE_EXCLUDE_TYPES="python,go,java"
./epyon.sh --target /path/to/app --app-name myapp
```

### Step 3: Identify Remaining False Positives

Run a scan with distro detection enabled:
```bash
export ANCHORE_SHOW_DISTRO="true"
./epyon.sh --target /path/to/app --app-name myapp --scan-mode quick
```

Check the scan log:
```bash
grep "Detected OS" scans/myapp_*/anchore/anchore-scan.log
```

**Expected output for Alpine:**
```
ℹ Detected OS: alpine 3.21.5
```

**If you see Debian when expecting Alpine:**
- Your Dockerfile may have a `FROM debian:*` in an earlier stage
- Volume mounts may be scanning the host filesystem
- Multi-arch builds may be confusing the detector

### Step 2: Exclude Build-Stage Dependencies

If your production image is Node.js-only but scan shows Go/Python/Java CVEs:

```bash
# Add to .github/workflows/epyon-scan.yml or your scan script
export ANCHORE_EXCLUDE_TYPES="python,go,java,ruby"
```

**Supported package types:**
- `python` — Python packages (pip, pipenv, poetry)
- `go` — Go modules
- `java` — Java/Maven/Gradle dependencies
- `ruby` — Ruby gems
- `rust` — Cargo packages
- `dotnet` — .NET/NuGet packages

### Step 3: Set Correct Platform

**For Apple Silicon Macs scanning ARM64 images:**
```bash
export ANCHORE_PLATFORM="linux/arm64"
# or
export ANCHORE_PLATFORM="linux/aarch64"
```

**For Intel/AMD64 images:**
```bash
export ANCHORE_PLATFORM="linux/amd64"
```

**Auto-detection behavior:**
- macOS ARM64 → defaults to `linux/arm64`
- All other hosts → defaults to `linux/amd64`

### Step 4: Verify Remediation

Re-run the scan with your configuration:
```bash
export ANCHORE_PLATFORM="linux/arm64"
export ANCHORE_EXCLUDE_TYPES="python,go"
export ANCHORE_SHOW_DISTRO="true"

./epyon.sh --target /path/to/app --app-name myapp
```

Check the filtered scan log:
```bash
grep "Filtered.*excluded" scans/myapp_*/anchore/anchore-scan.log
```

**Expected output:**
```
🔧 Filtered 45 excluded package type(s) (python,go)
```

## Advanced Configuration

### Multi-Stage Dockerfile Best Practices

To prevent build-stage artifacts from leaking into production scans:

```dockerfile
# ❌ BAD: Build tools in final stage
FROM node:22-alpine
RUN apk add --no-cache python3 go
COPY . .
RUN npm install

# ✅ GOOD: Multi-stage build
FROM node:22-alpine AS builder
RUN apk add --no-cache python3 g++ make  # Build-only deps
COPY package*.json ./
RUN npm ci --only=production

FROM node:22-alpine AS production
COPY --from=builder /app/node_modules ./node_modules
COPY . .
USER node
```

When scanning the `production` stage, only Node.js deps are present.

### GitHub Actions Workflow Integration

```yaml
- name: Run Epyon Security Scan
  env:
    ANCHORE_PLATFORM: linux/amd64
    ANCHORE_EXCLUDE_TYPES: python,go,java
    ANCHORE_SKIP_BUILD: true  # CI builds separately
    ANCHORE_SHOW_DISTRO: true
  run: |
    ./epyon.sh \
      --target ${{ github.workspace }} \
      --app-name ${{ github.event.repository.name }}
```

### Target-Specific Configuration

Create a `.anchore-config` file in your target repository:

```bash
# .anchore-config
export ANCHORE_PLATFORM="linux/arm64"
export ANCHORE_EXCLUDE_TYPES="python,go"
export ANCHORE_SHOW_DISTRO="true"
```

Source it before scanning:
```bash
if [[ -f "$TARGET_DIR/.anchore-config" ]]; then
  source "$TARGET_DIR/.anchore-config"
fi
./epyon.sh --target "$TARGET_DIR" --app-name myapp
```

## Troubleshooting

### "Detected OS: unknown"
**Cause**: Grype couldn't identify the base image OS.

**Solutions:**
1. Ensure your Dockerfile has a `FROM` directive with a recognized base image
2. Use a mainstream base image (Alpine, Debian, Ubuntu, Red Hat UBI)
3. Check that `docker image inspect <your-image>` shows proper OS metadata

### False positives persist after exclusions
**Cause**: Package type mismatch — Grype's metadata doesn't match your exclusion filter.

**Debug:**
```bash
# Check how Grype categorized the package
jq '.matches[] | {name: .artifact.name, type: .artifact.type, lang: .artifact.language}' \
  scans/myapp_*/anchore/anchore-filesystem-results.json | head -20
```

**Common mismatches:**
- Python packages may be `type: "python"` or `language: "python"`
- Go modules may be `type: "go-module"` or `language: "go"`

The filter checks all three fields (`type`, `language`, `metadata.type`).

### Platform flag ignored
**Cause**: Using Docker-wrapped Grype instead of native binary.

**Solution:**
```bash
# Install native grype binary
brew install grype  # macOS
# or
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

Native Grype respects `--platform` more consistently than the Docker image.

## Verification Checklist

After configuring, verify:

- [ ] `grep "Detected OS"` matches your actual base image
- [ ] `grep "Filtered.*excluded"` shows expected package types removed
- [ ] Critical/high CVE count drops to expected range
- [ ] Remaining CVEs are for packages actually present in production image
- [ ] `security-findings-summary.json` shows only relevant package ecosystems

## See Also

- [Grype Platform Detection](https://github.com/anchore/grype#platform-selection)
- [Multi-Stage Docker Builds](https://docs.docker.com/build/building/multi-stage/)
- [SCAN_MATRIX.md](./SCAN_MATRIX.md) — Epyon scan layer orchestration
- [IGNORE_RULES_GUIDE.md](./IGNORE_RULES_GUIDE.md) — Suppressing confirmed false positives

---

## Tracking Vulnerabilities to Specific Containers

### File Locations

Epyon stores container-specific vulnerability data in the scan directory:

```
scans/{app_name}_{timestamp}/
└── anchore/
    ├── anchore-scan.log                    # Scan process log with image names
    ├── anchore-filesystem-results.json      # Filesystem/directory scan results
    ├── anchore-sbom-results.json           # SBOM-based scan results
    └── images/                             # Per-container results
        ├── myapp_latest.json               # Vulnerabilities in myapp:latest
        ├── postgres_15-alpine.json         # Vulnerabilities in postgres:15-alpine
        └── baseline-dhi_caddy_latest.json  # Baseline image vulnerabilities
```

**Naming convention:** Image names are sanitized (`:` and `/` replaced with `_`):
- `myapp:latest` → `myapp_latest.json`
- `postgres:15-alpine` → `postgres_15-alpine.json`
- `ghcr.io/owner/app:v1.2.3` → `ghcr.io_owner_app_v1.2.3.json`

### Quick Reference Script

Use the provided script to see which containers have which vulnerabilities:

```bash
# View latest scan
./scripts/shell/list-container-vulnerabilities.sh

# View specific scan
./scripts/shell/list-container-vulnerabilities.sh scans/myapp_2026-06-22_14-30-45
```

**Example output:**
```
═══════════════════════════════════════════════════════════
   Container Vulnerability Breakdown
═══════════════════════════════════════════════════════════
Scan: myapp_2026-06-22_14-30-45

━━━ Container Image Scan Results (3 images) ━━━

🚨 myapp:latest
   OS: alpine 3.21.5
   Total: 12 vulnerabilities
   Critical: 2
   High: 5

   Top Critical/High CVEs:
   • CVE-2026-12087 [Critical] in perl-base@5.40.1-6
   • CVE-2026-27143 [Critical] in stdlib@go1.26.0
   • CVE-2026-3805 [High] in curl@8.14.1-2
   ... and 4 more critical/high vulnerabilities

✅ postgres:15-alpine
   OS: alpine 3.21.0
   Total: 0 vulnerabilities
   No vulnerabilities found

⚠️  nginx:1.25-alpine
   OS: alpine 3.21.3
   Total: 8 vulnerabilities
   High: 3

   Top Critical/High CVEs:
   • CVE-2026-5773 [High] in libcurl4@8.14.1
   ... and 2 more critical/high vulnerabilities
```

### Querying Specific Containers

#### Find all CVEs in a specific container

```bash
# List all CVEs in myapp:latest
jq -r '.matches[] | "\(.vulnerability.id) [\(.vulnerability.severity)] in \(.artifact.name)@\(.artifact.version)"' \
  scans/myapp_*/anchore/images/myapp_latest.json
```

#### Find which container has a specific CVE

```bash
# Find CVE-2026-12087 across all containers
for f in scans/myapp_*/anchore/images/*.json; do
  if jq -e '.matches[] | select(.vulnerability.id=="CVE-2026-12087")' "$f" > /dev/null 2>&1; then
    echo "Found in: $(basename "$f" .json | sed 's/_/:/2' | sed 's/_/\//g')"
    jq -r '.matches[] | select(.vulnerability.id=="CVE-2026-12087") | 
           "  Package: \(.artifact.name)@\(.artifact.version)"' "$f"
  fi
done
```

#### Export CVEs to CSV

```bash
# Export all container CVEs to CSV
echo "Container,CVE,Severity,Package,Version,Fix Available" > container_cves.csv

for f in scans/myapp_*/anchore/images/*.json; do
  container=$(basename "$f" .json | sed 's/_/:/2' | sed 's/_/\//g')
  jq -r --arg container "$container" \
    '.matches[] | [$container, .vulnerability.id, .vulnerability.severity, 
     .artifact.name, .artifact.version, 
     (.vulnerability.fix.versions[0] // "No fix")] | @csv' "$f" >> container_cves.csv
done

echo "Exported to container_cves.csv"
```

#### Get OS/distro for each container

```bash
# Show detected OS for all scanned containers
for f in scans/myapp_*/anchore/images/*.json; do
  container=$(basename "$f" .json | sed 's/_/:/2' | sed 's/_/\//g')
  os=$(jq -r '.distro.name // .distro.type // "unknown"' "$f")
  version=$(jq -r '.distro.version // ""' "$f")
  echo "$container: $os $version"
done
```

### Web UI Integration

The Epyon Web UI shows container-specific vulnerabilities in the scan detail view:

1. Start the web server:
   ```bash
   cd web && ./start.sh
   ```

2. Open http://127.0.0.1:8000

3. Click on a scan → **Container Vulnerabilities** section

4. Each container shows:
   - Image name with registry
   - Detected OS/distro
   - Vulnerability counts by severity
   - Expandable CVE list with package details

### Programmatic Access

For automation and CI/CD integration:

```python
import json
from pathlib import Path

def get_container_vulnerabilities(scan_dir: str) -> dict:
    """Parse Anchore container scan results."""
    anchore_dir = Path(scan_dir) / "anchore" / "images"
    
    results = {}
    for json_file in anchore_dir.glob("*.json"):
        # Decode image name
        image_name = json_file.stem.replace("_", ":", 1).replace("_", "/")
        
        with open(json_file) as f:
            data = json.load(f)
        
        # Extract key info
        results[image_name] = {
            "os": data.get("distro", {}).get("name", "unknown"),
            "os_version": data.get("distro", {}).get("version", ""),
            "vulnerabilities": {
                "critical": [m for m in data.get("matches", []) 
                           if m["vulnerability"]["severity"] == "Critical"],
                "high": [m for m in data.get("matches", []) 
                       if m["vulnerability"]["severity"] == "High"],
                "total": len(data.get("matches", []))
            }
        }
    
    return results

# Usage
vulns = get_container_vulnerabilities("scans/myapp_2026-06-22_14-30-45")
for image, data in vulns.items():
    print(f"{image}: {data['vulnerabilities']['total']} vulnerabilities")
```

### Finding Root Cause Images

If you see Debian CVEs in your Alpine container, trace back to the source:

```bash
# Show image build history to find Debian layers
docker image history --no-trunc myapp:latest | grep -i debian

# Check all base layers
docker image inspect myapp:latest | jq -r '.RootFS.Layers[]'

# See what the scanner detected
grep "Detected base OS\|Image OS" scans/myapp_*/anchore/anchore-scan.log
```

This helps identify multi-stage build leakage or incorrect base images.
