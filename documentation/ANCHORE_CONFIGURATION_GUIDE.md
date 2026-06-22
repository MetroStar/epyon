# Anchore Scanner Configuration Guide

## Overview

Epyon's Anchore/Grype scanner can misidentify container operating systems and report false positives when scanning multi-stage builds or cross-platform images. This guide shows how to configure the scanner to prevent false positives and accurately detect vulnerabilities.

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

### Environment Variables

| Variable | Values | Default | Purpose |
|----------|--------|---------|---------|
| `ANCHORE_PLATFORM` | `linux/amd64`<br>`linux/arm64`<br>`linux/aarch64` | Auto-detected | Force scanner to use specific platform architecture |
| `ANCHORE_EXCLUDE_TYPES` | `python,go,java,ruby`<br>(comma-separated) | _(none)_ | Exclude package ecosystems from scan results |
| `ANCHORE_SHOW_DISTRO` | `true` / `false` | `true` | Log detected OS/distro after each scan for debugging |
| `ANCHORE_SKIP_BUILD` | `true` / `false` | `false` | Skip `docker compose build`, pull images from registry instead |

### Usage Examples

#### Scan Alpine Node.js container from Mac ARM64
```bash
export ANCHORE_PLATFORM="linux/arm64"
export ANCHORE_EXCLUDE_TYPES="python,go"
export ANCHORE_SHOW_DISTRO="true"

./epyon.sh --target /path/to/app --app-name myapp
```

#### CI/CD: Skip build, scan production image only
```bash
export ANCHORE_SKIP_BUILD="true"
export ANCHORE_EXCLUDE_TYPES="python,go,java"

./scripts/shell/run-anchore-scan.sh /path/to/app
```

#### Debug false positives: Show OS detection
```bash
export ANCHORE_SHOW_DISTRO="true"
./scripts/shell/run-anchore-scan.sh --target /app
```

**Output:**
```
[2026-06-22 14:30:45] ℹ Detected OS: alpine 3.21.5
[2026-06-22 14:30:45] ℹ Image OS: alpine 3.21.5
```

If you see `debian` when expecting `alpine`, review your Dockerfile and ensure no Debian layers are leaking through.

## Remediation Workflows

### Step 1: Identify False Positives

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
