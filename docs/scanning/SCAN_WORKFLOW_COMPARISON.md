# Scan Workflow Comparison: Public vs Private

## Architecture Overview

### **scan-public-repo.yml** (External Repository Scanning)
```
GitHub Workspace Root
├── scripts/          (Epyon checked out here directly)
├── scans/
├── target-repo-REPONAME/   (Cloned from external URL)
│   └── .epyon-ignore.yml   (Target's ignore file)
└── /tmp/epyon-env
```

**Key Characteristics:**
- Epyon is checked out to workspace root (line 50: `uses: actions/checkout@v4` - no path parameter)
- Target repository is cloned dynamically from user-provided URL
- Scripts execute from workspace root (no `cd epyon` needed)
- Used for scanning ANY external public GitHub repository

**Workflow Trigger:**
- Manual (`workflow_dispatch`) with URL input
- User provides: repository URL, subdirectory (optional), scan mode

**Target Directory:**
- Dynamically created: `$PWD/target-repo-$REPO_NAME`
- Set in `/tmp/epyon-env` during initialization

---

### **scan-private-repo.yml** (Current Repository Scanning)
```
GitHub Workspace Root
├── target-repo/            (Current repo checked out here)
│   └── .epyon-ignore.yml   (This repo's ignore file)
├── epyon/                  (Epyon checked out as subdirectory)
│   ├── scripts/
│   └── scans/
└── /tmp/epyon-env
```

**Key Characteristics:**
- Target repo checked out first to `target-repo/` subdirectory (line 62-65)
- Epyon checked out to `epyon/` subdirectory (line 67-71)
- All script steps start with `cd epyon` before execution
- Used for scanning the repository WHERE the workflow runs

**Workflow Trigger:**
- Automatic: push, PR, schedule
- Manual: `workflow_dispatch` with optional subdirectory

**Target Directory:**
- Static path: `${{ github.workspace }}/target-repo`
- Set in `/tmp/epyon-env` during initialization

---

## Critical Differences That Affected Behavior

### 1. **Environment Variable Management**

**scan-public-repo.yml** (Before fix):
```bash
# BUG: Lines 112, 117 used > instead of >>
echo "TARGET_DIR=$PWD/target-repo-$REPO_NAME" > /tmp/epyon-env  # OVERWRITES!
```
This **erased** all previously set variables (TARGET_NAME, SCAN_MODE, etc.)

**scan-private-repo.yml** (Always correct):
```bash
echo "TARGET_DIR=$TARGET_DIR" > /tmp/epyon-env   # First write
echo "SCAN_MODE=$SCAN_MODE" >> /tmp/epyon-env    # Appends
```
Uses `>` for FIRST write, then `>>` for all subsequent appends.

**Impact:** Public scans had corrupted environment, causing TARGET_DIR to be wrong or undefined.

---

### 2. **Working Directory Context**

**scan-public-repo.yml:**
```yaml
- name: Layer 1 - Generate SBOM
  run: |
    source /tmp/epyon-env
    chmod +x scripts/shell/run-complete-sbom-scan.sh
    ./scripts/shell/run-complete-sbom-scan.sh
    # Runs from workspace root (Epyon location)
```

**scan-private-repo.yml:**
```yaml
- name: Layer 1 - Generate SBOM
  run: |
    source /tmp/epyon-env
    cd epyon                                      # ← Changes directory!
    chmod +x scripts/shell/run-complete-sbom-scan.sh
    ./scripts/shell/run-complete-sbom-scan.sh
```

**Impact:** Different relative path resolution, but both work because environment variables provide absolute paths.

---

### 3. **Dashboard Generation - TARGET_DIR Propagation**

**Before Fix:**
```bash
# consolidate-security-reports.sh line 624
SCAN_DIR="$SCAN_DIR" "$DASHBOARD_GENERATOR"
# Missing TARGET_DIR! Dashboard couldn't find .epyon-ignore.yml
```

**After Fix:**
```bash
SCAN_DIR="$SCAN_DIR" TARGET_DIR="$TARGET_DIR" "$DASHBOARD_GENERATOR"
# Now dashboard receives TARGET_DIR and can find ignore file
```

**Why Private Scans Worked:**
Private scans MAY have worked by accident because:
- The dashboard tries multiple fallback paths (line 156-159 in generate-security-dashboard.sh)
- One fallback: `"${LATEST_SCAN}/../../.epyon-ignore.yml"`
- From `epyon/scans/NAME/`, `../../` goes to workspace root
- Might accidentally find `target-repo/.epyon-ignore.yml`

**Why Public Scans Failed:**
- Fallback paths don't match the `target-repo-$REPO_NAME` structure
- Without TARGET_DIR, dashboard couldn't locate the ignore file
- Result: 0 suppressions loaded, all findings counted

---

## Fixes Applied

### ✅ scan-public-repo.yml
1. **Lines 112, 117**: Changed `>` to `>>` to append TARGET_DIR instead of overwriting
2. **Line 255**: Added `TARGET_DIR="$TARGET_DIR"` to dashboard generation step

### ✅ scan-private-repo.yml  
1. **Line 276**: Added `TARGET_DIR="$TARGET_DIR"` to dashboard generation step

### ✅ consolidate-security-reports.sh
1. **Line 624**: Added `TARGET_DIR="$TARGET_DIR"` when calling dashboard generator

### ✅ check-severity-gate.sh
1. **Line 304-308**: Added `log_suppressed()` call for Checkov suppressions

### ✅ generate-security-dashboard.sh
1. **Lines 832, 937**: Fixed Checkov JSON parsing (`.[]?` instead of `[.[] | select()]`)
2. **Lines 1738-1744**: Fixed HTML quoting in suppressed findings table
3. **Lines 1700-1704**: Added debug output for troubleshooting

---

## When to Use Each Workflow

### Use **scan-public-repo.yml** when:
- Scanning external/third-party repositories
- Testing security of open-source dependencies
- One-off security assessments of any public repo
- Need to scan a repository you don't own

### Use **scan-private-repo.yml** when:
- Scanning your own repository (where workflow runs)
- Automated security checks on push/PR
- Scheduled security scans of your codebase
- CI/CD pipeline integration

---

## Summary

The workflows appeared to behave differently because:

1. **Bug in scan-public-repo.yml**: Environment variable overwrite caused TARGET_DIR to be lost
2. **Missing TARGET_DIR propagation**: Dashboard couldn't find `.epyon-ignore.yml` in either workflow
3. **Accidental success in private scans**: Fallback path resolution might have worked by luck

All issues are now fixed in both workflows. They should behave identically in terms of suppression handling.
