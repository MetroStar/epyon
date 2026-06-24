#!/usr/bin/env bash
# create-stig-pr.sh — Create or update a PR with STIG findings in the target repository
#
# Creates/updates a file called `stig-findings.md` in the target repository root with the
# latest STIG assessment results and opens a pull request for review.
#
# Requirements:
#   - GITHUB_TOKEN or GH_PAT environment variable
#   - Running in GitHub Actions CI OR gh CLI available locally
#   - Target repository must be a Git repository
#
# Usage:
#   create-stig-pr.sh --target <repo-path> --scan-dir <scan-output-dir> --app-name <name>

set -euo pipefail

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Resolve script and project paths
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Color output
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Help
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

show_help() {
    cat <<EOF
Usage: create-stig-pr.sh --target <repo-path> --scan-dir <scan-output-dir> --app-name <name>

Create or update a PR with STIG findings in the target repository.

Options:
  --target PATH     Target repository path (must be a Git repo)
  --scan-dir PATH   Scan output directory containing findings-<app>.md
  --app-name NAME   Application name (used to locate findings file)
  -h, --help        Show this help message

Environment Variables:
  GITHUB_TOKEN      GitHub token for API access (preferred in CI)
  GH_PAT            GitHub personal access token (fallback)
  SKIP_STIG_PR      Set to 'true' to skip PR creation entirely

Example:
  create-stig-pr.sh \\
    --target /path/to/app \\
    --scan-dir scans/myapp_2026-06-24_10-00-00 \\
    --app-name myapp
EOF
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Parse arguments
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TARGET_DIR=""
SCAN_DIR=""
APP_NAME=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET_DIR="$2"
            shift 2
            ;;
        --scan-dir)
            SCAN_DIR="$2"
            shift 2
            ;;
        --app-name)
            APP_NAME="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Unknown argument: $1" >&2
            show_help
            exit 1
            ;;
    esac
done

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Validate arguments
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if [[ -z "$TARGET_DIR" ]] || [[ -z "$SCAN_DIR" ]] || [[ -z "$APP_NAME" ]]; then
    echo -e "${RED}[ERROR]${NC} Missing required arguments" >&2
    show_help
    exit 1
fi

if [[ ! -d "$TARGET_DIR" ]]; then
    echo -e "${RED}[ERROR]${NC} Target directory does not exist: $TARGET_DIR" >&2
    exit 1
fi

if [[ ! -d "$SCAN_DIR" ]]; then
    echo -e "${RED}[ERROR]${NC} Scan directory does not exist: $SCAN_DIR" >&2
    exit 1
fi

# Check if skip flag is set
if [[ "${SKIP_STIG_PR:-false}" == "true" ]]; then
    echo -e "${YELLOW}[INFO]${NC} SKIP_STIG_PR=true — skipping PR creation"
    exit 0
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Check for GitHub token
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

GITHUB_TOKEN="${GITHUB_TOKEN:-${GH_PAT:-}}"

if [[ -z "$GITHUB_TOKEN" ]]; then
    echo -e "${YELLOW}[WARNING]${NC} GITHUB_TOKEN or GH_PAT not set — cannot create PR" >&2
    echo -e "${YELLOW}[WARNING]${NC} Set GITHUB_TOKEN in CI or GH_PAT locally to enable PR creation" >&2
    exit 0  # Soft fail — don't block the scan
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Validate target is a Git repository
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if [[ ! -d "$TARGET_DIR/.git" ]]; then
    echo -e "${YELLOW}[WARNING]${NC} Target directory is not a Git repository: $TARGET_DIR" >&2
    echo -e "${YELLOW}[WARNING]${NC} Cannot create PR without Git repository" >&2
    exit 0  # Soft fail
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Locate findings file
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Derive app slug (same logic as run-stig-assessment.py)
APP_SLUG=$(echo "$APP_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]\+/-/g' | sed 's/^-\|-$//g')

FINDINGS_FILE="$SCAN_DIR/findings-${APP_SLUG}.md"

if [[ ! -f "$FINDINGS_FILE" ]]; then
    echo -e "${YELLOW}[WARNING]${NC} STIG findings file not found: $FINDINGS_FILE" >&2
    echo -e "${YELLOW}[WARNING]${NC} No STIG assessment was performed — skipping PR creation" >&2
    exit 0  # Soft fail
fi

echo -e "${GREEN}[INFO]${NC} Found STIG findings: $FINDINGS_FILE"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Get repository information
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

cd "$TARGET_DIR"

# Get default branch
DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo "main")

# Get repository owner and name from remote URL
REMOTE_URL=$(git remote get-url origin 2>/dev/null || echo "")
if [[ -z "$REMOTE_URL" ]]; then
    echo -e "${YELLOW}[WARNING]${NC} No Git remote 'origin' found — cannot determine repository" >&2
    exit 0  # Soft fail
fi

# Parse GitHub owner/repo from URL (handles both HTTPS and SSH)
if [[ "$REMOTE_URL" =~ github\.com[:/]([^/]+)/([^/\.]+) ]]; then
    REPO_OWNER="${BASH_REMATCH[1]}"
    REPO_NAME="${BASH_REMATCH[2]}"
else
    echo -e "${YELLOW}[WARNING]${NC} Could not parse GitHub repository from remote: $REMOTE_URL" >&2
    exit 0  # Soft fail
fi

echo -e "${GREEN}[INFO]${NC} Repository: $REPO_OWNER/$REPO_NAME"
echo -e "${GREEN}[INFO]${NC} Default branch: $DEFAULT_BRANCH"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Check if there are changes
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TARGET_FILE="$TARGET_DIR/stig-findings.md"
NEEDS_UPDATE=false

if [[ -f "$TARGET_FILE" ]]; then
    # File exists — check if content has changed
    if ! diff -q "$FINDINGS_FILE" "$TARGET_FILE" > /dev/null 2>&1; then
        echo -e "${YELLOW}[INFO]${NC} stig-findings.md has changes"
        NEEDS_UPDATE=true
    else
        echo -e "${GREEN}[INFO]${NC} stig-findings.md is up to date — no PR needed"
        exit 0
    fi
else
    echo -e "${YELLOW}[INFO]${NC} stig-findings.md does not exist — will create"
    NEEDS_UPDATE=true
fi

if [[ "$NEEDS_UPDATE" != "true" ]]; then
    exit 0
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Create branch
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BRANCH_DATE=$(date +%Y-%m-%d)
BRANCH_NAME="stig-update-${BRANCH_DATE}"

echo -e "${BLUE}[INFO]${NC} Creating branch: $BRANCH_NAME"

# Fetch latest from default branch
git fetch origin "$DEFAULT_BRANCH" --quiet 2>&1 || true

# Check if branch already exists
if git rev-parse --verify "origin/$BRANCH_NAME" > /dev/null 2>&1; then
    echo -e "${YELLOW}[INFO]${NC} Branch $BRANCH_NAME already exists — checking out"
    git checkout "$BRANCH_NAME" 2>&1 || git checkout -b "$BRANCH_NAME" "origin/$DEFAULT_BRANCH" 2>&1
    git pull origin "$BRANCH_NAME" --quiet 2>&1 || true
else
    echo -e "${GREEN}[INFO]${NC} Creating new branch from $DEFAULT_BRANCH"
    git checkout -b "$BRANCH_NAME" "origin/$DEFAULT_BRANCH" 2>&1
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Copy findings file
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

cp "$FINDINGS_FILE" "$TARGET_FILE"
echo -e "${GREEN}[INFO]${NC} Copied findings to $TARGET_FILE"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Commit changes
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

git add stig-findings.md

if git diff --cached --quiet; then
    echo -e "${GREEN}[INFO]${NC} No changes to commit (file content identical)"
    exit 0
fi

# Extract summary statistics from findings file
TOTAL_CONTROLS=$(grep -c "^### [0-9]\\+\\." "$TARGET_FILE" || echo "0")
OPEN_COUNT=$(grep -A2 "^| Open |" "$TARGET_FILE" | tail -1 | awk -F'|' '{print $3}' | tr -d ' ' || echo "0")
NOT_FINDING=$(grep -A2 "^| Not a Finding |" "$TARGET_FILE" | tail -1 | awk -F'|' '{print $3}' | tr -d ' ' || echo "0")
NOT_APPLICABLE=$(grep -A2 "^| Not Applicable |" "$TARGET_FILE" | tail -1 | awk -F'|' '{print $3}' | tr -d ' ' || echo "0")

COMMIT_MSG="chore: Update STIG findings assessment

Automated STIG compliance assessment update from Epyon scan.

Summary:
- Total Controls: ${TOTAL_CONTROLS}
- Open: ${OPEN_COUNT}
- Not a Finding: ${NOT_FINDING}
- Not Applicable: ${NOT_APPLICABLE}

Generated: ${BRANCH_DATE}"

git -c user.name="Epyon Security Bot" -c user.email="security@epyon.scan" commit -m "$COMMIT_MSG"

echo -e "${GREEN}[INFO]${NC} Committed changes"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Push branch
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo -e "${BLUE}[INFO]${NC} Pushing branch to origin"

# Configure git to use token for authentication
git remote set-url origin "https://x-access-token:${GITHUB_TOKEN}@github.com/${REPO_OWNER}/${REPO_NAME}.git"

git push origin "$BRANCH_NAME" --quiet 2>&1 || {
    echo -e "${RED}[ERROR]${NC} Failed to push branch — check token permissions" >&2
    exit 1
}

echo -e "${GREEN}[INFO]${NC} Pushed branch successfully"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Create or update PR using GitHub API
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PR_TITLE="STIG Findings Update - ${BRANCH_DATE}"
PR_BODY="## STIG Compliance Assessment Update

This automated PR updates the STIG findings based on the latest security scan.

### Summary
- **Total Controls Assessed**: ${TOTAL_CONTROLS}
- **Open Findings**: ${OPEN_COUNT}
- **Compliant (Not a Finding)**: ${NOT_FINDING}
- **Not Applicable**: ${NOT_APPLICABLE}

### Changes
- Updated \`stig-findings.md\` with the latest STIG assessment results

### Review Checklist
- [ ] Review new Open findings and determine remediation plans
- [ ] Verify Not Applicable justifications are still accurate
- [ ] Confirm Not a Finding evidence is still valid
- [ ] Update any related documentation or tracking tickets

---
*Generated by Epyon Security Scanner on ${BRANCH_DATE}*"

# Check if PR already exists
echo -e "${BLUE}[INFO]${NC} Checking for existing PR..."

EXISTING_PR=$(curl -s -H "Authorization: token ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/pulls?state=open&head=${REPO_OWNER}:${BRANCH_NAME}" \
    | grep -o '"number":[0-9]\+' | head -1 | cut -d':' -f2 || echo "")

if [[ -n "$EXISTING_PR" ]]; then
    echo -e "${YELLOW}[INFO]${NC} Updating existing PR #${EXISTING_PR}"
    
    curl -s -X PATCH \
        -H "Authorization: token ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/pulls/${EXISTING_PR}" \
        -d "{\"title\":\"${PR_TITLE}\",\"body\":$(echo "$PR_BODY" | jq -Rs .)}" \
        > /dev/null
    
    echo -e "${GREEN}[SUCCESS]${NC} Updated PR #${EXISTING_PR}: https://github.com/${REPO_OWNER}/${REPO_NAME}/pull/${EXISTING_PR}"
else
    echo -e "${BLUE}[INFO]${NC} Creating new PR..."
    
    PR_RESPONSE=$(curl -s -X POST \
        -H "Authorization: token ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/pulls" \
        -d "{\"title\":\"${PR_TITLE}\",\"body\":$(echo "$PR_BODY" | jq -Rs .),\"head\":\"${BRANCH_NAME}\",\"base\":\"${DEFAULT_BRANCH}\"}")
    
    PR_NUMBER=$(echo "$PR_RESPONSE" | grep -o '"number":[0-9]\+' | head -1 | cut -d':' -f2 || echo "")
    
    if [[ -n "$PR_NUMBER" ]]; then
        echo -e "${GREEN}[SUCCESS]${NC} Created PR #${PR_NUMBER}: https://github.com/${REPO_OWNER}/${REPO_NAME}/pull/${PR_NUMBER}"
    else
        echo -e "${RED}[ERROR]${NC} Failed to create PR" >&2
        echo "$PR_RESPONSE" >&2
        exit 1
    fi
fi

echo -e "${GREEN}[COMPLETE]${NC} STIG findings PR workflow completed successfully"
