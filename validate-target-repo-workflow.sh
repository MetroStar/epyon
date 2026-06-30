#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
# Target Repository Workflow Validation Script
# ══════════════════════════════════════════════════════════════════════════════
# Checks if a target repository's GitHub Actions workflow is properly configured
# to receive and forward webhook notifications from Barbatos to Epyon.
#
# Usage:
#   ./validate-target-repo-workflow.sh [path-to-workflow.yml]
#
# If no path provided, searches for workflows in .github/workflows/
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default workflow paths to check
DEFAULT_WORKFLOWS=(
    ".github/workflows/security-scan.yml"
    ".github/workflows/scan-private-repo.yml"
    ".github/workflows/epyon-scan.yml"
)

print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Target Repository Workflow Validation${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

check_workflow() {
    local workflow_file="$1"
    local errors=0
    local warnings=0
    
    echo -e "${YELLOW}Checking workflow: $workflow_file${NC}"
    echo ""
    
    if [[ ! -f "$workflow_file" ]]; then
        echo -e "${RED}✗ File not found: $workflow_file${NC}"
        return 1
    fi
    
    # Check 1: workflow_dispatch event
    echo -n "  [1/6] workflow_dispatch event.............. "
    if grep -q "workflow_dispatch:" "$workflow_file"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        echo -e "${RED}        Missing 'workflow_dispatch:' event${NC}"
        errors=$((errors + 1))
    fi
    
    # Check 2: epyon_callback_url input
    echo -n "  [2/6] epyon_callback_url input............. "
    if grep -q "epyon_callback_url:" "$workflow_file"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        echo -e "${RED}        Missing 'epyon_callback_url:' input${NC}"
        errors=$((errors + 1))
    fi
    
    # Check 3: epyon_job_id input
    echo -n "  [3/6] epyon_job_id input................... "
    if grep -q "epyon_job_id:" "$workflow_file"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}⚠${NC}"
        echo -e "${YELLOW}        Missing 'epyon_job_id:' input (optional but recommended)${NC}"
        warnings=$((warnings + 1))
    fi
    
    # Check 4: epyon_webhook_secret input
    echo -n "  [4/6] epyon_webhook_secret input........... "
    if grep -q "epyon_webhook_secret:" "$workflow_file"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}⚠${NC}"
        echo -e "${YELLOW}        Missing 'epyon_webhook_secret:' input (optional but recommended)${NC}"
        warnings=$((warnings + 1))
    fi
    
    # Check 5: Uses MetroStar/epyon reusable workflow
    echo -n "  [5/6] Uses reusable Epyon workflow......... "
    if grep -q "uses: MetroStar/epyon/.github/workflows/epyon-scan.yml" "$workflow_file"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        echo -e "${RED}        Not using 'MetroStar/epyon/.github/workflows/epyon-scan.yml'${NC}"
        errors=$((errors + 1))
    fi
    
    # Check 6: Forwards webhook inputs to reusable workflow
    echo -n "  [6/6] Forwards webhook inputs.............. "
    if grep -A 5 "with:" "$workflow_file" | grep -q "epyon_callback_url:"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        echo -e "${RED}        Workflow does not forward 'epyon_callback_url' to reusable workflow${NC}"
        errors=$((errors + 1))
    fi
    
    echo ""
    
    # Summary
    if [[ $errors -eq 0 ]]; then
        echo -e "${GREEN}✓ Workflow is properly configured for webhooks${NC}"
        if [[ $warnings -gt 0 ]]; then
            echo -e "${YELLOW}  $warnings optional improvements recommended${NC}"
        fi
        return 0
    else
        echo -e "${RED}✗ Workflow has $errors configuration error(s)${NC}"
        if [[ $warnings -gt 0 ]]; then
            echo -e "${YELLOW}  $warnings warning(s)${NC}"
        fi
        return 1
    fi
}

fix_workflow() {
    local workflow_file="$1"
    
    echo ""
    echo -e "${YELLOW}Fixing workflow: $workflow_file${NC}"
    echo ""
    
    # Backup original
    cp "$workflow_file" "${workflow_file}.backup"
    echo -e "${GREEN}✓${NC} Created backup: ${workflow_file}.backup"
    
    # Download template
    local template_url="https://raw.githubusercontent.com/MetroStar/epyon/main/.github/workflows/security-scan-template.yml"
    
    if curl -f -s -o "$workflow_file" "$template_url"; then
        echo -e "${GREEN}✓${NC} Downloaded corrected workflow template"
        echo ""
        echo "Changes made:"
        echo "  1. Added webhook inputs (epyon_callback_url, epyon_job_id, epyon_webhook_secret)"
        echo "  2. Configured workflow to forward inputs to reusable Epyon workflow"
        echo "  3. Set up proper workflow_dispatch event"
        echo ""
        echo -e "${YELLOW}Review the changes and commit:${NC}"
        echo "  git diff $workflow_file"
        echo "  git add $workflow_file"
        echo "  git commit -m 'fix: add webhook support to security scan workflow'"
        echo "  git push"
    else
        echo -e "${RED}✗${NC} Failed to download template"
        echo "  Restoring backup..."
        mv "${workflow_file}.backup" "$workflow_file"
        return 1
    fi
}

# Main
print_header

WORKFLOW_FILE="${1:-}"

if [[ -n "$WORKFLOW_FILE" ]]; then
    # User provided a specific file
    if check_workflow "$WORKFLOW_FILE"; then
        exit 0
    else
        echo ""
        read -p "Would you like to fix this workflow automatically? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            fix_workflow "$WORKFLOW_FILE"
        fi
        exit 1
    fi
else
    # Search for workflows
    echo "Searching for security scan workflows..."
    echo ""
    
    FOUND_WORKFLOWS=()
    for workflow in "${DEFAULT_WORKFLOWS[@]}"; do
        if [[ -f "$workflow" ]]; then
            FOUND_WORKFLOWS+=("$workflow")
        fi
    done
    
    if [[ ${#FOUND_WORKFLOWS[@]} -eq 0 ]]; then
        echo -e "${RED}✗ No security scan workflows found${NC}"
        echo ""
        echo "Expected locations:"
        for workflow in "${DEFAULT_WORKFLOWS[@]}"; do
            echo "  - $workflow"
        done
        echo ""
        echo "To create a new workflow:"
        echo "  mkdir -p .github/workflows"
        echo "  curl -o .github/workflows/security-scan.yml \\"
        echo "    https://raw.githubusercontent.com/MetroStar/epyon/main/.github/workflows/security-scan-template.yml"
        exit 1
    fi
    
    # Check all found workflows
    ALL_PASSED=true
    for workflow in "${FOUND_WORKFLOWS[@]}"; do
        if ! check_workflow "$workflow"; then
            ALL_PASSED=false
        fi
        echo ""
    done
    
    if $ALL_PASSED; then
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  All workflows are properly configured!${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        exit 0
    else
        echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${RED}  Some workflows need configuration${NC}"
        echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "Run with a specific file to fix:"
        echo "  $0 <workflow-file.yml>"
        exit 1
    fi
fi
