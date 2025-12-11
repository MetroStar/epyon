#!/bin/bash

# Script Cleanup for 8-Step Security Scan
# Removes unnecessary scripts and keeps only the essential ones

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Set up paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASH_DIR="$SCRIPT_DIR"

echo -e "${BLUE}🧹 Cleaning up scripts directory for 8-step security scan...${NC}"
echo

# Essential scripts that MUST be kept for the 8-step security scan
ESSENTIAL_SCRIPTS=(
    # Core orchestration
    "run-target-security-scan.sh"
    
    # 8 Security Layers
    "run-trufflehog-scan.sh"        # Layer 1: Secret Detection
    "run-clamav-scan.sh"            # Layer 2: Malware Detection  
    "run-checkov-scan.sh"           # Layer 3: Infrastructure Security
    "run-grype-scan.sh"             # Layer 4: Vulnerability Detection
    "run-trivy-scan.sh"             # Layer 5: Container Security
    "run-xeol-scan.sh"              # Layer 6: End-of-Life Detection
    "run-sonar-analysis.sh"         # Layer 7: Code Quality Analysis
    "run-helm-build.sh"             # Layer 8: Helm Chart Building
    
    # Summary and analysis
    "generate-critical-high-summary.sh"
    "consolidate-security-reports.sh"
    
    # Essential utilities
    "README.md"
)

# Additional clean versions (backup scripts)
CLEAN_SCRIPTS=(
    "run-trufflehog-scan-clean.sh"
    "run-clamav-scan-clean.sh"
    "run-checkov-scan-clean.sh"
    "run-grype-scan-clean.sh"
    "run-trivy-scan-clean.sh"
    "run-xeol-scan-clean.sh"
    "run-helm-build-clean.sh"
)

# Scripts to remove (legacy, duplicates, or unnecessary)
REMOVE_SCRIPTS=(
    # Legacy/broken versions
    "run-trufflehog-scan.sh.broken"
    "run-trivy-scan-fixed.sh"
    
    # Individual analysis scripts (replaced by consolidate-security-reports.sh)
    "analyze-checkov-results.sh"
    "analyze-clamav-results.sh" 
    "analyze-grype-results.sh"
    "analyze-helm-results.sh"
    "analyze-trivy-results.sh"
    "analyze-trufflehog-results.sh"
    "analyze-xeol-results.sh"
    
    # Demo and test scripts
    "demo-portable-scanner.sh"
    "portable-app-scanner.sh"
    "test-desktop-default.sh"
    "test-path-resolution.sh"
    
    # Specialized/niche scripts
    "nodejs-security-scanner.sh"
    "real-nodejs-scanner.sh"
    "real-nodejs-scanner-fixed.sh"
    "example-audited-checkov.sh"
    
    # Complete scan alternatives (redundant with run-target-security-scan.sh)
    "run-complete-security-scan.sh"
    
    # AWS/cloud specific utilities 
    "aws-ecr-helm-auth.sh"
    "aws-ecr-helm-auth-guide.sh"
    
    # Utility scripts that are less essential
    "audit-logger.sh"
    "compliance-logger.sh"
    "create-stub-dependencies.sh"
    "resolve-helm-dependencies.sh"
    "priority-issues-summary.txt"
)

# Backup important files before cleanup
BACKUP_DIR="$BASH_DIR/backup-$(date +%Y%m%d-%H%M%S)"
echo -e "${YELLOW}📦 Creating backup at: $BACKUP_DIR${NC}"
mkdir -p "$BACKUP_DIR"

# Create backup of scripts we're about to remove
for script in "${REMOVE_SCRIPTS[@]}"; do
    if [[ -f "$BASH_DIR/$script" ]]; then
        cp "$BASH_DIR/$script" "$BACKUP_DIR/" 2>/dev/null || true
        echo "  📄 Backed up: $script"
    fi
done

echo -e "${GREEN}✅ Backup completed${NC}"
echo

# Remove unnecessary scripts
echo -e "${RED}🗑️  Removing unnecessary scripts...${NC}"
removed_count=0

for script in "${REMOVE_SCRIPTS[@]}"; do
    if [[ -f "$BASH_DIR/$script" ]]; then
        rm "$BASH_DIR/$script"
        echo "  ❌ Removed: $script"
        ((removed_count++))
    fi
done

# Also remove any exclude-paths.txt directory if it exists
if [[ -d "$BASH_DIR/exclude-paths.txt" ]]; then
    rm -rf "$BASH_DIR/exclude-paths.txt"
    echo "  ❌ Removed directory: exclude-paths.txt"
    ((removed_count++))
fi

echo -e "${GREEN}✅ Removed $removed_count unnecessary files${NC}"
echo

# List remaining essential scripts
echo -e "${BLUE}📋 Essential scripts remaining for 8-step security scan:${NC}"
echo

echo -e "${GREEN}🎯 Core Orchestration:${NC}"
echo "  • run-target-security-scan.sh - Main orchestration script"
echo

echo -e "${GREEN}🛡️  8 Security Layers:${NC}"
echo "  • run-trufflehog-scan.sh  - Layer 1: Secret Detection"
echo "  • run-clamav-scan.sh      - Layer 2: Malware Detection"
echo "  • run-checkov-scan.sh     - Layer 3: Infrastructure Security"
echo "  • run-grype-scan.sh       - Layer 4: Vulnerability Detection"
echo "  • run-trivy-scan.sh       - Layer 5: Container Security"
echo "  • run-xeol-scan.sh        - Layer 6: End-of-Life Detection"
echo "  • run-sonar-analysis.sh   - Layer 7: Code Quality Analysis"
echo "  • run-helm-build.sh       - Layer 8: Helm Chart Building"
echo

echo -e "${GREEN}📊 Analysis & Reporting:${NC}"
echo "  • generate-critical-high-summary.sh - Critical/High findings summary"
echo "  • consolidate-security-reports.sh   - Report consolidation"
echo

echo -e "${GREEN}🔧 Clean Backup Versions:${NC}"
for script in "${CLEAN_SCRIPTS[@]}"; do
    if [[ -f "$BASH_DIR/$script" ]]; then
        echo "  • $script - Backup version"
    fi
done

echo
echo -e "${BLUE}📁 Current scripts directory structure:${NC}"
ls -la "$BASH_DIR" | grep "\.sh$" | wc -l | xargs -I {} echo "  📄 {} shell scripts remaining"

echo
echo -e "${GREEN}✅ Script cleanup completed!${NC}"
echo -e "${YELLOW}💡 To run the 8-step security scan, use:${NC}"
echo "   ./run-target-security-scan.sh <target_directory> [full|quick|images|analysis]"
echo
echo -e "${BLUE}📦 Backup location: $BACKUP_DIR${NC}"

# Show final count
FINAL_COUNT=$(find "$BASH_DIR" -name "*.sh" | wc -l)
echo -e "${GREEN}📊 Final count: $FINAL_COUNT scripts (down from $(($FINAL_COUNT + $removed_count)))${NC}"