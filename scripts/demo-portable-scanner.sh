#!/bin/bash

# Portable Scanner Demo Script
# Demonstrates how to use the portable security scanner on different applications

# Color definitions
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
NC='\033[0m'

SCANNER_SCRIPT="./portable-app-scanner.sh"

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}🎯 Portable Security Scanner Demonstration${NC}"
echo -e "${WHITE}============================================${NC}"
echo

# Demo 1: Quick scan of the original marketplace app
echo -e "${BLUE}📋 Demo 1: Quick scan of original marketplace application${NC}"
echo -e "${YELLOW}Command: $SCANNER_SCRIPT /Users/rnelson/Desktop/CDAO\ MarketPlace/Marketplace/advana-marketplace quick${NC}"
echo

read -p "Press Enter to run quick scan demo..."

$SCANNER_SCRIPT "/Users/rnelson/Desktop/CDAO MarketPlace/Marketplace/advana-marketplace" quick

echo
echo -e "${GREEN}✅ Demo 1 completed!${NC}"
echo

# Demo 2: Secrets-only scan
echo -e "${BLUE}📋 Demo 2: Secrets-only scan${NC}"
echo -e "${YELLOW}Command: $SCANNER_SCRIPT /Users/rnelson/Desktop/CDAO\ MarketPlace/Marketplace/advana-marketplace secrets-only${NC}"
echo

read -p "Press Enter to run secrets-only scan demo..."

$SCANNER_SCRIPT "/Users/rnelson/Desktop/CDAO MarketPlace/Marketplace/advana-marketplace" secrets-only --output-dir /tmp/secrets-scan-demo

echo
echo -e "${GREEN}✅ Demo 2 completed!${NC}"
echo

# Demo 3: Show how to scan any directory
echo -e "${BLUE}📋 Demo 3: How to scan any application directory${NC}"
echo
echo -e "${YELLOW}Examples of how to use the portable scanner:${NC}"
echo
echo "# Scan any Node.js application:"
echo "$SCANNER_SCRIPT /path/to/nodejs-app"
echo
echo "# Scan any Python application:"
echo "$SCANNER_SCRIPT /path/to/python-app vulns-only"
echo
echo "# Scan with custom output directory:"
echo "$SCANNER_SCRIPT /path/to/any-app full --output-dir /custom/output/path"
echo
echo "# Quick security check:"
echo "$SCANNER_SCRIPT /path/to/app quick"
echo
echo "# Check for secrets only:"
echo "$SCANNER_SCRIPT /path/to/app secrets-only"
echo
echo "# Infrastructure security only:"
echo "$SCANNER_SCRIPT /path/to/kubernetes-app iac-only"

echo
echo -e "${WHITE}============================================${NC}"
echo -e "${GREEN}🎉 Portable Scanner Demo Complete!${NC}"
echo -e "${WHITE}============================================${NC}"
echo
echo -e "${BLUE}💡 Key Features:${NC}"
echo "✅ Scans any application directory"
echo "✅ Auto-detects application type (Node.js, Python, Java, etc.)"
echo "✅ Multiple scan types (full, quick, secrets-only, etc.)"
echo "✅ Docker-based tools for consistency"
echo "✅ Generates comprehensive reports"
echo "✅ Works on any filesystem location"
echo
echo -e "${BLUE}🚀 Ready to scan any application!${NC}"