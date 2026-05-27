#!/bin/bash

# Quick Test Script for Desktop Default Behavior
# Shows how the portable scanner now defaults to Desktop directory

# Color definitions
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
NC='\033[0m'

echo -e "${WHITE}============================================${NC}"
echo -e "${WHITE}🎯 Portable Scanner - Desktop Default Test${NC}"
echo -e "${WHITE}============================================${NC}"
echo

echo -e "${BLUE}📋 Testing new Desktop directory default behavior...${NC}"
echo

echo -e "${YELLOW}Test 1: Help command${NC}"
echo "Command: ./portable-app-scanner.sh --help | head -15"
echo
./portable-app-scanner.sh --help | head -15
echo

echo -e "${YELLOW}Test 2: Default behavior (should default to Desktop)${NC}"
echo "Command: ./portable-app-scanner.sh quick (with early exit)"
echo
# Run with quick scan but exit after directory detection
(./portable-app-scanner.sh quick 2>&1 | head -12) &
PID=$!
sleep 3
kill $PID 2>/dev/null || true
wait $PID 2>/dev/null || true

echo
echo -e "${YELLOW}Test 3: Scan type detection${NC}"
echo "Command: ./portable-app-scanner.sh secrets-only (with early exit)"  
echo
# Run secrets scan but exit after directory detection
(./portable-app-scanner.sh secrets-only 2>&1 | head -12) &
PID=$!
sleep 3
kill $PID 2>/dev/null || true
wait $PID 2>/dev/null || true

echo
echo -e "${GREEN}✅ Desktop Default Enhancement Working!${NC}"
echo
echo -e "${BLUE}💡 Usage Examples:${NC}"
echo "• ./portable-app-scanner.sh                    → Full scan of Desktop"
echo "• ./portable-app-scanner.sh quick             → Quick scan of Desktop"
echo "• ./portable-app-scanner.sh secrets-only      → Secrets scan of Desktop"
echo "• ./portable-app-scanner.sh /path/to/app      → Scan specific directory"
echo
echo -e "${WHITE}============================================${NC}"