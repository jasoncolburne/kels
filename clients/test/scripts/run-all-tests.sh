#!/bin/bash
# run-all-tests.sh - Run all KELS test scripts
#
# Usage: run-all-tests.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=========================================${NC}"
echo -e "${CYAN}KELS Test Suite${NC}"
echo -e "${CYAN}=========================================${NC}"
echo ""

FAILED=0

# Run basic KEL operations test
echo -e "${CYAN}Running: test-kels.sh${NC}"
if "$SCRIPT_DIR/test-kels.sh"; then
    echo -e "${GREEN}test-kels.sh PASSED${NC}"
else
    echo -e "${RED}test-kels.sh FAILED${NC}"
    FAILED=1
fi
echo ""

# Run adversarial tests (requires dev-tools)
if kels-cli --help 2>&1 | grep -q "adversary"; then
    echo -e "${CYAN}Running: test-adversarial.sh${NC}"
    if "$SCRIPT_DIR/test-adversarial.sh"; then
        echo -e "${GREEN}test-adversarial.sh PASSED${NC}"
    else
        echo -e "${RED}test-adversarial.sh FAILED${NC}"
        FAILED=1
    fi
else
    echo -e "${CYAN}Skipping: test-adversarial.sh (dev-tools not enabled)${NC}"
fi
echo ""

# Final summary
echo -e "${CYAN}=========================================${NC}"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests PASSED${NC}"
    exit 0
else
    echo -e "${RED}Some tests FAILED${NC}"
    exit 1
fi
