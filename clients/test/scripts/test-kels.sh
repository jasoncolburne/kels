#!/bin/bash
# test-kels.sh - Basic KEL Operations Test
# Tests core KELS functionality: inception, rotation, anchoring, decommission
#
# Usage: test-kels.sh

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Service endpoints
TEST_KELS_HOST="${TEST_KELS_HOST:-kels}"
TEST_KELS_PORT="${TEST_KELS_PORT:-80}"
KELS_URL="http://${TEST_KELS_HOST}:${TEST_KELS_PORT}"

# Test state
TESTS_PASSED=0
TESTS_FAILED=0
TEMP_DIR=$(mktemp -d)
export KELS_CLI_HOME="$TEMP_DIR"

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Test helpers
run_test() {
    local name="$1"
    shift
    echo -e "${YELLOW}Testing: ${name}${NC}"
    local output
    if output=$("$@" 2>&1); then
        echo "$output"
        echo -e "${GREEN}PASSED: ${name}${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo "$output"
        echo -e "${RED}FAILED: ${name}${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

run_test_expect_fail() {
    local name="$1"
    shift
    echo -e "${YELLOW}Testing (expect fail): ${name}${NC}"
    local output
    if output=$("$@" 2>&1); then
        echo "$output"
        echo -e "${RED}FAILED: ${name} (expected failure but succeeded)${NC}"
        ((TESTS_FAILED++))
        return 1
    else
        echo -e "${GREEN}PASSED: ${name}${NC}"
        ((TESTS_PASSED++))
        return 0
    fi
}

echo "========================================="
echo "KELS Basic Operations Test"
echo "========================================="
echo "KELS URL: $KELS_URL"
echo "Config:   $KELS_CLI_HOME"
echo "========================================="
echo ""

# Wait for KELS to be ready
echo "Waiting for KELS server..."
for i in {1..30}; do
    if curl -s "$KELS_URL/health" > /dev/null 2>&1; then
        echo "KELS server is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}KELS server not ready after 30 seconds${NC}"
        exit 1
    fi
    sleep 1
done
echo ""

# Test 1: Create inception event
run_test "Create inception event" kels-cli -u "$KELS_URL" incept

# Get the prefix from the local KEL list
PREFIX=$(kels-cli -u "$KELS_URL" list 2>/dev/null | grep -v "Local KELs" | grep -v "(none)" | head -1 | tr -d ' ')
if [ -z "$PREFIX" ]; then
    echo -e "${RED}Failed to get prefix from inception${NC}"
    exit 1
fi
echo "Created KEL with prefix: $PREFIX"

# Test 2: Rotate signing key
run_test "Rotate signing key" kels-cli -u "$KELS_URL" rotate --prefix "$PREFIX"

# Test 3: Anchor a SAID
TEST_SAID="EBk8ZjTMvX4UJ9K5b_XQNJ1a9K_8QNsKJ1a9K_8QNsKJ"
run_test "Anchor SAID (interaction)" kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX" --said "$TEST_SAID"

# Test 4: Rotate recovery key
run_test "Rotate recovery key" kels-cli -u "$KELS_URL" rotate-recovery --prefix "$PREFIX"

# Test 5: Get KEL from server
run_test "Fetch KEL from server" kels-cli -u "$KELS_URL" get "$PREFIX"

# Test 6: Check local status
run_test "Check local KEL status" kels-cli -u "$KELS_URL" status --prefix "$PREFIX"

# Test 7: List local KELs
run_test "List local KELs" kels-cli -u "$KELS_URL" list

# Test 8: Create second KEL
run_test "Create second KEL" kels-cli -u "$KELS_URL" incept

# Test 9: Decommission first KEL
run_test "Decommission KEL" kels-cli -u "$KELS_URL" decommission --prefix "$PREFIX"

# Tests 10-13: Verify decommissioned KEL rejects normal event types
run_test_expect_fail "Reject anchor on decommissioned KEL" kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX" --said "$TEST_SAID"
run_test_expect_fail "Reject rotate on decommissioned KEL" kels-cli -u "$KELS_URL" rotate --prefix "$PREFIX"
run_test_expect_fail "Reject rotate-recovery on decommissioned KEL" kels-cli -u "$KELS_URL" rotate-recovery --prefix "$PREFIX"
run_test_expect_fail "Reject decommission on decommissioned KEL" kels-cli -u "$KELS_URL" decommission --prefix "$PREFIX"

# Test 14: Recover on decommissioned KEL contests (dec reveals recovery key)
# With simplified model, recover detects adversary revealed recovery and auto-contests
run_test "Recover on decommissioned KEL contests" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX"

# Test 15: Verify cnt event is present in KEL after contest
echo -e "${YELLOW}Testing: Verify cnt event present after contest${NC}"
KEL_OUTPUT=$(kels-cli -u "$KELS_URL" get "$PREFIX" 2>&1)
if echo "$KEL_OUTPUT" | grep -q 'CNT'; then
    echo -e "${GREEN}PASSED: cnt event found in KEL${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}FAILED: cnt event not found in KEL${NC}"
    echo "KEL output: $KEL_OUTPUT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Print summary
echo ""
echo "========================================="
echo "Test Summary"
echo "========================================="
echo -e "Passed: ${GREEN}${TESTS_PASSED}${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "Failed: ${RED}${TESTS_FAILED}${NC}"
else
    echo -e "Failed: ${GREEN}${TESTS_FAILED}${NC}"
fi
echo "========================================="

if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
fi
