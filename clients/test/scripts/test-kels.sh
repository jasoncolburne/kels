#!/usr/bin/env bash
# test-kels.sh - Basic KEL Operations Test
# Tests core KELS functionality: inception, rotation, anchoring, decommission
#
# Usage: test-kels.sh

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Service endpoints
TEST_KELS_HOST="${TEST_KELS_HOST:-kels}"
TEST_KELS_PORT="${TEST_KELS_PORT:-80}"
KELS_URL="http://${TEST_KELS_HOST}:${TEST_KELS_PORT}"

init_temp_dir

echo "========================================="
echo "KELS Basic Operations Test"
echo "========================================="
echo "KELS URL: $KELS_URL"
echo "Config:   $KELS_CLI_HOME"
echo "========================================="
echo ""

# Wait for KELS to be ready
echo "Waiting for KELS server..."
wait_for_health "$KELS_URL" "KELS server" || exit 1
echo ""

# Test 1: Create inception event
run_test "Create inception event" kels-cli --kels-url "$KELS_URL" kel incept

# Get the prefix from the local KEL list
PREFIX=$(kels-cli --kels-url "$KELS_URL" kel list 2>/dev/null | grep -v "Local KELs" | grep -v "(none)" | head -1 | tr -d ' ')
if [ -z "$PREFIX" ]; then
    echo -e "${RED}Failed to get prefix from inception${NC}"
    exit 1
fi
echo "Created KEL with prefix: $PREFIX"

# Test 2: Rotate signing key
run_test "Rotate signing key" kels-cli --kels-url "$KELS_URL" kel rotate --prefix "$PREFIX"

# Test 3: Anchor a SAID
TEST_SAID="KBk8ZjTMvX4UJ9K5b_XQNJ1a9K_8QNsKJ1a9K_8QNsKJ"
run_test "Anchor SAID (interaction)" kels-cli --kels-url "$KELS_URL" kel anchor --prefix "$PREFIX" --said "$TEST_SAID"

# Test 4: Rotate recovery key
run_test "Rotate recovery key" kels-cli --kels-url "$KELS_URL" kel rotate-recovery --prefix "$PREFIX"

# Test 5: Get KEL from server
run_test "Fetch KEL from server" kels-cli --kels-url "$KELS_URL" kel get "$PREFIX"

# Test 6: Check local status
run_test "Check local KEL kel status" kels-cli --kels-url "$KELS_URL" kel status --prefix "$PREFIX"

# Test 7: List local KELs
run_test "List local KELs" kels-cli --kels-url "$KELS_URL" kel list

# Test 8: Create second KEL
run_test "Create second KEL" kels-cli --kels-url "$KELS_URL" kel incept

# Test 9: Decommission first KEL
run_test "Decommission KEL" kels-cli --kels-url "$KELS_URL" kel decommission --prefix "$PREFIX"

# Tests 10-13: Verify decommissioned KEL rejects normal event types
run_test_expect_fail "Reject kel anchor on decommissioned KEL" kels-cli --kels-url "$KELS_URL" kel anchor --prefix "$PREFIX" --said "$TEST_SAID"
run_test_expect_fail "Reject kel rotate on decommissioned KEL" kels-cli --kels-url "$KELS_URL" kel rotate --prefix "$PREFIX"
run_test_expect_fail "Reject kel rotate-recovery on decommissioned KEL" kels-cli --kels-url "$KELS_URL" kel rotate-recovery --prefix "$PREFIX"
run_test_expect_fail "Reject kel decommission on decommissioned KEL" kels-cli --kels-url "$KELS_URL" kel decommission --prefix "$PREFIX"

# Test 14: Recover on self-decommissioned KEL should fail (no adversary to contest)
# Recovery is for adversarial situations, not for undoing your own decommission
run_test_expect_fail "Reject kel recover on self-decommissioned KEL" kels-cli --kels-url "$KELS_URL" kel recover --prefix "$PREFIX"

print_summary "KELS Basic Operations Test Summary"
exit_with_result
