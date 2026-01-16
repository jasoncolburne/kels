#!/bin/bash
# test-adversarial.sh - Adversarial Divergence and Recovery Tests
# Tests KELS divergence detection and recovery mechanisms
#
# Requires kels-cli built with --features dev-tools
#
# Usage: test-adversarial.sh

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
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

check_kel_status() {
    local prefix="$1"
    local expected_status="$2"
    local actual_status
    # Use "^  Status:" to match the indented status line, not "KEL Status:" header
    actual_status=$(kels-cli -u "$KELS_URL" status --prefix "$prefix" 2>&1 | grep "^  Status:" | awk '{print $2}')
    [ "$actual_status" = "$expected_status" ]
}

check_kel_event_count() {
    local prefix="$1"
    local expected_count="$2"
    local actual_count
    actual_count=$(kels-cli -u "$KELS_URL" get "$prefix" 2>&1 | grep "Events:" | awk '{print $2}')
    [ "$actual_count" = "$expected_count" ]
}

check_server_kel_event_count() {
    local prefix="$1"
    local expected_count="$2"
    local actual_count
    actual_count=$(curl -s "$KELS_URL/api/kels/kel/$prefix" | jq '. | length')
    [ "$actual_count" = "$expected_count" ]
}

echo "========================================="
echo "KELS Adversarial Test Suite"
echo "========================================="
echo "KELS URL: $KELS_URL"
echo "Config:   $KELS_CLI_HOME"
echo "========================================="
echo ""

# Check if dev-tools feature is available
if ! kels-cli --help 2>&1 | grep -q "adversary"; then
    echo -e "${RED}ERROR: kels-cli must be built with --features dev-tools${NC}"
    exit 1
fi

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

# ========================================
# Scenario 1: Adversary Injects Interaction
# ========================================
echo -e "${CYAN}=== Scenario 1: Adversary Injects Interaction ===${NC}"
echo "Owner creates KEL, adversary injects ixn, owner's event creates divergence, owner recovers"
echo ""

# Setup: Owner creates KEL and adds some events
PREFIX1=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX1"

kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX1" --said "EOwnerAnchor1_______________________________"
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX1" --said "EOwnerAnchor2_______________________________"

# Adversary injects event (simulating key compromise)
run_test "Adversary injects ixn event" kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX1" --events ixn

# Owner tries to add another event - should be stored but cause divergence
# The CLI will report failure because divergence is detected, but event IS stored on server
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX1" --said "EOwnerAnchor3_______________________________" 2>&1 || true

# Verify server has BOTH divergent events (5 total: icp + 2 owner ixn + adv ixn + owner ixn)
run_test "Server has both divergent events (5 total)" check_server_kel_event_count "$PREFIX1" "5"

# Fetch KEL and verify it shows divergence
run_test "Fetch KEL shows divergent events" kels-cli -u "$KELS_URL" get "$PREFIX1"

# Verify local status shows DIVERGENT
run_test "KEL status is DIVERGENT before recovery" check_kel_status "$PREFIX1" "DIVERGENT"

# Owner recovers
run_test "Owner recovers KEL" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX1"

# Verify KEL is now OK
run_test "KEL status is OK after recovery" check_kel_status "$PREFIX1" "OK"

# Owner can now add events again
run_test "Owner can add events after recovery" kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX1" --said "EPostRecoveryAnchor_________________________"

echo ""

# ========================================
# Scenario 2: Adversary Injects Rotation
# ========================================
echo -e "${CYAN}=== Scenario 2: Adversary Injects Rotation ===${NC}"
echo "Owner creates KEL, adversary rotates key, owner's event causes divergence, owner recovers"
echo ""

# Setup
PREFIX2=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX2"

kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX2" --said "EOwnerData__________________________________"

# Adversary injects rotation (they now control the signing key!)
run_test "Adversary injects rot event" kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX2" --events rot

# Owner tries to add event - this creates divergence (owner's event vs adversary's rot at same version)
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX2" --said "EOwnerAnchorAfterAdversaryRot_______________" 2>&1 || true

# Verify divergence occurred
run_test "KEL status is DIVERGENT after adversary rotation" check_kel_status "$PREFIX2" "DIVERGENT"

# Owner recovers (using recovery key)
run_test "Owner recovers after adversary rotation" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX2"

# Verify KEL is recovered
run_test "KEL status is OK after rotation recovery" check_kel_status "$PREFIX2" "OK"

echo ""

# ========================================
# Scenario 3: Multiple Adversary Events
# ========================================
echo -e "${CYAN}=== Scenario 3: Multiple Adversary Events ===${NC}"
echo "Adversary injects multiple events, owner's event causes divergence, owner recovers all"
echo ""

# Setup
PREFIX3=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX3"

# Adversary injects multiple events
run_test "Adversary injects multiple events" kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX3" --events "ixn,ixn,rot"

# Owner tries to add event - this creates divergence at version 1
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX3" --said "EOwnerAnchorAfterMultiAdversary_____________" 2>&1 || true

# Verify divergence occurred
run_test "KEL status is DIVERGENT after multiple adversary events" check_kel_status "$PREFIX3" "DIVERGENT"

# Owner recovers (all adversary events should be archived)
run_test "Owner recovers from multiple adversary events" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX3"

# Verify clean state
run_test "KEL is clean after multi-event recovery" check_kel_status "$PREFIX3" "OK"

echo ""

# ========================================
# Scenario 4: Data Integrity After Recovery
# ========================================
echo -e "${CYAN}=== Scenario 4: Data Integrity After Recovery ===${NC}"
echo "Verify anchors before attack are still valid after recovery"
echo ""

# Setup with specific anchors
PREFIX4=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX4"

ANCHOR1="EPreAttackAnchor1___________________________"
ANCHOR2="EPreAttackAnchor2___________________________"
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX4" --said "$ANCHOR1"
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX4" --said "$ANCHOR2"

# Adversary injects event
kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX4" --events ixn

# Owner tries to add event - this creates divergence
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX4" --said "EOwnerPostAttackAnchor______________________" 2>&1 || true

# Verify divergence occurred
run_test "KEL status is DIVERGENT before integrity check" check_kel_status "$PREFIX4" "DIVERGENT"

# Recover
run_test "Owner recovers for integrity test" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX4"

# Verify pre-attack anchors are still in KEL
run_test "Pre-attack anchors preserved" kels-cli -u "$KELS_URL" get "$PREFIX4"

echo ""

# ========================================
# Scenario 5: Owner Submits Divergent Rotation
# ========================================
echo -e "${CYAN}=== Scenario 5: Owner Submits Divergent Rotation ===${NC}"
echo "Adversary injects event, owner's rotation causes divergence, owner recovers"
echo ""

# Setup
PREFIX5=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX5"

kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX5" --said "EOwnerSetupAnchor___________________________"

# Adversary injects ixn (unknown to owner)
run_test "Adversary injects ixn (before owner rotation)" kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX5" --events ixn

# Owner tries to rotate - this causes divergence (owner's rot event is accepted but divergent)
kels-cli -u "$KELS_URL" rotate --prefix "$PREFIX5" 2>&1 || true

# Verify divergence occurred (server should have both events at the same version)
run_test "Server has divergent rotation" check_server_kel_event_count "$PREFIX5" "4"
run_test "KEL status is DIVERGENT after owner rotation" check_kel_status "$PREFIX5" "DIVERGENT"

# Owner recovers (must use keys from BEFORE the failed rotation)
run_test "Owner recovers after divergent rotation" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX5"

# Verify KEL is recovered
run_test "KEL status is OK after recovery from divergent rotation" check_kel_status "$PREFIX5" "OK"

# Owner can continue after recovery
run_test "Owner can add events after rotation recovery" kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX5" --said "EPostRotationRecoveryAnchor_________________"

echo ""

# ========================================
# Print Summary
# ========================================
echo ""
echo "========================================="
echo "Adversarial Test Summary"
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
