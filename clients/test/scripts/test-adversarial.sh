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
    # Strip ANSI color codes before comparing (sed removes escape sequences)
    actual_status=$(kels-cli -u "$KELS_URL" status --prefix "$prefix" 2>&1 | grep "^  Status:" | sed 's/\x1b\[[0-9;]*m//g' | awk '{print $2}')
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
# Scenario 6: Adversary Injects Recovery Rotation (ror)
# ========================================
echo -e "${CYAN}=== Scenario 6: Adversary Injects Recovery Rotation (ror) ===${NC}"
echo "Adversary uses ror event specifically, owner contests"
echo ""

# Setup
PREFIX6=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX6"

kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX6" --said "EOwnerAnchorBeforeAdversaryRor______________"

# Adversary injects ror event (they have both signing and recovery keys!)
run_test "Adversary injects ror event" kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX6" --events ror

# Owner tries to add event - this creates divergence
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX6" --said "EOwnerAnchorAfterAdversaryRor_______________" 2>&1 || true

# Verify divergence occurred
run_test "KEL status is DIVERGENT after adversary ror" check_kel_status "$PREFIX6" "DIVERGENT"

# Owner tries to recover - but adversary already used recovery key with ror
run_test "Owner contests (adversary used ror)" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX6"

# Verify KEL is now CONTESTED
run_test "KEL status is CONTESTED after ror contest" check_kel_status "$PREFIX6" "CONTESTED"

echo ""

# ========================================
# Scenario 7: Adversary Decommissions KEL
# ========================================
echo -e "${CYAN}=== Scenario 7: Adversary Decommissions KEL ===${NC}"
echo "Adversary tries to freeze the KEL with dec event"
echo ""

# Setup
PREFIX7=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX7"

kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX7" --said "EOwnerAnchorBeforeAdversaryDec______________"

# Adversary injects dec event (permanent freeze attempt!)
run_test "Adversary injects dec event" kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX7" --events dec

# Owner tries to add event - this creates divergence (owner's event at same version as dec)
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX7" --said "EOwnerAnchorAfterAdversaryDec_______________" 2>&1 || true

# Verify divergence occurred
run_test "KEL status is DIVERGENT after adversary dec" check_kel_status "$PREFIX7" "DIVERGENT"

# Owner tries to recover - adversary used recovery key for dec
run_test "Owner contests (adversary used dec)" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX7"

# Verify KEL is now CONTESTED
run_test "KEL status is CONTESTED after dec contest" check_kel_status "$PREFIX7" "CONTESTED"

echo ""

# ========================================
# Scenario 8: Adversary Rotates Then Anchors
# ========================================
echo -e "${CYAN}=== Scenario 8: Adversary Rotates Then Anchors ===${NC}"
echo "Adversary injects rot,ixn,ixn - controls KEL after rotation"
echo ""

# Setup
PREFIX8=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX8"

# Adversary injects rot followed by anchors
run_test "Adversary injects rot,ixn,ixn" kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX8" --events "rot,ixn,ixn"

# Owner tries to add event - diverges at v1 (owner's event vs adversary's rot)
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX8" --said "EOwnerFirstAnchorAfterAdversaryChain________" 2>&1 || true

# Verify divergence occurred
run_test "KEL status is DIVERGENT after adversary rot chain" check_kel_status "$PREFIX8" "DIVERGENT"

# Owner recovers
run_test "Owner recovers from adversary rot chain" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX8"

# Verify KEL is OK
run_test "KEL status is OK after rot chain recovery" check_kel_status "$PREFIX8" "OK"

# Owner can continue
run_test "Owner can add events after rot chain recovery" kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX8" --said "EPostRotChainRecoveryAnchor_________________"

echo ""

# ========================================
# Scenario 9: Adversary Double Rotation
# ========================================
echo -e "${CYAN}=== Scenario 9: Adversary Double Rotation ===${NC}"
echo "Adversary injects rot,rot - multiple key rotations"
echo ""

# Setup
PREFIX9=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX9"

# Adversary injects two rotations
run_test "Adversary injects rot,rot" kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX9" --events "rot,rot"

# Owner tries to add event - diverges at v1
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX9" --said "EOwnerAnchorAfterDoubleRot__________________" 2>&1 || true

# Verify divergence occurred
run_test "KEL status is DIVERGENT after double rotation" check_kel_status "$PREFIX9" "DIVERGENT"

# Owner recovers
run_test "Owner recovers from double rotation" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX9"

# Verify KEL is OK
run_test "KEL status is OK after double rotation recovery" check_kel_status "$PREFIX9" "OK"

echo ""

# ========================================
# Scenario 10: Owner Rotates, Then Adversary Attacks
# ========================================
echo -e "${CYAN}=== Scenario 10: Owner Rotates, Then Adversary Attacks ===${NC}"
echo "Owner rotates key, then adversary attacks with old key state"
echo ""

# Setup
PREFIX10=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX10"

# Owner rotates key first
run_test "Owner rotates key" kels-cli -u "$KELS_URL" rotate --prefix "$PREFIX10"

# Owner adds an anchor after rotation
run_test "Owner adds anchor after rotation" kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX10" --said "EOwnerAnchorAfterOwnRotation________________"

# Adversary tries to inject (using the stolen/cloned keys which have same state)
# Note: adversary has the rotated keys too since they're loaded from same files
run_test "Adversary injects ixn after owner rotation" kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX10" --events ixn

# Owner's next event will cause divergence
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX10" --said "EOwnerSecondAnchorCausesDivergence__________" 2>&1 || true

# Verify divergence
run_test "KEL status is DIVERGENT after post-rotation attack" check_kel_status "$PREFIX10" "DIVERGENT"

# Owner recovers
run_test "Owner recovers from post-rotation attack" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX10"

# Verify KEL is OK
run_test "KEL status is OK after post-rotation recovery" check_kel_status "$PREFIX10" "OK"

echo ""

# ========================================
# Scenario 11: Adversary Decommissions After Owner Anchors
# ========================================
echo -e "${CYAN}=== Scenario 11: Adversary Decommissions After Owner Anchors ===${NC}"
echo "Owner has anchored data, adversary tries to dec the KEL"
echo ""

# Setup
PREFIX11=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX11"

# Owner adds multiple anchors
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX11" --said "EOwnerImportantData1________________________"
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX11" --said "EOwnerImportantData2________________________"
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX11" --said "EOwnerImportantData3________________________"

# Adversary tries to decommission (freezing owner's data)
run_test "Adversary injects dec after owner anchors" kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX11" --events dec

# Owner tries to add more data - causes divergence
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX11" --said "EOwnerData4AfterAdversaryDec________________" 2>&1 || true

# Verify divergence
run_test "KEL status is DIVERGENT after dec attack on data" check_kel_status "$PREFIX11" "DIVERGENT"

# Owner tries to recover - but adversary used recovery key
run_test "Owner contests (adversary dec'd after anchors)" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX11"

# Verify CONTESTED
run_test "KEL status is CONTESTED after dec-on-data contest" check_kel_status "$PREFIX11" "CONTESTED"

# Verify pre-attack data is still in KEL (even though contested)
run_test "Pre-attack anchors still present" kels-cli -u "$KELS_URL" get "$PREFIX11"

echo ""

# ========================================
# Scenario 12: Adversary Injects Recovery (rec)
# ========================================
echo -e "${CYAN}=== Scenario 12: Adversary Injects Recovery (rec) ===${NC}"
echo "Adversary uses rec event specifically, owner contests"
echo ""

# Setup
PREFIX12=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX12"

kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX12" --said "EOwnerAnchorBeforeAdversaryRec______________"

# Adversary injects rec event (they have the recovery key!)
run_test "Adversary injects rec event" kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX12" --events rec

# Owner tries to add event - this creates divergence
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX12" --said "EOwnerAnchorAfterAdversaryRec_______________" 2>&1 || true

# Verify divergence occurred
run_test "KEL status is DIVERGENT after adversary rec" check_kel_status "$PREFIX12" "DIVERGENT"

# Owner tries to recover - but adversary already used recovery key
run_test "Owner contests (adversary used rec)" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX12"

# Verify KEL is now CONTESTED
run_test "KEL status is CONTESTED after rec contest" check_kel_status "$PREFIX12" "CONTESTED"

echo ""

# ========================================
# Scenario 13: Submission When Frozen
# ========================================
echo -e "${CYAN}=== Scenario 13: Submission When Frozen ===${NC}"
echo "Verify that submissions to a contested KEL are rejected"
echo ""

# Use the contested KEL from scenario 12
run_test_expect_fail "Anchor rejected on contested KEL" kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX12" --said "EAttemptedAnchorOnContestedKel______________"

run_test_expect_fail "Rotation rejected on contested KEL" kels-cli -u "$KELS_URL" rotate --prefix "$PREFIX12"

run_test_expect_fail "Recovery rejected on contested KEL" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX12"

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
