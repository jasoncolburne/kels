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

# Directory swap helpers for adversary simulation
save_adversary_keys() {
    cp -r "$KELS_CLI_HOME" "$KELS_CLI_HOME.adversary"
}

swap_to_adversary() {
    mv "$KELS_CLI_HOME" "$KELS_CLI_HOME.owner"
    cp -r "$KELS_CLI_HOME.adversary" "$KELS_CLI_HOME"
}

swap_to_owner() {
    rm -rf "$KELS_CLI_HOME"
    mv "$KELS_CLI_HOME.owner" "$KELS_CLI_HOME"
}

cleanup_adversary_backup() {
    rm -rf "$KELS_CLI_HOME.adversary"
    rm -rf "$KELS_CLI_HOME.owner"
}

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

# Test that expects divergence to be caused (returns error but with "Divergence detected" message)
run_test_expect_divergence() {
    local name="$1"
    local prefix="$2"
    shift 2
    echo -e "${YELLOW}Testing (expect divergence): ${name}${NC}"
    # Run the command (expected to fail)
    "$@" 2>&1 || true
    # Check server state for divergence
    local status
    status=$(kels-cli -u "$KELS_URL" get "$prefix" 2>&1 | grep "^  Status:" | sed 's/\x1b\[[0-9;]*m//g' | awk '{print $2}')
    if [ "$status" = "DIVERGENT" ]; then
        echo -e "${GREEN}PASSED: ${name}${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo "Expected status DIVERGENT but got: $status"
        echo -e "${RED}FAILED: ${name} (expected divergence but not detected)${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Test that expects recovery protection (adversary used recovery key)
run_test_expect_recovery_protected() {
    local name="$1"
    local prefix="$2"
    shift 2
    echo -e "${YELLOW}Testing (expect recovery protected): ${name}${NC}"
    # Run the command and capture output (expected to fail with recovery protected error)
    local output
    output=$("$@" 2>&1) || true
    echo "$output"
    # Check if the error message indicates recovery protection
    if echo "$output" | grep -qi "recovery protected"; then
        echo -e "${GREEN}PASSED: ${name}${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo "Expected 'Recovery protected' error but got: $output"
        echo -e "${RED}FAILED: ${name} (expected recovery protected but not detected)${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

check_kel_status() {
    local prefix="$1"
    local expected_status="$2"
    local actual_status
    # Use "get" to query server directly (not local storage)
    # Strip ANSI color codes before comparing (sed removes escape sequences)
    actual_status=$(kels-cli -u "$KELS_URL" get "$prefix" 2>&1 | grep "^  Status:" | sed 's/\x1b\[[0-9;]*m//g' | awk '{print $2}')
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

# Check that the last N events have specific kinds (comma-separated)
# e.g., check_kel_ends_with "$PREFIX" "rec,rot" checks last 2 events are rec then rot
check_kel_ends_with() {
    local prefix="$1"
    local expected_kinds="$2"  # comma-separated, e.g., "rec,rot"

    # Convert expected kinds to array
    IFS=',' read -ra expected_array <<< "$expected_kinds"
    local expected_count=${#expected_array[@]}

    # Get last N events from server
    local actual_kinds
    actual_kinds=$(curl -s "$KELS_URL/api/kels/kel/$prefix" | jq -r ".[-$expected_count:][].event.kind" | tr '\n' ',' | sed 's/,$//')

    if [ "$actual_kinds" = "$expected_kinds" ]; then
        return 0
    else
        echo "Expected last $expected_count events to be: $expected_kinds"
        echo "Actual last $expected_count events are: $actual_kinds"
        # Also show full KEL event kinds for context
        local all_kinds
        all_kinds=$(curl -s "$KELS_URL/api/kels/kel/$prefix" | jq -r '.[].event.kind' | tr '\n' ',' | sed 's/,$//')
        echo "Full KEL event kinds: $all_kinds"
        return 1
    fi
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
run_test_expect_divergence "Owner anchor triggers divergence" "$PREFIX1" \
    kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX1" --said "EOwnerAnchor3_______________________________"

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

# Verify recovery ends with rec
run_test "KEL ends with rec after ixn-only recovery" check_kel_ends_with "$PREFIX1" "rec"

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
run_test_expect_divergence "Owner anchor triggers divergence" "$PREFIX2" \
    kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX2" --said "EOwnerAnchorAfterAdversaryRot_______________"

# Verify divergence occurred
run_test "KEL status is DIVERGENT after adversary rotation" check_kel_status "$PREFIX2" "DIVERGENT"

# Owner recovers (using recovery key)
run_test "Owner recovers after adversary rotation" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX2"

# Verify KEL is recovered
run_test "KEL status is OK after rotation recovery" check_kel_status "$PREFIX2" "OK"

# Verify recovery from adversary rotation ends with rec,rot (extra rotation to escape compromised key)
run_test "KEL ends with rec,rot after adversary rotation recovery" check_kel_ends_with "$PREFIX2" "rec,rot"

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
run_test_expect_divergence "Owner anchor triggers divergence" "$PREFIX3" \
    kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX3" --said "EOwnerAnchorAfterMultiAdversary_____________"

# Verify divergence occurred
run_test "KEL status is DIVERGENT after multiple adversary events" check_kel_status "$PREFIX3" "DIVERGENT"

# Owner recovers (all adversary events should be archived)
run_test "Owner recovers from multiple adversary events" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX3"

# Verify clean state
run_test "KEL is clean after multi-event recovery" check_kel_status "$PREFIX3" "OK"

# Verify recovery ends with rec,rot (adversary had rotated)
run_test "KEL ends with rec,rot after multi-event recovery" check_kel_ends_with "$PREFIX3" "rec,rot"

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
run_test_expect_divergence "Owner anchor triggers divergence" "$PREFIX4" \
    kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX4" --said "EOwnerPostAttackAnchor______________________"

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
run_test_expect_divergence "Owner rotation triggers divergence" "$PREFIX5" \
    kels-cli -u "$KELS_URL" rotate --prefix "$PREFIX5"

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

# Owner tries to add event - blocked by recovery protection (adversary revealed recovery key)
run_test_expect_recovery_protected "Owner anchor blocked by recovery protection" "$PREFIX6" \
    kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX6" --said "EOwnerAnchorAfterAdversaryRor_______________"

# Owner contests directly (adversary revealed recovery key)
run_test "Owner contests (adversary used ror)" kels-cli -u "$KELS_URL" contest --prefix "$PREFIX6"

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

# Owner tries to add event - blocked by recovery protection (adversary revealed recovery key)
run_test_expect_recovery_protected "Owner anchor blocked by recovery protection" "$PREFIX7" \
    kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX7" --said "EOwnerAnchorAfterAdversaryDec_______________"

# Owner contests - adversary used recovery key for dec
run_test "Owner contests (adversary used dec)" kels-cli -u "$KELS_URL" contest --prefix "$PREFIX7"

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
run_test_expect_divergence "Owner anchor triggers divergence" "$PREFIX8" \
    kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX8" --said "EOwnerFirstAnchorAfterAdversaryChain________"

# Verify divergence occurred
run_test "KEL status is DIVERGENT after adversary rot chain" check_kel_status "$PREFIX8" "DIVERGENT"

# Owner recovers
run_test "Owner recovers from adversary rot chain" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX8"

# Verify KEL is OK
run_test "KEL status is OK after rot chain recovery" check_kel_status "$PREFIX8" "OK"

# Verify recovery ends with rec,rot (adversary had rotated)
run_test "KEL ends with rec,rot after rot chain recovery" check_kel_ends_with "$PREFIX8" "rec,rot"

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
run_test_expect_divergence "Owner anchor triggers divergence" "$PREFIX9" \
    kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX9" --said "EOwnerAnchorAfterDoubleRot__________________"

# Verify divergence occurred
run_test "KEL status is DIVERGENT after double rotation" check_kel_status "$PREFIX9" "DIVERGENT"

# Owner recovers
run_test "Owner recovers from double rotation" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX9"

# Verify KEL is OK
run_test "KEL status is OK after double rotation recovery" check_kel_status "$PREFIX9" "OK"

# Verify recovery ends with rec,rot (adversary had rotated)
run_test "KEL ends with rec,rot after double rotation recovery" check_kel_ends_with "$PREFIX9" "rec,rot"

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
run_test_expect_divergence "Owner anchor triggers divergence" "$PREFIX10" \
    kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX10" --said "EOwnerSecondAnchorCausesDivergence__________"

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

# Owner tries to add more data - blocked by recovery protection
run_test_expect_recovery_protected "Owner anchor blocked by recovery protection" "$PREFIX11" \
    kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX11" --said "EOwnerData4AfterAdversaryDec________________"

# Owner contests (adversary used recovery key)
run_test "Owner contests (adversary dec'd after anchors)" kels-cli -u "$KELS_URL" contest --prefix "$PREFIX11"

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

# Owner tries to add event - blocked by recovery protection
run_test_expect_recovery_protected "Owner anchor blocked by recovery protection" "$PREFIX12" \
    kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX12" --said "EOwnerAnchorAfterAdversaryRec_______________"

# Owner contests (adversary used recovery key)
run_test "Owner contests (adversary used rec)" kels-cli -u "$KELS_URL" contest --prefix "$PREFIX12"

# Verify KEL is now CONTESTED
run_test "KEL status is CONTESTED after rec contest" check_kel_status "$PREFIX12" "CONTESTED"

echo ""

# ========================================
# Scenario 13: Adversary Attacks Old Version After Multiple Rotations
# ========================================
echo -e "${CYAN}=== Scenario 13: Adversary Attacks Old Version After Multiple Rotations ===${NC}"
echo "Owner rotates twice after adversary steals keys, adversary attacks with old keys"
echo "Owner recovers without extra rotation (already escaped to new keys)"
echo ""

# Setup: owner builds initial chain
PREFIX13=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX13"

kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX13" --said "EOwnerAnchorV1______________________________"
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX13" --said "EOwnerAnchorV2______________________________"

# Adversary steals keys at this point (v2)
save_adversary_keys

# Owner rotates twice, escaping to new keys adversary doesn't have
run_test "Owner rotates (v3)" kels-cli -u "$KELS_URL" rotate --prefix "$PREFIX13"
run_test "Owner rotates again (v4)" kels-cli -u "$KELS_URL" rotate --prefix "$PREFIX13"

# Owner's chain: icp(v0), ixn(v1), ixn(v2), rot(v3), rot(v4)

# Adversary attacks using stolen keys (from before owner's rotations)
swap_to_adversary

# Adversary injects rot at v3 - creates divergence with owner's rot(v3)
run_test_expect_divergence "Adversary injects rot using stolen keys" "$PREFIX13" \
    kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX13" --events rot

# Restore owner's state
swap_to_owner

# Owner recovers - no extra rotation needed because owner already rotated past compromised keys
run_test "Owner recovers" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX13"

# Verify recovery succeeded
run_test "KEL status is OK after recovery" check_kel_status "$PREFIX13" "OK"

# Recovery should end with just rec (no extra rot needed - owner already escaped)
run_test "KEL ends with rec (no extra rot - owner already rotated)" check_kel_ends_with "$PREFIX13" "rec"

# Owner can continue
run_test "Owner can add events after recovery" kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX13" --said "EPostHistoricalRecoveryAnchor_______________"

# Cleanup
cleanup_adversary_backup

echo ""

# ========================================
# Scenario 14: Submission When Frozen
# ========================================
echo -e "${CYAN}=== Scenario 14: Submission When Frozen ===${NC}"
echo "Verify that submissions to a contested KEL are rejected"
echo ""

# Use the contested KEL from scenario 12
run_test_expect_fail "Anchor rejected on contested KEL" kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX12" --said "EAttemptedAnchorOnContestedKel______________"

run_test_expect_fail "Rotation rejected on contested KEL" kels-cli -u "$KELS_URL" rotate --prefix "$PREFIX12"

run_test_expect_fail "Recovery rejected on contested KEL" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX12"

echo ""

# ========================================
# Scenario 15: Proactive Recovery Protection via ROR
# ========================================
echo -e "${CYAN}=== Scenario 15: Proactive Recovery Protection via ROR ===${NC}"
echo "Owner rotates recovery key proactively, preventing historical injection"
echo ""

# Setup
PREFIX15=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX15"

# Adversary steals keys at v0
save_adversary_keys

# Owner continues: ixn (v1), ror (v2)
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX15" --said "EOwnerAnchorV1______________________________"
run_test "Owner rotates recovery key proactively" kels-cli -u "$KELS_URL" rotate-recovery --prefix "$PREFIX15"

# Adversary tries to inject at v1 (from their perspective) - should be rejected
# because ror at v2 protects earlier versions
swap_to_adversary

run_test_expect_fail "Adversary injection rejected (RecoveryProtected)" \
    kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX15" --events ixn

swap_to_owner

# KEL should still be OK (no divergence occurred)
run_test "KEL status is OK (protected by ror)" check_kel_status "$PREFIX15" "OK"

# Owner can still add events normally
run_test "Owner can add events after ror" kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX15" --said "EOwnerAnchorAfterRor________________________"

cleanup_adversary_backup

echo ""

# ========================================
# Scenario 16: Post-Recovery Protection
# ========================================
echo -e "${CYAN}=== Scenario 16: Post-Recovery Protection ===${NC}"
echo "After recovery, adversary cannot re-diverge at earlier versions"
echo ""

# Setup: create divergence and recover
PREFIX16=$(kels-cli -u "$KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL: $PREFIX16"

# Adversary steals keys at v0
save_adversary_keys

# Owner continues: ixn (v1), ixn (v2)
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX16" --said "EOwnerAnchorV1______________________________"
kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX16" --said "EOwnerAnchorV2______________________________"

# Adversary injects at v1 (from their perspective), creating divergence
swap_to_adversary

run_test_expect_divergence "Adversary injects (creates divergence)" "$PREFIX16" \
    kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX16" --events ixn

swap_to_owner

# Owner syncs divergence and recovers
run_test_expect_divergence "Owner anchor syncs divergence" "$PREFIX16" \
    kels-cli -u "$KELS_URL" anchor --prefix "$PREFIX16" --said "EOwnerAnchorV3TriggersDivergence____________"
run_test "Owner recovers" kels-cli -u "$KELS_URL" recover --prefix "$PREFIX16"

# KEL is now: icp(v0), ixn(v1), ixn(v2), rec(v3) (rec at divergence point)
run_test "KEL status is OK after recovery" check_kel_status "$PREFIX16" "OK"

# Adversary tries to re-diverge at v1 (still has v0 keys) - should be rejected
# because rec at v3 protects earlier versions
swap_to_adversary

run_test_expect_fail "Adversary re-injection rejected (RecoveryProtected)" \
    kels-cli -u "$KELS_URL" adversary inject --prefix "$PREFIX16" --events ixn

swap_to_owner

# KEL should still be OK
run_test "KEL status still OK after blocked re-injection" check_kel_status "$PREFIX16" "OK"

cleanup_adversary_backup

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
