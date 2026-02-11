#!/bin/bash
# test-adversarial-advanced.sh - Advanced Adversarial Tests (Multi-Node)
# Tests 3-way fork recovery scenarios where adversary events are injected
# on separate nodes simultaneously, requiring gossip-based recovery.
#
# Uses regional nodes (d, e, f) to reduce flakiness from fast local gossip.
#
# Requires kels-cli built with --features dev-tools
# Must be run from a test-client pod with access to all three nodes.
#
# Usage: test-adversarial-advanced.sh
#
# Environment variables:
#   GOSSIP_PROPAGATION_DELAY - Time to wait for gossip propagation (default: 5s)
#   NODE_D_KELS_HOST - node-d KELS hostname (default: kels.kels-node-d.kels)
#   NODE_E_KELS_HOST - node-e KELS hostname (default: kels.kels-node-e.kels)
#   NODE_F_KELS_HOST - node-f KELS hostname (default: kels.kels-node-f.kels)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
GOSSIP_PROPAGATION_DELAY="${GOSSIP_PROPAGATION_DELAY:-2.5}"
NODE_D_KELS_HOST="${NODE_D_KELS_HOST:-kels.kels-node-d.kels}"
NODE_E_KELS_HOST="${NODE_E_KELS_HOST:-kels.kels-node-e.kels}"
NODE_F_KELS_HOST="${NODE_F_KELS_HOST:-kels.kels-node-f.kels}"
NODE_D_URL="http://${NODE_D_KELS_HOST}"
NODE_E_URL="http://${NODE_E_KELS_HOST}"
NODE_F_URL="http://${NODE_F_KELS_HOST}"

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

wait_for_propagation() {
    echo "Waiting ${GOSSIP_PROPAGATION_DELAY}s for gossip propagation..."
    sleep "$GOSSIP_PROPAGATION_DELAY"
}

# Get the KEL hash for a prefix on a given node
get_kel_hash() {
    local url="$1"
    local prefix="$2"
    curl -s "$url/api/kels/kel/$prefix" | jq -cS '[.[] | .signatures |= sort_by(.publicKey)]' | md5sum | awk '{print $1}'
}

# Compare KELs across all three nodes
kels_match_all() {
    local prefix="$1"
    local hash_d hash_e hash_f
    hash_d=$(get_kel_hash "$NODE_D_URL" "$prefix")
    hash_e=$(get_kel_hash "$NODE_E_URL" "$prefix")
    hash_f=$(get_kel_hash "$NODE_F_URL" "$prefix")
    if [ "$hash_d" = "$hash_e" ] && [ "$hash_e" = "$hash_f" ]; then
        return 0
    else
        echo "KEL hash mismatch: D=$hash_d E=$hash_e F=$hash_f"
        return 1
    fi
}

# Get event count for a KEL on a given node
get_event_count() {
    local url="$1"
    local prefix="$2"
    curl -s "$url/api/kels/kel/$prefix" | jq 'length'
}

# Check if a KEL exists on a given node
kel_exists_on_node() {
    local url="$1"
    local prefix="$2"
    local response
    response=$(curl -s -w "\n%{http_code}" "$url/api/kels/kel/$prefix")
    local http_code
    http_code=$(echo "$response" | tail -n1)
    [ "$http_code" = "200" ]
}

echo "========================================="
echo "KELS Advanced Adversarial Test Suite"
echo "========================================="
echo "Node-D URL:       $NODE_D_URL"
echo "Node-E URL:       $NODE_E_URL"
echo "Node-F URL:       $NODE_F_URL"
echo "Propagation wait: ${GOSSIP_PROPAGATION_DELAY}s"
echo "Config:           $KELS_CLI_HOME"
echo "========================================="
echo ""

# Check if dev-tools feature is available
if ! kels-cli --help 2>&1 | grep -q "adversary"; then
    echo -e "${RED}ERROR: kels-cli must be built with --features dev-tools${NC}"
    exit 1
fi

# Wait for all KELS servers to be ready
echo "Waiting for KELS servers..."
for url in "$NODE_D_URL" "$NODE_E_URL" "$NODE_F_URL"; do
    for i in {1..30}; do
        if curl -s "$url/health" > /dev/null 2>&1; then
            echo "  $url is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${RED}$url not ready after 30 seconds${NC}"
            exit 1
        fi
        sleep 1
    done
done
echo ""

# ========================================
# Scenario 1: Dual Adversary Injection + Owner Recovery Propagation
# ========================================
echo -e "${CYAN}=== Scenario 1: Dual Adversary Injection + Owner Recovery ===${NC}"
echo "Inject adv1 on node-d, adv2 on node-e, owner recovers on node-d, verify all nodes converge"
echo ""

# Create KEL on node-d
PREFIX1=$(kels-cli -u "$NODE_D_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL on node-d: $PREFIX1"

# Wait for propagation to all nodes
wait_for_propagation

# Verify KEL propagated
run_test "KEL exists on node-d" kel_exists_on_node "$NODE_D_URL" "$PREFIX1"
run_test "KEL exists on node-e" kel_exists_on_node "$NODE_E_URL" "$PREFIX1"
run_test "KEL exists on node-f" kel_exists_on_node "$NODE_F_URL" "$PREFIX1"

# Inject adversary ixn on node-d, rot on node-e (different types → different SAIDs)
run_test "Inject adv ixn on node-d" kels-cli -u "$NODE_D_URL" adversary inject --prefix "$PREFIX1" --events ixn
run_test "Inject adv rot on node-e" kels-cli -u "$NODE_E_URL" adversary inject --prefix "$PREFIX1" --events rot

# Wait for gossip — nodes should see both adversary events and freeze
wait_for_propagation
wait_for_propagation

# Verify nodes are frozen (have divergent events)
COUNT_D=$(get_event_count "$NODE_D_URL" "$PREFIX1")
COUNT_E=$(get_event_count "$NODE_E_URL" "$PREFIX1")
COUNT_F=$(get_event_count "$NODE_F_URL" "$PREFIX1")
echo "Event counts: D=$COUNT_D E=$COUNT_E F=$COUNT_F"

# Each node should have 3 events (icp + adv ixn + adv rot)
run_test "Node-d has 3 events (icp + adv ixn + adv rot)" [ "$COUNT_D" = "3" ]
run_test "Node-e has 3 events (icp + adv ixn + adv rot)" [ "$COUNT_E" = "3" ]
run_test "Node-f has 3 events (icp + adv ixn + adv rot)" [ "$COUNT_F" = "3" ]

# Owner recovers on node-d
run_test "Owner recovers on node-d" kels-cli -u "$NODE_D_URL" recover --prefix "$PREFIX1"

# Wait for recovery to propagate
wait_for_propagation
wait_for_propagation

# Verify all nodes converge to the same recovered state
run_test "All nodes have matching KELs after recovery" kels_match_all "$PREFIX1"

echo ""

# ========================================
# Scenario 2: Triple Simultaneous Events (adv + adv + owner)
# ========================================
echo -e "${CYAN}=== Scenario 2: Triple Simultaneous Events ===${NC}"
echo "Inject adv1 on node-e, adv2 on node-f, owner anchor on node-d — near-simultaneously"
echo ""

# Create KEL on node-d with an anchor
PREFIX2=$(kels-cli -u "$NODE_D_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL on node-d: $PREFIX2"

kels-cli -u "$NODE_D_URL" anchor --prefix "$PREFIX2" --said "EPreAttackAnchor____________________________"

# Wait for propagation
wait_for_propagation

# Verify initial state
run_test "KEL propagated to all nodes" kels_match_all "$PREFIX2"

# Submit all three events near-simultaneously (different adv types → different SAIDs)
kels-cli -u "$NODE_E_URL" adversary inject --prefix "$PREFIX2" --events ixn &
PID_ADV1=$!
kels-cli -u "$NODE_F_URL" adversary inject --prefix "$PREFIX2" --events rot &
PID_ADV2=$!
kels-cli -u "$NODE_D_URL" anchor --prefix "$PREFIX2" --said "EOwnerAnchorRace____________________________" 2>&1 || true &
PID_OWNER=$!

# Wait for all submissions
wait $PID_ADV1 2>/dev/null || true
wait $PID_ADV2 2>/dev/null || true
wait $PID_OWNER 2>/dev/null || true

echo "All three events submitted"

# Wait for full propagation
wait_for_propagation
wait_for_propagation
wait_for_propagation

# Check event counts (should all have divergent events)
COUNT_D=$(get_event_count "$NODE_D_URL" "$PREFIX2")
COUNT_E=$(get_event_count "$NODE_E_URL" "$PREFIX2")
COUNT_F=$(get_event_count "$NODE_F_URL" "$PREFIX2")
echo "Event counts after race: D=$COUNT_D E=$COUNT_E F=$COUNT_F"

# Owner recovers on node-d
run_test "Owner recovers on node-d" kels-cli -u "$NODE_D_URL" recover --prefix "$PREFIX2"

# Wait for recovery to propagate
wait_for_propagation
wait_for_propagation

# Verify all nodes converge
run_test "All nodes have matching KELs after recovery" kels_match_all "$PREFIX2"

echo ""

# ========================================
# Scenario 3: Adversary Attack During Owner ROR
# ========================================
echo -e "${CYAN}=== Scenario 3: Adversary times attack with owner ror ===${NC}"
echo "Adversaries inject rot/ixn on nodes e/f, owner does ror on node-d."
echo "Owner's ror propagates to frozen nodes (Recoverable), then rec recovers them."
echo ""

# Create KEL on node-d
PREFIX3=$(kels-cli -u "$NODE_D_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL on node-d: $PREFIX3"

# Wait for propagation to all nodes
wait_for_propagation

run_test "KEL exists on all nodes" kels_match_all "$PREFIX3"

# Inject adversary rot on node-e, ixn on node-f (different types → different SAIDs)
run_test "Inject adversary rot on node-e" kels-cli -u "$NODE_E_URL" adversary inject --prefix "$PREFIX3" --events rot
run_test "Inject adversary ixn on node-f" kels-cli -u "$NODE_F_URL" adversary inject --prefix "$PREFIX3" --events ixn

# Owner does rotate-recovery (ror) on node-d
# This creates a 3-way fork: adv_rot on node-e, adv_ixn on node-f, ror on node-d
# Node-d's ror reveals recovery, so adversary events arriving at node-d are RecoveryProtected
# Owner's ror propagates to frozen nodes as Recoverable (they accept it into the fork)
run_test "Owner rotates recovery key on node-d" kels-cli -u "$NODE_D_URL" rotate-recovery --prefix "$PREFIX3"

# Wait for gossip — ror needs to propagate to frozen nodes
wait_for_propagation
wait_for_propagation
wait_for_propagation

COUNT_D=$(get_event_count "$NODE_D_URL" "$PREFIX3")
COUNT_E=$(get_event_count "$NODE_E_URL" "$PREFIX3")
COUNT_F=$(get_event_count "$NODE_F_URL" "$PREFIX3")
echo "Event counts after ror propagation: D=$COUNT_D E=$COUNT_E F=$COUNT_F"

# Owner recovers on node-d (non-divergent append: rec chains from ror)
# Gossip propagates rec to nodes e/f where ror is on the owner's chain → recovery succeeds
run_test "Owner recovers on node-d" kels-cli -u "$NODE_D_URL" recover --prefix "$PREFIX3"

# Wait for recovery to propagate
wait_for_propagation
wait_for_propagation

# Verify all nodes converge to the same recovered state [icp, ror, rec]
run_test "All nodes have matching KELs after ror+rec recovery" kels_match_all "$PREFIX3"

echo ""

# ========================================
# Print Summary
# ========================================
echo ""
echo "========================================="
echo "Advanced Adversarial Test Summary"
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
