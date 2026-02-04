#!/bin/bash
# test-bootstrap.sh - Bootstrap Sync Integration Tests
# Tests peer allowlist, bootstrap sync, and cross-node event propagation
#
# This script tests the KELS peer allowlist and bootstrap sync protocol:
# 1. Registry lists peers in allowlist
# 2. Nodes sync KELs during bootstrap
# 3. Events submitted to regional nodes propagate to core nodes
#
# Node topology:
#   Registry A: nodes a (core), d (regional)
#   Registry B: node b (core)
#   Registry C: node c (core)
#
# Usage: test-bootstrap.sh
#
# Environment variables:
#   NODE_A_KELS_HOST - node-a KELS hostname (default: kels)
#   NODE_B_KELS_HOST - node-b KELS hostname (default: kels.kels-node-b.kels)
#   NODE_C_KELS_HOST - node-c KELS hostname (default: kels.kels-node-c.kels)
#   NODE_D_KELS_HOST - node-d KELS hostname (default: kels.kels-node-d.kels)
#   REGISTRY_HOST - registry hostname (default: kels-registry.kels-registry-a.kels)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
NODE_A_KELS_HOST="${NODE_A_KELS_HOST:-kels}"
NODE_B_KELS_HOST="${NODE_B_KELS_HOST:-kels.kels-node-b.kels}"
NODE_C_KELS_HOST="${NODE_C_KELS_HOST:-kels.kels-node-c.kels}"
NODE_D_KELS_HOST="${NODE_D_KELS_HOST:-kels.kels-node-d.kels}"
NODE_E_KELS_HOST="${NODE_E_KELS_HOST:-kels.kels-node-e.kels}"
REGISTRY_HOST="${REGISTRY_HOST:-kels-registry.kels-registry-a.kels}"
NODE_A_URL="http://${NODE_A_KELS_HOST}"
NODE_B_URL="http://${NODE_B_KELS_HOST}"
NODE_C_URL="http://${NODE_C_KELS_HOST}"
NODE_D_URL="http://${NODE_D_KELS_HOST}"
NODE_E_URL="http://${NODE_E_KELS_HOST}"
REGISTRY_URL="http://${REGISTRY_HOST}"

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

check_registry_health() {
    curl -s "$REGISTRY_URL/health" > /dev/null 2>&1
}

get_peer_count() {
    # Get active peers from the allowlist
    curl -s "$REGISTRY_URL/api/peers" | jq '[.peers[].records[-1] | select(.active == true)] | length'
}

peer_exists() {
    local peer_id="$1"
    curl -s "$REGISTRY_URL/api/peers" | jq -e ".peers[].records[-1] | select(.peerId == \"$peer_id\")" > /dev/null
}

get_prefix_count() {
    local url="$1"
    local count
    count=$(curl -s "$url/api/kels/prefixes?limit=1000" | jq '.prefixes | length')
    echo "${count:-0}"
}

echo "========================================="
echo "KELS Bootstrap Sync Test Suite"
echo "========================================="
echo "Node-A URL:    $NODE_A_URL"
echo "Node-B URL:    $NODE_B_URL"
echo "Node-C URL:    $NODE_C_URL"
echo "Node-D URL:    $NODE_D_URL"
echo "Node-E URL:    $NODE_E_URL"
echo "Registry URL:  $REGISTRY_URL"
echo "Config:        $KELS_CLI_HOME"
echo "========================================="
echo ""

# ========================================
# Wait for services to be ready
# ========================================
echo "Waiting for services..."

# Wait for registry
for i in {1..30}; do
    if check_registry_health; then
        echo "  Registry is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${YELLOW}Warning: Registry not available, some tests will be skipped${NC}"
    fi
    sleep 1
done

# Wait for KELS servers
for url in "$NODE_A_URL" "$NODE_B_URL" "$NODE_C_URL" "$NODE_D_URL" "$NODE_E_URL"; do
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
# Scenario 1: Registry Health Check
# ========================================
echo -e "${CYAN}=== Scenario 1: Registry Health Check ===${NC}"
echo "Verify registry service is running and healthy"
echo ""

if check_registry_health; then
    run_test "Registry health check" true
else
    echo -e "${YELLOW}Skipping registry tests - registry not available${NC}"
    echo ""
    # Skip to non-registry tests
fi

# ========================================
# Scenario 2: Peer Allowlist
# ========================================
if check_registry_health; then
    echo -e "${CYAN}=== Scenario 2: Peer Allowlist ===${NC}"
    echo "Verify peers are in the allowlist"
    echo ""

    PEER_COUNT=$(get_peer_count)
    echo "Active peers: $PEER_COUNT"
    run_test "At least one peer in allowlist" [ "$PEER_COUNT" -ge 1 ]

    # List all peers
    echo ""
    echo "Allowlist peers:"
    curl -s "$REGISTRY_URL/api/peers" | jq -r '.peers[].records[-1] | select(.active == true) | "  \(.nodeId) - \(.kelsUrl)"'
    echo ""
fi

# ========================================
# Scenario 4: Prefix Listing API
# ========================================
echo -e "${CYAN}=== Scenario 4: Prefix Listing API ===${NC}"
echo "Verify the prefix listing endpoint works"
echo ""

# Create some KELs first
echo "Creating test KELs..."
PREFIX1=$(kels-cli -u "$NODE_A_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
PREFIX2=$(kels-cli -u "$NODE_A_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created: $PREFIX1, $PREFIX2"

# Test prefix listing
RESPONSE=$(curl -s "$NODE_A_URL/api/kels/prefixes?limit=10")
echo "Prefix list response: $RESPONSE"

PREFIX_COUNT=$(echo "$RESPONSE" | jq '.prefixes | length')
run_test "Prefix list contains entries" [ "$PREFIX_COUNT" -ge 2 ]

# Check that prefixes include SAID
HAS_SAID=$(echo "$RESPONSE" | jq -e '.prefixes[0].said' > /dev/null 2>&1 && echo "true" || echo "false")
run_test "Prefix entries include SAID" [ "$HAS_SAID" = "true" ]

echo ""

# ========================================
# Scenario 5: Pagination
# ========================================
echo -e "${CYAN}=== Scenario 5: Prefix List Pagination ===${NC}"
echo "Test cursor-based pagination"
echo ""

# Create a few more KELs
for i in {1..3}; do
    kels-cli -u "$NODE_A_URL" incept > /dev/null 2>&1
done

# Test pagination with limit=2
PAGE1=$(curl -s "$NODE_A_URL/api/kels/prefixes?limit=2")
CURSOR=$(echo "$PAGE1" | jq -r '.nextCursor // empty')
PAGE1_COUNT=$(echo "$PAGE1" | jq '.prefixes | length')

echo "Page 1: $PAGE1_COUNT prefixes, cursor: ${CURSOR:-none}"

if [ -n "$CURSOR" ]; then
    PAGE2=$(curl -s "$NODE_A_URL/api/kels/prefixes?limit=2&since=$CURSOR")
    PAGE2_COUNT=$(echo "$PAGE2" | jq '.prefixes | length')
    echo "Page 2: $PAGE2_COUNT prefixes"

    run_test "Pagination returns results" [ "$PAGE2_COUNT" -ge 1 ]
else
    echo "No more pages (all results fit in first page)"
    run_test "Single page pagination" [ "$PAGE1_COUNT" -ge 2 ]
fi

echo ""

# ========================================
# Scenario 6: Bootstrap Sync Verification
# ========================================
echo -e "${CYAN}=== Scenario 6: Bootstrap Sync Verification ===${NC}"
echo "Verify KELs created on node-a are visible on node-b"
echo ""

# Wait for gossip propagation
sleep 2

# Compare prefix counts
COUNT_A=$(get_prefix_count "$NODE_A_URL")
COUNT_B=$(get_prefix_count "$NODE_B_URL")

echo "Node-A prefix count: $COUNT_A"
echo "Node-B prefix count: $COUNT_B"

# They should be equal after bootstrap sync
run_test "Prefix counts match between nodes" [ "$COUNT_A" = "$COUNT_B" ]

# Verify specific prefix exists on both
kel_exists_on_node() {
    local url="$1"
    local prefix="$2"
    curl -s -w "\n%{http_code}" "$url/api/kels/kel/$prefix" | tail -n1 | grep -q "200"
}

run_test "Created KEL exists on node-a" kel_exists_on_node "$NODE_A_URL" "$PREFIX1"
run_test "Created KEL synced to node-b" kel_exists_on_node "$NODE_B_URL" "$PREFIX1"
run_test "Created KEL synced to node-c" kel_exists_on_node "$NODE_C_URL" "$PREFIX1"
run_test "Created KEL synced to node-d" kel_exists_on_node "$NODE_D_URL" "$PREFIX1"

echo ""

# ========================================
# Scenario 7: Cross-Node Event Propagation
# ========================================
echo -e "${CYAN}=== Scenario 7: Cross-Node Event Propagation ===${NC}"
echo "Submit events via node-d (regional peer), verify propagation to nodes b and c"
echo ""

# Get the current KEL length on node A (source of truth for this KEL)
get_kel_length() {
    local url="$1"
    local prefix="$2"
    curl -s "$url/api/kels/kel/$prefix" | jq 'length'
}

INITIAL_LENGTH_A=$(get_kel_length "$NODE_A_URL" "$PREFIX1")
echo "Initial KEL length on node-a: $INITIAL_LENGTH_A"

# Submit an anchor event via node-d
# Generate a test SAID (44 chars, starts with E)
TEST_SAID="ETestAnchorSaid_$(date +%s)_________________________"
TEST_SAID="${TEST_SAID:0:44}"
echo "Submitting anchor event via node-d with SAID: $TEST_SAID"

ANCHOR_OUTPUT=$(kels-cli -u "$NODE_D_URL" anchor --prefix "$PREFIX1" --said "$TEST_SAID" 2>&1)
echo "$ANCHOR_OUTPUT"

if echo "$ANCHOR_OUTPUT" | grep -q "Anchored"; then
    run_test "Anchor event submitted via node-d" true
else
    run_test "Anchor event submitted via node-d" false
fi

# Wait for gossip propagation
echo "Waiting for gossip propagation..."
sleep 6

# Verify KEL length increased on all nodes
NEW_LENGTH_A=$(get_kel_length "$NODE_A_URL" "$PREFIX1")
NEW_LENGTH_B=$(get_kel_length "$NODE_B_URL" "$PREFIX1")
NEW_LENGTH_C=$(get_kel_length "$NODE_C_URL" "$PREFIX1")
NEW_LENGTH_D=$(get_kel_length "$NODE_D_URL" "$PREFIX1")
NEW_LENGTH_E=$(get_kel_length "$NODE_E_URL" "$PREFIX1")

echo "KEL lengths after anchor:"
echo "  Node-A: $NEW_LENGTH_A"
echo "  Node-B: $NEW_LENGTH_B"
echo "  Node-C: $NEW_LENGTH_C"
echo "  Node-D: $NEW_LENGTH_D"
echo "  Node-E: $NEW_LENGTH_E"

# All nodes should have the same KEL length, greater than initial
run_test "KEL grew after anchor on node-a" [ "$NEW_LENGTH_A" -gt "$INITIAL_LENGTH_A" ]
run_test "Anchor propagated to node-b" [ "$NEW_LENGTH_B" = "$NEW_LENGTH_A" ]
run_test "Anchor propagated to node-c" [ "$NEW_LENGTH_C" = "$NEW_LENGTH_A" ]
run_test "Anchor propagated to node-d" [ "$NEW_LENGTH_D" = "$NEW_LENGTH_A" ]
run_test "Anchor propagated to node-e" [ "$NEW_LENGTH_E" = "$NEW_LENGTH_A" ]

echo ""

# ========================================
# Scenario 8: Auto-Select Node (if registry available)
# ========================================
if check_registry_health; then
    echo -e "${CYAN}=== Scenario 8: Auto-Select Fastest Node ===${NC}"
    echo "Test CLI auto-select functionality"
    echo ""

    # This should work without error
    run_test "CLI with auto-select" kels-cli --registry "$REGISTRY_URL" --auto-select list
    echo ""
fi

# ========================================
# Print Summary
# ========================================
echo ""
echo "========================================="
echo "Bootstrap Sync Test Summary"
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
