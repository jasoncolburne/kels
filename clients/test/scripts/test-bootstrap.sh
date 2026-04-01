#!/usr/bin/env bash
# test-bootstrap.sh - Bootstrap Sync Integration Tests
# Tests peer allowlist, bootstrap sync, and cross-node event propagation
#
# This script tests the KELS peer allowlist and bootstrap sync protocol:
# 1. Registry lists peers in allowlist
# 2. Nodes sync KELs during bootstrap
# 3. Events submitted to any node propagate to all nodes
#
# Node topology:
#   All nodes added via proposal/vote through the federation
#
# Usage: test-bootstrap.sh
#
# Environment variables:
#   NODE_A_KELS_HOST - node-a KELS hostname (default: kels)
#   NODE_B_KELS_HOST - node-b KELS hostname (default: kels.kels-node-b.kels)
#   NODE_C_KELS_HOST - node-c KELS hostname (default: kels.kels-node-c.kels)
#   NODE_D_KELS_HOST - node-d KELS hostname (default: kels.kels-node-d.kels)
#   REGISTRY_HOST - registry hostname (default: registry.kels-registry-a.kels)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
NODE_A_KELS_HOST="${NODE_A_KELS_HOST:-kels}"
NODE_B_KELS_HOST="${NODE_B_KELS_HOST:-kels.kels-node-b.kels}"
NODE_C_KELS_HOST="${NODE_C_KELS_HOST:-kels.kels-node-c.kels}"
NODE_D_KELS_HOST="${NODE_D_KELS_HOST:-kels.kels-node-d.kels}"
NODE_E_KELS_HOST="${NODE_E_KELS_HOST:-kels.kels-node-e.kels}"
NODE_F_KELS_HOST="${NODE_F_KELS_HOST:-kels.kels-node-f.kels}"
REGISTRY_HOST="${REGISTRY_HOST:-registry.kels-registry-a.kels}"
NODE_A_URL="http://${NODE_A_KELS_HOST}"
NODE_B_URL="http://${NODE_B_KELS_HOST}"
NODE_C_URL="http://${NODE_C_KELS_HOST}"
NODE_D_URL="http://${NODE_D_KELS_HOST}"
NODE_E_URL="http://${NODE_E_KELS_HOST}"
NODE_F_URL="http://${NODE_F_KELS_HOST}"
REGISTRY_URL="http://${REGISTRY_HOST}"

CONVERGENCE_TIMEOUT="${CONVERGENCE_TIMEOUT:-30}"

init_temp_dir

check_registry_health() {
    curl -s "$REGISTRY_URL/health" > /dev/null 2>&1
}

get_peer_count() {
    # Get active peers from the allowlist
    curl -s "$REGISTRY_URL/api/v1/peers" | jq '[.peers[].records[-1] | select(.active == true)] | length'
}

peer_exists() {
    local peer_prefix="$1"
    curl -s "$REGISTRY_URL/api/v1/peers" | jq -e ".peers[].records[-1] | select(.peerPrefix == \"$peer_prefix\")" > /dev/null
}

get_prefix_count() {
    local url="$1"
    local body
    body=$(jq -n --arg nonce "$(openssl rand -hex 32)" '{payload:{timestamp:0,nonce:$nonce,cursor:null,limit:1000},peerPrefix:"test",publicKey:"test",signature:"test"}')
    local count
    count=$(curl -s -X POST -H 'Content-Type: application/json' -d "$body" "$url/api/test/prefixes" | jq '.prefixes | length')
    echo "${count:-0}"
}

wait_for_kel_on_node() {
    local url="$1"
    local prefix="$2"
    local deadline=$((SECONDS + CONVERGENCE_TIMEOUT))
    while [ $SECONDS -lt $deadline ]; do
        if curl -s -w "\n%{http_code}" "$url/api/v1/kels/kel/$prefix" | tail -n1 | grep -q "200"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

get_kel_length() {
    local url="$1"
    local prefix="$2"
    local resp
    local events
    events=$(fetch_all_events "$url" "$prefix")
    echo "$events" | jq 'length'
}

# Poll until prefix counts match between two nodes (or timeout)
wait_for_prefix_counts_match() {
    local url_a="$1"
    local url_b="$2"
    local deadline=$((SECONDS + CONVERGENCE_TIMEOUT))
    echo "Waiting for prefix counts to match (timeout: ${CONVERGENCE_TIMEOUT}s)..."
    while [ $SECONDS -lt $deadline ]; do
        local count_a count_b
        count_a=$(get_prefix_count "$url_a")
        count_b=$(get_prefix_count "$url_b")
        if [ "$count_a" = "$count_b" ]; then
            echo "Prefix counts match: $count_a"
            return 0
        fi
        sleep 1
    done
    local count_a count_b
    count_a=$(get_prefix_count "$url_a")
    count_b=$(get_prefix_count "$url_b")
    echo "Timeout: counts A=$count_a B=$count_b"
    # Dump prefixes unique to each node
    local body_diag
    body_diag=$(jq -n --arg nonce "$(openssl rand -hex 32)" '{payload:{timestamp:0,nonce:$nonce,cursor:null,limit:1000},peerPrefix:"test",publicKey:"test",signature:"test"}')
    local pa pb
    pa=$(curl -s -X POST -H 'Content-Type: application/json' -d "$body_diag" "$url_a/api/test/prefixes" | jq -r '.prefixes[].prefix' | sort)
    pb=$(curl -s -X POST -H 'Content-Type: application/json' -d "$body_diag" "$url_b/api/test/prefixes" | jq -r '.prefixes[].prefix' | sort)
    echo "Only on A: $(comm -23 <(echo "$pa") <(echo "$pb"))"
    echo "Only on B: $(comm -13 <(echo "$pa") <(echo "$pb"))"
    return 1
}

# Poll until KEL length matches across all 6 nodes (or timeout)
wait_for_kel_length_on_all_nodes() {
    local prefix="$1"
    local deadline=$((SECONDS + CONVERGENCE_TIMEOUT))
    echo "Waiting for KEL $prefix to have matching length on all nodes (timeout: ${CONVERGENCE_TIMEOUT}s)..."
    while [ $SECONDS -lt $deadline ]; do
        local len_a len_b len_c len_d len_e len_f
        len_a=$(get_kel_length "$NODE_A_URL" "$prefix")
        len_b=$(get_kel_length "$NODE_B_URL" "$prefix")
        len_c=$(get_kel_length "$NODE_C_URL" "$prefix")
        len_d=$(get_kel_length "$NODE_D_URL" "$prefix")
        len_e=$(get_kel_length "$NODE_E_URL" "$prefix")
        len_f=$(get_kel_length "$NODE_F_URL" "$prefix")
        if [ "$len_a" = "$len_b" ] && [ "$len_b" = "$len_c" ] \
            && [ "$len_c" = "$len_d" ] && [ "$len_d" = "$len_e" ] \
            && [ "$len_e" = "$len_f" ] && [ "$len_a" -gt 0 ]; then
            echo "All nodes have KEL length: $len_a"
            return 0
        fi
        sleep 1
    done
    echo "Timeout: A=$(get_kel_length "$NODE_A_URL" "$prefix") B=$(get_kel_length "$NODE_B_URL" "$prefix") C=$(get_kel_length "$NODE_C_URL" "$prefix") D=$(get_kel_length "$NODE_D_URL" "$prefix") E=$(get_kel_length "$NODE_E_URL" "$prefix") F=$(get_kel_length "$NODE_F_URL" "$prefix")"
    return 1
}

echo "========================================="
echo "KELS Bootstrap Sync Test Suite"
echo "========================================="
echo "Node-A URL:    $NODE_A_URL"
echo "Node-B URL:    $NODE_B_URL"
echo "Node-C URL:    $NODE_C_URL"
echo "Node-D URL:    $NODE_D_URL"
echo "Node-E URL:    $NODE_E_URL"
echo "Node-F URL:    $NODE_F_URL"
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
for url in "$NODE_A_URL" "$NODE_B_URL" "$NODE_C_URL" "$NODE_D_URL" "$NODE_E_URL" "$NODE_F_URL"; do
    wait_for_health "$url" "$url" || exit 1
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
    curl -s "$REGISTRY_URL/api/v1/peers" | jq -r '.peers[].records[-1] | select(.active == true) | "  \(.nodeId) - \(.kelsUrl)"'
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
PREFIX1=$(kels-cli --kels-url "$NODE_A_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
PREFIX2=$(kels-cli --kels-url "$NODE_A_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created: $PREFIX1, $PREFIX2"

# Test prefix listing (POST with mock signed request — test endpoint skips auth)
RESPONSE=$(curl -s -X POST -H 'Content-Type: application/json' \
    -d "$(jq -n --arg nonce "$(openssl rand -hex 32)" '{payload:{timestamp:0,nonce:$nonce,cursor:null,limit:10},peerPrefix:"test",publicKey:"test",signature:"test"}')" \
    "$NODE_A_URL/api/test/prefixes")
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
    kels-cli --kels-url "$NODE_A_URL" incept > /dev/null 2>&1
done

# Test pagination with limit=2
PAGE1=$(curl -s -X POST -H 'Content-Type: application/json' \
    -d "$(jq -n --arg nonce "$(openssl rand -hex 32)" '{payload:{timestamp:0,nonce:$nonce,cursor:null,limit:2},peerPrefix:"test",publicKey:"test",signature:"test"}')" \
    "$NODE_A_URL/api/test/prefixes")
CURSOR=$(echo "$PAGE1" | jq -r '.nextCursor // empty')
PAGE1_COUNT=$(echo "$PAGE1" | jq '.prefixes | length')

echo "Page 1: $PAGE1_COUNT prefixes, cursor: ${CURSOR:-none}"

if [ -n "$CURSOR" ]; then
    PAGE2=$(curl -s -X POST -H 'Content-Type: application/json' \
        -d "$(jq -n --arg cursor "$CURSOR" --arg nonce "$(openssl rand -hex 32)" '{payload:{timestamp:0,nonce:$nonce,cursor:$cursor,limit:2},peerPrefix:"test",publicKey:"test",signature:"test"}')" \
        "$NODE_A_URL/api/test/prefixes")
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

# Poll until prefix counts match between nodes
run_test "Prefix counts match between nodes" wait_for_prefix_counts_match "$NODE_A_URL" "$NODE_B_URL"

run_test "Created KEL exists on node-a" wait_for_kel_on_node "$NODE_A_URL" "$PREFIX1"
run_test "Created KEL synced to node-b" wait_for_kel_on_node "$NODE_B_URL" "$PREFIX1"
run_test "Created KEL synced to node-c" wait_for_kel_on_node "$NODE_C_URL" "$PREFIX1"
run_test "Created KEL synced to node-d" wait_for_kel_on_node "$NODE_D_URL" "$PREFIX1"

echo ""

# ========================================
# Scenario 7: Cross-Node Event Propagation
# ========================================
echo -e "${CYAN}=== Scenario 7: Cross-Node Event Propagation ===${NC}"
echo "Submit events via node-d, verify propagation to all nodes"
echo ""

INITIAL_LENGTH_A=$(get_kel_length "$NODE_A_URL" "$PREFIX1")
echo "Initial KEL length on node-a: $INITIAL_LENGTH_A"

# Submit an anchor event via node-d
# Generate a test SAID (44 chars, starts with E)
TEST_SAID="KTestAnchorSaid_$(date +%s)_________________________"
TEST_SAID="${TEST_SAID:0:44}"
echo "Submitting anchor event via node-d with SAID: $TEST_SAID"

ANCHOR_OUTPUT=$(kels-cli --kels-url "$NODE_D_URL" anchor --prefix "$PREFIX1" --said "$TEST_SAID" 2>&1)
echo "$ANCHOR_OUTPUT"

if echo "$ANCHOR_OUTPUT" | grep -q "Anchored"; then
    run_test "Anchor event submitted via node-d" true
else
    run_test "Anchor event submitted via node-d" false
fi

# Poll until all nodes have matching KEL length
run_test "Anchor propagated to all nodes" wait_for_kel_length_on_all_nodes "$PREFIX1"

# Verify KEL actually grew
NEW_LENGTH_A=$(get_kel_length "$NODE_A_URL" "$PREFIX1")
run_test "KEL grew after anchor" [ "$NEW_LENGTH_A" -gt "$INITIAL_LENGTH_A" ]

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

print_summary "Bootstrap Sync Test Summary"
exit_with_result
