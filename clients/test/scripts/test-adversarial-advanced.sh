#!/usr/bin/env bash
# test-adversarial-advanced.sh - Advanced Adversarial Tests (Multi-Node)
# Tests 3-way fork recovery scenarios where adversary events are injected
# on separate nodes simultaneously, requiring gossip-based recovery.
#
# Uses nodes d, e, f to test multi-node adversarial scenarios.
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

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
GOSSIP_PROPAGATION_DELAY="${GOSSIP_PROPAGATION_DELAY:-3}"
CONVERGENCE_TIMEOUT="${CONVERGENCE_TIMEOUT:-30}"
NODE_D_KELS_HOST="${NODE_D_KELS_HOST:-kels.kels-node-d.kels}"
NODE_E_KELS_HOST="${NODE_E_KELS_HOST:-kels.kels-node-e.kels}"
NODE_F_KELS_HOST="${NODE_F_KELS_HOST:-kels.kels-node-f.kels}"
NODE_D_URL="http://${NODE_D_KELS_HOST}"
NODE_E_URL="http://${NODE_E_KELS_HOST}"
NODE_F_URL="http://${NODE_F_KELS_HOST}"

init_temp_dir

wait_for_propagation() {
    echo "Waiting ${GOSSIP_PROPAGATION_DELAY}s for gossip propagation..."
    sleep "$GOSSIP_PROPAGATION_DELAY"
}

# Poll until a KEL exists on all three nodes (or timeout)
wait_for_kel_on_all_nodes() {
    local prefix="$1"
    local deadline=$((SECONDS + CONVERGENCE_TIMEOUT))
    echo "Waiting for KEL $prefix to exist on all nodes (timeout: ${CONVERGENCE_TIMEOUT}s)..."
    while [ $SECONDS -lt $deadline ]; do
        if kel_exists_on_node "$NODE_D_URL" "$prefix" \
            && kel_exists_on_node "$NODE_E_URL" "$prefix" \
            && kel_exists_on_node "$NODE_F_URL" "$prefix"; then
            return 0
        fi
        sleep 1
    done
    echo "Timeout waiting for KEL on all nodes"
    return 1
}

# Poll until all three nodes have matching KELs (or timeout)
wait_for_convergence() {
    local prefix="$1"
    local deadline=$((SECONDS + CONVERGENCE_TIMEOUT))
    echo "Waiting for KEL $prefix to converge on all nodes (timeout: ${CONVERGENCE_TIMEOUT}s)..."
    while [ $SECONDS -lt $deadline ]; do
        if kels_match_all "$prefix" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    # Final check with error output
    kels_match_all "$prefix"
}

# Get the KEL hash for a prefix on a given node
get_kel_hash() {
    local url="$1"
    local prefix="$2"
    fetch_all_events "$url" "$prefix" | jq -cS '[.[] | .signatures |= sort_by(.publicKey)]' | md5sum | awk '{print $1}'
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
wait_for_health "$NODE_D_URL" "$NODE_D_URL" || exit 1
wait_for_health "$NODE_E_URL" "$NODE_E_URL" || exit 1
wait_for_health "$NODE_F_URL" "$NODE_F_URL" || exit 1
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

# Wait for KEL to exist on all nodes before injecting adversary events
run_test "KEL propagated to all nodes" wait_for_kel_on_all_nodes "$PREFIX1"

# Inject adversary ixn on node-d, rot on node-e concurrently (different types → different SAIDs)
kels-cli -u "$NODE_D_URL" adversary inject --prefix "$PREFIX1" --events ixn &
PID_ADV1=$!
kels-cli -u "$NODE_E_URL" adversary inject --prefix "$PREFIX1" --events rot &
PID_ADV2=$!
wait $PID_ADV1 2>/dev/null || true
wait $PID_ADV2 2>/dev/null || true
echo "Adversary events injected on node-d and node-e"

# Wait for gossip propagation then recover
wait_for_propagation
run_test "Owner recovers on node-d" kels-cli -u "$NODE_D_URL" recover --prefix "$PREFIX1"

# Poll until all nodes converge to the same recovered state
run_test "All nodes have matching KELs after recovery" wait_for_convergence "$PREFIX1"

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

# Wait for KEL to propagate to all nodes before injecting
run_test "KEL propagated to all nodes" wait_for_convergence "$PREFIX2"

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

# Wait then recover
wait_for_propagation
run_test "Owner recovers on node-d" kels-cli -u "$NODE_D_URL" recover --prefix "$PREFIX2"

# Poll until all nodes converge
run_test "All nodes have matching KELs after recovery" wait_for_convergence "$PREFIX2"

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

# Wait for KEL to propagate to all nodes
run_test "KEL exists on all nodes" wait_for_kel_on_all_nodes "$PREFIX3"

# Inject adversary rot on node-e, ixn on node-f concurrently to avoid race
kels-cli -u "$NODE_E_URL" adversary inject --prefix "$PREFIX3" --events rot &
PID_ADV1=$!
kels-cli -u "$NODE_F_URL" adversary inject --prefix "$PREFIX3" --events ixn &
PID_ADV2=$!
wait $PID_ADV1 2>/dev/null || true
wait $PID_ADV2 2>/dev/null || true
echo "Adversary events injected on node-e and node-f"

# Owner does rotate-recovery (ror) on node-d
# This creates a 3-way fork: adv_rot on node-e, adv_ixn on node-f, ror on node-d
# Node-d's ror reveals recovery, so adversary events arriving at node-d are ContestRequired
# Owner's ror propagates to frozen nodes as Recoverable (they accept it into the fork)
run_test "Owner rotates recovery key on node-d" kels-cli -u "$NODE_D_URL" rotate-recovery --prefix "$PREFIX3"

# Wait then recover
wait_for_propagation
run_test "Owner recovers on node-d" kels-cli -u "$NODE_D_URL" recover --prefix "$PREFIX3"

# Poll until all nodes converge to the same recovered state [icp, ror, rec]
run_test "All nodes have matching KELs after ror+rec recovery" wait_for_convergence "$PREFIX3"

echo ""

print_summary "Advanced Adversarial Test Summary"
exit_with_result
