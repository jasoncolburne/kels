#!/usr/bin/env bash
# test-reconciliation.sh - Reconciliation Proof Test Suite
# Validates every case in docs/design/reconciliation-proof.md against
# a live multi-node deployment.
#
# Uses nodes d, e, f. Requires kels-cli built with --features dev-tools.
#
# Usage: test-reconciliation.sh
#
# Environment variables:
#   GOSSIP_PROPAGATION_DELAY - Time to wait for gossip propagation (default: 3s)
#   CONVERGENCE_TIMEOUT      - Timeout for convergence checks (default: 30s)
#   NODE_D_KELS_HOST         - node-d KELS hostname (default: kels.kels-node-d.kels)
#   NODE_E_KELS_HOST         - node-e KELS hostname (default: kels.kels-node-e.kels)
#   NODE_F_KELS_HOST         - node-f KELS hostname (default: kels.kels-node-f.kels)

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

# ==================== Helpers ====================

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

wait_for_gossip() {
    echo "Waiting ${GOSSIP_PROPAGATION_DELAY}s for gossip propagation..."
    sleep "$GOSSIP_PROPAGATION_DELAY"
}

get_kel_hash() {
    local url="$1"
    local prefix="$2"
    fetch_all_events "$url" "$prefix" | jq -cS '[.[] | .signatures |= sort_by(.label)]' | md5sum | awk '{print $1}'
}

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

kel_summary() {
    local url="$1"
    local prefix="$2"
    local live archived audit
    live=$(curl -s "$url/api/v1/kels/kel/$prefix" | jq -c '[.events[].event | {s:.serial, k:(.kind|split("/")|last), id:.said[0:8]}]')
    archived=$(curl -s "$url/api/v1/kels/kel/$prefix/archived" | jq -c '[.events[].event | {s:.serial, k:(.kind|split("/")|last), id:.said[0:8]}]')
    audit=$(curl -s "$url/api/v1/kels/kel/$prefix/audit" | jq -c '[.[] | {v:.version, st:.state[0:4]}]')
    echo "{live:$live,arch:$archived,aud:$audit}"
}

wait_for_convergence() {
    local prefix="$1"
    local deadline=$((SECONDS + CONVERGENCE_TIMEOUT))
    local last_state=""
    echo "Waiting for KEL $prefix to converge on all nodes (timeout: ${CONVERGENCE_TIMEOUT}s)..."
    while [ $SECONDS -lt $deadline ]; do
        if kels_match_all "$prefix" 2>/dev/null; then
            return 0
        fi
        last_state="D=$(kel_summary "$NODE_D_URL" "$prefix") E=$(kel_summary "$NODE_E_URL" "$prefix") F=$(kel_summary "$NODE_F_URL" "$prefix")"
        sleep 1
    done
    kels_match_all "$prefix"
    echo "$last_state"
    return 1
}

# Check that all nodes report contested status for a prefix
all_nodes_contested() {
    local prefix="$1"
    for url in "$NODE_D_URL" "$NODE_E_URL" "$NODE_F_URL"; do
        local events
        events=$(fetch_all_events "$url" "$prefix")
        local has_cnt
        has_cnt=$(echo "$events" | jq '[.[].event.kind] | any(. == "kels/v1/cnt")')
        if [ "$has_cnt" != "true" ]; then
            echo "Node $url missing cnt for $prefix"
            return 1
        fi
    done
    return 0
}

wait_for_all_contested() {
    local prefix="$1"
    local deadline=$((SECONDS + CONVERGENCE_TIMEOUT))
    echo "Waiting for all nodes to have cnt for $prefix (timeout: ${CONVERGENCE_TIMEOUT}s)..."
    while [ $SECONDS -lt $deadline ]; do
        if all_nodes_contested "$prefix" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    all_nodes_contested "$prefix"
}

# Wait for recovery to complete, accepting either recovered or contested as terminal
wait_for_recovery_or_contest() {
    local url="$1"
    local prefix="$2"
    local timeout="${3:-30}"
    echo "Waiting for recovery to reach terminal state (timeout: ${timeout}s)..."
    for _ in $(seq 1 $((timeout * 5))); do
        local latest_state
        latest_state=$(curl -s "$url/api/v1/kels/kel/$prefix/audit" | jq -r '.[-1].state // empty')
        if [ "$latest_state" = "recovered" ] || [ "$latest_state" = "contested" ]; then
            return 0
        fi
        sleep 0.2
    done
    echo "Recovery did not reach terminal state within ${timeout}s (latest state: $latest_state)"
    return 1
}

echo "========================================="
echo "KELS Reconciliation Proof Test Suite"
echo "========================================="
echo "Node-D URL:       $NODE_D_URL"
echo "Node-E URL:       $NODE_E_URL"
echo "Node-F URL:       $NODE_F_URL"
echo "Propagation wait: ${GOSSIP_PROPAGATION_DELAY}s"
echo "Config:           $KELS_CLI_HOME"
echo "========================================="
echo ""

# Check for dev-tools
if ! kels-cli --help 2>&1 | grep -q "adversary"; then
    echo -e "${RED}ERROR: kels-cli must be built with --features dev-tools${NC}"
    exit 1
fi

# Wait for servers
echo "Waiting for KELS servers..."
wait_for_health "$NODE_D_URL" "$NODE_D_URL" || exit 1
wait_for_health "$NODE_E_URL" "$NODE_E_URL" || exit 1
wait_for_health "$NODE_F_URL" "$NODE_F_URL" || exit 1
echo ""

# ========================================
# Scenario 1: Recovered KEL propagates to node with adversary chain
# ========================================
echo -e "${CYAN}=== Scenario 1: Recovered KEL → Adversary Node ===${NC}"
echo "Owner creates KEL on node-d, adversary injects on node-e, owner recovers on node-d."
echo "Verify recovery propagates to node-e (which has adversary chain) and all nodes converge."
echo ""

PREFIX1=$(kels-cli -u "$NODE_D_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL on node-d: $PREFIX1"
run_test "KEL propagated to all nodes" wait_for_propagation "$PREFIX1" "$CONVERGENCE_TIMEOUT" "$NODE_D_URL" "$NODE_E_URL" "$NODE_F_URL"

save_adversary_keys
kels-cli -u "$NODE_E_URL" adversary inject --prefix "$PREFIX1" --events ixn
echo "Adversary ixn injected on node-e"

wait_for_gossip
run_test "Owner recovers on node-d" kels-cli -u "$NODE_D_URL" recover --prefix "$PREFIX1"
run_test "Recovery completes on node-d" wait_for_recovery_complete "$NODE_D_URL" "$PREFIX1"
run_test "All nodes converge after recovery" wait_for_convergence "$PREFIX1"

cleanup_adversary_backup
echo ""

# ========================================
# Scenario 2: Post-recovery events propagate to adversary node
# ========================================
echo -e "${CYAN}=== Scenario 2: Post-Recovery Events → Adversary Node ===${NC}"
echo "After recovery, owner adds new events. Verify they propagate to nodes that had adversary chain."
echo ""

PREFIX2=$(kels-cli -u "$NODE_D_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL on node-d: $PREFIX2"
run_test "KEL propagated" wait_for_propagation "$PREFIX2" "$CONVERGENCE_TIMEOUT" "$NODE_D_URL" "$NODE_E_URL" "$NODE_F_URL"

save_adversary_keys
kels-cli -u "$NODE_E_URL" adversary inject --prefix "$PREFIX2" --events ixn
wait_for_gossip

run_test "Owner recovers" kels-cli -u "$NODE_D_URL" recover --prefix "$PREFIX2"
run_test "Recovery completes" wait_for_recovery_complete "$NODE_D_URL" "$PREFIX2"

# Add post-recovery event
run_test "Owner anchors after recovery" kels-cli -u "$NODE_D_URL" anchor --prefix "$PREFIX2" --said KPostRecoveryAnchor_________________________
run_test "All nodes converge with post-recovery event" wait_for_convergence "$PREFIX2"

cleanup_adversary_backup
echo ""

# ========================================
# Scenario 3: Adversary rotation chain + recovery propagation
# ========================================
echo -e "${CYAN}=== Scenario 3: Adversary rot,ixn,ixn + Recovery Propagation ===${NC}"
echo "Adversary injects rot+ixns on node-e. Owner recovers on node-d with extra rot."
echo "Verify all nodes converge including post-recovery anchor."
echo ""

PREFIX3=$(kels-cli -u "$NODE_D_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL on node-d: $PREFIX3"
run_test "KEL propagated" wait_for_propagation "$PREFIX3" "$CONVERGENCE_TIMEOUT" "$NODE_D_URL" "$NODE_E_URL" "$NODE_F_URL"

save_adversary_keys
kels-cli -u "$NODE_E_URL" adversary inject --prefix "$PREFIX3" --events rot,ixn,ixn
echo "Adversary rot,ixn,ixn injected on node-e"
wait_for_gossip

run_test "Owner recovers" kels-cli -u "$NODE_D_URL" recover --prefix "$PREFIX3"
run_test "Recovery completes" wait_for_recovery_complete "$NODE_D_URL" "$PREFIX3"
run_test "Owner anchors after recovery" kels-cli -u "$NODE_D_URL" anchor --prefix "$PREFIX3" --said KPostRotChainRecoveryAnchor_________________
run_test "All nodes converge" wait_for_convergence "$PREFIX3"

cleanup_adversary_backup
echo ""

# ========================================
# Scenario 4: Contested KEL propagation (cnt on shorter chain)
# ========================================
echo -e "${CYAN}=== Scenario 4: Contested KEL Propagation (cnt on shorter chain) ===${NC}"
echo "Adversary injects ror+ixn (longer chain) on node-e. Owner contests on node-d."
echo "Verify cnt reaches all nodes despite being on the shorter chain."
echo ""

PREFIX4=$(kels-cli -u "$NODE_D_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL on node-d: $PREFIX4"
run_test "KEL propagated" wait_for_propagation "$PREFIX4" "$CONVERGENCE_TIMEOUT" "$NODE_D_URL" "$NODE_E_URL" "$NODE_F_URL"

save_adversary_keys
kels-cli -u "$NODE_E_URL" adversary inject --prefix "$PREFIX4" --events ror,ixn
echo "Adversary ror,ixn injected on node-e (reveals recovery)"
wait_for_gossip

run_test "Owner contests" kels-cli -u "$NODE_D_URL" contest --prefix "$PREFIX4"
run_test "All nodes have cnt" wait_for_all_contested "$PREFIX4"

cleanup_adversary_backup
echo ""

# ========================================
# Scenario 5: Contested KEL propagation (cnt on longer chain)
# ========================================
echo -e "${CYAN}=== Scenario 5: Contested KEL Propagation (cnt on longer chain) ===${NC}"
echo "Adversary injects ror (shorter) on node-e. Owner has ixn+cnt (longer chain) on node-d."
echo "cnt is on the longer chain and should propagate naturally."
echo ""

PREFIX5=$(kels-cli -u "$NODE_D_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
kels-cli -u "$NODE_D_URL" anchor --prefix "$PREFIX5" --said KOwnerAnchorBeforeContest___________________
echo "Created KEL with anchor on node-d: $PREFIX5"
run_test "KEL propagated" wait_for_propagation "$PREFIX5" "$CONVERGENCE_TIMEOUT" "$NODE_D_URL" "$NODE_E_URL" "$NODE_F_URL"

save_adversary_keys
kels-cli -u "$NODE_E_URL" adversary inject --prefix "$PREFIX5" --events ror
echo "Adversary ror injected on node-e (reveals recovery, shorter chain)"
wait_for_gossip

run_test "Owner contests" kels-cli -u "$NODE_D_URL" contest --prefix "$PREFIX5"
run_test "All nodes have cnt" wait_for_all_contested "$PREFIX5"

cleanup_adversary_backup
echo ""

# ========================================
# Scenario 6: Contest during active archival
# ========================================
echo -e "${CYAN}=== Scenario 6: Contest During Active Archival ===${NC}"
echo "Adversary submits rec on node-d (triggering archival). Owner contests."
echo "Archival should detect cnt and transition to contested terminal state."
echo ""

PREFIX6=$(kels-cli -u "$NODE_D_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
kels-cli -u "$NODE_D_URL" anchor --prefix "$PREFIX6" --said KOwnerAnchorBeforeAdvRec____________________
echo "Created KEL with anchor on node-d: $PREFIX6"
run_test "KEL propagated" wait_for_propagation "$PREFIX6" "$CONVERGENCE_TIMEOUT" "$NODE_D_URL" "$NODE_E_URL" "$NODE_F_URL"

# Adversary submits rec directly (reveals recovery key)
save_adversary_keys
swap_to_adversary
kels-cli -u "$NODE_D_URL" adversary inject --prefix "$PREFIX6" --events rec
echo "Adversary rec injected on node-d"
swap_to_owner

# Owner contests (adversary revealed recovery via rec).
# No RecoveryRecord exists — the adversary rec was a normal append, not an
# overlap/divergent submission. The contest creates divergence directly.
run_test "Owner contests after adversary rec" kels-cli -u "$NODE_D_URL" contest --prefix "$PREFIX6"
run_test "All nodes have cnt" wait_for_all_contested "$PREFIX6"

cleanup_adversary_backup
echo ""

# ========================================
# Scenario 7: Double rec rejected
# ========================================
echo -e "${CYAN}=== Scenario 7: Double Recovery Rejected ===${NC}"
echo "Owner recovers, then adversary tries to submit a second rec. Should be rejected."
echo ""

PREFIX7=$(kels-cli -u "$NODE_D_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL on node-d: $PREFIX7"
run_test "KEL propagated" wait_for_propagation "$PREFIX7" "$CONVERGENCE_TIMEOUT" "$NODE_D_URL" "$NODE_E_URL" "$NODE_F_URL"

save_adversary_keys
kels-cli -u "$NODE_E_URL" adversary inject --prefix "$PREFIX7" --events ixn
wait_for_gossip

run_test "Owner recovers" kels-cli -u "$NODE_D_URL" recover --prefix "$PREFIX7"
run_test "Recovery completes" wait_for_recovery_complete "$NODE_D_URL" "$PREFIX7"

# Adversary tries another rec — should fail with ContestRequired
swap_to_adversary
run_test_expect_fail "Second rec rejected" kels-cli -u "$NODE_D_URL" adversary inject --prefix "$PREFIX7" --events rec
swap_to_owner

cleanup_adversary_backup
echo ""

# ========================================
# Scenario 8: Effective SAID convergence for contested KELs
# ========================================
echo -e "${CYAN}=== Scenario 8: Contested Effective SAID Convergence ===${NC}"
echo "After contest, all nodes should report the same effective SAID"
echo "even if their event counts differ (different archival progress)."
echo ""

# Reuse PREFIX4 (already contested from scenario 4)
effective_d=$(curl -s "$NODE_D_URL/api/v1/kels/kel/$PREFIX4/effective-said" | jq -r '.said // empty')
effective_e=$(curl -s "$NODE_E_URL/api/v1/kels/kel/$PREFIX4/effective-said" | jq -r '.said // empty')
effective_f=$(curl -s "$NODE_F_URL/api/v1/kels/kel/$PREFIX4/effective-said" | jq -r '.said // empty')

check_contested_saids() {
    [ -n "$effective_d" ] && [ "$effective_d" = "$effective_e" ] && [ "$effective_e" = "$effective_f" ]
}

echo "  D: $effective_d"
echo "  E: $effective_e"
echo "  F: $effective_f"
run_test "Contested effective SAIDs match across nodes" check_contested_saids

echo ""

# ========================================
# Scenario 9: Submissions rejected on contested KEL
# ========================================
echo -e "${CYAN}=== Scenario 9: Submissions Rejected on Contested KEL ===${NC}"
echo "All event types should be rejected on a contested KEL."
echo ""

# Reuse PREFIX4 (contested)
run_test_expect_fail "ixn rejected on contested KEL" kels-cli -u "$NODE_D_URL" anchor --prefix "$PREFIX4" --said KRejectedAnchor_____________________________
run_test_expect_fail "rot rejected on contested KEL" kels-cli -u "$NODE_D_URL" rotate --prefix "$PREFIX4"
run_test_expect_fail "dec rejected on contested KEL" kels-cli -u "$NODE_D_URL" decommission --prefix "$PREFIX4"

echo ""

# ========================================
# Scenario 10: Submissions rejected on decommissioned KEL
# ========================================
echo -e "${CYAN}=== Scenario 10: Submissions Rejected on Decommissioned KEL ===${NC}"
echo ""

PREFIX10=$(kels-cli -u "$NODE_D_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL on node-d: $PREFIX10"
run_test "Decommission KEL" kels-cli -u "$NODE_D_URL" decommission --prefix "$PREFIX10"
run_test_expect_fail "ixn rejected on decommissioned KEL" kels-cli -u "$NODE_D_URL" anchor --prefix "$PREFIX10" --said KRejected___________________________________

echo ""

# ========================================
# Summary
# ========================================
print_summary
exit_with_result
