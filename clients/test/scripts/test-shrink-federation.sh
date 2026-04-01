#!/usr/bin/env bash
# test-shrink-federation.sh - Federation Shrink Verification
# Verifies that after decommissioning registry-b, the remaining 3 registries
# (a, c, d) form a healthy federation and gossip still works. Historical votes
# from decommissioned registry-b must still be valid during Raft log replay.
#
# Tests:
#   1. Active registries (a, c, d) are healthy
#   2. Decommissioned registry (b) is not contactable or not in federation
#   3. A leader is elected across 3 active members
#   4. Each active registry reports 3 members
#   5. Gossip propagation still works between nodes
#
# Usage: test-shrink-federation.sh

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Active registry URLs (b is decommissioned)
ACTIVE_REGISTRY_URLS=(
    "http://kels-registry.kels-registry-a.kels"
    "http://kels-registry.kels-registry-c.kels"
    "http://kels-registry.kels-registry-d.kels"
)
ACTIVE_REGISTRY_NAMES=(a c d)

DECOMMISSIONED_URL="http://kels-registry.kels-registry-b.kels"

NODE_URLS=(
    "http://kels.kels-node-a.kels"
    "http://kels.kels-node-b.kels"
    "http://kels.kels-node-c.kels"
    "http://kels.kels-node-d.kels"
    "http://kels.kels-node-e.kels"
    "http://kels.kels-node-f.kels"
)
NODE_NAMES=(a b c d e f)
NODE_A_URL="${NODE_URLS[0]}"

init_temp_dir

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Federation Shrink Verification${NC}"
echo -e "${CYAN}========================================${NC}"
echo

# ========================================
# Scenario 1: Active registries are healthy
# ========================================
echo -e "${CYAN}=== Scenario 1: Active Registry Health ===${NC}"
echo "Waiting for active registries (a, c, d) to be healthy..."
echo

for i in "${!ACTIVE_REGISTRY_URLS[@]}"; do
    url="${ACTIVE_REGISTRY_URLS[$i]}"
    name="${ACTIVE_REGISTRY_NAMES[$i]}"
    wait_for_health "$url" "registry-${name}" 60 || true
    run_test "registry-${name} is healthy" curl -sf "${url}/health"
done

echo

# ========================================
# Scenario 2: Decommissioned registry is down
# ========================================
echo -e "${CYAN}=== Scenario 2: Decommissioned Registry ===${NC}"
echo "Verifying registry-b is not serving federation requests..."
echo

run_test_expect_fail "registry-b federation status unreachable" \
    curl -sf --connect-timeout 5 "${DECOMMISSIONED_URL}/api/v1/federation/status"

echo

# ========================================
# Scenario 3: Leader election with 3 active members
# ========================================
echo -e "${CYAN}=== Scenario 3: Leader Election ===${NC}"
echo "Polling for leader election across 3-member cluster..."
echo

LEADER_ID=""
for attempt in {1..60}; do
    for i in "${!ACTIVE_REGISTRY_URLS[@]}"; do
        url="${ACTIVE_REGISTRY_URLS[$i]}"
        STATUS=$(curl -sf "${url}/api/v1/federation/status" 2>/dev/null || echo "{}")
        IS_LEADER=$(echo "$STATUS" | jq -r '.isLeader // false')
        if [ "$IS_LEADER" = "true" ]; then
            LEADER_ID=$(echo "$STATUS" | jq -r '.nodeId // empty')
            break 2
        fi
    done
    sleep 1
done

run_test "Leader elected in 3-member cluster" [ -n "$LEADER_ID" ]
echo "  Leader node ID: $LEADER_ID"
echo

# ========================================
# Scenario 4: Each active registry reports 3 members
# ========================================
echo -e "${CYAN}=== Scenario 4: Member Count ===${NC}"
echo "Verifying each active registry reports 3 members..."
echo

for i in "${!ACTIVE_REGISTRY_URLS[@]}"; do
    url="${ACTIVE_REGISTRY_URLS[$i]}"
    name="${ACTIVE_REGISTRY_NAMES[$i]}"
    STATUS=$(curl -sf "${url}/api/v1/federation/status" 2>/dev/null || echo "{}")
    MEMBER_COUNT=$(echo "$STATUS" | jq -r '.members | length // 0')
    echo "  registry-${name}: ${MEMBER_COUNT} members"
    run_test "registry-${name} reports 3 members" [ "$MEMBER_COUNT" -eq 3 ]
done

echo

# ========================================
# Scenario 5: Gossip still works
# ========================================
echo -e "${CYAN}=== Scenario 5: Gossip Propagation ===${NC}"
echo "Creating KEL on node-a, verifying propagation to all nodes..."
echo

# Wait for nodes to be ready
for url in "${NODE_URLS[@]}"; do
    wait_for_health "$url" "$url" || true
done

PREFIX=$(kels-cli --kels-url "$NODE_A_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL on node-a: $PREFIX"

run_test "KEL exists on node-a" curl -sf "$NODE_A_URL/api/v1/kels/kel/$PREFIX"

run_test "KEL propagated to all nodes after shrink" \
    wait_for_propagation "$PREFIX" 90 "${NODE_URLS[@]}"

echo

print_summary "Federation Shrink Test Summary"
exit_with_result
