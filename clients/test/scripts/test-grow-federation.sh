#!/usr/bin/env bash
# test-grow-federation.sh - Federation Growth Verification
# Verifies that a 4th registry has been added to the federation and all
# registries report consistent Raft membership.
#
# Tests:
#   1. All 4 registries are healthy
#   2. A leader is elected across 4 members
#   3. Each registry reports 4 members
#   4. All registries agree on the same leader
#   5. Node 0 reports itself correctly
#
# Usage: test-grow-federation.sh

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Registry URLs
REGISTRY_URLS=(
    "http://registry.registry-a.kels"
    "http://registry.registry-b.kels"
    "http://registry.registry-c.kels"
    "http://registry.registry-d.kels"
)
REGISTRY_NAMES=(a b c d)

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Federation Growth Verification${NC}"
echo -e "${CYAN}========================================${NC}"
echo

# ========================================
# Scenario 1: Wait for all 4 registries to be healthy
# ========================================
echo -e "${CYAN}=== Scenario 1: Registry Health ===${NC}"
echo "Waiting for all 4 registries to be healthy..."
echo

for i in "${!REGISTRY_URLS[@]}"; do
    url="${REGISTRY_URLS[$i]}"
    name="${REGISTRY_NAMES[$i]}"
    wait_for_health "$url" "registry-${name}" 60 || true
    run_test "registry-${name} is healthy" curl -sf "${url}/health"
done

echo

# ========================================
# Scenario 2: Wait for leader election
# ========================================
echo -e "${CYAN}=== Scenario 2: Leader Election ===${NC}"
echo "Polling for leader election across 4-member cluster..."
echo

LEADER_ID=""
for attempt in {1..60}; do
    for i in "${!REGISTRY_URLS[@]}"; do
        url="${REGISTRY_URLS[$i]}"
        STATUS=$(curl -sf "${url}/api/v1/federation/status" 2>/dev/null || echo "{}")
        IS_LEADER=$(echo "$STATUS" | jq -r '.isLeader // false')
        if [ "$IS_LEADER" = "true" ]; then
            LEADER_ID=$(echo "$STATUS" | jq -r '.nodeId // empty')
            break 2
        fi
    done
    sleep 1
done

run_test "Leader elected in 4-member cluster" [ -n "$LEADER_ID" ]
echo "  Leader node ID: $LEADER_ID"
echo

# ========================================
# Scenario 3: Verify each registry reports 4 members
# ========================================
echo -e "${CYAN}=== Scenario 3: Member Count ===${NC}"
echo "Polling for all registries to report 4 members..."
echo

ALL_HAVE_4=false
for attempt in {1..60}; do
    ALL_HAVE_4=true
    for i in "${!REGISTRY_URLS[@]}"; do
        url="${REGISTRY_URLS[$i]}"
        STATUS=$(curl -sf "${url}/api/v1/federation/status" 2>/dev/null || echo "{}")
        MEMBER_COUNT=$(echo "$STATUS" | jq -r '.members | length // 0')
        if [ "$MEMBER_COUNT" -ne 4 ]; then
            ALL_HAVE_4=false
            break
        fi
    done
    if [ "$ALL_HAVE_4" = "true" ]; then
        break
    fi
    sleep 1
done

for i in "${!REGISTRY_URLS[@]}"; do
    url="${REGISTRY_URLS[$i]}"
    name="${REGISTRY_NAMES[$i]}"
    STATUS=$(curl -sf "${url}/api/v1/federation/status" 2>/dev/null || echo "{}")
    MEMBER_COUNT=$(echo "$STATUS" | jq -r '.members | length // 0')
    echo "  registry-${name}: ${MEMBER_COUNT} members"
    run_test "registry-${name} reports 4 members" [ "$MEMBER_COUNT" -eq 4 ]
done

echo

# ========================================
# Scenario 4: Verify all registries agree on the same leader
# ========================================
echo -e "${CYAN}=== Scenario 4: Leader Agreement ===${NC}"
echo "Polling for all registries to agree on the same leader..."
echo

ALL_SAME=false
for attempt in {1..60}; do
    LEADERS=()
    for i in "${!REGISTRY_URLS[@]}"; do
        url="${REGISTRY_URLS[$i]}"
        STATUS=$(curl -sf "${url}/api/v1/federation/status" 2>/dev/null || echo "{}")
        REPORTED_LEADER=$(echo "$STATUS" | jq -r '.leaderId // empty')
        LEADERS+=("$REPORTED_LEADER")
    done

    ALL_SAME=true
    for leader in "${LEADERS[@]}"; do
        if [ -z "$leader" ] || [ "$leader" != "${LEADERS[0]}" ]; then
            ALL_SAME=false
            break
        fi
    done

    if [ "$ALL_SAME" = "true" ]; then
        break
    fi
    sleep 1
done

for i in "${!REGISTRY_URLS[@]}"; do
    name="${REGISTRY_NAMES[$i]}"
    echo "  registry-${name} reports leader: ${LEADERS[$i]}"
done

run_test "All registries agree on the same leader" [ "$ALL_SAME" = "true" ]
echo

# ========================================
# Scenario 5: Verify node 0 reports itself correctly
# ========================================
echo -e "${CYAN}=== Scenario 5: Node 0 Self-Report ===${NC}"
echo "Polling for node 0 to report its own ID correctly..."
echo

NODE_ID_0=""
for attempt in {1..60}; do
    STATUS_0=$(curl -sf "${REGISTRY_URLS[0]}/api/v1/federation/status" 2>/dev/null || echo "{}")
    NODE_ID_0=$(echo "$STATUS_0" | jq -r '.nodeId // empty')
    if [ "$NODE_ID_0" = "0" ]; then
        break
    fi
    sleep 1
done

echo "  Node 0 reports nodeId: $NODE_ID_0"
run_test "Node 0 reports nodeId 0" [ "$NODE_ID_0" = "0" ]

echo

print_summary "Federation Growth Test Summary"
exit_with_result
