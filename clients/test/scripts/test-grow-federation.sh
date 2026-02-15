#!/bin/bash
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

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Registry URLs
REGISTRY_URLS=(
    "http://kels-registry.kels-registry-a.kels"
    "http://kels-registry.kels-registry-b.kels"
    "http://kels-registry.kels-registry-c.kels"
    "http://kels-registry.kels-registry-d.kels"
)
REGISTRY_NAMES=(a b c d)

# Test state
TESTS_PASSED=0
TESTS_FAILED=0

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
    for attempt in {1..60}; do
        if curl -sf "${url}/health" > /dev/null 2>&1; then
            break
        fi
        if [ "$attempt" -eq 60 ]; then
            echo -e "${RED}registry-${name} not healthy after 60 seconds${NC}"
        fi
        sleep 1
    done
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
        STATUS=$(curl -sf "${url}/api/federation/status" 2>/dev/null || echo "{}")
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
echo "Verifying each registry reports 4 members..."
echo

for i in "${!REGISTRY_URLS[@]}"; do
    url="${REGISTRY_URLS[$i]}"
    name="${REGISTRY_NAMES[$i]}"
    STATUS=$(curl -sf "${url}/api/federation/status" 2>/dev/null || echo "{}")
    MEMBER_COUNT=$(echo "$STATUS" | jq -r '.members | length // 0')
    echo "  registry-${name}: ${MEMBER_COUNT} members"
    run_test "registry-${name} reports 4 members" [ "$MEMBER_COUNT" -eq 4 ]
done

echo

# ========================================
# Scenario 4: Verify all registries agree on the same leader
# ========================================
echo -e "${CYAN}=== Scenario 4: Leader Agreement ===${NC}"
echo "Verifying all registries agree on the same leader..."
echo

LEADERS=()
for i in "${!REGISTRY_URLS[@]}"; do
    url="${REGISTRY_URLS[$i]}"
    name="${REGISTRY_NAMES[$i]}"
    STATUS=$(curl -sf "${url}/api/federation/status" 2>/dev/null || echo "{}")
    REPORTED_LEADER=$(echo "$STATUS" | jq -r '.leaderId // empty')
    echo "  registry-${name} reports leader: $REPORTED_LEADER"
    LEADERS+=("$REPORTED_LEADER")
done

# Check all leaders are the same
ALL_SAME=true
for leader in "${LEADERS[@]}"; do
    if [ "$leader" != "${LEADERS[0]}" ]; then
        ALL_SAME=false
        break
    fi
done

run_test "All registries agree on the same leader" [ "$ALL_SAME" = "true" ]
echo

# ========================================
# Scenario 5: Verify node 0 reports itself correctly
# ========================================
echo -e "${CYAN}=== Scenario 5: Node 0 Self-Report ===${NC}"
echo "Verifying node 0 reports its own ID correctly..."
echo

STATUS_0=$(curl -sf "${REGISTRY_URLS[0]}/api/federation/status" 2>/dev/null || echo "{}")
NODE_ID_0=$(echo "$STATUS_0" | jq -r '.nodeId // empty')
echo "  Node 0 reports nodeId: $NODE_ID_0"
run_test "Node 0 reports nodeId 0" [ "$NODE_ID_0" = "0" ]

echo

# ========================================
# Print Summary
# ========================================
echo -e "${CYAN}========================================${NC}"
echo "Federation Growth Test Summary"
echo -e "${CYAN}========================================${NC}"
echo -e "Passed: ${GREEN}${TESTS_PASSED}${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "Failed: ${RED}${TESTS_FAILED}${NC}"
else
    echo -e "Failed: ${GREEN}${TESTS_FAILED}${NC}"
fi
echo -e "${CYAN}========================================${NC}"

if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
fi
