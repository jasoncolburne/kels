#!/bin/bash
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

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Active registry URLs (b is decommissioned)
ACTIVE_REGISTRY_URLS=(
    "http://kels-registry.kels-registry-a.kels"
    "http://kels-registry.kels-registry-c.kels"
    "http://kels-registry.kels-registry-d.kels"
)
ACTIVE_REGISTRY_NAMES=(a c d)

DECOMMISSIONED_URL="http://kels-registry.kels-registry-b.kels"

NODE_A_URL="http://kels.kels-node-a.kels"
NODE_B_URL="http://kels.kels-node-b.kels"

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
# Scenario 2: Decommissioned registry is down
# ========================================
echo -e "${CYAN}=== Scenario 2: Decommissioned Registry ===${NC}"
echo "Verifying registry-b is not serving federation requests..."
echo

run_test_expect_fail "registry-b federation status unreachable" \
    curl -sf --connect-timeout 5 "${DECOMMISSIONED_URL}/api/federation/status"

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
        STATUS=$(curl -sf "${url}/api/federation/status" 2>/dev/null || echo "{}")
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
    STATUS=$(curl -sf "${url}/api/federation/status" 2>/dev/null || echo "{}")
    MEMBER_COUNT=$(echo "$STATUS" | jq -r '.members | length // 0')
    echo "  registry-${name}: ${MEMBER_COUNT} members"
    run_test "registry-${name} reports 3 members" [ "$MEMBER_COUNT" -eq 3 ]
done

echo

# ========================================
# Scenario 5: Gossip still works
# ========================================
echo -e "${CYAN}=== Scenario 5: Gossip Propagation ===${NC}"
echo "Creating KEL on node-a, verifying propagation to node-b..."
echo

# Wait for nodes to be ready
for url in "$NODE_A_URL" "$NODE_B_URL"; do
    for i in {1..30}; do
        if curl -s "$url/health" > /dev/null 2>&1; then
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${RED}$url not ready after 30 seconds${NC}"
        fi
        sleep 1
    done
done

PREFIX=$(kels-cli -u "$NODE_A_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL on node-a: $PREFIX"

run_test "KEL exists on node-a" curl -sf "$NODE_A_URL/api/kels/kel/$PREFIX"

# Wait for propagation
CONVERGED=false
for attempt in {1..30}; do
    if curl -sf "$NODE_B_URL/api/kels/kel/$PREFIX" > /dev/null 2>&1; then
        CONVERGED=true
        break
    fi
    sleep 1
done

run_test "KEL propagated to node-b after shrink" [ "$CONVERGED" = "true" ]

echo

# ========================================
# Print Summary
# ========================================
echo -e "${CYAN}========================================${NC}"
echo "Federation Shrink Test Summary"
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
