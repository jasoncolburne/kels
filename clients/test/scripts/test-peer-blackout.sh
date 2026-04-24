#!/usr/bin/env bash
# test-peer-blackout.sh - Verify a removed peer cannot participate in gossip
#
# Creates a KEL on node-a, verifies it propagates to all active nodes but
# NOT to the blacklisted node.
#
# Usage: test-peer-blackout.sh <blacklisted-node-name>
#   e.g. test-peer-blackout.sh node-f

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

BLACKLISTED_NODE="$1"
if [ -z "$BLACKLISTED_NODE" ]; then
    echo "Usage: test-peer-blackout.sh <blacklisted-node-name>"
    exit 1
fi

ALL_NODES=(node-a node-b node-c node-d node-e node-f)
ACTIVE_NODES=()
ACTIVE_URLS=()
BLACKLISTED_URL="http://kels.${BLACKLISTED_NODE}.kels"

for node in "${ALL_NODES[@]}"; do
    if [ "$node" != "$BLACKLISTED_NODE" ]; then
        ACTIVE_NODES+=("$node")
        ACTIVE_URLS+=("http://kels.${node}.kels")
    fi
done

NODE_A_URL="http://kels.node-a.kels"

init_temp_dir

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Peer Blackout Verification${NC}"
echo -e "${CYAN}  Blacklisted: ${BLACKLISTED_NODE}${NC}"
echo -e "${CYAN}========================================${NC}"
echo

# Wait for active nodes to be healthy
for i in "${!ACTIVE_NODES[@]}"; do
    wait_for_health "${ACTIVE_URLS[$i]}" "${ACTIVE_NODES[$i]}" 30 || true
done

# Create a KEL on node-a
PREFIX=$(kels-cli --kels-url "$NODE_A_URL" kel incept 2>&1 | grep "Prefix:" | awk '{print $2}')
echo "Created KEL on node-a: $PREFIX"
run_test "KEL exists on node-a" curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"$PREFIX\"}" "$NODE_A_URL/api/v1/kels/kel/fetch"

# Wait for propagation to active nodes
run_test "KEL propagated to active nodes" \
    wait_for_propagation "$PREFIX" 90 "${ACTIVE_URLS[@]}"

# Verify the blacklisted node does NOT have the KEL
# Give it a few seconds in case there's any residual connectivity
sleep 5
if curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"$PREFIX\"}" "$BLACKLISTED_URL/api/v1/kels/kel/fetch" > /dev/null 2>&1; then
    run_test "${BLACKLISTED_NODE} excluded from gossip" false
else
    run_test "${BLACKLISTED_NODE} excluded from gossip" true
fi

echo
print_summary "Peer Blackout Test Summary"
exit_with_result
