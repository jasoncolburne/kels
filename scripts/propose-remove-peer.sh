#!/usr/bin/env bash
set -e

NODE_NAME="$1"

if [ -z "$NODE_NAME" ]; then
    echo "Usage: propose-remove-peer.sh <node-name>"
    echo "  Proposes removal of a peer for the given node."
    echo "  Outputs the proposal ID on success."
    exit 1
fi

# Get the garden binary path
GARDEN_BIN="${GARDEN_BIN:-garden}"

# Fetch the peer prefix from the node's gossip service
PEER_PREFIX=$("$GARDEN_BIN" run fetch-gossip-identity --env "$NODE_NAME" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -oE '[a-zA-Z0-9_-]{44}' | tail -1)
if [ -z "$PEER_PREFIX" ]; then
    echo "Error: Could not fetch PeerPrefix from $NODE_NAME" >&2
    exit 1
fi

# Find all available registries
REGISTRIES=(kels-registry-a kels-registry-b kels-registry-c kels-registry-d)
LEADER_NS=""

# Find the federation leader
for ns in "${REGISTRIES[@]}"; do
    LEADER_INFO=$(curl -s "http://kels-registry.${ns}.kels/api/federation/status" 2>/dev/null || echo "{}")
    IS_LEADER=$(echo "$LEADER_INFO" | jq -r '.isLeader // false')

    if [ "$IS_LEADER" = "true" ]; then
        LEADER_NS="$ns"
        break
    fi
done

if [ -z "$LEADER_NS" ]; then
    echo "Error: Could not find federation leader" >&2
    exit 1
fi

echo "Found leader: $LEADER_NS" >&2
echo "Creating removal proposal for $NODE_NAME (prefix: $PEER_PREFIX)..." >&2

# Create removal proposal on leader
PROPOSE_OUTPUT=$(kubectl exec -n "$LEADER_NS" deploy/kels-registry -c kels-registry -- \
    /app/kels-registry-admin peer propose-removal \
    --peer-prefix "$PEER_PREFIX" 2>&1)

echo "$PROPOSE_OUTPUT" >&2

# Extract proposal ID from "Removal proposal created: <id>" line
PROPOSAL_ID=$(echo "$PROPOSE_OUTPUT" | grep "proposal created:" | grep -oE 'E[A-Za-z0-9_-]{43}')

if [ -z "$PROPOSAL_ID" ]; then
    echo "Error: Could not extract proposal ID from output" >&2
    exit 1
fi

# Output just the proposal ID to stdout for piping
echo "$PROPOSAL_ID"
