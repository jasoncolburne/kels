#!/usr/bin/env bash
set -e

NODE_NAME="$1"

if [ -z "$NODE_NAME" ]; then
    echo "Usage: propose-remove-peer.sh <node-name>"
    echo "  Proposes removal of a peer for the given node."
    echo "  Outputs the proposal ID on success."
    exit 1
fi

# Fetch the peer prefix from the node's gossip service
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PEER_PREFIX=$("$SCRIPT_DIR/fetch-gossip-identity.sh" "kels-${NODE_NAME}")
if [ -z "$PEER_PREFIX" ]; then
    echo "Error: Could not fetch PeerPrefix from $NODE_NAME" >&2
    exit 1
fi

# Find the federation leader (curl runs inside cluster via test-client)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LEADER_NS=$("$SCRIPT_DIR/find-leader.sh")

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
PROPOSAL_ID=$(echo "$PROPOSE_OUTPUT" | grep "proposal created:" | grep -oE 'K[A-Za-z0-9_-]{43}')

if [ -z "$PROPOSAL_ID" ]; then
    echo "Error: Could not extract proposal ID from output" >&2
    exit 1
fi

# Output just the proposal ID to stdout for piping
echo "$PROPOSAL_ID"
