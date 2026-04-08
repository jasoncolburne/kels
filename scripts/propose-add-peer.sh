#!/usr/bin/env bash
set -e

NODE_NAME="$1"

if [ -z "$NODE_NAME" ]; then
    echo "Usage: propose-add-peer.sh <node-name>"
    echo "  Proposes a peer for the given node."
    echo "  Outputs the proposal prefix on success."
    exit 1
fi

# Construct base domain and gossip address for the node
BASE_DOMAIN="${NODE_NAME}.kels"
GOSSIP_ADDR="gossip.${NODE_NAME}.kels:4001"

# Fetch the peer prefix from the node's gossip service
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PEER_PREFIX=$("$SCRIPT_DIR/fetch-gossip-identity.sh" "kels-${NODE_NAME}")
if [ -z "$PEER_PREFIX" ]; then
    echo "Error: Could not fetch PeerPrefix from $NODE_NAME" >&2
    exit 1
fi

# Find the federation leader (curl runs inside cluster via test-client)
LEADER_NS=$("$SCRIPT_DIR/find-leader.sh")

if [ -z "$LEADER_NS" ]; then
    echo "Error: Could not find federation leader" >&2
    exit 1
fi

echo "Found leader: $LEADER_NS" >&2
echo "Creating proposal for $NODE_NAME (prefix: $PEER_PREFIX)..." >&2

# Create proposal on leader
PROPOSE_OUTPUT=$(kubectl exec -n "kels-$LEADER_NS" deploy/registry -c registry -- \
    /app/registry-admin peer propose \
    --peer-kel-prefix "$PEER_PREFIX" \
    --node-id "$NODE_NAME" \
    --base-domain "$BASE_DOMAIN" \
    --gossip-addr "$GOSSIP_ADDR" 2>&1)

echo "$PROPOSE_OUTPUT" >&2

# Extract proposal prefix from "Proposal created: <id>" line
PROPOSAL_PREFIX=$(echo "$PROPOSE_OUTPUT" | grep "Proposal created:" | grep -oE 'K[A-Za-z0-9_-]{43}')

if [ -z "$PROPOSAL_PREFIX" ]; then
    echo "Error: Could not extract proposal prefix from output" >&2
    exit 1
fi

# Output just the proposal prefix to stdout for piping
echo "$PROPOSAL_PREFIX"
