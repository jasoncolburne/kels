#!/usr/bin/env bash
set -e

NODE_NAME="$1"
ENV_NAMESPACE="$2"

if [ -z "$NODE_NAME" ] || [ -z "$ENV_NAMESPACE" ]; then
    echo "Usage: add-regional-node.sh <node-name> <env-namespace>"
    echo "  Adds a regional peer to the specified registry."
    echo "  For core peers, use propose-peer.sh and vote-peer.sh instead."
    exit 1
fi

# Construct URLs for the node
KELS_URL="http://kels.kels-${NODE_NAME}.kels:80"
GOSSIP_MULTIADDR="/dns4/kels-gossip.kels-${NODE_NAME}.kels/tcp/4001"

# Get the garden binary path
GARDEN_BIN="${GARDEN_BIN:-garden}"

# Fetch the peer ID from the node's gossip service
PEER_ID=$("$GARDEN_BIN" run fetch-gossip-identity --env "$NODE_NAME" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E '^[a-zA-Z0-9]{40,60}$' | tail -1)
if [ -z "$PEER_ID" ]; then
    echo "Error: Could not fetch PeerId from $NODE_NAME"
    exit 1
fi

kubectl exec -n "$ENV_NAMESPACE" deploy/kels-registry -c kels-registry -- \
    /app/kels-registry-admin peer add \
    --peer-id "$PEER_ID" \
    --node-id "$NODE_NAME" \
    --scope regional \
    --kels-url "$KELS_URL" \
    --gossip-multiaddr "$GOSSIP_MULTIADDR"

echo "Regional node $NODE_NAME added to $ENV_NAMESPACE with peer ID: $PEER_ID"
