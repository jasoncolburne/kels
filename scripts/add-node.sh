#!/usr/bin/env bash
set -e

NODE_NAME="$1"
ENV_NAMESPACE="$2"
SCOPE="${3:-regional}"

if [ -z "$NODE_NAME" ] || [ -z "$ENV_NAMESPACE" ]; then
    echo "Usage: add-node.sh <node-name> <env-namespace> [scope]"
    echo "  scope: 'core' (replicated via federation) or 'regional' (local only, default)"
    exit 1
fi

# Get the garden binary path
GARDEN_BIN="${GARDEN_BIN:-garden}"

# Fetch the peer ID from the node's gossip service
PEER_ID=$("$GARDEN_BIN" run fetch-gossip-identity --env "$NODE_NAME" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E '^[a-zA-Z0-9]{40,60}$' | tail -1)
if [ -z "$PEER_ID" ]; then
    echo "Error: Could not fetch PeerId from $NODE_NAME"
    exit 1
fi

# Determine which registry namespace to use
TARGET_NAMESPACE="$ENV_NAMESPACE"

if [ "$SCOPE" = "core" ]; then
    # For core peers, find the federation leader and use that registry
    echo "Finding federation leader for core peer..."

    # Try each registry to find the leader
    for ns in kels-registry-a kels-registry-b kels-registry-c; do
        LEADER_INFO=$(curl -s "http://kels-registry.${ns}.local/api/federation/status" 2>/dev/null || echo "{}")
        IS_LEADER=$(echo "$LEADER_INFO" | jq -r '.isLeader // false')

        if [ "$IS_LEADER" = "true" ]; then
            TARGET_NAMESPACE="$ns"
            echo "Found leader: $TARGET_NAMESPACE"
            break
        fi
    done

    if [ "$TARGET_NAMESPACE" = "$ENV_NAMESPACE" ]; then
        # Check if we actually found a leader or just fell back
        LEADER_CHECK=$(curl -s "http://kels-registry.${TARGET_NAMESPACE}.local/api/federation/status" 2>/dev/null || echo "{}")
        IS_LEADER=$(echo "$LEADER_CHECK" | jq -r '.isLeader // false')
        if [ "$IS_LEADER" != "true" ]; then
            echo "Warning: Could not find federation leader, using $ENV_NAMESPACE"
        fi
    fi
fi

# Add the peer to the registry
kubectl exec -n "$TARGET_NAMESPACE" deploy/kels-registry -c kels-registry -- \
    /app/kels-registry-admin peer add --peer-id "$PEER_ID" --node-id "$NODE_NAME" --scope "$SCOPE"

echo "Node $NODE_NAME added to $TARGET_NAMESPACE with peer ID: $PEER_ID (scope: $SCOPE)"
