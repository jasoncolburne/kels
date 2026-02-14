#!/usr/bin/env bash
set -e

PROPOSAL_ID="$1"
REGISTRY_NS="${2:-}"  # Optional: specific registry to withdraw from

if [ -z "$PROPOSAL_ID" ]; then
    echo "Usage: withdraw-peer.sh <proposal-id> [registry-namespace]"
    echo "  Withdraws a peer proposal."
    echo "  If registry-namespace is not specified, finds the federation leader."
    exit 1
fi

# Find all available registries
REGISTRIES=(kels-registry-a kels-registry-b kels-registry-c)

if [ -z "$REGISTRY_NS" ]; then
    # Find the leader registry (proposals are submitted to leader)
    for ns in "${REGISTRIES[@]}"; do
        LEADER_INFO=$(curl -s "http://kels-registry.${ns}.kels/api/federation/status" 2>/dev/null || echo "{}")
        IS_LEADER=$(echo "$LEADER_INFO" | jq -r '.isLeader // false')

        if [ "$IS_LEADER" = "true" ]; then
            REGISTRY_NS="$ns"
            break
        fi
    done
fi

if [ -z "$REGISTRY_NS" ]; then
    echo "Error: Could not find registry to withdraw from" >&2
    exit 1
fi

echo "Withdrawing proposal $PROPOSAL_ID from $REGISTRY_NS..." >&2

# Withdraw the proposal
WITHDRAW_OUTPUT=$(kubectl exec -n "$REGISTRY_NS" deploy/kels-registry -c kels-registry -- \
    /app/kels-registry-admin peer withdraw \
    --proposal-id "$PROPOSAL_ID" 2>&1)

echo "$WITHDRAW_OUTPUT"

if echo "$WITHDRAW_OUTPUT" | grep -qi "withdrawn"; then
    echo "Proposal $PROPOSAL_ID withdrawn!" >&2
fi
