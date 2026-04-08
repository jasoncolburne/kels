#!/usr/bin/env bash
set -e

PROPOSAL_PREFIX="$1"
REGISTRY_NS="${2:-}"  # Optional: specific registry to withdraw from

if [ -z "$PROPOSAL_PREFIX" ]; then
    echo "Usage: withdraw-peer.sh <proposal-prefix> [registry-namespace]"
    echo "  Withdraws a peer proposal."
    echo "  If registry-namespace is not specified, finds the federation leader."
    exit 1
fi

# Find all available registries
REGISTRIES=(registry-a registry-b registry-c registry-d)

if [ -z "$REGISTRY_NS" ]; then
    # Find the leader registry (proposals are submitted to leader)
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    REGISTRY_NS=$("$SCRIPT_DIR/find-leader.sh")
fi

if [ -z "$REGISTRY_NS" ]; then
    echo "Error: Could not find registry to withdraw from" >&2
    exit 1
fi

echo "Withdrawing proposal $PROPOSAL_PREFIX from $REGISTRY_NS..." >&2

# Withdraw the proposal
WITHDRAW_OUTPUT=$(kubectl exec -n "kels-$REGISTRY_NS" deploy/registry -c registry -- \
    /app/registry-admin peer withdraw \
    --proposal-prefix "$PROPOSAL_PREFIX" 2>&1)

echo "$WITHDRAW_OUTPUT"

if echo "$WITHDRAW_OUTPUT" | grep -qi "withdrawn"; then
    echo "Proposal $PROPOSAL_PREFIX withdrawn!" >&2
fi
