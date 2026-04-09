#!/usr/bin/env bash
set -e

PROPOSAL_PREFIX="$1"
REGISTRY_NS="${2:-}"  # Optional: specific registry to vote from
APPROVE="${3:-true}"  # Optional: true to approve, false to reject

if [ -z "$PROPOSAL_PREFIX" ]; then
    echo "Usage: vote-peer.sh <proposal-prefix> [registry-namespace] [true|false]"
    echo "  Votes on a peer proposal."
    echo "  If registry-namespace is not specified, finds a non-leader registry to vote from."
    echo "  Third argument: true (default) to approve, false to reject."
    exit 1
fi

# Find all available registries
REGISTRIES=(registry-a registry-b registry-c registry-d)

if [ -z "$REGISTRY_NS" ]; then
    # Find the leader, then pick a follower to vote from
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    LEADER_NS=$("$SCRIPT_DIR/find-leader.sh")

    for ns in "${REGISTRIES[@]}"; do
        if [ "$ns" != "$LEADER_NS" ]; then
            REGISTRY_NS="$ns"
            break
        fi
    done
fi

if [ -z "$REGISTRY_NS" ]; then
    echo "Error: Could not find registry to vote from" >&2
    exit 1
fi

if [ "$APPROVE" = "true" ]; then
    echo "Voting APPROVE from $REGISTRY_NS on proposal $PROPOSAL_PREFIX..." >&2
else
    echo "Voting REJECT from $REGISTRY_NS on proposal $PROPOSAL_PREFIX..." >&2
fi

# Vote on the proposal
APPROVE_FLAG=""
if [ "$APPROVE" = "true" ]; then
    APPROVE_FLAG="--approve"
fi

VOTE_OUTPUT=$(kubectl exec -n "kels-$REGISTRY_NS" deploy/registry -c registry -- \
    /app/registry-admin peer vote \
    --proposal-prefix "$PROPOSAL_PREFIX" \
    $APPROVE_FLAG 2>&1)

echo "$VOTE_OUTPUT"

# Check if peer was approved
if echo "$VOTE_OUTPUT" | grep -qi "approved"; then
    echo "Proposal $PROPOSAL_PREFIX approved!" >&2
fi
