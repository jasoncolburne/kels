#!/usr/bin/env bash
set -e

PROPOSAL_ID="$1"
REGISTRY_NS="${2:-}"  # Optional: specific registry to vote from

if [ -z "$PROPOSAL_ID" ]; then
    echo "Usage: vote-peer.sh <proposal-id> [registry-namespace]"
    echo "  Votes on a peer proposal."
    echo "  If registry-namespace is not specified, finds a non-leader registry to vote from."
    exit 1
fi

# Find all available registries
REGISTRIES=(kels-registry-a kels-registry-b kels-registry-c)

if [ -z "$REGISTRY_NS" ]; then
    # Find a follower registry to vote from
    LEADER_NS=""

    for ns in "${REGISTRIES[@]}"; do
        LEADER_INFO=$(curl -s "http://kels-registry.${ns}.kels/api/federation/status" 2>/dev/null || echo "{}")
        IS_LEADER=$(echo "$LEADER_INFO" | jq -r '.isLeader // false')

        if [ "$IS_LEADER" = "true" ]; then
            LEADER_NS="$ns"
            break
        fi
    done

    # Find a follower
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

echo "Voting from $REGISTRY_NS on proposal $PROPOSAL_ID..." >&2

# Vote on the proposal
VOTE_OUTPUT=$(kubectl exec -n "$REGISTRY_NS" deploy/kels-registry -c kels-registry -- \
    /app/kels-registry-admin peer vote \
    --proposal-id "$PROPOSAL_ID" \
    --approve 2>&1)

echo "$VOTE_OUTPUT"

# Check if peer was approved
if echo "$VOTE_OUTPUT" | grep -qi "approved"; then
    echo "Proposal $PROPOSAL_ID approved!" >&2
fi
