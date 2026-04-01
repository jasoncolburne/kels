#!/usr/bin/env bash
set -e

PROPOSAL_ID="$1"
REGISTRY_NS="${2:-}"  # Optional: specific registry to query

if [ -z "$PROPOSAL_ID" ]; then
    echo "Usage: proposal-status.sh <proposal-id> [registry-namespace]"
    echo "  Gets the status of a peer proposal."
    echo "  If registry-namespace is not specified, uses registry-a."
    exit 1
fi

if [ -z "$REGISTRY_NS" ]; then
    REGISTRY_NS="kels-registry-a"
fi

echo "Querying proposal $PROPOSAL_ID from $REGISTRY_NS..." >&2

STATUS_OUTPUT=$(kubectl exec -n "$REGISTRY_NS" deploy/registry -c registry -- \
    /app/registry-admin peer proposal-status \
    --proposal-id "$PROPOSAL_ID" 2>&1)

echo "$STATUS_OUTPUT"
