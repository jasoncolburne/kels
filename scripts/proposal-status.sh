#!/usr/bin/env bash
set -e

PROPOSAL_PREFIX="$1"
REGISTRY_NS="${2:-}"  # Optional: specific registry to query

if [ -z "$PROPOSAL_PREFIX" ]; then
    echo "Usage: proposal-status.sh <proposal-prefix> [registry-namespace]"
    echo "  Gets the status of a peer proposal."
    echo "  If registry-namespace is not specified, uses registry-a."
    exit 1
fi

if [ -z "$REGISTRY_NS" ]; then
    REGISTRY_NS="registry-a"
fi

echo "Querying proposal $PROPOSAL_PREFIX from $REGISTRY_NS..." >&2

STATUS_OUTPUT=$(kubectl exec -n "kels-$REGISTRY_NS" deploy/registry -c registry -- \
    /app/registry-admin peer proposal-status \
    --proposal-prefix "$PROPOSAL_PREFIX" 2>&1)

echo "$STATUS_OUTPUT"
