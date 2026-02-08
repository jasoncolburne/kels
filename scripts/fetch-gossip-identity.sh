#!/usr/bin/env bash
set -e

ENV_NAMESPACE="$1"

if [ -z "$ENV_NAMESPACE" ]; then
    echo "Usage: fetch-gossip-identity.sh <env-namespace>" >&2
    exit 1
fi

PEER_ID=$(kubectl logs -n "$ENV_NAMESPACE" deploy/kels-gossip -c kels-gossip 2>/dev/null | rg "Local PeerId: " | jq -r '.fields.message // empty' | cut -f 3 -d ' ')
if [ -z "$PEER_ID" ]; then
    echo "Error: Could not fetch PeerId from kels-gossip logs" >&2
    exit 1
fi
echo -n "$PEER_ID"
