#!/usr/bin/env bash
set -e

ENV_NAMESPACE="$1"

if [ -z "$ENV_NAMESPACE" ]; then
    echo "Usage: fetch-gossip-identity.sh <env-namespace>" >&2
    exit 1
fi

PEER_PREFIX=$(kubectl logs -n "$ENV_NAMESPACE" deploy/kels-gossip -c kels-gossip 2>/dev/null | grep "Local PeerPrefix:" | jq -r '.fields.message // empty' | awk '{print $NF}')
if [ -z "$PEER_PREFIX" ]; then
    echo "Error: Could not fetch PeerPrefix from kels-gossip logs" >&2
    exit 1
fi
echo -n "$PEER_PREFIX"
