#!/usr/bin/env bash
# restart-gossip.sh - Restart gossip on specified nodes (fast parallel rollout)
#
# Usage: restart-gossip.sh node-a node-b node-c ...
#        restart-gossip.sh   (no args = all 6 nodes)

source "$(cd "$(dirname "$0")" && pwd)/common.sh"

NODES=("$@")
if [ ${#NODES[@]} -eq 0 ]; then
    NODES=(node-a node-b node-c node-d node-e node-f)
fi

for node in "${NODES[@]}"; do
    echo "Restarting gossip on ${node}..."
    kubectl rollout restart deployment/gossip -n "kels-${node}"
done

for node in "${NODES[@]}"; do
    echo "Waiting for ${node}..."
    kubectl rollout status deployment/gossip -n "kels-${node}"
done
