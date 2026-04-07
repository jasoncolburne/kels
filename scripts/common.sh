#!/usr/bin/env bash
# common.sh - Shared utilities for host-side orchestration scripts
#
# Source this at the top of scripts:
#   source "$(cd "$(dirname "$0")" && pwd)/common.sh"

set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Proposal helpers ---

propose_add() {
    "$SCRIPTS_DIR/propose-add-peer.sh" "$1"
}

propose_remove() {
    "$SCRIPTS_DIR/propose-remove-peer.sh" "$1"
}

vote() {
    "$SCRIPTS_DIR/vote-peer.sh" "$1" "$2" "${3:-true}"
}

vote_all() {
    local proposal="$1"; shift
    for reg in "$@"; do
        vote "$proposal" "$reg"
    done
}

# --- Deployment helpers ---

# Deploy nodes by name.
# Usage: deploy_nodes node-a node-b node-c
deploy_nodes() {
    for node in "$@"; do
        garden deploy --env="$node"
    done
}

# Restart gossip on a single node and wait for rollout.
restart_gossip() {
    local node="$1"
    echo "Restarting gossip on ${node}..."
    kubectl rollout restart deployment/gossip -n "kels-${node}"
    kubectl rollout status deployment/gossip -n "kels-${node}"
}

# Wait for all given nodes' gossip services to report ready.
# Usage: wait_for_gossip 120 node-a node-b node-c
wait_for_gossip() {
    local timeout="$1"; shift
    local nodes=("$@")
    echo "Waiting for gossip nodes to be ready (timeout: ${timeout}s)..."

    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        local all_ready=true
        for node in "${nodes[@]}"; do
            status=$(kubectl exec -n kels-node-a test-client -- \
                curl -s -o /dev/null -w "%{http_code}" "http://gossip.${node}.kels/ready" 2>/dev/null) || true
            if [ "$status" != "200" ]; then
                all_ready=false
                break
            fi
        done
        if $all_ready; then
            echo "All gossip nodes ready"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    echo "Timeout waiting for gossip nodes after ${timeout}s" >&2
    return 1
}

# --- Leader election ---

# Wait for a Raft leader across the given registries.
# Usage: wait_for_leader 60 registry-a registry-c registry-d
wait_for_leader() {
    local timeout="$1"; shift
    local registries=("$@")

    for i in $(seq 1 "$timeout"); do
        for reg in "${registries[@]}"; do
            leader=$(kubectl exec -n kels-node-a test-client -- \
                curl -sf "http://registry.${reg}.kels/api/v1/federation/status" 2>/dev/null \
                | jq -r '.isLeader // false') || true
            if [ "$leader" = "true" ]; then
                echo "Leader elected on ${reg} after ${i}s"
                return 0
            fi
        done
        sleep 1
    done

    echo "Timeout waiting for leader election after ${timeout}s" >&2
    return 1
}
