#!/usr/bin/env bash
# vote-nodes.sh - Propose and approve peers for a list of nodes
#
# Usage: vote-nodes.sh <registries> -- <nodes>
#   e.g. vote-nodes.sh registry-a registry-b registry-c -- node-a node-b node-c

source "$(cd "$(dirname "$0")" && pwd)/common.sh"

REGISTRIES=()
NODES=()
parsing_nodes=false

for arg in "$@"; do
    if [ "$arg" = "--" ]; then
        parsing_nodes=true
        continue
    fi
    if $parsing_nodes; then
        NODES+=("$arg")
    else
        REGISTRIES+=("$arg")
    fi
done

if [ ${#REGISTRIES[@]} -eq 0 ] || [ ${#NODES[@]} -eq 0 ]; then
    echo "Usage: vote-nodes.sh <registry1> [registry2...] -- <node1> [node2...]"
    exit 1
fi

for node in "${NODES[@]}"; do
    echo "=== Proposing and voting: $node ==="
    PROPOSAL=$(propose_add "$node")
    echo "  Proposal: $PROPOSAL"
    vote_all "$PROPOSAL" "${REGISTRIES[@]}"
    echo
done
