#!/usr/bin/env bash
# test-peer-lifecycle.sh - Remove a peer via voting, verify gossip blackout, re-add it
#
# Usage: test-peer-lifecycle.sh <node> <registry1> <registry2> [registry3...]
#   e.g. test-peer-lifecycle.sh node-f registry-a registry-c registry-d

source "$(cd "$(dirname "$0")" && pwd)/common.sh"

NODE="$1"; shift
REGISTRIES=("$@")

if [ ${#REGISTRIES[@]} -lt 2 ]; then
    echo "Usage: test-peer-lifecycle.sh <node> <registry1> <registry2> [registry3...]"
    echo "  Need at least 2 registries for voting quorum."
    exit 1
fi

echo "=== Peer Lifecycle Test ==="
echo "  Node: $NODE"
echo "  Registries: ${REGISTRIES[*]}"
echo

# --- Phase 1: Remove peer ---
echo "--- Phase 1: Remove $NODE ---"
PROPOSAL=$(propose_remove "$NODE")
echo "Removal proposal: $PROPOSAL"
vote_all "$PROPOSAL" "${REGISTRIES[@]}"
restart_gossip "$NODE"
echo

# --- Phase 2: Verify blackout ---
echo "--- Phase 2: Verify gossip blackout ---"
kubectl exec -n kels-node-a -it test-client -- ./test-peer-blackout.sh "$NODE"
echo

# --- Phase 3: Re-add peer ---
echo "--- Phase 3: Re-add $NODE ---"
PROPOSAL=$(propose_add "$NODE")
echo "Addition proposal: $PROPOSAL"
vote_all "$PROPOSAL" "${REGISTRIES[@]}"
restart_gossip "$NODE"

echo
echo "=== Peer Lifecycle Test Complete ==="
echo "  $NODE removed, blackout verified, re-added."
echo "  Run consistency tests to verify full recovery."
