#!/usr/bin/env bash
# test-shrink-federation.sh - Deactivate registry-b and verify 3-member federation

source "$(cd "$(dirname "$0")" && pwd)/common.sh"

ALL_NODES=(node-a node-b node-c node-d node-e node-f)

echo "=== Shrinking Federation to 3 Members ==="
echo

# Deactivate registry-b in federation config
"$SCRIPTS_DIR/federation-deactivate.sh" registry-b .

# Tear down registry-b
garden cleanup namespace --env=registry-b

# Recompile and redeploy remaining active registries (a, c, d)
garden deploy --env=registry-a
garden deploy --env=registry-c
garden deploy --env=registry-d

# Wait for Raft leader election (3-member cluster)
wait_for_leader 60 registry-a registry-c registry-d

# Redeploy nodes so they pick up the new federation config
deploy_nodes "${ALL_NODES[@]}"
wait_for_gossip 120 "${ALL_NODES[@]}"

# Verify 3-member federation and gossip from test-client pod
kubectl exec -n kels-node-a -it test-client -- ./test-shrink-federation.sh
