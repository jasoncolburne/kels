#!/usr/bin/env bash
# test-grow-federation.sh - Deploy 4th registry and verify 4-member federation

source "$(cd "$(dirname "$0")" && pwd)/common.sh"

echo "=== Growing Federation to 4 Members ==="
echo

# Deploy 4th registry standalone (generates identity)
garden deploy identity --env=registry-d

# Fetch its prefix (auto-assigns id=3)
garden run federation-fetch --env=registry-d

# Recompile and redeploy ALL 4 registries with updated trust anchors
garden deploy --env=registry-a
garden deploy --env=registry-b
garden deploy --env=registry-c
garden deploy --env=registry-d

# Wait for Raft leader election
wait_for_leader 60 registry-a registry-b registry-c registry-d

# Verify 4-member federation from test-client pod
kubectl exec -n kels-node-a -it test-client -- ./test-grow-federation.sh
