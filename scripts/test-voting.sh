#!/usr/bin/env bash
# test-voting.sh - Comprehensive voting protocol tests
#
# Tests propose, withdraw, reject, re-propose, vote-then-withdraw-fails,
# approve, and removal flows. Uses node-a as the test subject and
# registries a, b, c for voting.
#
# Assumes registries a, b, c are deployed and a leader is elected.
# Deploys node-a at the start, cleans it up at the end.

source "$(cd "$(dirname "$0")" && pwd)/common.sh"

echo "=== Voting Protocol Tests ==="
echo

# Deploy test node
garden deploy --env=node-a

# Wait for Raft leader election
wait_for_leader 60 registry-a registry-b registry-c

# --- Test 1: Propose, then verify API access ---
echo "--- Test 1: Propose + API access ---"
PROPOSAL=$(propose_add node-a)
echo "Proposal: $PROPOSAL"

# 1a: POST fetch to proposals endpoint should succeed
kubectl exec -n kels-node-a test-client -- \
    curl -sf -X POST -H 'Content-Type: application/json' \
    -d "{\"prefix\":\"$PROPOSAL\"}" \
    "http://registry.registry-a.kels/api/v1/federation/proposals/fetch"

# 1c: proposal-status via admin CLI
"$SCRIPTS_DIR/proposal-status.sh" "$PROPOSAL" registry-a

echo

# --- Test 2: Duplicate proposal should fail ---
echo "--- Test 2: Duplicate proposal ---"
! propose_add node-a 2>&1

echo

# --- Test 3: Withdraw (no votes) should succeed ---
echo "--- Test 3: Withdraw ---"
"$SCRIPTS_DIR/withdraw-peer.sh" "$PROPOSAL" registry-a

# Re-propose after withdrawal
PROPOSAL=$(propose_add node-a)
echo "Re-proposed: $PROPOSAL"

echo

# --- Test 4: Two rejections kill the proposal ---
echo "--- Test 4: Rejection threshold ---"
vote "$PROPOSAL" registry-a false
vote "$PROPOSAL" registry-b false
! vote "$PROPOSAL" registry-c true

# Re-propose after rejection
PROPOSAL=$(propose_add node-a)
echo "Re-proposed: $PROPOSAL"

echo

# --- Test 5: Vote then withdraw should fail ---
echo "--- Test 5: Withdraw after vote ---"
vote "$PROPOSAL" registry-a
! "$SCRIPTS_DIR/withdraw-peer.sh" "$PROPOSAL" registry-a

echo

# --- Continue voting to approve ---
echo "--- Approving node-a ---"
vote "$PROPOSAL" registry-b
vote "$PROPOSAL" registry-c
restart_gossip node-a

echo

# --- Remove node-a ---
echo "--- Removing node-a ---"
REMOVAL=$(propose_remove node-a)
echo "Removal proposal: $REMOVAL"
vote_all "$REMOVAL" registry-a registry-b registry-c

echo

# Clean up
garden cleanup namespace --env node-a

echo "=== Voting Protocol Tests Complete ==="
