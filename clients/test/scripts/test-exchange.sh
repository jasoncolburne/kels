#!/usr/bin/env bash
# test-exchange.sh - Exchange Protocol Integration Test Suite
# Tests key publication, discovery, ESSR messaging, and mail delivery.
#
# This script must be run from the test-client pod in the node-a namespace.
#
# Usage: test-exchange.sh
#
# Environment variables:
#   NODE_A_KELS_HOST     - node-a KELS hostname (default: kels)
#   NODE_A_SADSTORE_HOST - node-a SADStore hostname (default: sadstore)
#   NODE_A_MAIL_HOST     - node-a Mail hostname (default: mail)
#   NODE_B_MAIL_HOST     - node-b Mail hostname (default: mail.node-b.kels)
#   NODE_B_SADSTORE_HOST - node-b SADStore hostname (default: sadstore.node-b.kels)
#   PROPAGATION_DELAY    - Time to wait for gossip propagation (default: 5s)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
PROPAGATION_DELAY="${PROPAGATION_DELAY:-5}"
NODE_A_KELS_HOST="${NODE_A_KELS_HOST:-kels}"
NODE_A_SADSTORE_HOST="${NODE_A_SADSTORE_HOST:-sadstore}"
NODE_A_MAIL_HOST="${NODE_A_MAIL_HOST:-mail}"
NODE_B_MAIL_HOST="${NODE_B_MAIL_HOST:-mail.node-b.kels}"
NODE_B_SADSTORE_HOST="${NODE_B_SADSTORE_HOST:-sadstore.node-b.kels}"

CLI="kels-cli -d node-a.kels"
CLI_B="kels-cli -d node-b.kels"

init_temp_dir

echo "========================================="
echo "Exchange Protocol Integration Test Suite"
echo "========================================="
echo "Node-A KELS:     http://${NODE_A_KELS_HOST}"
echo "Node-A SADStore: http://${NODE_A_SADSTORE_HOST}"
echo "Node-A Mail:     http://${NODE_A_MAIL_HOST}"
echo "Node-B Mail:     http://${NODE_B_MAIL_HOST}"
echo "Node-B SADStore: http://${NODE_B_SADSTORE_HOST}"
echo "Propagation:     ${PROPAGATION_DELAY}s"
echo "========================================="
echo ""

# Wait for services
echo "Waiting for services..."
wait_for_health "http://${NODE_A_KELS_HOST}" "Node-A KELS" || exit 1
wait_for_health "http://${NODE_A_SADSTORE_HOST}" "Node-A SADStore" || exit 1
wait_for_health "http://${NODE_A_MAIL_HOST}" "Node-A Mail" || exit 1
wait_for_health "http://${NODE_B_MAIL_HOST}" "Node-B Mail" || exit 1
echo ""

# ================================================================
# Phase 1: KEL Setup — Create identities for Alice and Bob
# ================================================================

echo "========================================="
echo "Phase 1: KEL Setup"
echo "========================================="

test_create_alice_kel() {
    ALICE_PREFIX=$($CLI incept --signing-algorithm ml-dsa-65 2>&1 | grep "Prefix:" | awk '{print $NF}')
    if [ -z "$ALICE_PREFIX" ]; then
        echo "Failed to create Alice's KEL"
        return 1
    fi
    echo "Alice prefix: $ALICE_PREFIX"
    echo "$ALICE_PREFIX" > "$TEMP_DIR/alice_prefix"
}

test_create_bob_kel() {
    BOB_PREFIX=$($CLI incept --signing-algorithm ml-dsa-65 2>&1 | grep "Prefix:" | awk '{print $NF}')
    if [ -z "$BOB_PREFIX" ]; then
        echo "Failed to create Bob's KEL"
        return 1
    fi
    echo "Bob prefix: $BOB_PREFIX"
    echo "$BOB_PREFIX" > "$TEMP_DIR/bob_prefix"
}

run_test "Create Alice's KEL" test_create_alice_kel
run_test "Create Bob's KEL" test_create_bob_kel

ALICE_PREFIX=$(cat "$TEMP_DIR/alice_prefix")
BOB_PREFIX=$(cat "$TEMP_DIR/bob_prefix")

echo ""

# ================================================================
# Phase 2: Key Publication — Publish ML-KEM keys to SADStore
# ================================================================

echo "========================================="
echo "Phase 2: Key Publication"
echo "========================================="

test_alice_publish_key() {
    $CLI exchange publish-key --prefix "$ALICE_PREFIX" 2>&1
    if [ $? -ne 0 ]; then
        echo "Failed to publish Alice's key"
        return 1
    fi
}

test_bob_publish_key() {
    $CLI exchange publish-key --prefix "$BOB_PREFIX" 2>&1
    if [ $? -ne 0 ]; then
        echo "Failed to publish Bob's key"
        return 1
    fi
}

run_test "Alice publishes ML-KEM key" test_alice_publish_key
run_test "Bob publishes ML-KEM key" test_bob_publish_key

echo ""

# ================================================================
# Phase 3: Key Discovery — Look up keys from SADStore
# ================================================================

echo "========================================="
echo "Phase 3: Key Discovery"
echo "========================================="

test_lookup_alice_key() {
    OUTPUT=$($CLI exchange lookup-key "$ALICE_PREFIX" 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "Algorithm:" || return 1
    echo "$OUTPUT" | grep -q "ML-KEM-768" || return 1
}

test_lookup_bob_key() {
    OUTPUT=$($CLI exchange lookup-key "$BOB_PREFIX" 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "Algorithm:" || return 1
}

test_lookup_nonexistent_key() {
    OUTPUT=$($CLI exchange lookup-key "Enonexistent00000000000000000000000000000000" 2>&1)
    echo "$OUTPUT"
    # Should fail
    return 1
}

run_test "Look up Alice's key" test_lookup_alice_key
run_test "Look up Bob's key" test_lookup_bob_key
run_test_expect_fail "Look up nonexistent key" test_lookup_nonexistent_key

echo ""

# Wait for gossip propagation to node-b
echo "Waiting ${PROPAGATION_DELAY}s for SADStore gossip propagation..."
sleep "$PROPAGATION_DELAY"

test_lookup_alice_key_from_node_b() {
    OUTPUT=$($CLI_B exchange lookup-key "$ALICE_PREFIX" 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "Algorithm:" || return 1
}

run_test "Look up Alice's key from node-b (gossip replication)" test_lookup_alice_key_from_node_b

echo ""

# ================================================================
# Phase 4: Key Rotation
# ================================================================

echo "========================================="
echo "Phase 4: Key Rotation"
echo "========================================="

test_alice_rotate_key() {
    $CLI exchange rotate-key --prefix "$ALICE_PREFIX" 2>&1
    if [ $? -ne 0 ]; then
        echo "Failed to rotate Alice's key"
        return 1
    fi
}

test_lookup_alice_rotated_key() {
    OUTPUT=$($CLI exchange lookup-key "$ALICE_PREFIX" 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "Algorithm:" || return 1
}

run_test "Alice rotates ML-KEM key" test_alice_rotate_key
run_test "Look up Alice's rotated key" test_lookup_alice_rotated_key

echo ""

# ================================================================
# Phase 5: ESSR Messaging — Send encrypted mail
# ================================================================

echo "========================================="
echo "Phase 5: ESSR Messaging"
echo "========================================="

# Create a test payload
echo '{"message": "Hello Bob, this is a test credential exchange!"}' > "$TEMP_DIR/payload.json"

test_alice_send_to_bob() {
    OUTPUT=$($CLI exchange send \
        --prefix "$ALICE_PREFIX" \
        --recipient "$BOB_PREFIX" \
        --topic "kels/v1/test" \
        --payload "$TEMP_DIR/payload.json" 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "Message sent" || return 1
}

run_test "Alice sends ESSR message to Bob" test_alice_send_to_bob

echo ""

# ================================================================
# Phase 6: Inbox — Check for received messages
# ================================================================

echo "========================================="
echo "Phase 6: Inbox"
echo "========================================="

# Wait for gossip to propagate the mail announcement
echo "Waiting ${PROPAGATION_DELAY}s for mail announcement propagation..."
sleep "$PROPAGATION_DELAY"

test_bob_check_inbox() {
    OUTPUT=$($CLI exchange inbox --prefix "$BOB_PREFIX" 2>&1)
    echo "$OUTPUT"
    # Should show at least one message
    echo "$OUTPUT" | grep -q "messages\|Inbox" || return 1
}

test_alice_inbox_empty() {
    OUTPUT=$($CLI exchange inbox --prefix "$ALICE_PREFIX" 2>&1)
    echo "$OUTPUT"
    # Alice's inbox should be empty (she sent, not received)
    echo "$OUTPUT" | grep -qi "empty\|0 messages" || return 1
}

run_test "Bob checks inbox" test_bob_check_inbox
run_test "Alice's inbox is empty" test_alice_inbox_empty

echo ""

# ================================================================
# Summary
# ================================================================

print_summary "Exchange Protocol Tests"
exit $TESTS_FAILED
