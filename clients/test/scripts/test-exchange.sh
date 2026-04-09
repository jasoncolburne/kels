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
#   CONVERGENCE_TIMEOUT  - Timeout for gossip propagation polling (default: 30s)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
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
echo "Convergence:     ${CONVERGENCE_TIMEOUT}s"
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
    OUTPUT=$($CLI exchange lookup-key "Knonexistent00000000000000000000000000000000" 2>&1)
    echo "$OUTPUT"
    # Should fail
    return 1
}

run_test "Look up Alice's key" test_lookup_alice_key
run_test "Look up Bob's key" test_lookup_bob_key
run_test_expect_fail "Look up nonexistent key" test_lookup_nonexistent_key

echo ""

CONVERGENCE_TIMEOUT="${CONVERGENCE_TIMEOUT:-30}"

test_lookup_alice_key_from_node_b() {
    local deadline=$((SECONDS + CONVERGENCE_TIMEOUT))
    while [ $SECONDS -lt $deadline ]; do
        OUTPUT=$($CLI_B exchange lookup-key "$ALICE_PREFIX" 2>&1)
        if echo "$OUTPUT" | grep -q "Algorithm:"; then
            echo "$OUTPUT"
            return 0
        fi
        sleep 2
    done
    echo "$OUTPUT"
    echo "Timeout waiting for Alice's key to propagate to node-b (${CONVERGENCE_TIMEOUT}s)"
    return 1
}

run_test "Look up Alice's key from node-b (gossip replication)" test_lookup_alice_key_from_node_b

echo ""

# ================================================================
# Phase 4: Key Rotation
# ================================================================

echo "========================================="
echo "Phase 4: Key Rotation"
echo "========================================="

test_alice_rotate_kem_key() {
    $CLI exchange rotate-key --prefix "$ALICE_PREFIX" 2>&1
    if [ $? -ne 0 ]; then
        echo "Failed to rotate Alice's KEM key"
        return 1
    fi
}

test_lookup_alice_rotated_key() {
    OUTPUT=$($CLI exchange lookup-key "$ALICE_PREFIX" 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "Algorithm:" || return 1
}

run_test "Alice rotates KEM key" test_alice_rotate_kem_key
run_test "Look up Alice's rotated key" test_lookup_alice_rotated_key

echo ""

# ================================================================
# Phase 4b: Key Operations After Signing Key Rotation
# ================================================================

echo "========================================="
echo "Phase 4b: KEM Key Ops After Signing Key Rotation"
echo "========================================="

test_alice_rotate_signing_key() {
    OUTPUT=$($CLI rotate --prefix "$ALICE_PREFIX" 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "Rotation successful\|rotated" || return 1
}

test_alice_rotate_kem_after_signing_rotation() {
    $CLI exchange rotate-key --prefix "$ALICE_PREFIX" 2>&1
    if [ $? -ne 0 ]; then
        echo "Failed to rotate Alice's KEM key after signing key rotation"
        return 1
    fi
}

test_lookup_alice_key_after_rotations() {
    OUTPUT=$($CLI exchange lookup-key "$ALICE_PREFIX" 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "Algorithm:" || return 1
}

test_bob_rotate_signing_key() {
    OUTPUT=$($CLI rotate --prefix "$BOB_PREFIX" 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "Rotation successful\|rotated" || return 1
}

test_bob_publish_key_after_signing_rotation() {
    # Bob deletes his KEM chain and re-publishes after signing key rotation
    $CLI exchange rotate-key --prefix "$BOB_PREFIX" 2>&1
    if [ $? -ne 0 ]; then
        echo "Failed to rotate Bob's KEM key after signing key rotation"
        return 1
    fi
}

run_test "Alice rotates signing key" test_alice_rotate_signing_key
run_test "Alice rotates KEM key after signing rotation" test_alice_rotate_kem_after_signing_rotation
run_test "Look up Alice's key after both rotations" test_lookup_alice_key_after_rotations
run_test "Bob rotates signing key" test_bob_rotate_signing_key
run_test "Bob rotates KEM key after signing rotation" test_bob_publish_key_after_signing_rotation

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
        --topic "kels/exchange/v1/topics/test" \
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

test_bob_check_inbox() {
    local deadline=$((SECONDS + CONVERGENCE_TIMEOUT))
    while [ $SECONDS -lt $deadline ]; do
        OUTPUT=$($CLI exchange inbox --prefix "$BOB_PREFIX" 2>&1)
        if echo "$OUTPUT" | grep -q "messages):"; then
            echo "$OUTPUT"
            return 0
        fi
        sleep 2
    done
    echo "$OUTPUT"
    echo "Timeout waiting for Bob's inbox to have messages (${CONVERGENCE_TIMEOUT}s)"
    return 1
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
# Phase 7: Cross-Node Mail Gossip — Send on node-a, receive on node-b
# ================================================================

echo "========================================="
echo "Phase 7: Cross-Node Mail Gossip"
echo "========================================="

test_alice_send_cross_node() {
    OUTPUT=$($CLI exchange send \
        --prefix "$ALICE_PREFIX" \
        --recipient "$BOB_PREFIX" \
        --topic "kels/exchange/v1/topics/cross-node-test" \
        --payload "$TEMP_DIR/payload.json" 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "Message sent" || return 1
}

test_bob_inbox_on_node_b() {
    local deadline=$((SECONDS + CONVERGENCE_TIMEOUT))
    while [ $SECONDS -lt $deadline ]; do
        OUTPUT=$($CLI_B exchange inbox --prefix "$BOB_PREFIX" 2>&1)
        if echo "$OUTPUT" | grep -q "messages):"; then
            echo "$OUTPUT"
            return 0
        fi
        sleep 2
    done
    echo "$OUTPUT"
    echo "Timeout waiting for Bob's inbox on node-b (${CONVERGENCE_TIMEOUT}s)"
    return 1
}

run_test "Alice sends cross-node message to Bob" test_alice_send_cross_node
run_test "Bob sees message on node-b (gossip replication)" test_bob_inbox_on_node_b

echo ""

# ================================================================
# Phase 8: Fetch & Decrypt — Verify payload roundtrip
# ================================================================

echo "========================================="
echo "Phase 8: Fetch & Decrypt"
echo "========================================="

test_bob_fetch_and_verify() {
    # Get the first message SAID from Bob's inbox
    INBOX_OUTPUT=$($CLI exchange inbox --prefix "$BOB_PREFIX" 2>&1)
    MAIL_SAID=$(echo "$INBOX_OUTPUT" | grep '|' | head -1 | awk '{print $1}')
    if [ -z "$MAIL_SAID" ]; then
        echo "No message SAID found in inbox"
        echo "$INBOX_OUTPUT"
        return 1
    fi
    echo "Fetching message: $MAIL_SAID"
    echo "$MAIL_SAID" > "$TEMP_DIR/mail_said"

    # Fetch and decrypt
    PAYLOAD=$($CLI exchange fetch --prefix "$BOB_PREFIX" --said "$MAIL_SAID" 2>&1)
    FETCH_EXIT=$?
    echo "$PAYLOAD"
    if [ $FETCH_EXIT -ne 0 ]; then
        echo "Fetch failed"
        return 1
    fi

    # Verify the decrypted payload matches what Alice sent
    ORIGINAL=$(cat "$TEMP_DIR/payload.json")
    # The payload output includes status lines before the actual payload on stdout
    # The last line should be the JSON payload
    DECRYPTED=$(echo "$PAYLOAD" | tail -1)
    if [ "$DECRYPTED" = "$ORIGINAL" ]; then
        echo "Payload matches!"
        return 0
    else
        echo "MISMATCH!"
        echo "  Original:  $ORIGINAL"
        echo "  Decrypted: $DECRYPTED"
        return 1
    fi
}

run_test "Bob fetches and decrypts message (payload roundtrip)" test_bob_fetch_and_verify

echo ""

# ================================================================
# Phase 9: Acknowledge & Verify Deletion
# ================================================================

echo "========================================="
echo "Phase 9: Acknowledge & Verify Deletion"
echo "========================================="

test_bob_ack_message() {
    MAIL_SAID=$(cat "$TEMP_DIR/mail_said")
    OUTPUT=$($CLI exchange ack --prefix "$BOB_PREFIX" --saids "$MAIL_SAID" 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "acknowledged" || return 1
}

test_bob_inbox_message_removed() {
    MAIL_SAID=$(cat "$TEMP_DIR/mail_said")
    local deadline=$((SECONDS + CONVERGENCE_TIMEOUT))
    while [ $SECONDS -lt $deadline ]; do
        OUTPUT=$($CLI exchange inbox --prefix "$BOB_PREFIX" 2>&1)
        # Check that the acked message is no longer in the inbox
        if ! echo "$OUTPUT" | grep -q "$MAIL_SAID"; then
            echo "$OUTPUT"
            echo "Message $MAIL_SAID removed from inbox"
            return 0
        fi
        sleep 2
    done
    echo "$OUTPUT"
    echo "Timeout waiting for message removal (${CONVERGENCE_TIMEOUT}s)"
    return 1
}

run_test "Bob acknowledges message" test_bob_ack_message
run_test "Message removed from Bob's inbox" test_bob_inbox_message_removed

echo ""

# ================================================================
# Summary
# ================================================================

print_summary "Exchange Protocol Tests"
exit $TESTS_FAILED
