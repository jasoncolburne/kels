#!/usr/bin/env bash
# test-creds.sh - Credential Management Integration Test Suite
# Tests credential issuance, storage, listing, display, and poisoning.
#
# This script must be run from the test-client pod in the node-a namespace.
#
# Usage: test-creds.sh

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

FEDERATED="${FEDERATED:-true}"

if [ "$FEDERATED" = "false" ]; then
    CLI="kels-cli --kels-url http://kels --sadstore-url http://sadstore"
else
    CLI="kels-cli -d node-a.kels"
fi

init_temp_dir

echo "========================================="
echo "Credential Management Test Suite"
echo "========================================="
echo ""

# Wait for services
echo "Waiting for services..."
wait_for_health "http://kels" "KELS" || exit 1
echo ""

# ================================================================
# Phase 1: Setup — Create a KEL for the issuer
# ================================================================

echo "========================================="
echo "Phase 1: Setup"
echo "========================================="

test_create_issuer_kel() {
    ISSUER_PREFIX=$($CLI kel incept --signing-algorithm ml-dsa-65 2>&1 | grep "Prefix:" | awk '{print $NF}')
    if [ -z "$ISSUER_PREFIX" ]; then
        echo "Failed to create issuer KEL"
        return 1
    fi
    echo "Issuer prefix: $ISSUER_PREFIX"
    echo "$ISSUER_PREFIX" > "$TEMP_DIR/issuer_prefix"
}

run_test "Create issuer KEL" test_create_issuer_kel

ISSUER_PREFIX=$(cat "$TEMP_DIR/issuer_prefix")
echo ""

# ================================================================
# Phase 2: Prepare schema and policy files
# ================================================================

echo "========================================="
echo "Phase 2: Prepare Schema & Policy"
echo "========================================="

# Build a self-addressed schema
test_create_schema() {
    # Schema must define all credential envelope fields + custom claims fields.
    # The "claims" field is compactable and its sub-fields define the actual payload.
    local schema_template
    schema_template=$(cat <<'SCHEMA'
{
    "said": "############################################",
    "name": "test/v1/greeting",
    "description": "A simple test credential schema",
    "version": "1.0.0",
    "fields": {
        "schema": { "type": "said" },
        "policy": { "type": "said" },
        "issuedAt": { "type": "datetime" },
        "claims": {
            "type": "object",
            "compactable": true,
            "fields": {
                "greeting": { "type": "string" },
                "target": { "type": "string", "optional": true }
            }
        },
        "subject": { "type": "prefix", "optional": true },
        "nonce": { "type": "string", "optional": true },
        "expiresAt": { "type": "datetime", "optional": true },
        "edges": { "type": "object", "compactable": true, "optional": true },
        "rules": { "type": "object", "compactable": true, "optional": true }
    }
}
SCHEMA
)
    # Compute SAID
    local said
    said=$(cesr_blake3 "$(echo "$schema_template" | jq -c '.')")
    echo "$schema_template" | jq --arg s "$said" '.said = $s' > "$TEMP_DIR/schema.json"
    echo "Schema SAID: $said"
    echo "$said" > "$TEMP_DIR/schema_said"
}

test_create_policy() {
    local policy_template
    policy_template=$(cat <<POLICY
{
    "said": "$PLACEHOLDER",
    "expression": "endorse($ISSUER_PREFIX)"
}
POLICY
)
    local said
    said=$(cesr_blake3 "$(echo "$policy_template" | jq -c '.')")
    echo "$policy_template" | jq --arg s "$said" '.said = $s' > "$TEMP_DIR/policy.json"
    echo "Policy SAID: $said"
    echo "$said" > "$TEMP_DIR/policy_said"
}

test_create_claims() {
    cat > "$TEMP_DIR/claims.json" <<'CLAIMS'
{
    "said": "############################################",
    "greeting": "Hello",
    "target": "World"
}
CLAIMS
    echo "Claims written to $TEMP_DIR/claims.json"
}

run_test "Create schema" test_create_schema
run_test "Create policy" test_create_policy
run_test "Create claims" test_create_claims

echo ""

# ================================================================
# Phase 3: Issue a credential
# ================================================================

echo "========================================="
echo "Phase 3: Issue Credential"
echo "========================================="

test_issue_credential() {
    OUTPUT=$($CLI cred issue \
        --prefix "$ISSUER_PREFIX" \
        --schema "$TEMP_DIR/schema.json" \
        --policy "$TEMP_DIR/policy.json" \
        --claims "$TEMP_DIR/claims.json" 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "Credential issued" || return 1

    # Extract the credential SAID (the expanded form, used for local storage)
    CRED_SAID=$(echo "$OUTPUT" | grep "Credential SAID:" | awk '{print $NF}')
    echo "$CRED_SAID" > "$TEMP_DIR/cred_said"
    echo "Credential SAID: $CRED_SAID"
}

test_issue_unique_credential() {
    OUTPUT=$($CLI cred issue \
        --prefix "$ISSUER_PREFIX" \
        --schema "$TEMP_DIR/schema.json" \
        --policy "$TEMP_DIR/policy.json" \
        --claims "$TEMP_DIR/claims.json" \
        --unique 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "Credential issued" || return 1

    UNIQUE_SAID=$(echo "$OUTPUT" | grep "Credential SAID:" | awk '{print $NF}')
    echo "$UNIQUE_SAID" > "$TEMP_DIR/unique_cred_said"

    # Unique credential should have a different SAID than the non-unique one
    CRED_SAID=$(cat "$TEMP_DIR/cred_said")
    if [ "$UNIQUE_SAID" = "$CRED_SAID" ]; then
        echo "ERROR: Unique credential has same SAID as non-unique"
        return 1
    fi
    echo "Unique credential SAID: $UNIQUE_SAID (differs from $CRED_SAID)"
}

run_test "Issue credential" test_issue_credential
run_test "Issue unique credential" test_issue_unique_credential

echo ""

# ================================================================
# Phase 4: List and show credentials
# ================================================================

echo "========================================="
echo "Phase 4: List & Show"
echo "========================================="

test_list_credentials() {
    OUTPUT=$($CLI cred list 2>&1)
    echo "$OUTPUT"
    # Should show at least 2 credentials
    echo "$OUTPUT" | grep -q "credential(s)" || return 1
}

test_show_credential() {
    CRED_SAID=$(cat "$TEMP_DIR/cred_said")
    if [ -z "$CRED_SAID" ]; then
        echo "No credential SAID available"
        return 1
    fi
    OUTPUT=$($CLI cred show "$CRED_SAID" 2>&1)
    echo "$OUTPUT"
    # Should contain the greeting claim
    echo "$OUTPUT" | grep -q "greeting" || echo "$OUTPUT" | grep -q "said" || return 1
}

test_show_nonexistent() {
    OUTPUT=$($CLI cred show "Knonexistent0000000000000000000000000000000000" 2>&1)
    echo "$OUTPUT"
    return 1
}

run_test "List credentials" test_list_credentials
run_test "Show credential" test_show_credential
run_test_expect_fail "Show nonexistent credential" test_show_nonexistent

echo ""

# ================================================================
# Phase 5: Store a credential from file
# ================================================================

echo "========================================="
echo "Phase 5: Store Credential"
echo "========================================="

test_store_credential() {
    CRED_SAID=$(cat "$TEMP_DIR/cred_said")
    # Export the credential to a file, then store it under a different flow
    OUTPUT=$($CLI cred show "$CRED_SAID" 2>&1)
    echo "$OUTPUT" > "$TEMP_DIR/exported_cred.json"

    # Store it (should succeed — idempotent)
    STORE_OUTPUT=$($CLI cred store \
        --file "$TEMP_DIR/exported_cred.json" \
        --schema "$TEMP_DIR/schema.json" 2>&1)
    echo "$STORE_OUTPUT"
    echo "$STORE_OUTPUT" | grep -q "Credential stored" || return 1
}

run_test "Store credential from file" test_store_credential

echo ""

# ================================================================
# Phase 6: Poison a credential
# ================================================================

echo "========================================="
echo "Phase 6: Poison Credential"
echo "========================================="

test_poison_credential() {
    UNIQUE_SAID=$(cat "$TEMP_DIR/unique_cred_said")
    OUTPUT=$($CLI cred poison \
        --prefix "$ISSUER_PREFIX" \
        --said "$UNIQUE_SAID" 2>&1)
    echo "$OUTPUT"
    echo "$OUTPUT" | grep -q "poisoned" || return 1
    echo "$OUTPUT" | grep -q "Poison hash:" || return 1
}

run_test "Poison credential" test_poison_credential

echo ""

# ================================================================
# Summary
# ================================================================

print_summary "Credential Management Tests"
exit $TESTS_FAILED
