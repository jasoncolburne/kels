#!/usr/bin/env bash
# test-sadstore.sh - SADStore Integration Test Suite
# Tests SAD object storage, chain operations, gossip replication,
# and deterministic conflict resolution across nodes.
#
# This script must be run from the test-client pod in the node-a namespace.
#
# Usage: test-sadstore.sh
#
# Environment variables:
#   NODE_A_SADSTORE_HOST - node-a SADStore hostname (default: sadstore)
#   NODE_B_SADSTORE_HOST - node-b SADStore hostname (default: sadstore.node-b.kels)
#   NODE_A_KELS_HOST     - node-a KELS hostname (default: kels)
#   PROPAGATION_DELAY    - Time to wait for gossip propagation (default: 5s)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
PROPAGATION_DELAY="${PROPAGATION_DELAY:-5}"
CONVERGENCE_TIMEOUT="${CONVERGENCE_TIMEOUT:-30}"
NODE_A_SADSTORE_HOST="${NODE_A_SADSTORE_HOST:-sadstore}"
NODE_B_SADSTORE_HOST="${NODE_B_SADSTORE_HOST:-sadstore.node-b.kels}"
NODE_A_KELS_HOST="${NODE_A_KELS_HOST:-kels}"
# Dummy CESR values for test endpoints that skip auth but still deserialize
MOCK_SAID="KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
MOCK_PREFIX="KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
MOCK_SIGNATURE="0CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
MOCK_CREATED_AT="2026-01-01T00:00:00.000000Z"
MOCK_NONCE="NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

NODE_A_SAD_URL="http://${NODE_A_SADSTORE_HOST}"
NODE_B_SAD_URL="http://${NODE_B_SADSTORE_HOST}"
NODE_A_KELS_URL="http://${NODE_A_KELS_HOST}"

init_temp_dir

echo "========================================="
echo "SADStore Integration Test Suite"
echo "========================================="
echo "Node-A SADStore: $NODE_A_SAD_URL"
echo "Node-B SADStore: $NODE_B_SAD_URL"
echo "Node-A KELS:     $NODE_A_KELS_URL"
echo "Propagation:     ${PROPAGATION_DELAY}s"
echo "========================================="
echo ""

# Wait for services
echo "Waiting for services..."
wait_for_health "$NODE_A_SAD_URL" "Node-A SADStore" || exit 1
wait_for_health "$NODE_B_SAD_URL" "Node-B SADStore" || exit 1
wait_for_health "$NODE_A_KELS_URL" "Node-A KELS" || exit 1
echo ""

# === Constants ===

PLACEHOLDER="############################################"

# === Helper functions ===

# Compute a CESR Blake3 SAID from a string argument.
cesr_blake3() {
    local data="$1"
    local padded
    padded=$(echo "00$(printf '%s' "$data" | b3sum --no-names)" | xxd -r -p | base64 | tr '/' '_' | tr '+' '-')
    echo "K${padded:(-43)}"
}

# Compute a SAID for a JSON object (blanks "said" field, hashes).
compute_said() {
    local json="$1"
    local with_placeholder
    with_placeholder=$(echo "$json" | jq -c --arg p "$PLACEHOLDER" '.said = $p')
    cesr_blake3 "$with_placeholder"
}

# Compute prefix for a v0 inception pointer (blanks both said AND prefix).
compute_prefix() {
    local json="$1"
    local with_placeholders
    with_placeholders=$(echo "$json" | jq -c --arg p "$PLACEHOLDER" '.said = $p | .prefix = $p')
    cesr_blake3 "$with_placeholders"
}

sad_object_exists() {
    local url="$1"
    local said="$2"
    [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "{\"said\":\"${said}\"}" "${url}/api/v1/sad/fetch")" = "200" ]
}

sad_chain_exists() {
    local url="$1"
    local prefix="$2"
    [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${prefix}\"}" "${url}/api/v1/sad/pointers/fetch")" = "200" ]
}

get_chain_tip_said() {
    local url="$1"
    local prefix="$2"
    curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${prefix}\"}" "${url}/api/v1/sad/pointers/fetch" | jq -r '.pointers[-1].pointer.said // empty'
}

get_effective_said() {
    local url="$1"
    local prefix="$2"
    curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${prefix}\"}" "${url}/api/v1/sad/pointers/effective-said" | jq -r '.said // empty'
}

get_chain_length() {
    local url="$1"
    local prefix="$2"
    curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${prefix}\"}" "${url}/api/v1/sad/pointers/fetch" | jq '.pointers | length'
}

wait_for_sad_object_propagation() {
    local said="$1"
    local timeout="$2"
    local url="$3"
    local deadline=$((SECONDS + timeout))
    while [ $SECONDS -lt $deadline ]; do
        if sad_object_exists "$url" "$said"; then
            return 0
        fi
        sleep 1
    done
    echo "Timeout waiting for SAD object $said to propagate to $url"
    return 1
}

wait_for_chain_propagation() {
    local prefix="$1"
    local expected_tip="$2"
    local timeout="$3"
    local url="$4"
    local deadline=$((SECONDS + timeout))
    while [ $SECONDS -lt $deadline ]; do
        local tip
        tip=$(get_chain_tip_said "$url" "$prefix")
        if [ "$tip" = "$expected_tip" ]; then
            return 0
        fi
        sleep 1
    done
    echo "Timeout waiting for chain $prefix tip $expected_tip on $url"
    return 1
}

wait_for_divergence_convergence() {
    local prefix="$1"
    local timeout="$2"
    local url_a="$3"
    local url_b="$4"
    local deadline=$((SECONDS + timeout))
    while [ $SECONDS -lt $deadline ]; do
        local a_div b_div a_eff b_eff
        a_div=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${prefix}\"}" "${url_a}/api/v1/sad/pointers/effective-said" | jq -r '.divergent // false')
        b_div=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${prefix}\"}" "${url_b}/api/v1/sad/pointers/effective-said" | jq -r '.divergent // false')
        a_eff=$(get_effective_said "$url_a" "$prefix")
        b_eff=$(get_effective_said "$url_b" "$prefix")
        if [ "$a_div" = "true" ] && [ "$b_div" = "true" ] && [ "$a_eff" = "$b_eff" ]; then
            return 0
        fi
        sleep 1
    done
    echo "Timeout waiting for divergence convergence on $prefix"
    return 1
}

# ========================================
# Scenario 1: SAD Object CRUD
# ========================================
echo -e "${CYAN}=== Scenario 1: SAD Object CRUD ===${NC}"
echo ""

# PUT with invalid JSON
run_test "POST invalid JSON rejected" \
    bash -c "[ \$(curl -s -o /dev/null -w '%{http_code}' -X POST '${NODE_A_SAD_URL}/api/v1/sad' -H 'Content-Type: application/json' -d 'not json') = '400' ]"

# POST with mismatched SAID
run_test "POST mismatched SAID rejected" \
    bash -c "[ \$(curl -s -o /dev/null -w '%{http_code}' -X POST '${NODE_A_SAD_URL}/api/v1/sad' -H 'Content-Type: application/json' -d '{\"said\":\"Kwrong_said_that_does_not_match_data________\",\"data\":\"test\"}') = '400' ]"

# POST fetch non-existent object
run_test "POST fetch non-existent object returns 404" \
    bash -c "[ \$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{\"said\":\"Knonexistent________________________________\"}' '${NODE_A_SAD_URL}/api/v1/sad/fetch') = '404' ]"

echo ""

# ========================================
# Scenario 2: Chain Operations
# ========================================
echo -e "${CYAN}=== Scenario 2: Chain Operations ===${NC}"
echo ""

# GET non-existent chain
run_test "GET non-existent chain returns 404" \
    bash -c "[ \$(curl -s -o /dev/null -w '%{http_code}' '${NODE_A_SAD_URL}/api/v1/sad/pointers/Knonexistent________________________________') = '404' ]"

# Effective SAID non-existent
run_test "Effective SAID non-existent returns 404" \
    bash -c "[ \$(curl -s -o /dev/null -w '%{http_code}' '${NODE_A_SAD_URL}/api/v1/sad/pointers/Knonexistent________________________________/effective-said') = '404' ]"

# Submit pointer with tampered SAID
run_test "Submit tampered SAID rejected" \
    bash -c "[ \$(curl -s -o /dev/null -w '%{http_code}' -X POST '${NODE_A_SAD_URL}/api/v1/sad/pointers' -H 'Content-Type: application/json' -d '[{\"pointer\":{\"said\":\"KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"prefix\":\"KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB\",\"version\":0,\"kelPrefix\":\"KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC\",\"kind\":\"test\"},\"signature\":\"${MOCK_SIGNATURE}\",\"establishmentSerial\":0}]') = '400' ]"

echo ""

# ========================================
# Scenario 3: Prefix Computation
# ========================================
echo -e "${CYAN}=== Scenario 3: Prefix Computation ===${NC}"
echo ""

PREFIX_A=$(kels-cli sad prefix "Kkel_a______________________________________" "kels/v1/mlkem" 2>/dev/null)
PREFIX_B=$(kels-cli sad prefix "Kkel_a______________________________________" "kels/v1/mlkem" 2>/dev/null)
run_test "Prefix is deterministic" [ "$PREFIX_A" = "$PREFIX_B" ]

PREFIX_C=$(kels-cli sad prefix "Kkel_b______________________________________" "kels/v1/mlkem" 2>/dev/null)
run_test "Different KEL prefix -> different chain prefix" [ "$PREFIX_A" != "$PREFIX_C" ]

PREFIX_D=$(kels-cli sad prefix "Kkel_a______________________________________" "kels/v1/other" 2>/dev/null)
run_test "Different kind -> different chain prefix" [ "$PREFIX_A" != "$PREFIX_D" ]

echo ""

# ========================================
# Scenario 4: Listing Endpoints
# ========================================
echo -e "${CYAN}=== Scenario 4: Listing Endpoints ===${NC}"
echo ""

PREFIX_LISTING_BODY="{\"payload\":{\"said\":\"${MOCK_SAID}\",\"createdAt\":\"${MOCK_CREATED_AT}\",\"nonce\":\"${MOCK_NONCE}\",\"cursor\":null,\"limit\":null},\"signatures\":{\"${MOCK_PREFIX}\":\"${MOCK_SIGNATURE}\"}}"
PREFIX_LISTING_BODY_LIMIT="{\"payload\":{\"said\":\"${MOCK_SAID}\",\"createdAt\":\"${MOCK_CREATED_AT}\",\"nonce\":\"${MOCK_NONCE}\",\"cursor\":null,\"limit\":5},\"signatures\":{\"${MOCK_PREFIX}\":\"${MOCK_SIGNATURE}\"}}"
OBJECT_LISTING_BODY="{\"payload\":{\"said\":\"${MOCK_SAID}\",\"createdAt\":\"${MOCK_CREATED_AT}\",\"nonce\":\"${MOCK_NONCE}\",\"cursor\":null,\"limit\":null},\"signatures\":{\"${MOCK_PREFIX}\":\"${MOCK_SIGNATURE}\"}}"

run_test "List chain prefixes" \
    bash -c "curl -sf -X POST '${NODE_A_SAD_URL}/api/test/sad/pointers/prefixes' -H 'Content-Type: application/json' -d '${PREFIX_LISTING_BODY}' | jq -e '.prefixes != null'"

run_test "List SAD objects" \
    bash -c "curl -sf -X POST '${NODE_A_SAD_URL}/api/test/sad/saids' -H 'Content-Type: application/json' -d '${OBJECT_LISTING_BODY}' | jq -e '.saids != null'"

run_test "List with pagination limit" \
    bash -c "curl -sf -X POST '${NODE_A_SAD_URL}/api/test/sad/pointers/prefixes' -H 'Content-Type: application/json' -d '${PREFIX_LISTING_BODY_LIMIT}' | jq -e '.prefixes | length <= 5'"

echo ""

# ========================================
# Scenario 5: Chain Record Submission via CLI
# ========================================
echo -e "${CYAN}=== Scenario 5: Chain Record Submission via CLI ===${NC}"
echo "Create a KEL, build chain pointers, sign + submit via CLI, fetch via CLI"
echo ""

SAD_KIND="kels/v1/test-data"

# Create a KEL on node-a to use as the chain owner
KEL_PREFIX=$(kels-cli --kels-url "$NODE_A_KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
if [ -z "$KEL_PREFIX" ]; then
    echo -e "${RED}Failed to create KEL${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    echo "Created KEL: $KEL_PREFIX"

    # Compute the chain prefix via CLI
    CHAIN_PREFIX=$(kels-cli sad prefix "$KEL_PREFIX" "$SAD_KIND" 2>/dev/null)
    echo "Chain prefix: $CHAIN_PREFIX"
    run_test "Chain prefix computed" [ -n "$CHAIN_PREFIX" ]

    run_test "Chain does not exist yet" \
        bash -c "[ \$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{\"prefix\":\"${CHAIN_PREFIX}\"}' '${NODE_A_SAD_URL}/api/v1/sad/pointers/fetch') = '404' ]"

    # --- Build v0 inception pointer ---
    V0_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg kp "$KEL_PREFIX" --arg k "$SAD_KIND" \
        '{said: $p, prefix: $p, version: 0, kelPrefix: $kp, kind: $k}')
    V0_PREFIX=$(compute_prefix "$V0_JSON")
    V0_JSON=$(echo "$V0_JSON" | jq -c --arg pfx "$V0_PREFIX" '.prefix = $pfx')
    V0_SAID=$(compute_said "$V0_JSON")
    V0_JSON=$(echo "$V0_JSON" | jq -c --arg s "$V0_SAID" '.said = $s')

    # Verify our prefix matches the CLI's
    run_test "Computed prefix matches CLI" [ "$V0_PREFIX" = "$CHAIN_PREFIX" ]

    # Sign v0 with the KEL's signing key via CLI
    V0_SIG=$(kels-cli sign --prefix "$KEL_PREFIX" "$V0_SAID" 2>/dev/null)
    run_test "v0 signed via CLI" [ -n "$V0_SIG" ]

    # Build the submission JSON and write to file
    echo "[$(jq -nc --argjson r "$V0_JSON" --arg sig "$V0_SIG" \
        '{pointer: $r, signature: $sig, establishmentSerial: 0}')]" > "$TEMP_DIR/v0-submit.json"

    # Submit via kels-cli sad submit
    run_test "v0 submitted via CLI (sad submit)" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sad submit "$TEMP_DIR/v0-submit.json"

    # Fetch the chain via kels-cli sad pointer
    CHAIN_OUTPUT=$(kels-cli --sadstore-url "$NODE_A_SAD_URL" sad pointer "$CHAIN_PREFIX" 2>/dev/null)
    CHAIN_LEN=$(echo "$CHAIN_OUTPUT" | jq '.pointers | length' 2>/dev/null)
    run_test "Chain fetched via CLI (sad pointer) with 1 pointer" [ "$CHAIN_LEN" = "1" ]

    # Verify the fetched pointer's SAID matches
    FETCHED_SAID=$(echo "$CHAIN_OUTPUT" | jq -r '.pointers[0].pointer.said' 2>/dev/null)
    run_test "Fetched pointer SAID matches v0" [ "$FETCHED_SAID" = "$V0_SAID" ]

    # --- Build v1 pointer ---
    V1_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$CHAIN_PREFIX" --arg prev "$V0_SAID" \
        --arg kp "$KEL_PREFIX" --arg k "$SAD_KIND" \
        '{said: $p, prefix: $pfx, previous: $prev, version: 1, kelPrefix: $kp, kind: $k}')
    V1_SAID=$(compute_said "$V1_JSON")
    V1_JSON=$(echo "$V1_JSON" | jq -c --arg s "$V1_SAID" '.said = $s')

    V1_SIG=$(kels-cli sign --prefix "$KEL_PREFIX" "$V1_SAID" 2>/dev/null)
    run_test "v1 signed via CLI" [ -n "$V1_SIG" ]

    echo "[$(jq -nc --argjson r "$V1_JSON" --arg sig "$V1_SIG" \
        '{pointer: $r, signature: $sig, establishmentSerial: 0}')]" > "$TEMP_DIR/v1-submit.json"

    run_test "v1 submitted via CLI (sad submit)" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sad submit "$TEMP_DIR/v1-submit.json"

    # Verify chain now has 2 pointers
    CHAIN_OUTPUT=$(kels-cli --sadstore-url "$NODE_A_SAD_URL" sad pointer "$CHAIN_PREFIX" 2>/dev/null)
    CHAIN_LEN=$(echo "$CHAIN_OUTPUT" | jq '.pointers | length' 2>/dev/null)
    run_test "Chain has 2 pointers after v1 submit" [ "$CHAIN_LEN" = "2" ]

    # Wait for gossip propagation and verify chain on node-b
    run_test "Chain propagated to node-b" \
        wait_for_chain_propagation "$CHAIN_PREFIX" "$V1_SAID" "$CONVERGENCE_TIMEOUT" "$NODE_B_SAD_URL"
fi

echo ""

# ========================================
# Scenario 6: SAD Object Put/Get via CLI + Gossip Propagation
# ========================================
echo -e "${CYAN}=== Scenario 6: SAD Object Put/Get via CLI + Gossip ===${NC}"
echo "Store a SAD object via CLI, retrieve it via CLI, verify gossip propagation"
echo ""

# Create a unique test object file (unique per run to avoid false pass from prior ae sync)
UNIQUE_VALUE="gossip-test-$(date +%s%N)-$$"
echo "{\"said\":\"\",\"testField\":\"${UNIQUE_VALUE}\"}" > "$TEMP_DIR/test-object.json"

# POST via CLI using --sadstore-url
SAD_SAID=$(kels-cli --sadstore-url "$NODE_A_SAD_URL" sad put "$TEMP_DIR/test-object.json" 2>/dev/null)
run_test "SAD object stored via CLI (sad put)" [ -n "$SAD_SAID" ]

if [ -n "$SAD_SAID" ]; then
    echo "Stored SAD object: $SAD_SAID"

    run_test "Object exists on node-a" sad_object_exists "$NODE_A_SAD_URL" "$SAD_SAID"

    # GET via CLI and verify the content
    GET_OUTPUT=$(kels-cli --sadstore-url "$NODE_A_SAD_URL" sad get "$SAD_SAID" 2>/dev/null)
    GET_SAID=$(echo "$GET_OUTPUT" | jq -r '.said // empty' 2>/dev/null)
    run_test "SAD object retrieved via CLI (sad get)" [ "$GET_SAID" = "$SAD_SAID" ]

    GET_FIELD=$(echo "$GET_OUTPUT" | jq -r '.testField // empty' 2>/dev/null)
    run_test "Retrieved object content matches" [ "$GET_FIELD" = "$UNIQUE_VALUE" ]

    # Wait for gossip propagation to node-b
    run_test "Object propagated to node-b" \
        wait_for_sad_object_propagation "$SAD_SAID" "$CONVERGENCE_TIMEOUT" "$NODE_B_SAD_URL"

    # GET from node-b via CLI
    GET_B_SAID=$(kels-cli --sadstore-url "$NODE_B_SAD_URL" sad get "$SAD_SAID" 2>/dev/null | jq -r '.said // empty' 2>/dev/null)
    run_test "Object retrievable from node-b via CLI (sad get)" [ "$GET_B_SAID" = "$SAD_SAID" ]
fi

echo ""

# ========================================
# Scenario 7: Divergence Detection + Repair
# ========================================
echo -e "${CYAN}=== Scenario 7: Divergence Detection + Repair ===${NC}"
echo "Create divergence by submitting conflicting pointers at the same version"
echo "to different nodes, then repair the chain."
echo ""

DIV_KIND="kels/v1/test-diverge"

# Create a KEL for the divergence test
DIV_KEL_PREFIX=$(kels-cli --kels-url "$NODE_A_KELS_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
if [ -z "$DIV_KEL_PREFIX" ]; then
    echo -e "${RED}Failed to create KEL for divergence test${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    echo "Created KEL: $DIV_KEL_PREFIX"

    DIV_PREFIX=$(kels-cli sad prefix "$DIV_KEL_PREFIX" "$DIV_KIND" 2>/dev/null)
    echo "Chain prefix: $DIV_PREFIX"

    # --- Build and submit v0 to node-a ---
    D_V0_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg kp "$DIV_KEL_PREFIX" --arg k "$DIV_KIND" \
        '{said: $p, prefix: $p, version: 0, kelPrefix: $kp, kind: $k}')
    D_V0_PREFIX=$(compute_prefix "$D_V0_JSON")
    D_V0_JSON=$(echo "$D_V0_JSON" | jq -c --arg pfx "$D_V0_PREFIX" '.prefix = $pfx')
    D_V0_SAID=$(compute_said "$D_V0_JSON")
    D_V0_JSON=$(echo "$D_V0_JSON" | jq -c --arg s "$D_V0_SAID" '.said = $s')

    D_V0_SIG=$(kels-cli sign --prefix "$DIV_KEL_PREFIX" "$D_V0_SAID" 2>/dev/null)
    echo "[$(jq -nc --argjson r "$D_V0_JSON" --arg sig "$D_V0_SIG" \
        '{pointer: $r, signature: $sig, establishmentSerial: 0}')]" > "$TEMP_DIR/div-v0.json"

    run_test "Divergence: v0 submitted to node-a" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sad submit "$TEMP_DIR/div-v0.json"

    # Wait for v0 to propagate to node-b
    run_test "Divergence: v0 propagated to node-b" \
        wait_for_chain_propagation "$DIV_PREFIX" "$D_V0_SAID" "$CONVERGENCE_TIMEOUT" "$NODE_B_SAD_URL"

    # --- Build two conflicting v1 pointers ---
    # v1-a: submitted to node-a
    D_V1A_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$DIV_PREFIX" --arg prev "$D_V0_SAID" \
        --arg kp "$DIV_KEL_PREFIX" --arg k "$DIV_KIND" \
        '{said: $p, prefix: $pfx, previous: $prev, version: 1, kelPrefix: $kp, kind: $k, contentSaid: "Kcontent_a__________________________________"}')
    D_V1A_SAID=$(compute_said "$D_V1A_JSON")
    D_V1A_JSON=$(echo "$D_V1A_JSON" | jq -c --arg s "$D_V1A_SAID" '.said = $s')

    D_V1A_SIG=$(kels-cli sign --prefix "$DIV_KEL_PREFIX" "$D_V1A_SAID" 2>/dev/null)
    echo "[$(jq -nc --argjson r "$D_V1A_JSON" --arg sig "$D_V1A_SIG" \
        '{pointer: $r, signature: $sig, establishmentSerial: 0}')]" > "$TEMP_DIR/div-v1a.json"

    # v1-b: submitted to node-b (different content_said → different SAID)
    D_V1B_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$DIV_PREFIX" --arg prev "$D_V0_SAID" \
        --arg kp "$DIV_KEL_PREFIX" --arg k "$DIV_KIND" \
        '{said: $p, prefix: $pfx, previous: $prev, version: 1, kelPrefix: $kp, kind: $k, contentSaid: "Kcontent_b__________________________________"}')
    D_V1B_SAID=$(compute_said "$D_V1B_JSON")
    D_V1B_JSON=$(echo "$D_V1B_JSON" | jq -c --arg s "$D_V1B_SAID" '.said = $s')

    D_V1B_SIG=$(kels-cli sign --prefix "$DIV_KEL_PREFIX" "$D_V1B_SAID" 2>/dev/null)
    echo "[$(jq -nc --argjson r "$D_V1B_JSON" --arg sig "$D_V1B_SIG" \
        '{pointer: $r, signature: $sig, establishmentSerial: 0}')]" > "$TEMP_DIR/div-v1b.json"

    run_test "Divergence: v1-a and v1-b have different SAIDs" [ "$D_V1A_SAID" != "$D_V1B_SAID" ]

    # Submit conflicting pointers to different nodes
    run_test "Divergence: v1-a submitted to node-a" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sad submit "$TEMP_DIR/div-v1a.json"

    run_test "Divergence: v1-b submitted to node-b" \
        kels-cli --sadstore-url "$NODE_B_SAD_URL" sad submit "$TEMP_DIR/div-v1b.json"

    # Wait for both nodes to detect divergence and agree on effective SAID
    run_test "Divergence: both nodes converge on divergent state" \
        wait_for_divergence_convergence "$DIV_PREFIX" "$CONVERGENCE_TIMEOUT" "$NODE_A_SAD_URL" "$NODE_B_SAD_URL"

    A_EFFECTIVE=$(get_effective_said "$NODE_A_SAD_URL" "$DIV_PREFIX")
    B_EFFECTIVE=$(get_effective_said "$NODE_B_SAD_URL" "$DIV_PREFIX")
    A_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${DIV_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/pointers/effective-said" | jq -r '.divergent // false')
    B_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${DIV_PREFIX}\"}" "${NODE_B_SAD_URL}/api/v1/sad/pointers/effective-said" | jq -r '.divergent // false')
    echo "Node-a effective: $A_EFFECTIVE (divergent: $A_DIVERGENT)"
    echo "Node-b effective: $B_EFFECTIVE (divergent: $B_DIVERGENT)"

    # --- Repair: submit replacement v1 with --repair ---
    D_REPAIR_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$DIV_PREFIX" --arg prev "$D_V0_SAID" \
        --arg kp "$DIV_KEL_PREFIX" --arg k "$DIV_KIND" \
        '{said: $p, prefix: $pfx, previous: $prev, version: 1, kelPrefix: $kp, kind: $k, contentSaid: "Kcontent_repaired___________________________"}')
    D_REPAIR_SAID=$(compute_said "$D_REPAIR_JSON")
    D_REPAIR_JSON=$(echo "$D_REPAIR_JSON" | jq -c --arg s "$D_REPAIR_SAID" '.said = $s')

    D_REPAIR_SIG=$(kels-cli sign --prefix "$DIV_KEL_PREFIX" "$D_REPAIR_SAID" 2>/dev/null)
    echo "[$(jq -nc --argjson r "$D_REPAIR_JSON" --arg sig "$D_REPAIR_SIG" \
        '{pointer: $r, signature: $sig, establishmentSerial: 0}')]" > "$TEMP_DIR/div-repair.json"

    run_test "Repair: submitted with --repair to node-a" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sad submit --repair "$TEMP_DIR/div-repair.json"

    # Verify node-a is no longer divergent
    A_POST_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${DIV_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/pointers/effective-said" | jq -r '.divergent // false')
    A_POST_EFFECTIVE=$(get_effective_said "$NODE_A_SAD_URL" "$DIV_PREFIX")
    run_test "Repair: node-a no longer divergent" [ "$A_POST_DIVERGENT" = "false" ]
    run_test "Repair: node-a tip is repair record" [ "$A_POST_EFFECTIVE" = "$D_REPAIR_SAID" ]

    # Verify repair audit record exists
    REPAIR_COUNT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${DIV_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/pointers/repairs" | jq '.repairs | length')
    run_test "Repair: audit record created" [ "$REPAIR_COUNT" -ge 1 ]

    # Wait for repair to propagate to node-b via gossip
    run_test "Repair: propagated to node-b" \
        wait_for_chain_propagation "$DIV_PREFIX" "$D_REPAIR_SAID" "$CONVERGENCE_TIMEOUT" "$NODE_B_SAD_URL"
fi

echo ""

print_summary "SADStore Test Summary"
exit_with_result
