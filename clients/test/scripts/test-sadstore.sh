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
#
# **Round-9 note (#147 migration path).** Scenarios 7-9 cover the round-9
# repair surface (divergent / silent extension / clean state). They exercise
# the **server-side** Rpr contract by building events with raw JSON and
# submitting via `kels-cli sel submit` (which is just an HTTP wrapper).
# This is the right shape for testing the truncate_and_replace contract.
# When the higher-level `kels sel repair` subcommand lands (#147), migrate
# the construction to drive `SadEventBuilder::repair` end-to-end so the
# owner-local boundary discovery is also exercised here. Until then, the
# in-process integration tests at `services/sadstore/tests/sad_builder_tests.rs`
# cover the builder side; this script covers the wire contract.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
FEDERATED="${FEDERATED:-true}"
PROPAGATION_DELAY="${PROPAGATION_DELAY:-5}"
CONVERGENCE_TIMEOUT="${CONVERGENCE_TIMEOUT:-30}"
NODE_A_SADSTORE_HOST="${NODE_A_SADSTORE_HOST:-sadstore}"
NODE_B_SADSTORE_HOST="${NODE_B_SADSTORE_HOST:-sadstore.node-b.kels}"
NODE_A_KELS_HOST="${NODE_A_KELS_HOST:-kels}"
# Dummy CESR values for test endpoints that skip auth but still deserialize
MOCK_SAID="KMOCK_SAID__________________________________"
MOCK_PREFIX="KMOCK_PREFIX________________________________"
MOCK_SIGNATURE="0CMOCK_SIGNATURE________________________________________________________________________"
MOCK_CREATED_AT="2026-01-01T00:00:00.000000Z"
MOCK_NONCE="NMOCK_NONCE_________________________________"

NODE_A_SAD_URL="http://${NODE_A_SADSTORE_HOST}"
NODE_B_SAD_URL="http://${NODE_B_SADSTORE_HOST}"
NODE_A_KELS_URL="http://${NODE_A_KELS_HOST}"

init_temp_dir

echo "========================================="
echo "SADStore Integration Test Suite"
echo "========================================="
echo "Node-A SADStore: $NODE_A_SAD_URL"
if [ "$FEDERATED" = "true" ]; then
    echo "Node-B SADStore: $NODE_B_SAD_URL"
fi
echo "Node-A KELS:     $NODE_A_KELS_URL"
echo "Federated:       ${FEDERATED}"
echo "Propagation:     ${PROPAGATION_DELAY}s"
echo "========================================="
echo ""

# Wait for services
echo "Waiting for services..."
wait_for_health "$NODE_A_SAD_URL" "Node-A SADStore" || exit 1
if [ "$FEDERATED" = "true" ]; then
    wait_for_health "$NODE_B_SAD_URL" "Node-B SADStore" || exit 1
fi
wait_for_health "$NODE_A_KELS_URL" "Node-A KELS" || exit 1
echo ""

# === Helper functions ===

sad_object_exists() {
    local url="$1"
    local said="$2"
    [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "{\"said\":\"${said}\"}" "${url}/api/v1/sad/fetch")" = "200" ]
}

sel_exists() {
    local url="$1"
    local prefix="$2"
    [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${prefix}\"}" "${url}/api/v1/sad/events/fetch")" = "200" ]
}

get_chain_tip_said() {
    local url="$1"
    local prefix="$2"
    curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${prefix}\"}" "${url}/api/v1/sad/events/fetch" | jq -r '.events[-1].said // empty'
}

get_effective_said() {
    local url="$1"
    local prefix="$2"
    curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${prefix}\"}" "${url}/api/v1/sad/events/effective-said" | jq -r '.said // empty'
}

get_chain_length() {
    local url="$1"
    local prefix="$2"
    curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${prefix}\"}" "${url}/api/v1/sad/events/fetch" | jq '.events | length'
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

wait_for_sad_event_divergence_convergence() {
    local prefix="$1"
    local timeout="$2"
    local url_a="$3"
    local url_b="$4"
    local deadline=$((SECONDS + timeout))
    while [ $SECONDS -lt $deadline ]; do
        local a_div b_div a_eff b_eff
        a_div=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${prefix}\"}" "${url_a}/api/v1/sad/events/effective-said" | jq -r '.divergent // false')
        b_div=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${prefix}\"}" "${url_b}/api/v1/sad/events/effective-said" | jq -r '.divergent // false')
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
    bash -c "[ \$(curl -s -o /dev/null -w '%{http_code}' '${NODE_A_SAD_URL}/api/v1/sad/events/Knonexistent________________________________') = '404' ]"

# Effective SAID non-existent
run_test "Effective SAID non-existent returns 404" \
    bash -c "[ \$(curl -s -o /dev/null -w '%{http_code}' '${NODE_A_SAD_URL}/api/v1/sad/events/Knonexistent________________________________/effective-said') = '404' ]"

# Submit event with tampered SAID
run_test "Submit tampered SAID rejected" \
    bash -c "[ \$(curl -s -o /dev/null -w '%{http_code}' -X POST '${NODE_A_SAD_URL}/api/v1/sad/events' -H 'Content-Type: application/json' -d '[{\"said\":\"KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"prefix\":\"KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB\",\"version\":0,\"topic\":\"test\",\"kind\":\"kels/sad/v1/events/icp\",\"writePolicy\":\"KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC\"}]') = '400' ]"

echo ""

# ========================================
# Scenario 3: Prefix Computation
# ========================================
echo -e "${CYAN}=== Scenario 3: Prefix Computation ===${NC}"
echo ""

PREFIX_A=$(kels-cli sel prefix "Kkel_a______________________________________" "kels/sad/v1/test-mlkem" 2>/dev/null)
PREFIX_B=$(kels-cli sel prefix "Kkel_a______________________________________" "kels/sad/v1/test-mlkem" 2>/dev/null)
run_test "Prefix is deterministic" [ "$PREFIX_A" = "$PREFIX_B" ]

PREFIX_C=$(kels-cli sel prefix "Kkel_b______________________________________" "kels/sad/v1/test-mlkem" 2>/dev/null)
run_test "Different KEL prefix -> different SEL prefix" [ "$PREFIX_A" != "$PREFIX_C" ]

PREFIX_D=$(kels-cli sel prefix "Kkel_a______________________________________" "kels/sad/v1/test-other" 2>/dev/null)
run_test "Different topic -> different SEL prefix" [ "$PREFIX_A" != "$PREFIX_D" ]

echo ""

# ========================================
# Scenario 4: Listing Endpoints
# ========================================
echo -e "${CYAN}=== Scenario 4: Listing Endpoints ===${NC}"
echo ""

PREFIX_LISTING_BODY="{\"payload\":{\"said\":\"${MOCK_SAID}\",\"createdAt\":\"${MOCK_CREATED_AT}\",\"nonce\":\"${MOCK_NONCE}\",\"cursor\":null,\"limit\":null},\"signatures\":{\"${MOCK_PREFIX}\":\"${MOCK_SIGNATURE}\"}}"
PREFIX_LISTING_BODY_LIMIT="{\"payload\":{\"said\":\"${MOCK_SAID}\",\"createdAt\":\"${MOCK_CREATED_AT}\",\"nonce\":\"${MOCK_NONCE}\",\"cursor\":null,\"limit\":5},\"signatures\":{\"${MOCK_PREFIX}\":\"${MOCK_SIGNATURE}\"}}"
OBJECT_LISTING_BODY="{\"payload\":{\"said\":\"${MOCK_SAID}\",\"createdAt\":\"${MOCK_CREATED_AT}\",\"nonce\":\"${MOCK_NONCE}\",\"cursor\":null,\"limit\":null},\"signatures\":{\"${MOCK_PREFIX}\":\"${MOCK_SIGNATURE}\"}}"

run_test "List SEL prefixes" \
    bash -c "curl -sf -X POST '${NODE_A_SAD_URL}/api/test/sad/events/prefixes' -H 'Content-Type: application/json' -d '${PREFIX_LISTING_BODY}' | jq -e '.prefixes != null'"

run_test "List SAD objects" \
    bash -c "curl -sf -X POST '${NODE_A_SAD_URL}/api/test/sad/saids' -H 'Content-Type: application/json' -d '${OBJECT_LISTING_BODY}' | jq -e '.saids != null'"

run_test "List with pagination limit" \
    bash -c "curl -sf -X POST '${NODE_A_SAD_URL}/api/test/sad/events/prefixes' -H 'Content-Type: application/json' -d '${PREFIX_LISTING_BODY_LIMIT}' | jq -e '.prefixes | length <= 5'"

echo ""

# ========================================
# Scenario 5: SAD Event Submission via CLI
# ========================================
echo -e "${CYAN}=== Scenario 5: SAD Event Submission via CLI ===${NC}"
echo "Create a KEL, build SAD events, submit via CLI, fetch via CLI"
echo ""

SAD_TOPIC="kels/sad/v1/test-data"

# Create a KEL on node-a to use as the chain owner
KEL_PREFIX=$(kels-cli --kels-url "$NODE_A_KELS_URL" kel incept 2>&1 | grep "Prefix:" | awk '{print $2}')
if [ -z "$KEL_PREFIX" ]; then
    echo -e "${RED}Failed to create KEL${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    echo "Created KEL: $KEL_PREFIX"

    # Build a real policy (single endorser) and store as SAD object
    POLICY_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg expr "endorse($KEL_PREFIX)" \
        '{said: $p, expression: $expr}')
    POLICY_SAID=$(compute_said "$POLICY_JSON")
    POLICY_JSON=$(echo "$POLICY_JSON" | jq -c --arg s "$POLICY_SAID" '.said = $s')
    POLICY_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${NODE_A_SAD_URL}/api/v1/sad" \
        -H 'Content-Type: application/json' -d "$POLICY_JSON")
    run_test "Policy uploaded" \
        bash -c "[ '$POLICY_CODE' = '201' ] || [ '$POLICY_CODE' = '200' ]"

    # Compute the SEL prefix via CLI (using policy SAID, not KEL prefix)
    SEL_PREFIX=$(kels-cli sel prefix "$POLICY_SAID" "$SAD_TOPIC" 2>/dev/null)
    echo "SEL prefix: $SEL_PREFIX"
    run_test "SEL prefix computed" [ -n "$SEL_PREFIX" ]

    run_test "Chain does not exist yet" \
        bash -c "[ \$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{\"prefix\":\"${SEL_PREFIX}\"}' '${NODE_A_SAD_URL}/api/v1/sad/events/fetch') = '404' ]"

    # --- Build v0 inception event ---
    V0_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg wp "$POLICY_SAID" --arg k "$SAD_TOPIC" \
        '{said: $p, prefix: $p, version: 0, topic: $k, kind: "kels/sad/v1/events/icp", writePolicy: $wp}')
    V0_PREFIX=$(compute_prefix "$V0_JSON")
    V0_JSON=$(echo "$V0_JSON" | jq -c --arg pfx "$V0_PREFIX" '.prefix = $pfx')
    V0_SAID=$(compute_said "$V0_JSON")
    V0_JSON=$(echo "$V0_JSON" | jq -c --arg s "$V0_SAID" '.said = $s')

    # Verify our prefix matches the CLI's
    run_test "Computed prefix matches CLI" [ "$V0_PREFIX" = "$SEL_PREFIX" ]

    # --- Build v1 event (declares governance_policy) ---
    GOVERNANCE_POLICY_SAID=$(build_governance_policy "$NODE_A_SAD_URL" "$KEL_PREFIX")
    V1_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$SEL_PREFIX" --arg prev "$V0_SAID" \
        --arg k "$SAD_TOPIC" --arg gp "$GOVERNANCE_POLICY_SAID" \
        '{said: $p, prefix: $pfx, previous: $prev, version: 1, topic: $k, kind: "kels/sad/v1/events/est", governancePolicy: $gp}')
    V1_SAID=$(compute_said "$V1_JSON")
    V1_JSON=$(echo "$V1_JSON" | jq -c --arg s "$V1_SAID" '.said = $s')

    # Anchor both SAIDs in the KEL (required for write_policy authorization)
    run_test "v0 SAID anchored in KEL" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$KEL_PREFIX" --said "$V0_SAID"
    run_test "v1 SAID anchored in KEL" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$KEL_PREFIX" --said "$V1_SAID"

    # Submit [v0, v1] as inception batch (v1 declares governance_policy)
    echo "[$V0_JSON,$V1_JSON]" > "$TEMP_DIR/inception-submit.json"

    run_test "Inception batch [v0, v1] submitted via CLI (sel submit)" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sel submit "$TEMP_DIR/inception-submit.json"

    # Fetch the chain via kels-cli sel get
    CHAIN_OUTPUT=$(kels-cli --sadstore-url "$NODE_A_SAD_URL" sel get "$SEL_PREFIX" 2>/dev/null)
    CHAIN_LEN=$(echo "$CHAIN_OUTPUT" | jq '.events | length' 2>/dev/null)
    run_test "Chain fetched via CLI (sel get) with 2 events" [ "$CHAIN_LEN" = "2" ]

    # Wait for gossip propagation and verify chain on node-b
    if [ "$FEDERATED" = "true" ]; then
        run_test "Chain propagated to node-b" \
            wait_for_chain_propagation "$SEL_PREFIX" "$V1_SAID" "$CONVERGENCE_TIMEOUT" "$NODE_B_SAD_URL"
    fi
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

    if [ "$FEDERATED" = "true" ]; then
        # Wait for gossip propagation to node-b
        run_test "Object propagated to node-b" \
            wait_for_sad_object_propagation "$SAD_SAID" "$CONVERGENCE_TIMEOUT" "$NODE_B_SAD_URL"

        # GET from node-b via CLI
        GET_B_SAID=$(kels-cli --sadstore-url "$NODE_B_SAD_URL" sad get "$SAD_SAID" 2>/dev/null | jq -r '.said // empty' 2>/dev/null)
        run_test "Object retrievable from node-b via CLI (sad get)" [ "$GET_B_SAID" = "$SAD_SAID" ]
    fi
fi

echo ""

if [ "$FEDERATED" = "true" ]; then

# ========================================
# Scenario 7: Divergence Detection + Repair
# ========================================
echo -e "${CYAN}=== Scenario 7: Divergence Detection + Repair ===${NC}"
echo "Create divergence by submitting conflicting events at the same version"
echo "to different nodes, then repair the chain."
echo ""

DIV_TOPIC="kels/sad/v1/test-diverge"

# Create a KEL for the divergence test
DIV_KEL_PREFIX=$(kels-cli --kels-url "$NODE_A_KELS_URL" kel incept 2>&1 | grep "Prefix:" | awk '{print $2}')
if [ -z "$DIV_KEL_PREFIX" ]; then
    echo -e "${RED}Failed to create KEL for divergence test${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    echo "Created KEL: $DIV_KEL_PREFIX"

    # Build a real policy and upload as SAD object
    DIV_POLICY_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg expr "endorse($DIV_KEL_PREFIX)" \
        '{said: $p, expression: $expr}')
    DIV_POLICY_SAID=$(compute_said "$DIV_POLICY_JSON")
    DIV_POLICY_JSON=$(echo "$DIV_POLICY_JSON" | jq -c --arg s "$DIV_POLICY_SAID" '.said = $s')
    curl -s -o /dev/null -X POST "${NODE_A_SAD_URL}/api/v1/sad" \
        -H 'Content-Type: application/json' -d "$DIV_POLICY_JSON"

    # Build governance policy before v0 so v0 can declare it
    DIV_GP_SAID=$(build_governance_policy "$NODE_A_SAD_URL" "$DIV_KEL_PREFIX")

    # --- Build and submit v0 (with governance_policy) to node-a ---
    D_V0_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg wp "$DIV_POLICY_SAID" --arg k "$DIV_TOPIC" \
        --arg gp "$DIV_GP_SAID" \
        '{said: $p, prefix: $p, version: 0, topic: $k, kind: "kels/sad/v1/events/icp", writePolicy: $wp, governancePolicy: $gp}')
    D_V0_PREFIX=$(compute_prefix "$D_V0_JSON")
    D_V0_JSON=$(echo "$D_V0_JSON" | jq -c --arg pfx "$D_V0_PREFIX" '.prefix = $pfx')
    D_V0_SAID=$(compute_said "$D_V0_JSON")
    D_V0_JSON=$(echo "$D_V0_JSON" | jq -c --arg s "$D_V0_SAID" '.said = $s')

    # governance_policy changes the prefix — use computed prefix, not CLI prefix
    DIV_PREFIX="$D_V0_PREFIX"
    echo "SEL prefix: $DIV_PREFIX"

    # Anchor v0 SAID in the KEL
    run_test "Divergence: v0 SAID anchored" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$DIV_KEL_PREFIX" --said "$D_V0_SAID"

    echo "[$D_V0_JSON]" > "$TEMP_DIR/div-v0.json"

    run_test "Divergence: v0 submitted to node-a" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sel submit "$TEMP_DIR/div-v0.json"

    # Wait for v0 to propagate to node-b
    run_test "Divergence: v0 propagated to node-b" \
        wait_for_chain_propagation "$DIV_PREFIX" "$D_V0_SAID" "$CONVERGENCE_TIMEOUT" "$NODE_B_SAD_URL"

    # --- Build two conflicting v1 events ---

    # v1-a: submitted to node-a (no evaluation — allows fork at this version)
    D_V1A_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$DIV_PREFIX" --arg prev "$D_V0_SAID" \
        --arg k "$DIV_TOPIC" \
        '{said: $p, prefix: $pfx, previous: $prev, version: 1, topic: $k, kind: "kels/sad/v1/events/upd", content: "Kcontent_a__________________________________"}')
    D_V1A_SAID=$(compute_said "$D_V1A_JSON")
    D_V1A_JSON=$(echo "$D_V1A_JSON" | jq -c --arg s "$D_V1A_SAID" '.said = $s')

    # Anchor v1-a SAID in the KEL
    run_test "Divergence: v1-a SAID anchored" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$DIV_KEL_PREFIX" --said "$D_V1A_SAID"

    echo "[$D_V1A_JSON]" > "$TEMP_DIR/div-v1a.json"

    # v1-b: submitted to node-b (adversary fork — no evaluation, bounded by governance_policy)
    D_V1B_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$DIV_PREFIX" --arg prev "$D_V0_SAID" \
        --arg k "$DIV_TOPIC" \
        '{said: $p, prefix: $pfx, previous: $prev, version: 1, topic: $k, kind: "kels/sad/v1/events/upd", content: "Kcontent_b__________________________________"}')
    D_V1B_SAID=$(compute_said "$D_V1B_JSON")
    D_V1B_JSON=$(echo "$D_V1B_JSON" | jq -c --arg s "$D_V1B_SAID" '.said = $s')

    # Anchor v1-b SAID in the KEL
    run_test "Divergence: v1-b SAID anchored" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$DIV_KEL_PREFIX" --said "$D_V1B_SAID"

    echo "[$D_V1B_JSON]" > "$TEMP_DIR/div-v1b.json"

    run_test "Divergence: v1-a and v1-b have different SAIDs" [ "$D_V1A_SAID" != "$D_V1B_SAID" ]

    # Submit conflicting events to different nodes
    run_test "Divergence: v1-a submitted to node-a" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sel submit "$TEMP_DIR/div-v1a.json"

    run_test "Divergence: v1-b submitted to node-b" \
        kels-cli --sadstore-url "$NODE_B_SAD_URL" sel submit "$TEMP_DIR/div-v1b.json"

    # Wait for both nodes to detect divergence and agree on effective SAID
    run_test "Divergence: both nodes converge on divergent state" \
        wait_for_sad_event_divergence_convergence "$DIV_PREFIX" "$CONVERGENCE_TIMEOUT" "$NODE_A_SAD_URL" "$NODE_B_SAD_URL"

    A_EFFECTIVE=$(get_effective_said "$NODE_A_SAD_URL" "$DIV_PREFIX")
    B_EFFECTIVE=$(get_effective_said "$NODE_B_SAD_URL" "$DIV_PREFIX")
    A_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${DIV_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/events/effective-said" | jq -r '.divergent // false')
    B_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${DIV_PREFIX}\"}" "${NODE_B_SAD_URL}/api/v1/sad/events/effective-said" | jq -r '.divergent // false')
    echo "Node-a effective: $A_EFFECTIVE (divergent: $A_DIVERGENT)"
    echo "Node-b effective: $B_EFFECTIVE (divergent: $B_DIVERGENT)"

    # --- Repair: submit replacement v1 with Rpr kind ---
    D_REPAIR_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$DIV_PREFIX" --arg prev "$D_V0_SAID" \
        --arg k "$DIV_TOPIC" \
        '{said: $p, prefix: $pfx, previous: $prev, version: 1, topic: $k, kind: "kels/sad/v1/events/rpr", content: "Kcontent_repaired___________________________"}')
    D_REPAIR_SAID=$(compute_said "$D_REPAIR_JSON")
    D_REPAIR_JSON=$(echo "$D_REPAIR_JSON" | jq -c --arg s "$D_REPAIR_SAID" '.said = $s')

    # Anchor repair SAID in the KEL
    run_test "Divergence: repair SAID anchored" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$DIV_KEL_PREFIX" --said "$D_REPAIR_SAID"

    echo "[$D_REPAIR_JSON]" > "$TEMP_DIR/div-repair.json"

    run_test "Repair: submitted to node-a" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sel submit "$TEMP_DIR/div-repair.json"

    # Verify node-a is no longer divergent
    A_POST_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${DIV_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/events/effective-said" | jq -r '.divergent // false')
    A_POST_EFFECTIVE=$(get_effective_said "$NODE_A_SAD_URL" "$DIV_PREFIX")
    run_test "Repair: node-a no longer divergent" [ "$A_POST_DIVERGENT" = "false" ]
    run_test "Repair: node-a tip is repair event" [ "$A_POST_EFFECTIVE" = "$D_REPAIR_SAID" ]

    # Verify repair audit entry exists
    REPAIR_COUNT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${DIV_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/events/repairs" | jq '.repairs | length')
    run_test "Repair: audit entry created" [ "$REPAIR_COUNT" -ge 1 ]

    # Wait for repair to propagate to node-b via gossip
    run_test "Repair: propagated to node-b" \
        wait_for_chain_propagation "$DIV_PREFIX" "$D_REPAIR_SAID" "$CONVERGENCE_TIMEOUT" "$NODE_B_SAD_URL"
fi

echo ""

# ========================================
# Scenario 8: Silent Adversarial Extension + Repair
# ========================================
echo -e "${CYAN}=== Scenario 8: Silent Adversarial Extension + Repair ===${NC}"
echo "Owner authors v0+v1, then a third party (with write_policy auth)"
echo "extends the chain with an unauthorized v2 (no fork — linear extension)."
echo "Owner runs repair, building Rpr@v2 with previous=v1.said. Server's"
echo "truncate_and_replace archives the rogue v2 and inserts the Rpr."
echo ""

EXT_TOPIC="kels/sad/v1/test-extension"

EXT_KEL_PREFIX=$(kels-cli --kels-url "$NODE_A_KELS_URL" kel incept 2>&1 | grep "Prefix:" | awk '{print $2}')
if [ -z "$EXT_KEL_PREFIX" ]; then
    echo -e "${RED}Failed to create KEL for extension test${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    echo "Created KEL: $EXT_KEL_PREFIX"

    EXT_POLICY_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg expr "endorse($EXT_KEL_PREFIX)" \
        '{said: $p, expression: $expr}')
    EXT_POLICY_SAID=$(compute_said "$EXT_POLICY_JSON")
    EXT_POLICY_JSON=$(echo "$EXT_POLICY_JSON" | jq -c --arg s "$EXT_POLICY_SAID" '.said = $s')
    curl -s -o /dev/null -X POST "${NODE_A_SAD_URL}/api/v1/sad" \
        -H 'Content-Type: application/json' -d "$EXT_POLICY_JSON"

    EXT_GP_SAID=$(build_governance_policy "$NODE_A_SAD_URL" "$EXT_KEL_PREFIX")

    # v0: Icp with governance_policy
    E_V0_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg wp "$EXT_POLICY_SAID" --arg k "$EXT_TOPIC" \
        --arg gp "$EXT_GP_SAID" \
        '{said: $p, prefix: $p, version: 0, topic: $k, kind: "kels/sad/v1/events/icp", writePolicy: $wp, governancePolicy: $gp}')
    E_V0_PREFIX=$(compute_prefix "$E_V0_JSON")
    E_V0_JSON=$(echo "$E_V0_JSON" | jq -c --arg pfx "$E_V0_PREFIX" '.prefix = $pfx')
    E_V0_SAID=$(compute_said "$E_V0_JSON")
    E_V0_JSON=$(echo "$E_V0_JSON" | jq -c --arg s "$E_V0_SAID" '.said = $s')
    EXT_PREFIX="$E_V0_PREFIX"
    echo "SEL prefix: $EXT_PREFIX"

    run_test "Extension: v0 SAID anchored" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$EXT_KEL_PREFIX" --said "$E_V0_SAID"
    echo "[$E_V0_JSON]" > "$TEMP_DIR/ext-v0.json"
    run_test "Extension: v0 submitted to node-a" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sel submit "$TEMP_DIR/ext-v0.json"

    # v1: Upd authored by owner — this is owner's authoritative tip
    E_V1_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$EXT_PREFIX" --arg prev "$E_V0_SAID" \
        --arg k "$EXT_TOPIC" \
        '{said: $p, prefix: $pfx, previous: $prev, version: 1, topic: $k, kind: "kels/sad/v1/events/upd", content: "Kowner_v1_content___________________________"}')
    E_V1_SAID=$(compute_said "$E_V1_JSON")
    E_V1_JSON=$(echo "$E_V1_JSON" | jq -c --arg s "$E_V1_SAID" '.said = $s')
    run_test "Extension: v1 (owner) SAID anchored" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$EXT_KEL_PREFIX" --said "$E_V1_SAID"
    echo "[$E_V1_JSON]" > "$TEMP_DIR/ext-v1.json"
    run_test "Extension: v1 (owner) submitted to node-a" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sel submit "$TEMP_DIR/ext-v1.json"

    # v2: rogue extension (still write_policy-authorized — anchored by the same KEL).
    # In a real adversarial scenario the KEL would be controlled by a compromised
    # signer; for this script we anchor with the same KEL as a stand-in for the
    # silent-extension shape. The point being tested is that owner can repair.
    E_V2_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$EXT_PREFIX" --arg prev "$E_V1_SAID" \
        --arg k "$EXT_TOPIC" \
        '{said: $p, prefix: $pfx, previous: $prev, version: 2, topic: $k, kind: "kels/sad/v1/events/upd", content: "Krogue_v2_content___________________________"}')
    E_V2_SAID=$(compute_said "$E_V2_JSON")
    E_V2_JSON=$(echo "$E_V2_JSON" | jq -c --arg s "$E_V2_SAID" '.said = $s')
    run_test "Extension: rogue v2 SAID anchored" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$EXT_KEL_PREFIX" --said "$E_V2_SAID"
    echo "[$E_V2_JSON]" > "$TEMP_DIR/ext-v2.json"
    run_test "Extension: rogue v2 submitted to node-a (linear, no divergence)" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sel submit "$TEMP_DIR/ext-v2.json"

    EXT_PRE_EFFECTIVE=$(get_effective_said "$NODE_A_SAD_URL" "$EXT_PREFIX")
    EXT_PRE_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${EXT_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/events/effective-said" | jq -r '.divergent // false')
    run_test "Extension: chain still linear after rogue v2 (effective != divergent SAID)" [ "$EXT_PRE_DIVERGENT" = "false" ]
    run_test "Extension: rogue v2 is current effective tip" [ "$EXT_PRE_EFFECTIVE" = "$E_V2_SAID" ]

    # Owner builds Rpr@v2 with previous=v1.said. Server's truncate_and_replace
    # archives the rogue v2 and inserts the Rpr at v2.
    E_RPR_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$EXT_PREFIX" --arg prev "$E_V1_SAID" \
        --arg k "$EXT_TOPIC" \
        '{said: $p, prefix: $pfx, previous: $prev, version: 2, topic: $k, kind: "kels/sad/v1/events/rpr", content: "Krepaired_v2_content________________________"}')
    E_RPR_SAID=$(compute_said "$E_RPR_JSON")
    E_RPR_JSON=$(echo "$E_RPR_JSON" | jq -c --arg s "$E_RPR_SAID" '.said = $s')
    run_test "Extension: Rpr SAID anchored" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$EXT_KEL_PREFIX" --said "$E_RPR_SAID"
    echo "[$E_RPR_JSON]" > "$TEMP_DIR/ext-rpr.json"
    run_test "Extension: Rpr submitted to node-a" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sel submit "$TEMP_DIR/ext-rpr.json"

    EXT_POST_EFFECTIVE=$(get_effective_said "$NODE_A_SAD_URL" "$EXT_PREFIX")
    EXT_POST_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${EXT_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/events/effective-said" | jq -r '.divergent // false')
    run_test "Extension: post-repair chain still linear" [ "$EXT_POST_DIVERGENT" = "false" ]
    run_test "Extension: post-repair tip is the Rpr" [ "$EXT_POST_EFFECTIVE" = "$E_RPR_SAID" ]
fi

echo ""

# ========================================
# Scenario 9: Clean State (NothingToRepair shape)
# ========================================
echo -e "${CYAN}=== Scenario 9: Clean State (no-op repair) ===${NC}"
echo "Owner submits v0+v1. No adversary, no fork. Server's effective_said"
echo "matches owner's tip. Owner-local repair would return NothingToRepair;"
echo "this script asserts the wire-level invariant that effective_said equals"
echo "owner's last submission."
echo ""

CLEAN_TOPIC="kels/sad/v1/test-clean"

CLEAN_KEL_PREFIX=$(kels-cli --kels-url "$NODE_A_KELS_URL" kel incept 2>&1 | grep "Prefix:" | awk '{print $2}')
if [ -z "$CLEAN_KEL_PREFIX" ]; then
    echo -e "${RED}Failed to create KEL for clean-state test${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    echo "Created KEL: $CLEAN_KEL_PREFIX"

    CLEAN_POLICY_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg expr "endorse($CLEAN_KEL_PREFIX)" \
        '{said: $p, expression: $expr}')
    CLEAN_POLICY_SAID=$(compute_said "$CLEAN_POLICY_JSON")
    CLEAN_POLICY_JSON=$(echo "$CLEAN_POLICY_JSON" | jq -c --arg s "$CLEAN_POLICY_SAID" '.said = $s')
    curl -s -o /dev/null -X POST "${NODE_A_SAD_URL}/api/v1/sad" \
        -H 'Content-Type: application/json' -d "$CLEAN_POLICY_JSON"

    CLEAN_GP_SAID=$(build_governance_policy "$NODE_A_SAD_URL" "$CLEAN_KEL_PREFIX")

    C_V0_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg wp "$CLEAN_POLICY_SAID" --arg k "$CLEAN_TOPIC" \
        --arg gp "$CLEAN_GP_SAID" \
        '{said: $p, prefix: $p, version: 0, topic: $k, kind: "kels/sad/v1/events/icp", writePolicy: $wp, governancePolicy: $gp}')
    C_V0_PREFIX=$(compute_prefix "$C_V0_JSON")
    C_V0_JSON=$(echo "$C_V0_JSON" | jq -c --arg pfx "$C_V0_PREFIX" '.prefix = $pfx')
    C_V0_SAID=$(compute_said "$C_V0_JSON")
    C_V0_JSON=$(echo "$C_V0_JSON" | jq -c --arg s "$C_V0_SAID" '.said = $s')
    CLEAN_PREFIX="$C_V0_PREFIX"

    kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$CLEAN_KEL_PREFIX" --said "$C_V0_SAID" >/dev/null
    echo "[$C_V0_JSON]" > "$TEMP_DIR/clean-v0.json"
    run_test "Clean: v0 submitted to node-a" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sel submit "$TEMP_DIR/clean-v0.json"

    C_V1_JSON=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$CLEAN_PREFIX" --arg prev "$C_V0_SAID" \
        --arg k "$CLEAN_TOPIC" \
        '{said: $p, prefix: $pfx, previous: $prev, version: 1, topic: $k, kind: "kels/sad/v1/events/upd", content: "Kclean_v1_content___________________________"}')
    C_V1_SAID=$(compute_said "$C_V1_JSON")
    C_V1_JSON=$(echo "$C_V1_JSON" | jq -c --arg s "$C_V1_SAID" '.said = $s')
    kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$CLEAN_KEL_PREFIX" --said "$C_V1_SAID" >/dev/null
    echo "[$C_V1_JSON]" > "$TEMP_DIR/clean-v1.json"
    run_test "Clean: v1 submitted to node-a" \
        kels-cli --sadstore-url "$NODE_A_SAD_URL" sel submit "$TEMP_DIR/clean-v1.json"

    # Owner's tip == server's effective_said. NothingToRepair shape.
    CLEAN_EFFECTIVE=$(get_effective_said "$NODE_A_SAD_URL" "$CLEAN_PREFIX")
    CLEAN_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${CLEAN_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/events/effective-said" | jq -r '.divergent // false')
    run_test "Clean: effective SAID == owner's last submission (v1)" [ "$CLEAN_EFFECTIVE" = "$C_V1_SAID" ]
    run_test "Clean: chain not divergent" [ "$CLEAN_DIVERGENT" = "false" ]
fi

echo ""

fi # FEDERATED

print_summary "SADStore Test Summary"
exit_with_result
