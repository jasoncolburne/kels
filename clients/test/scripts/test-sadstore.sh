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
# #147 migration. All happy-path scenarios drive the post-#147 CLI
# surface: `kels iel incept` for identity setup, `kels sel incept` for
# atomic [Icp, Upd] inception, `kels sel update` for content advances,
# `kels sel repair` for divergence resolution, `kels kel anchor` for the
# KEL Ixn anchors, and `kels {iel,sel} submit` for the multi-device flow's
# submit step. Scenarios 1, 2, 4 retain direct-curl negative tests against
# the SADStore HTTP surface (these test the server's API behavior, not
# the CLI flow).

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
FEDERATED="${FEDERATED:-true}"
PROPAGATION_DELAY="${PROPAGATION_DELAY:-5}"
CONVERGENCE_TIMEOUT="${CONVERGENCE_TIMEOUT:-30}"
NODE_A_SADSTORE_HOST="${NODE_A_SADSTORE_HOST:-sadstore}"
NODE_B_SADSTORE_HOST="${NODE_B_SADSTORE_HOST:-sadstore.node-b.kels}"
NODE_A_KELS_HOST="${NODE_A_KELS_HOST:-kels}"
NODE_B_KELS_HOST="${NODE_B_KELS_HOST:-kels.node-b.kels}"
# Dummy CESR values for test endpoints that skip auth but still deserialize
MOCK_SAID="KMOCK_SAID__________________________________"
MOCK_PREFIX="KMOCK_PREFIX________________________________"
MOCK_SIGNATURE="0CMOCK_SIGNATURE________________________________________________________________________"
MOCK_CREATED_AT="2026-01-01T00:00:00.000000Z"
MOCK_NONCE="NMOCK_NONCE_________________________________"

NODE_A_SAD_URL="http://${NODE_A_SADSTORE_HOST}"
NODE_B_SAD_URL="http://${NODE_B_SADSTORE_HOST}"
NODE_A_KELS_URL="http://${NODE_A_KELS_HOST}"
NODE_B_KELS_URL="http://${NODE_B_KELS_HOST}"

# CLI invocations that target a specific node need BOTH URLs because any
# command that triggers verification (`sel get`, `sel update`, `sel repair`,
# `sel incept`, `iel evolve`, `iel contest`, `iel decommission`, `iel get`)
# uses a checker that walks the KEL service for anchor checks. `sel submit`
# and `kel anchor` are exceptions — they don't run the verifier — but
# wiring both URLs uniformly keeps the call sites simple.
NODE_A_CLI="kels-cli --kels-url $NODE_A_KELS_URL --sadstore-url $NODE_A_SAD_URL"
NODE_B_CLI="kels-cli --kels-url $NODE_B_KELS_URL --sadstore-url $NODE_B_SAD_URL"

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

# Submit event with tampered SAID (#147 Icp shape: identity-rooted, no policy fields)
run_test "Submit tampered SAID rejected" \
    bash -c "[ \$(curl -s -o /dev/null -w '%{http_code}' -X POST '${NODE_A_SAD_URL}/api/v1/sad/events' -H 'Content-Type: application/json' -d '[{\"said\":\"KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"prefix\":\"KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB\",\"version\":0,\"topic\":\"test\",\"kind\":\"kels/sad/v1/events/icp\",\"identity\":\"KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC\"}]') = '400' ]"

echo ""

# ========================================
# Scenario 3: Prefix Computation
# ========================================
echo -e "${CYAN}=== Scenario 3: Prefix Computation ===${NC}"
echo ""

PREFIX_A=$(kels-cli sel prefix "Kid_a_______________________________________" "kels/sad/v1/test-mlkem" 2>/dev/null)
PREFIX_B=$(kels-cli sel prefix "Kid_a_______________________________________" "kels/sad/v1/test-mlkem" 2>/dev/null)
run_test "Prefix is deterministic" [ "$PREFIX_A" = "$PREFIX_B" ]

PREFIX_C=$(kels-cli sel prefix "Kid_b_______________________________________" "kels/sad/v1/test-mlkem" 2>/dev/null)
run_test "Different identity -> different SEL prefix" [ "$PREFIX_A" != "$PREFIX_C" ]

PREFIX_D=$(kels-cli sel prefix "Kid_a_______________________________________" "kels/sad/v1/test-other" 2>/dev/null)
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
echo "Create KEL + IEL identity, set up content object, drive sel incept"
echo "(atomic [Icp, Upd]) → anchor → sel submit. Verify chain via sel get."
echo ""

SAD_TOPIC="kels/sad/v1/test-data"

# Create a KEL on node-a to use as the chain owner
KEL_PREFIX=$(kels-cli --kels-url "$NODE_A_KELS_URL" kel incept 2>&1 | grep "Prefix:" | awk '{print $2}')
if [ -z "$KEL_PREFIX" ]; then
    echo -e "${RED}Failed to create KEL${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    echo "Created KEL: $KEL_PREFIX"

    # Set up an IEL identity bound to the KEL
    IEL_PREFIX=$(setup_iel_identity "$NODE_A_CLI" "$KEL_PREFIX" "scenario5")
    run_test "IEL identity created" [ -n "$IEL_PREFIX" ]
    echo "IEL prefix: $IEL_PREFIX"

    # Compute SEL prefix from (identity, topic) — #147 derivation
    SEL_PREFIX=$(kels-cli sel prefix "$IEL_PREFIX" "$SAD_TOPIC" 2>/dev/null)
    echo "SEL prefix: $SEL_PREFIX"
    run_test "SEL prefix computed" [ -n "$SEL_PREFIX" ]

    run_test "Chain does not exist yet" \
        bash -c "[ \$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{\"prefix\":\"${SEL_PREFIX}\"}' '${NODE_A_SAD_URL}/api/v1/sad/events/fetch') = '404' ]"

    # Put initial content object
    echo "{\"said\":\"$PLACEHOLDER\",\"value\":\"scenario5-v1-content\"}" > "$TEMP_DIR/scenario5-content.json"
    CONTENT_SAID=$(put_sad_object "$NODE_A_CLI" "$TEMP_DIR/scenario5-content.json")
    run_test "Content SAD object stored" [ -n "$CONTENT_SAID" ]

    # Stage atomic [Icp, Upd] via sel incept
    SE_OUTPUT=$($NODE_A_CLI sel incept "$SAD_TOPIC" \
        --identity "$IEL_PREFIX" --initial-content "$CONTENT_SAID" --publish 2>&1)
    ICP_SAID=$(echo "$SE_OUTPUT" | head -1)
    UPD_SAID=$(echo "$SE_OUTPUT" | tail -1)
    run_test "sel incept printed Icp + Upd SAIDs" [ -n "$ICP_SAID" -a -n "$UPD_SAID" -a "$ICP_SAID" != "$UPD_SAID" ]

    # Anchor both SAIDs in the KEL
    run_test "Icp SAID anchored in KEL" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$KEL_PREFIX" --said "$ICP_SAID"
    run_test "Upd SAID anchored in KEL" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$KEL_PREFIX" --said "$UPD_SAID"

    # Submit the atomic batch via sel submit
    run_test "Inception batch [Icp, Upd] submitted via CLI (sel submit)" \
        $NODE_A_CLI sel submit "$ICP_SAID" "$UPD_SAID"

    # Fetch the chain via kels-cli sel get
    CHAIN_OUTPUT=$($NODE_A_CLI sel get "$SEL_PREFIX" 2>/dev/null)
    CHAIN_LEN=$(echo "$CHAIN_OUTPUT" | jq '.events | length' 2>/dev/null)
    run_test "Chain fetched via CLI (sel get) with 2 events" [ "$CHAIN_LEN" = "2" ]

    # Wait for gossip propagation and verify chain on node-b
    if [ "$FEDERATED" = "true" ]; then
        run_test "Chain propagated to node-b" \
            wait_for_chain_propagation "$SEL_PREFIX" "$UPD_SAID" "$CONVERGENCE_TIMEOUT" "$NODE_B_SAD_URL"
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
SAD_SAID=$($NODE_A_CLI sad put "$TEMP_DIR/test-object.json" 2>/dev/null)
run_test "SAD object stored via CLI (sad put)" [ -n "$SAD_SAID" ]

if [ -n "$SAD_SAID" ]; then
    echo "Stored SAD object: $SAD_SAID"

    run_test "Object exists on node-a" sad_object_exists "$NODE_A_SAD_URL" "$SAD_SAID"

    # GET via CLI and verify the content
    GET_OUTPUT=$($NODE_A_CLI sad get "$SAD_SAID" 2>/dev/null)
    GET_SAID=$(echo "$GET_OUTPUT" | jq -r '.said // empty' 2>/dev/null)
    run_test "SAD object retrieved via CLI (sad get)" [ "$GET_SAID" = "$SAD_SAID" ]

    GET_FIELD=$(echo "$GET_OUTPUT" | jq -r '.testField // empty' 2>/dev/null)
    run_test "Retrieved object content matches" [ "$GET_FIELD" = "$UNIQUE_VALUE" ]

    if [ "$FEDERATED" = "true" ]; then
        # Wait for gossip propagation to node-b
        run_test "Object propagated to node-b" \
            wait_for_sad_object_propagation "$SAD_SAID" "$CONVERGENCE_TIMEOUT" "$NODE_B_SAD_URL"

        # GET from node-b via CLI
        GET_B_SAID=$($NODE_B_CLI sad get "$SAD_SAID" 2>/dev/null | jq -r '.said // empty' 2>/dev/null)
        run_test "Object retrievable from node-b via CLI (sad get)" [ "$GET_B_SAID" = "$SAD_SAID" ]
    fi
fi

echo ""

if [ "$FEDERATED" = "true" ]; then

# ========================================
# Scenario 7: Divergence Detection + Repair
# ========================================
echo -e "${CYAN}=== Scenario 7: Divergence Detection + Repair ===${NC}"
echo "Create a chain via sel incept (atomic [Icp, Upd@v1]), then stage two"
echo "competing v2 Upd events against different nodes via sel update"
echo "BEFORE submitting either (each builder hydrates from its own node's"
echo "view of [v0, v1]). Submit both in parallel — divergence at v2."
echo "Resolve via sel repair on node-a."
echo ""

DIV_TOPIC="kels/sad/v1/test-diverge"

# Create a KEL for the divergence test
DIV_KEL_PREFIX=$(kels-cli --kels-url "$NODE_A_KELS_URL" kel incept 2>&1 | grep "Prefix:" | awk '{print $2}')
if [ -z "$DIV_KEL_PREFIX" ]; then
    echo -e "${RED}Failed to create KEL for divergence test${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    echo "Created KEL: $DIV_KEL_PREFIX"

    DIV_IEL_PREFIX=$(setup_iel_identity "$NODE_A_CLI" "$DIV_KEL_PREFIX" "scenario7")
    run_test "Divergence: IEL identity created" [ -n "$DIV_IEL_PREFIX" ]

    DIV_PREFIX=$(kels-cli sel prefix "$DIV_IEL_PREFIX" "$DIV_TOPIC" 2>/dev/null)
    echo "SEL prefix: $DIV_PREFIX"

    # Initial content for sel incept
    echo "{\"said\":\"$PLACEHOLDER\",\"value\":\"scenario7-initial\"}" > "$TEMP_DIR/div-content-initial.json"
    DIV_CONTENT_INIT=$(put_sad_object "$NODE_A_CLI" "$TEMP_DIR/div-content-initial.json")

    # Stage atomic [Icp, Upd@v1] via sel incept
    DIV_INCEPT_OUT=$($NODE_A_CLI sel incept "$DIV_TOPIC" \
        --identity "$DIV_IEL_PREFIX" --initial-content "$DIV_CONTENT_INIT" --publish 2>&1)
    D_ICP_SAID=$(echo "$DIV_INCEPT_OUT" | head -1)
    D_V1_SAID=$(echo "$DIV_INCEPT_OUT" | tail -1)

    run_test "Divergence: Icp SAID anchored" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$DIV_KEL_PREFIX" --said "$D_ICP_SAID"
    run_test "Divergence: v1 (Upd) SAID anchored" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$DIV_KEL_PREFIX" --said "$D_V1_SAID"

    run_test "Divergence: [Icp, v1] submitted to node-a" \
        $NODE_A_CLI sel submit "$D_ICP_SAID" "$D_V1_SAID"

    # Wait for [Icp, v1] to propagate to node-b — both nodes share the same
    # v1 tip before we stage competing v2 updates.
    run_test "Divergence: [Icp, v1] propagated to node-b" \
        wait_for_chain_propagation "$DIV_PREFIX" "$D_V1_SAID" "$CONVERGENCE_TIMEOUT" "$NODE_B_SAD_URL"

    # Put two distinct v2 content objects (one per node)
    echo "{\"said\":\"$PLACEHOLDER\",\"value\":\"scenario7-content-a\"}" > "$TEMP_DIR/div-content-a.json"
    echo "{\"said\":\"$PLACEHOLDER\",\"value\":\"scenario7-content-b\"}" > "$TEMP_DIR/div-content-b.json"
    DIV_CONTENT_A=$(put_sad_object "$NODE_A_CLI" "$TEMP_DIR/div-content-a.json")
    DIV_CONTENT_B=$(put_sad_object "$NODE_B_CLI" "$TEMP_DIR/div-content-b.json")

    # Stage two competing v2 Upd events against the two nodes BEFORE
    # submitting either. Each `sel update` invocation hydrates from its
    # own node's view (still [v0, v1]) and stages a v2 extending v1.
    D_V2A_SAID=$($NODE_A_CLI sel update "$DIV_PREFIX" "$DIV_CONTENT_A" --publish)
    D_V2B_SAID=$($NODE_B_CLI sel update "$DIV_PREFIX" "$DIV_CONTENT_B" --publish)

    run_test "Divergence: v2-a and v2-b have different SAIDs" [ "$D_V2A_SAID" != "$D_V2B_SAID" ]

    # Anchor both v2 SAIDs (anchors propagate via gossip, but we wait
    # explicitly for each to reach the peer KEL)
    run_test "Divergence: v2-a SAID anchored" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$DIV_KEL_PREFIX" --said "$D_V2A_SAID"
    run_test "Divergence: v2-b SAID anchored" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$DIV_KEL_PREFIX" --said "$D_V2B_SAID"

    # Submit each to its own node — divergence is created at v2 once both
    # commits land server-side and gossip converges.
    run_test "Divergence: v2-a submitted to node-a" \
        $NODE_A_CLI sel submit "$D_V2A_SAID"
    run_test "Divergence: v2-b submitted to node-b" \
        $NODE_B_CLI sel submit "$D_V2B_SAID"

    # Wait for both nodes to detect divergence and agree on effective SAID
    run_test "Divergence: both nodes converge on divergent state" \
        wait_for_sad_event_divergence_convergence "$DIV_PREFIX" "$CONVERGENCE_TIMEOUT" "$NODE_A_SAD_URL" "$NODE_B_SAD_URL"

    A_EFFECTIVE=$(get_effective_said "$NODE_A_SAD_URL" "$DIV_PREFIX")
    B_EFFECTIVE=$(get_effective_said "$NODE_B_SAD_URL" "$DIV_PREFIX")
    A_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${DIV_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/events/effective-said" | jq -r '.divergent // false')
    B_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${DIV_PREFIX}\"}" "${NODE_B_SAD_URL}/api/v1/sad/events/effective-said" | jq -r '.divergent // false')
    echo "Node-a effective: $A_EFFECTIVE (divergent: $A_DIVERGENT)"
    echo "Node-b effective: $B_EFFECTIVE (divergent: $B_DIVERGENT)"

    # Repair via sel repair (builder discovers boundary, builds Rpr@v2)
    D_REPAIR_SAID=$($NODE_A_CLI sel repair "$DIV_PREFIX" --publish)
    run_test "Repair: sel repair printed Rpr SAID" [ -n "$D_REPAIR_SAID" ]

    run_test "Repair: SAID anchored" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$DIV_KEL_PREFIX" --said "$D_REPAIR_SAID"

    run_test "Repair: submitted to node-a" \
        $NODE_A_CLI sel submit "$D_REPAIR_SAID"

    A_POST_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${DIV_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/events/effective-said" | jq -r '.divergent // false')
    A_POST_EFFECTIVE=$(get_effective_said "$NODE_A_SAD_URL" "$DIV_PREFIX")
    run_test "Repair: node-a no longer divergent" [ "$A_POST_DIVERGENT" = "false" ]
    run_test "Repair: node-a tip is repair event" [ "$A_POST_EFFECTIVE" = "$D_REPAIR_SAID" ]

    REPAIR_COUNT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${DIV_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/events/repairs" | jq '.repairs | length')
    run_test "Repair: audit entry created" [ "$REPAIR_COUNT" -ge 1 ]

    run_test "Repair: propagated to node-b" \
        wait_for_chain_propagation "$DIV_PREFIX" "$D_REPAIR_SAID" "$CONVERGENCE_TIMEOUT" "$NODE_B_SAD_URL"
fi

echo ""

# ========================================
# Scenario 8: Silent Adversarial Extension + Repair
# ========================================
echo -e "${CYAN}=== Scenario 8: Silent Adversarial Extension + Repair ===${NC}"
echo "Two-KEL setup with an OR policy: Alice and Bob can both author."
echo "Alice incepts and updates to v2_Alice. Bob silently extends with"
echo "v3_Bob (anchored only by Bob's KEL). Alice runs sel repair with"
echo "--owner-prefix \$ALICE_KEL — the builder walks Alice's KEL"
echo "anchors, identifies v3_Bob as the rogue boundary, and stages an"
echo "Rpr@v3 with previous=v2_Alice.said."
echo ""

EXT_TOPIC="kels/sad/v1/test-extension"

ALICE_KEL=$(kels-cli --kels-url "$NODE_A_KELS_URL" kel incept 2>&1 | grep "Prefix:" | awk '{print $2}')
BOB_KEL=$(kels-cli --kels-url "$NODE_A_KELS_URL" kel incept 2>&1 | grep "Prefix:" | awk '{print $2}')
if [ -z "$ALICE_KEL" ] || [ -z "$BOB_KEL" ]; then
    echo -e "${RED}Failed to create KELs for extension test${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    echo "Alice KEL: $ALICE_KEL"
    echo "Bob KEL:   $BOB_KEL"

    # Disjunctive OR policy — both Alice and Bob are legitimate endorsers.
    EXT_OR_POLICY=$(build_immune_or_policy "$NODE_A_CLI" "$ALICE_KEL" "$BOB_KEL")
    run_test "Extension: OR policy uploaded" [ -n "$EXT_OR_POLICY" ]

    # IEL identity, anchored by Alice. Both Alice and Bob can author SE
    # events on chains under this identity (the OR policy gates auth).
    EXT_IEL=$(setup_iel_identity_with_policy "$NODE_A_CLI" "$ALICE_KEL" "$EXT_OR_POLICY" "scenario8")
    run_test "Extension: IEL identity created" [ -n "$EXT_IEL" ]
    EXT_PREFIX=$(kels-cli sel prefix "$EXT_IEL" "$EXT_TOPIC" 2>/dev/null)
    echo "SEL prefix: $EXT_PREFIX"

    # Alice incepts the SEL chain (atomic [Icp, v1]).
    echo "{\"said\":\"$PLACEHOLDER\",\"value\":\"scenario8-initial\"}" > "$TEMP_DIR/ext-content-init.json"
    EXT_CONTENT_INIT=$(put_sad_object "$NODE_A_CLI" "$TEMP_DIR/ext-content-init.json")

    EXT_INCEPT_OUT=$($NODE_A_CLI sel incept "$EXT_TOPIC" \
        --identity "$EXT_IEL" --initial-content "$EXT_CONTENT_INIT" --publish 2>&1)
    E_ICP_SAID=$(echo "$EXT_INCEPT_OUT" | head -1)
    E_V1_SAID=$(echo "$EXT_INCEPT_OUT" | tail -1)

    run_test "Extension: Icp anchored by Alice" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$ALICE_KEL" --said "$E_ICP_SAID"
    run_test "Extension: v1 anchored by Alice" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$ALICE_KEL" --said "$E_V1_SAID"
    run_test "Extension: [Icp, v1] submitted" \
        $NODE_A_CLI sel submit "$E_ICP_SAID" "$E_V1_SAID"

    # v2: Alice's authoritative update.
    echo "{\"said\":\"$PLACEHOLDER\",\"value\":\"scenario8-alice-v2\"}" > "$TEMP_DIR/ext-content-alice.json"
    EXT_CONTENT_ALICE=$(put_sad_object "$NODE_A_CLI" "$TEMP_DIR/ext-content-alice.json")
    E_V2_ALICE=$($NODE_A_CLI sel update "$EXT_PREFIX" "$EXT_CONTENT_ALICE" --publish)
    run_test "Extension: v2 (Alice) anchored by Alice" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$ALICE_KEL" --said "$E_V2_ALICE"
    run_test "Extension: v2 (Alice) submitted" \
        $NODE_A_CLI sel submit "$E_V2_ALICE"

    # v3: Bob silently extends. The OR policy authorizes Bob; the chain
    # accepts. Bob anchors v3 with HIS KEL, not Alice's — that's what
    # makes it "silent" from Alice's perspective.
    echo "{\"said\":\"$PLACEHOLDER\",\"value\":\"scenario8-bob-v3-rogue\"}" > "$TEMP_DIR/ext-content-bob.json"
    EXT_CONTENT_BOB=$(put_sad_object "$NODE_A_CLI" "$TEMP_DIR/ext-content-bob.json")
    E_V3_BOB=$($NODE_A_CLI sel update "$EXT_PREFIX" "$EXT_CONTENT_BOB" --publish)
    run_test "Extension: rogue v3 (Bob) anchored by Bob" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$BOB_KEL" --said "$E_V3_BOB"
    run_test "Extension: rogue v3 (Bob) submitted" \
        $NODE_A_CLI sel submit "$E_V3_BOB"

    EXT_PRE_TIP=$(get_chain_tip_said "$NODE_A_SAD_URL" "$EXT_PREFIX")
    EXT_PRE_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${EXT_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/events/effective-said" | jq -r '.divergent // false')
    run_test "Extension: chain still linear after rogue v3" [ "$EXT_PRE_DIVERGENT" = "false" ]
    run_test "Extension: rogue v3 is current effective tip" [ "$EXT_PRE_TIP" = "$E_V3_BOB" ]

    # Alice repairs. Builder walks Alice's KEL anchors, identifies v3 as
    # not-Alice-anchored, builds Rpr@v3 with previous=v2_Alice.said.
    E_RPR_SAID=$($NODE_A_CLI sel repair "$EXT_PREFIX" \
        --owner-prefix "$ALICE_KEL" --publish)
    run_test "Extension: sel repair printed Rpr SAID" [ -n "$E_RPR_SAID" ]

    run_test "Extension: Rpr anchored by Alice" \
        kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$ALICE_KEL" --said "$E_RPR_SAID"
    run_test "Extension: Rpr submitted" \
        $NODE_A_CLI sel submit "$E_RPR_SAID"

    EXT_POST_TIP=$(get_effective_said "$NODE_A_SAD_URL" "$EXT_PREFIX")
    EXT_POST_DIVERGENT=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"${EXT_PREFIX}\"}" "${NODE_A_SAD_URL}/api/v1/sad/events/effective-said" | jq -r '.divergent // false')
    run_test "Extension: post-repair chain still linear" [ "$EXT_POST_DIVERGENT" = "false" ]
    run_test "Extension: post-repair tip is the Rpr" [ "$EXT_POST_TIP" = "$E_RPR_SAID" ]
fi

echo ""

# ========================================
# Scenario 9: Clean State (NothingToRepair shape)
# ========================================
echo -e "${CYAN}=== Scenario 9: Clean State (no-op repair) ===${NC}"
echo "Owner stages atomic [Icp, Upd@v1] via sel incept. No adversary, no fork."
echo "Server's effective_said matches the owner's last-submitted tip."
echo ""

CLEAN_TOPIC="kels/sad/v1/test-clean"

CLEAN_KEL_PREFIX=$(kels-cli --kels-url "$NODE_A_KELS_URL" kel incept 2>&1 | grep "Prefix:" | awk '{print $2}')
if [ -z "$CLEAN_KEL_PREFIX" ]; then
    echo -e "${RED}Failed to create KEL for clean-state test${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    echo "Created KEL: $CLEAN_KEL_PREFIX"

    CLEAN_IEL_PREFIX=$(setup_iel_identity "$NODE_A_CLI" "$CLEAN_KEL_PREFIX" "scenario9")
    run_test "Clean: IEL identity created" [ -n "$CLEAN_IEL_PREFIX" ]
    CLEAN_PREFIX=$(kels-cli sel prefix "$CLEAN_IEL_PREFIX" "$CLEAN_TOPIC" 2>/dev/null)

    echo "{\"said\":\"$PLACEHOLDER\",\"value\":\"scenario9-v1-content\"}" > "$TEMP_DIR/clean-content.json"
    CLEAN_CONTENT=$(put_sad_object "$NODE_A_CLI" "$TEMP_DIR/clean-content.json")

    CLEAN_INCEPT_OUT=$($NODE_A_CLI sel incept "$CLEAN_TOPIC" \
        --identity "$CLEAN_IEL_PREFIX" --initial-content "$CLEAN_CONTENT" --publish 2>&1)
    C_ICP_SAID=$(echo "$CLEAN_INCEPT_OUT" | head -1)
    C_V1_SAID=$(echo "$CLEAN_INCEPT_OUT" | tail -1)

    kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$CLEAN_KEL_PREFIX" --said "$C_ICP_SAID" >/dev/null
    kels-cli --kels-url "$NODE_A_KELS_URL" kel anchor --prefix "$CLEAN_KEL_PREFIX" --said "$C_V1_SAID" >/dev/null

    run_test "Clean: [Icp, v1] submitted to node-a" \
        $NODE_A_CLI sel submit "$C_ICP_SAID" "$C_V1_SAID"

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
