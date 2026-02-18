#!/bin/bash
# test-resync.sh - Periodic Resync / Retry Queue Integration Tests
# Tests that failed gossip fetches are queued and resolved by the resync loop.
#
# Two modes:
#   test-resync.sh setup   — run with node-b DNS already broken
#   test-resync.sh verify  — run after node-b DNS is repaired
#
# The Makefile orchestrates: break DNS → setup → repair DNS → verify.
#
# Usage: test-resync.sh <setup|verify>
#
# Environment variables:
#   NODE_A_KELS_HOST  - node-a KELS hostname (default: kels)
#   NODE_A_REDIS_HOST - node-a Redis hostname (default: redis)
#   RESYNC_WAIT       - seconds to wait for resync loop (default: 20)

MODE="${1:-}"
if [ "$MODE" != "setup" ] && [ "$MODE" != "verify" ]; then
    echo "Usage: $0 <setup|verify>"
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
NODE_A_URL="http://${NODE_A_KELS_HOST:-kels}"
NODE_B_FQDN_URL="http://kels.kels-node-b.svc.cluster.local"
REDIS_HOST="${NODE_A_REDIS_HOST:-redis}"
RESYNC_WAIT="${RESYNC_WAIT:-30}"
RETRY_QUEUE_KEY="kels:resync:retry"
STATE_FILE="/tmp/resync-test-state"

# Test state
TESTS_PASSED=0
TESTS_FAILED=0
TEMP_DIR=$(mktemp -d)
export KELS_CLI_HOME="$TEMP_DIR"

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Test helpers
run_test() {
    local name="$1"
    shift
    echo -e "${YELLOW}Testing: ${name}${NC}"
    local output
    if output=$("$@" 2>&1); then
        echo "$output"
        echo -e "${GREEN}PASSED: ${name}${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo "$output"
        echo -e "${RED}FAILED: ${name}${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Redis helpers
redis_cmd() {
    redis-cli -h "$REDIS_HOST" "$@"
}

queue_count() {
    redis_cmd SCARD "$RETRY_QUEUE_KEY"
}

queue_add() {
    redis_cmd SADD "$RETRY_QUEUE_KEY" "$1"
}

queue_clear() {
    redis_cmd DEL "$RETRY_QUEUE_KEY"
}

queue_members() {
    redis_cmd SMEMBERS "$RETRY_QUEUE_KEY"
}

# KEL helpers
get_event_count() {
    local url="$1"
    local prefix="$2"
    local resp
    resp=$(curl -s -f "$url/api/kels/kel/$prefix" 2>/dev/null) || { echo 0; return; }
    echo "$resp" | jq 'if type == "array" then length else 0 end'
}

get_latest_said() {
    local url="$1"
    local prefix="$2"
    local resp
    resp=$(curl -s -f "$url/api/kels/kel/$prefix" 2>/dev/null) || { echo ""; return; }
    echo "$resp" | jq -r 'if type == "array" then sort_by(.event.version) | .[-1].event.said // empty else empty end'
}

print_summary() {
    local suite_name="$1"
    echo ""
    echo "========================================="
    echo "$suite_name"
    echo "========================================="
    echo -e "Passed: ${GREEN}${TESTS_PASSED}${NC}"
    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "Failed: ${RED}${TESTS_FAILED}${NC}"
    else
        echo -e "Failed: ${GREEN}${TESTS_FAILED}${NC}"
    fi
    echo "========================================="
}

# =====================================================================
# SETUP MODE — DNS for node-b is broken
# =====================================================================
if [ "$MODE" = "setup" ]; then
    echo "========================================="
    echo "KELS Resync Test Suite — Setup Phase"
    echo "========================================="
    echo "Node-A URL:       $NODE_A_URL"
    echo "Node-B FQDN URL:  $NODE_B_FQDN_URL"
    echo "Redis Host:        $REDIS_HOST"
    echo "========================================="
    echo ""

    # Wait for node-a KELS to be ready
    echo "Waiting for KELS servers..."
    for url in "$NODE_A_URL" "$NODE_B_FQDN_URL"; do
        for i in {1..30}; do
            if curl -s "$url/health" > /dev/null 2>&1; then
                echo "  $url is ready"
                break
            fi
            if [ $i -eq 30 ]; then
                echo -e "${RED}$url not ready after 30 seconds${NC}"
                exit 1
            fi
            sleep 1
        done
    done
    echo ""

    # ========================================
    # Scenario 1: Seed fake entry
    # ========================================
    echo -e "${CYAN}=== Scenario 1: Seed Fake Entry ===${NC}"
    echo "Add a fake retry queue entry (should be dropped during verify)"
    echo ""

    queue_clear > /dev/null
    FAKE_ENTRY="fakeprefix:Efakesaid000000000000000000000000000000000000"
    queue_add "$FAKE_ENTRY" > /dev/null

    COUNT=$(queue_count)
    run_test "Fake entry seeded (SCARD == 1)" [ "$COUNT" = "1" ]

    echo ""

    # ========================================
    # Scenario 2: Create real fetch failure
    # ========================================
    echo -e "${CYAN}=== Scenario 2: Trigger Real Fetch Failure ===${NC}"
    echo "Create KEL on node-a, submit two ixns to node-b via FQDN."
    echo "Use the first ixn as a sync point, then verify the second fails to fetch."
    echo ""

    # Wait for DNS caches to expire so .kels lookups for node-b actually fail.
    # When run via test-comprehensive, DNS_CACHE_TTL=2 is set on CoreDNS before
    # tests start, so node-level caches expire within seconds of CoreDNS restart.
    echo "Waiting for DNS caches to expire (kels.kels-node-b.kels must fail)..."
    for i in {1..60}; do
        if ! nslookup kels.kels-node-b.kels > /dev/null 2>&1; then
            echo "  DNS broken after ${i}s"
            break
        fi
        if [ $i -eq 60 ]; then
            echo -e "${RED}DNS for kels.kels-node-b.kels still resolves after 60s${NC}"
            exit 1
        fi
        sleep 1
    done

    # Brief additional wait for node-level DNS caches (NodeLocal DNSCache, etc.)
    # on other K8s nodes where gossip pods may run. With DNS_CACHE_TTL=2 set at
    # the start of test-comprehensive, stale entries expire within 2s.
    sleep 5
    echo ""

    # Create KEL on node-a
    PREFIX=$(kels-cli -u "$NODE_A_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
    echo "Created KEL on node-a: $PREFIX"

    # Wait for gossip to propagate the icp to node-b (poll instead of fixed sleep)
    echo "Waiting for icp to propagate to node-b..."
    NODE_B_COUNT=0
    for i in {1..30}; do
        NODE_B_COUNT=$(get_event_count "$NODE_B_FQDN_URL" "$PREFIX")
        if [ "$NODE_B_COUNT" = "1" ]; then
            echo "  Propagated after ${i}s"
            break
        fi
        sleep 1
    done

    echo "Node-B event count: $NODE_B_COUNT"
    run_test "KEL propagated to node-b" [ "$NODE_B_COUNT" = "1" ]

    # Submit first ixn (sync event) to node-b via FQDN
    echo "Submitting sync anchor (ixn #1) to node-b via FQDN..."
    SYNC_SAID="EResyncSyncAnchor___________________________"
    kels-cli -u "$NODE_B_FQDN_URL" anchor --prefix "$PREFIX" --said "$SYNC_SAID"

    # Get the sync event's SAID from node-b
    SYNC_EVENT_SAID=$(get_latest_said "$NODE_B_FQDN_URL" "$PREFIX")
    echo "Sync event SAID: $SYNC_EVENT_SAID"

    # Wait for the gossip handler to process the sync announcement.
    # Two possible outcomes:
    #   - Fetch succeeded (DNS cache/connection pool still alive): node-a count == 2
    #   - Fetch failed (DNS properly broken): entry appears in retry queue
    # Either way, the gossip handler has finished with the sync event.
    echo "Waiting for sync event to be processed..."
    SYNC_FETCHED=false
    SYNC_ENTRY="${PREFIX}:${SYNC_EVENT_SAID}"
    for i in {1..30}; do
        NODE_A_COUNT=$(get_event_count "$NODE_A_URL" "$PREFIX")
        if [ "$NODE_A_COUNT" = "2" ]; then
            echo "  Sync event fetched directly after ${i}s"
            SYNC_FETCHED=true
            break
        fi
        MEMBERS=$(queue_members 2>/dev/null)
        if echo "$MEMBERS" | grep -qF "$SYNC_ENTRY"; then
            echo "  Sync event queued (DNS confirmed broken) after ${i}s"
            break
        fi
        sleep 1
    done

    # Submit second ixn (test event) to node-b via FQDN.
    # By now, DNS caches and HTTP connection pools should be stale.
    echo "Submitting test anchor (ixn #2) to node-b via FQDN..."
    TEST_SAID="EResyncTestAnchor___________________________"
    kels-cli -u "$NODE_B_FQDN_URL" anchor --prefix "$PREFIX" --said "$TEST_SAID"

    # Get the new SAID from node-b
    NODE_B_SAID=$(get_latest_said "$NODE_B_FQDN_URL" "$PREFIX")
    echo "Node-B latest SAID: $NODE_B_SAID"

    # Wait for gossip announcement + fetch attempt for the test event
    echo "Waiting for gossip announcement + fetch failure..."
    sleep 5

    # Log retry queue state (informational — may be empty if resync loop is mid-cycle)
    COUNT=$(queue_count)
    echo "Retry queue size: $COUNT"

    # Verify node-a does NOT have the test ixn yet.
    # Expected count depends on whether the sync event's fetch succeeded:
    #   - Sync fetched: count == 2 (icp + sync ixn, missing test ixn)
    #   - Sync queued:  count == 1 (icp only, missing both ixns)
    NODE_A_COUNT=$(get_event_count "$NODE_A_URL" "$PREFIX")
    if [ "$SYNC_FETCHED" = "true" ]; then
        EXPECTED_COUNT=2
    else
        EXPECTED_COUNT=1
    fi
    echo "Node-A event count: $NODE_A_COUNT (should be $EXPECTED_COUNT, missing test ixn)"
    run_test "Node-A missing test ixn (count == $EXPECTED_COUNT)" [ "$NODE_A_COUNT" = "$EXPECTED_COUNT" ]

    # Save state for verify phase
    echo "$PREFIX" > "$STATE_FILE"

    echo ""
    echo "Queue contents:"
    queue_members
    echo ""

    print_summary "Resync Setup Phase Summary"

    if [ $TESTS_FAILED -gt 0 ]; then
        exit 1
    fi
fi

# =====================================================================
# VERIFY MODE — DNS for node-b is repaired
# =====================================================================
if [ "$MODE" = "verify" ]; then
    echo "========================================="
    echo "KELS Resync Test Suite — Verify Phase"
    echo "========================================="
    echo "Node-A URL:      $NODE_A_URL"
    echo "Redis Host:       $REDIS_HOST"
    echo "Resync Wait:      ${RESYNC_WAIT}s"
    echo "========================================="
    echo ""

    # Load state from setup phase
    if [ ! -f "$STATE_FILE" ]; then
        echo -e "${RED}State file not found — run setup first${NC}"
        exit 1
    fi
    PREFIX=$(cat "$STATE_FILE")
    echo "Prefix from setup: $PREFIX"
    echo ""

    # ========================================
    # Wait for resync loop (poll instead of fixed sleep)
    # ========================================
    echo -e "${CYAN}=== Waiting for Resync Loop ===${NC}"
    echo "Polling up to ${RESYNC_WAIT}s for the periodic resync loop to resolve entries..."

    RESYNC_RESOLVED=false
    for i in $(seq 1 "$RESYNC_WAIT"); do
        NODE_A_COUNT=$(get_event_count "$NODE_A_URL" "$PREFIX")
        QUEUE_SIZE=$(queue_count)
        if [ "$NODE_A_COUNT" = "3" ] && [ "$QUEUE_SIZE" = "0" ]; then
            echo "  Resync resolved after ${i}s"
            RESYNC_RESOLVED=true
            break
        fi
        sleep 1
    done

    if [ "$RESYNC_RESOLVED" = "false" ]; then
        echo "  Resync did not fully resolve within ${RESYNC_WAIT}s"
    fi
    echo ""

    # ========================================
    # Verify: All entries resolved
    # ========================================
    echo -e "${CYAN}=== Verify: All Entries Resolved ===${NC}"
    echo "Node-a should have all events and retry queue should be empty"
    echo ""

    NODE_A_COUNT=$(get_event_count "$NODE_A_URL" "$PREFIX")
    echo "Node-A event count: $NODE_A_COUNT (should be 3)"
    run_test "Node-A has all events (count == 3)" [ "$NODE_A_COUNT" = "3" ]

    COUNT=$(queue_count)
    echo "Retry queue size: $COUNT"
    if [ "$COUNT" != "0" ]; then
        echo "Remaining queue contents:"
        queue_members
    fi
    run_test "Retry queue is empty" [ "$COUNT" = "0" ]

    echo ""
    print_summary "Resync Verify Phase Summary"

    # Clean up state file
    rm -f "$STATE_FILE"

    if [ $TESTS_FAILED -gt 0 ]; then
        exit 1
    fi
fi
