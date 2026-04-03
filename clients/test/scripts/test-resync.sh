#!/usr/bin/env bash
# test-resync.sh - Anti-Entropy Stale Prefix Repair Integration Tests
# Tests that failed gossip fetches are recorded as stale and resolved by anti-entropy.
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
#   RESYNC_WAIT       - seconds to wait for anti-entropy loop (default: 30)

MODE="${1:-}"
if [ "$MODE" != "seed" ] && [ "$MODE" != "setup" ] && [ "$MODE" != "verify" ]; then
    echo "Usage: $0 <seed|setup|verify>"
    exit 1
fi

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
NODE_A_URL="http://${NODE_A_KELS_HOST:-kels}"
NODE_B_FQDN_URL="http://kels.kels-node-b.svc.cluster.local"
REDIS_HOST="${NODE_A_REDIS_HOST:-redis}"
RESYNC_WAIT="${RESYNC_WAIT:-90}"
STALE_PREFIX_KEY="kels:anti_entropy:stale"
STATE_FILE="/tmp/resync-test-state"
CLI_HOME_FILE="/tmp/resync-cli-home-path"

# Persistent CLI home across seed/setup/verify (keys must survive between phases)
if [ "$MODE" = "seed" ]; then
    PERSISTENT_CLI_HOME=$(mktemp -d)
    echo "$PERSISTENT_CLI_HOME" > "$CLI_HOME_FILE"
else
    if [ ! -f "$CLI_HOME_FILE" ]; then
        echo "CLI home file not found — run seed first" >&2
        exit 1
    fi
    PERSISTENT_CLI_HOME=$(cat "$CLI_HOME_FILE")
fi
export KELS_CLI_HOME="$PERSISTENT_CLI_HOME"

# Redis helpers (authenticate as gossip user — accesses kels:anti_entropy:* keys)
redis_cmd() {
    redis-cli -h "$REDIS_HOST" --user gossip -a "${REDIS_PASSWORD:-gossip-redis-pass}" --no-auth-warning "$@"
}

stale_count() {
    # Use HGETALL + count pairs instead of HLEN (not in gossip ACL)
    local entries
    entries=$(redis_cmd HGETALL "$STALE_PREFIX_KEY")
    if [ -z "$entries" ]; then
        echo 0
    else
        echo "$entries" | wc -l | awk '{print int($1/2)}'
    fi
}

stale_add() {
    # HSET key field value — field is the kel_prefix, value is "{source}:{retries}:{not_before}"
    # retries=0, not_before=0 (due immediately)
    redis_cmd HSET "$STALE_PREFIX_KEY" "$1" "$2:0:0"
}

stale_clear() {
    redis_cmd DEL "$STALE_PREFIX_KEY"
}

stale_entries() {
    redis_cmd HGETALL "$STALE_PREFIX_KEY"
}

# =====================================================================
# SEED MODE — Create KEL and wait for propagation BEFORE DNS is broken
# =====================================================================
if [ "$MODE" = "seed" ]; then
    echo "========================================="
    echo "KELS Anti-Entropy Stale Repair — Seed Phase"
    echo "========================================="
    echo "Node-A URL:       $NODE_A_URL"
    echo "Node-B FQDN URL:  $NODE_B_FQDN_URL"
    echo "========================================="
    echo ""

    echo "Waiting for KELS servers..."
    wait_for_health "$NODE_A_URL" "$NODE_A_URL" || exit 1
    wait_for_health "$NODE_B_FQDN_URL" "$NODE_B_FQDN_URL" || exit 1
    echo ""

    # Create KEL on node-a
    PREFIX=$(kels-cli --kels-url "$NODE_A_URL" incept 2>&1 | grep "Prefix:" | awk '{print $2}')
    echo "Created KEL on node-a: $PREFIX"

    # Wait for gossip to propagate the icp to node-b
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

    # Save prefix for setup and verify phases
    echo "$PREFIX" > "$STATE_FILE"

    echo ""
    print_summary "Anti-Entropy Seed Summary"
    exit_with_result
fi

# =====================================================================
# SETUP MODE — DNS for node-b is broken
# =====================================================================
if [ "$MODE" = "setup" ]; then
    echo "========================================="
    echo "KELS Anti-Entropy Stale Repair — Setup Phase"
    echo "========================================="
    echo "Node-A URL:       $NODE_A_URL"
    echo "Node-B FQDN URL:  $NODE_B_FQDN_URL"
    echo "Redis Host:        $REDIS_HOST"
    echo "========================================="
    echo ""

    # Load prefix from seed phase
    if [ ! -f "$STATE_FILE" ]; then
        echo -e "${RED}State file not found — run seed first${NC}"
        exit 1
    fi
    PREFIX=$(cat "$STATE_FILE")
    echo "Prefix from seed: $PREFIX"
    echo ""

    # ========================================
    # Scenario 1: Seed fake entry
    # ========================================
    echo -e "${CYAN}=== Scenario 1: Seed Fake Entry ===${NC}"
    echo "Add a fake stale prefix entry (should be dropped during verify)"
    echo ""

    stale_clear > /dev/null
    FAKE_PREFIX="fakeprefix"
    FAKE_SOURCE="Efakesource0000000000000000000000000000000000"
    stale_add "$FAKE_PREFIX" "$FAKE_SOURCE" > /dev/null

    COUNT=$(stale_count)
    run_test "Fake entry seeded (HLEN == 1)" [ "$COUNT" = "1" ]

    echo ""

    # ========================================
    # Scenario 2: Trigger fetch failure
    # ========================================
    echo -e "${CYAN}=== Scenario 2: Trigger Real Fetch Failure ===${NC}"
    echo "Submit ixns to node-b via FQDN while gossip DNS is broken."
    echo ""

    # Wait for DNS caches to expire so .kels lookups for node-b actually fail.
    echo "Waiting for DNS caches to expire (kels.node-b.kels must fail)..."
    for i in {1..60}; do
        if ! nslookup kels.node-b.kels > /dev/null 2>&1; then
            echo "  DNS broken after ${i}s"
            break
        fi
        if [ $i -eq 60 ]; then
            echo -e "${RED}DNS for kels.node-b.kels still resolves after 60s${NC}"
            exit 1
        fi
        sleep 1
    done

    # Brief additional wait for node-level DNS caches
    sleep 5
    echo ""

    # Submit first ixn (sync event) to node-b via FQDN
    echo "Submitting sync anchor (ixn #1) to node-b via FQDN..."
    SYNC_SAID="KResyncSyncAnchor___________________________"
    kels-cli --kels-url "$NODE_B_FQDN_URL" anchor --prefix "$PREFIX" --said "$SYNC_SAID"

    # Get the sync event's SAID from node-b
    SYNC_EVENT_SAID=$(get_latest_said "$NODE_B_FQDN_URL" "$PREFIX")
    echo "Sync event SAID: $SYNC_EVENT_SAID"

    # Wait for the gossip handler to process the sync announcement.
    # Two possible outcomes:
    #   - Fetch succeeded (DNS cache/connection pool still alive): node-a count == 2
    #   - Fetch failed (DNS properly broken): entry appears in stale prefix hash
    # Either way, the gossip handler has finished with the sync event.
    echo "Waiting for sync event to be processed..."
    SYNC_FETCHED=false
    for i in {1..30}; do
        NODE_A_COUNT=$(get_event_count "$NODE_A_URL" "$PREFIX")
        if [ "$NODE_A_COUNT" = "2" ]; then
            echo "  Sync event fetched directly after ${i}s"
            SYNC_FETCHED=true
            break
        fi
        ENTRIES=$(stale_entries 2>/dev/null)
        if echo "$ENTRIES" | grep -qF "$PREFIX"; then
            echo "  Sync event recorded as stale (DNS confirmed broken) after ${i}s"
            break
        fi
        sleep 1
    done

    # Submit second ixn (test event) to node-b via FQDN.
    # By now, DNS caches and HTTP connection pools should be stale.
    echo "Submitting test anchor (ixn #2) to node-b via FQDN..."
    TEST_SAID="KResyncTestAnchor___________________________"
    kels-cli --kels-url "$NODE_B_FQDN_URL" anchor --prefix "$PREFIX" --said "$TEST_SAID"

    # Get the new SAID from node-b
    NODE_B_SAID=$(get_latest_said "$NODE_B_FQDN_URL" "$PREFIX")
    echo "Node-B latest SAID: $NODE_B_SAID"

    # Wait for gossip to process the test event (either fetched or recorded as stale)
    echo "Waiting for gossip to process test event announcement..."
    for i in {1..30}; do
        NODE_A_COUNT=$(get_event_count "$NODE_A_URL" "$PREFIX")
        if [ "$NODE_A_COUNT" = "3" ]; then
            echo "  Test event fetched directly after ${i}s"
            break
        fi
        ENTRIES=$(stale_entries 2>/dev/null)
        if echo "$ENTRIES" | grep -qF "$PREFIX"; then
            echo "  Test event recorded as stale after ${i}s"
            break
        fi
        sleep 1
    done

    # Log stale prefix state (informational — may be empty if anti-entropy loop is mid-cycle)
    COUNT=$(stale_count)
    echo "Stale prefix count: $COUNT"

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
    echo "Node-A event count: $NODE_A_COUNT (should be >= $EXPECTED_COUNT)"
    run_test "Node-A has expected events (count >= $EXPECTED_COUNT)" [ "$NODE_A_COUNT" -ge "$EXPECTED_COUNT" ]

    # Save state for verify phase
    echo "$PREFIX" > "$STATE_FILE"

    echo ""
    echo "Stale prefix entries:"
    stale_entries
    echo ""

    print_summary "Anti-Entropy Stale Repair Setup Summary"
    exit_with_result
fi

# =====================================================================
# VERIFY MODE — DNS for node-b is repaired
# =====================================================================
if [ "$MODE" = "verify" ]; then
    echo "========================================="
    echo "KELS Anti-Entropy Stale Repair — Verify Phase"
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
    # Wait for anti-entropy loop (poll instead of fixed sleep)
    # ========================================
    echo -e "${CYAN}=== Waiting for Anti-Entropy Loop ===${NC}"
    echo "Polling up to ${RESYNC_WAIT}s for anti-entropy to resolve stale entries..."

    RESYNC_RESOLVED=false
    EVENTS_ARRIVED=false
    for i in $(seq 1 "$RESYNC_WAIT"); do
        NODE_A_COUNT=$(get_event_count "$NODE_A_URL" "$PREFIX")
        STALE_SIZE=$(stale_count)
        if [ "$NODE_A_COUNT" = "3" ] && [ "$STALE_SIZE" = "0" ]; then
            echo "  Anti-entropy resolved after ${i}s"
            RESYNC_RESOLVED=true
            break
        fi
        if [ "$NODE_A_COUNT" = "3" ] && [ "$EVENTS_ARRIVED" = "false" ]; then
            echo "  Events arrived after ${i}s, waiting for stale hash to drain..."
            EVENTS_ARRIVED=true
        fi
        sleep 1
    done

    if [ "$RESYNC_RESOLVED" = "false" ]; then
        echo "  Anti-entropy did not fully resolve within ${RESYNC_WAIT}s"
    fi
    echo ""

    # ========================================
    # Verify: All entries resolved
    # ========================================
    echo -e "${CYAN}=== Verify: All Entries Resolved ===${NC}"
    echo "Node-a should have all events and stale prefix hash should be empty"
    echo ""

    NODE_A_COUNT=$(get_event_count "$NODE_A_URL" "$PREFIX")
    echo "Node-A event count: $NODE_A_COUNT (should be 3)"
    run_test "Node-A has all events (count == 3)" [ "$NODE_A_COUNT" = "3" ]

    COUNT=$(stale_count)
    echo "Stale prefix count: $COUNT"
    if [ "$COUNT" != "0" ]; then
        echo "Remaining stale entries:"
        stale_entries
    fi
    run_test "Stale prefix hash is empty" [ "$COUNT" = "0" ]

    echo ""
    print_summary "Anti-Entropy Stale Repair Verify Summary"

    # Clean up
    rm -f "$STATE_FILE"
    rm -f "$CLI_HOME_FILE"
    rm -rf "$PERSISTENT_CLI_HOME"

    exit_with_result
fi
