#!/usr/bin/env bash
# test-common.sh - Shared utilities for KELS integration tests.
# Source this at the top of each test script.

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test state
TESTS_PASSED=0
TESTS_FAILED=0

# --- Core test functions ---

run_test() {
    local name="$1"
    shift
    echo -e "${YELLOW}Testing: ${name}${NC}"
    local output
    if output=$("$@" 2>&1); then
        echo "$output"
        echo -e "${GREEN}PASSED: ${name}${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo "$output"
        echo -e "${RED}FAILED: ${name}${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

run_test_expect_fail() {
    local name="$1"
    shift
    echo -e "${YELLOW}Testing (expect fail): ${name}${NC}"
    local output
    if output=$("$@" 2>&1); then
        echo "$output"
        echo -e "${RED}FAILED: ${name} (expected failure but succeeded)${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    else
        echo -e "${GREEN}PASSED: ${name}${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi
}

print_summary() {
    local suite_name="$1"
    echo ""
    echo -e "${CYAN}=========================================${NC}"
    echo "$suite_name"
    echo -e "${CYAN}=========================================${NC}"
    echo -e "Passed: ${GREEN}${TESTS_PASSED}${NC}"
    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "Failed: ${RED}${TESTS_FAILED}${NC}"
    else
        echo -e "Failed: ${GREEN}${TESTS_FAILED}${NC}"
    fi
    echo -e "${CYAN}=========================================${NC}"
}

exit_with_result() {
    if [ $TESTS_FAILED -gt 0 ]; then
        exit 1
    fi
}

# --- Setup helpers ---

init_temp_dir() {
    TEMP_DIR=$(mktemp -d)
    export KELS_CLI_HOME="$TEMP_DIR"
    trap 'rm -rf "$TEMP_DIR"' EXIT
}

wait_for_health() {
    local url="$1"
    local label="$2"
    local timeout="${3:-30}"
    for i in $(seq 1 "$timeout"); do
        if curl -s "$url/health" > /dev/null 2>&1; then
            echo "  $label is ready"
            return 0
        fi
        if [ "$i" -eq "$timeout" ]; then
            echo -e "${RED}${label} not ready after ${timeout} seconds${NC}"
            return 1
        fi
        sleep 1
    done
}

# --- KEL helpers ---

kel_exists_on_node() {
    local url="$1"
    local prefix="$2"
    local response
    response=$(curl -s -w "\n%{http_code}" "$url/api/v1/kels/kel/$prefix")
    local http_code
    http_code=$(echo "$response" | tail -n1)
    [ "$http_code" = "200" ]
}

# Fetch all events for a prefix, paginating through all pages.
# Outputs a JSON array of all signed events.
# No max-page guard — test scripts run against known-good servers with finite KELs.
fetch_all_events() {
    local url="$1"
    local prefix="$2"
    local all_events="[]"
    local since=""

    while true; do
        local query_url="$url/api/v1/kels/kel/$prefix"
        if [ -n "$since" ]; then
            query_url="${query_url}?since=${since}"
        fi

        local resp
        resp=$(curl -s -f "$query_url" 2>/dev/null) || break

        local events has_more
        events=$(echo "$resp" | jq '.events')
        has_more=$(echo "$resp" | jq '.hasMore')

        if [ "$(echo "$events" | jq 'length')" -eq 0 ]; then
            break
        fi

        all_events=$(printf '%s\n%s' "$all_events" "$events" | jq -s '[.[0][], .[1][] | .signatures |= sort_by(.label)]')

        if [ "$has_more" != "true" ]; then
            break
        fi

        since=$(echo "$events" | jq -r '.[-1].event.said')
    done

    echo "$all_events"
}

# Wait for async recovery archival to complete for a prefix.
# The background task runs every 5s and needs multiple cycles
# (pending → archiving → cleanup → recovered), so this polls
# the audit endpoint until the latest recovery record reaches
# the terminal "recovered" state.
wait_for_recovery_complete() {
    local url="$1"
    local prefix="$2"
    local timeout="${3:-30}"
    echo "Waiting for recovery archival to complete (timeout: ${timeout}s)..."
    for _ in $(seq 1 $((timeout * 5))); do
        local latest_state
        latest_state=$(curl -s "$url/api/v1/kels/kel/$prefix/audit" | jq -r '.[-1].state // empty')
        [ "$latest_state" = "recovered" ] && return 0
        sleep 0.2
    done
    echo "Recovery did not complete within ${timeout}s (latest state: $latest_state)"
    return 1
}

get_event_count() {
    local url="$1"
    local prefix="$2"
    local events
    events=$(fetch_all_events "$url" "$prefix")
    echo "$events" | jq 'length'
}

# Wait for a KEL to propagate to all given node URLs.
# Usage: wait_for_propagation PREFIX TIMEOUT URL1 URL2 ...
wait_for_propagation() {
    local prefix="$1"
    local timeout="$2"
    shift 2
    local urls=("$@")

    for url in "${urls[@]}"; do
        local converged=false
        for attempt in $(seq 1 "$timeout"); do
            if kel_exists_on_node "$url" "$prefix"; then
                converged=true
                break
            fi
            sleep 1
        done
        if [ "$converged" != "true" ]; then
            echo -e "${RED}KEL $prefix did not propagate to $url within ${timeout}s${NC}"
            return 1
        fi
    done
    return 0
}

get_latest_said() {
    local url="$1"
    local prefix="$2"
    local events
    events=$(fetch_all_events "$url" "$prefix")
    echo "$events" | jq -r 'sort_by(.event.serial) | .[-1].event.said // empty'
}
