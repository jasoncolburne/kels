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

# --- CESR / SAID helpers ---

PLACEHOLDER="############################################"

# Compute a CESR Blake3 SAID from a string argument.
# Prepend 00 to hex hash, convert to binary, base64url, take last 43 chars, prepend "K".
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

# Build a checkpoint policy and store it as a SAD object.
# Sets CHECKPOINT_POLICY_SAID for use in pointer JSON.
# Usage: build_checkpoint_policy "$SAD_URL" "$KEL_PREFIX"
# TODO: Production checkpoint policies should use higher thresholds than write_policy
# (e.g., threshold(3, [...]) vs threshold(2, [...])). Single-endorser is fine for tests.
build_checkpoint_policy() {
    local sad_url="$1"
    local kel_prefix="$2"
    local cp_json
    cp_json=$(jq -nc --arg p "$PLACEHOLDER" --arg expr "endorse($kel_prefix)" \
        '{said: $p, expression: $expr}')
    CHECKPOINT_POLICY_SAID=$(compute_said "$cp_json")
    cp_json=$(echo "$cp_json" | jq -c --arg s "$CHECKPOINT_POLICY_SAID" '.said = $s')
    curl -s -o /dev/null -X POST "${sad_url}/api/v1/sad" \
        -H 'Content-Type: application/json' -d "$cp_json"
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
    response=$(curl -s -w "\n%{http_code}" -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"$prefix\"}" "$url/api/v1/kels/kel/fetch")
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
        local body="{\"prefix\":\"$prefix\"}"
        if [ -n "$since" ]; then
            body="{\"prefix\":\"$prefix\",\"since\":\"$since\"}"
        fi

        local resp
        resp=$(curl -s -f -X POST -H 'Content-Type: application/json' -d "$body" "$url/api/v1/kels/kel/fetch" 2>/dev/null) || break

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

# Compute a deterministic hash of a KEL on a node (for convergence comparison).
get_kel_hash() {
    local url="$1"
    local prefix="$2"
    fetch_all_events "$url" "$prefix" | jq -cS '[.[] | .signatures |= sort_by(.label)]' | md5sum | awk '{print $1}'
}

# Check if KELs match across a list of node URLs.
# Usage: kels_match_nodes PREFIX URL1 URL2 [URL3 ...]
kels_match_nodes() {
    local prefix="$1"
    shift
    local urls=("$@")
    local first_hash
    first_hash=$(get_kel_hash "${urls[0]}" "$prefix")
    for url in "${urls[@]:1}"; do
        local h
        h=$(get_kel_hash "$url" "$prefix")
        if [ "$h" != "$first_hash" ]; then
            return 1
        fi
    done
    return 0
}

# Poll until KELs match on all given nodes (or timeout).
# Usage: wait_for_convergence PREFIX TIMEOUT URL1 URL2 [URL3 ...]
wait_for_convergence() {
    local prefix="$1"
    local timeout="$2"
    shift 2
    local urls=("$@")
    local deadline=$((SECONDS + timeout))
    echo "Waiting for KEL $prefix to converge on ${#urls[@]} nodes (timeout: ${timeout}s)..."
    while [ $SECONDS -lt $deadline ]; do
        if kels_match_nodes "$prefix" "${urls[@]}" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    kels_match_nodes "$prefix" "${urls[@]}"
}

# Poll until event count on a node reaches expected value (or timeout).
# Usage: wait_for_event_count URL PREFIX EXPECTED TIMEOUT
wait_for_event_count() {
    local url="$1"
    local prefix="$2"
    local expected="$3"
    local timeout="$4"
    local deadline=$((SECONDS + timeout))
    echo "Waiting for $expected events on $url (timeout: ${timeout}s)..."
    while [ $SECONDS -lt $deadline ]; do
        local count
        count=$(get_event_count "$url" "$prefix")
        if [ "$count" = "$expected" ]; then
            return 0
        fi
        sleep 1
    done
    echo "Timeout: expected $expected events, got $(get_event_count "$url" "$prefix")"
    return 1
}

# Check if a KEL on a node contains an event of a given kind.
# Usage: kel_has_event_kind URL PREFIX KIND
kel_has_event_kind() {
    local url="$1"
    local prefix="$2"
    local kind="$3"
    local events
    events=$(fetch_all_events "$url" "$prefix")
    echo "$events" | jq -e --arg k "$kind" '[.[].event.kind] | any(. == $k)' > /dev/null 2>&1
}

# Poll until a KEL contains a specific event kind on all given nodes (or timeout).
# Usage: wait_for_event_kind PREFIX KIND TIMEOUT URL1 URL2 [URL3 ...]
wait_for_event_kind() {
    local prefix="$1"
    local kind="$2"
    local timeout="$3"
    shift 3
    local urls=("$@")
    local deadline=$((SECONDS + timeout))
    echo "Waiting for '$kind' event in KEL $prefix on ${#urls[@]} nodes (timeout: ${timeout}s)..."
    while [ $SECONDS -lt $deadline ]; do
        local all_have=true
        for url in "${urls[@]}"; do
            if ! kel_has_event_kind "$url" "$prefix" "$kind"; then
                all_have=false
                break
            fi
        done
        if $all_have; then
            return 0
        fi
        sleep 1
    done
    echo "Timeout: not all nodes have '$kind' event"
    return 1
}

# Check if a node is either DIVERGENT or has the ror event (for scenario 4-style tests
# where the ror may protect against divergence depending on event arrival order).
# Usage: node_is_divergent_or_has_ror URL PREFIX
node_is_divergent_or_has_ror() {
    local url="$1"
    local prefix="$2"
    local status
    status=$(get_kel_status "$url" "$prefix")
    if [ "$status" = "DIVERGENT" ]; then
        return 0
    fi
    kel_has_event_kind "$url" "$prefix" "kels/events/v1/ror"
}

# Poll until all nodes are either DIVERGENT or have a ror event (or timeout).
# Usage: wait_for_divergence_or_ror PREFIX TIMEOUT URL1 URL2 [URL3 ...]
wait_for_divergence_or_ror() {
    local prefix="$1"
    local timeout="$2"
    shift 2
    local urls=("$@")
    local deadline=$((SECONDS + timeout))
    echo "Waiting for KEL $prefix to be DIVERGENT or have ROR on ${#urls[@]} nodes (timeout: ${timeout}s)..."
    while [ $SECONDS -lt $deadline ]; do
        local all_ready=true
        for url in "${urls[@]}"; do
            if ! node_is_divergent_or_has_ror "$url" "$prefix"; then
                all_ready=false
                break
            fi
        done
        if $all_ready; then
            return 0
        fi
        sleep 1
    done
    echo "Timeout: not all nodes are DIVERGENT or have ROR"
    return 1
}

# Get KEL status (OK, DIVERGENT, CONTESTED, DECOMMISSIONED) from kels-cli.
# Usage: get_kel_status URL PREFIX
get_kel_status() {
    local url="$1"
    local prefix="$2"
    kels-cli --kels-url "$url" get "$prefix" 2>&1 | grep "Status:" | sed "s/$(printf '\033')\[[0-9;]*m//g" | awk '{print $2}'
}

# Poll until KEL reaches expected status (or timeout).
# Usage: await_kel_status URL PREFIX EXPECTED_STATUS [TIMEOUT]
await_kel_status() {
    local url="$1"
    local prefix="$2"
    local expected="$3"
    local timeout="${4:-10}"
    local deadline=$((SECONDS + timeout))
    while [ $SECONDS -lt $deadline ]; do
        local actual
        actual=$(get_kel_status "$url" "$prefix")
        [ "$actual" = "$expected" ] && return 0
        sleep 1
    done
    return 1
}

# Poll until KEL is DIVERGENT on all given nodes (or timeout).
# Usage: wait_for_divergence PREFIX TIMEOUT URL1 URL2 [URL3 ...]
wait_for_divergence() {
    local prefix="$1"
    local timeout="$2"
    shift 2
    local urls=("$@")
    local deadline=$((SECONDS + timeout))
    echo "Waiting for KEL $prefix to be DIVERGENT on ${#urls[@]} nodes (timeout: ${timeout}s)..."
    while [ $SECONDS -lt $deadline ]; do
        local all_divergent=true
        for url in "${urls[@]}"; do
            local status
            status=$(get_kel_status "$url" "$prefix")
            if [ "$status" != "DIVERGENT" ]; then
                all_divergent=false
                break
            fi
        done
        if $all_divergent; then
            return 0
        fi
        sleep 1
    done
    echo "Timeout: not all nodes are DIVERGENT"
    return 1
}
