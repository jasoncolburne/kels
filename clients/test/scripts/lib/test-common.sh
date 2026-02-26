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
    response=$(curl -s -w "\n%{http_code}" "$url/api/kels/kel/$prefix")
    local http_code
    http_code=$(echo "$response" | tail -n1)
    [ "$http_code" = "200" ]
}

get_event_count() {
    local url="$1"
    local prefix="$2"
    local resp
    resp=$(curl -s -f "$url/api/kels/kel/$prefix" 2>/dev/null) || { echo 0; return; }
    echo "$resp" | jq '.events | length'
}

get_latest_said() {
    local url="$1"
    local prefix="$2"
    local resp
    resp=$(curl -s -f "$url/api/kels/kel/$prefix" 2>/dev/null) || { echo ""; return; }
    echo "$resp" | jq -r '.events | sort_by(.event.version) | .[-1].event.said // empty'
}
