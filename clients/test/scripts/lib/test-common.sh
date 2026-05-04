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

# Compute prefix for a v0 inception event (blanks both said AND prefix).
compute_prefix() {
    local json="$1"
    local with_placeholders
    with_placeholders=$(echo "$json" | jq -c --arg p "$PLACEHOLDER" '.said = $p | .prefix = $p')
    cesr_blake3 "$with_placeholders"
}

# All `kels-cli`-driven helpers below take a **CLI invocation string** as
# their first argument — typically the caller's pre-assembled
# `kels-cli --kels-url ... --sadstore-url ... [--config-dir ...]`. Passing
# the full invocation lets callers wire arbitrary flags (notably
# `--config-dir` for parallel workers that need isolated key stores)
# without each helper having to know about every flag the CLI accepts.

# Build a single-endorser immune policy SAD object via `kels-cli sad put`.
# Used as both auth_policy and governance_policy on IEL chains in tests.
# Echoes the policy SAID to stdout.
# Usage: POLICY_SAID=$(build_immune_policy "$CLI_INVOCATION" "$KEL_PREFIX")
build_immune_policy() {
    local cli_invocation="$1"
    local kel_prefix="$2"
    local tmp; tmp=$(mktemp)
    jq -nc --arg p "$PLACEHOLDER" --arg expr "endorse($kel_prefix)" \
        '{said: $p, expression: $expr, immune: true}' > "$tmp"
    local said
    said=$($cli_invocation sad put "$tmp")
    local rc=$?
    rm -f "$tmp"
    [ "$rc" -eq 0 ] || {
        echo "build_immune_policy: sad put failed for endorse($kel_prefix)" >&2
        return "$rc"
    }
    echo "$said"
}

# Build an immune 1-of-2 threshold policy SAD object that accepts either
# of two endorsers (`threshold(1, [endorse(A), endorse(B)])`). Used by
# tests that need multiple legitimate authors on the same chain — e.g.,
# a silent-extension scenario where Bob extends past Alice's
# authoritative tip. The policy DSL has no infix OR; threshold is the
# canonical disjunction.
# Echoes the policy SAID to stdout.
# Usage: POLICY_SAID=$(build_immune_or_policy "$CLI_INVOCATION" "$KEL_A" "$KEL_B")
build_immune_or_policy() {
    local cli_invocation="$1"
    local kel_a="$2"
    local kel_b="$3"
    local tmp; tmp=$(mktemp)
    jq -nc --arg p "$PLACEHOLDER" \
        --arg expr "threshold(1, [endorse($kel_a), endorse($kel_b)])" \
        '{said: $p, expression: $expr, immune: true}' > "$tmp"
    local said
    said=$($cli_invocation sad put "$tmp")
    local rc=$?
    rm -f "$tmp"
    [ "$rc" -eq 0 ] || {
        echo "build_immune_or_policy: sad put failed for threshold(1, [endorse($kel_a), endorse($kel_b)])" >&2
        return "$rc"
    }
    echo "$said"
}

# Set up a fresh IEL identity for a KEL: builds an immune single-endorser
# policy (used as both auth_policy and governance_policy), stages an Icp
# via `kels iel incept --publish`, anchors in the KEL, submits.
# Echoes IEL_PREFIX to stdout.
# Usage: IEL_PREFIX=$(setup_iel_identity "$CLI_INVOCATION" "$KEL_PREFIX")
# Optional 3rd arg: a unique tag for the IEL topic (default: random).
setup_iel_identity() {
    local cli_invocation="$1"
    local kel_prefix="$2"
    local tag="${3:-${RANDOM}-$$}"

    local policy_said
    policy_said=$(build_immune_policy "$cli_invocation" "$kel_prefix")

    setup_iel_identity_with_policy "$cli_invocation" "$kel_prefix" "$policy_said" "$tag"
}

# Set up a fresh IEL identity using a pre-built policy SAID. The same
# policy serves as both `auth_policy` and `governance_policy`. The IEL
# Icp is anchored by `anchor_kel` regardless of the policy's expression
# — the anchor only needs to satisfy the policy at submit time. Used by
# tests that need multi-endorser policies (e.g., the silent-extension
# scenario where Alice and Bob are both legitimate endorsers under an
# OR policy).
# Echoes IEL_PREFIX to stdout.
# Usage: IEL_PREFIX=$(setup_iel_identity_with_policy "$CLI_INVOCATION" "$ANCHOR_KEL" "$POLICY_SAID")
# Optional 4th arg: a unique tag for the IEL topic (default: random).
setup_iel_identity_with_policy() {
    local cli_invocation="$1"
    local anchor_kel="$2"
    local policy_said="$3"
    local tag="${4:-${RANDOM}-$$}"
    local topic="kels/iel/v1/identity/test-${tag}"

    # Error checking is explicit because `local var=$(cmd)` always returns
    # the exit status of `local`, which is 0. Without these guards a
    # silent timeout in `iel submit` lets the caller proceed with an
    # IEL prefix the server never actually committed — the next
    # `sel incept` then fails with a confusing `IEL not found`.
    local icp_said
    icp_said=$($cli_invocation iel incept "$topic" \
        --auth-policy "$policy_said" \
        --governance-policy "$policy_said" \
        --publish) || {
        echo "setup_iel_identity_with_policy: iel incept failed for tag $tag" >&2
        return 1
    }

    $cli_invocation kel anchor --prefix "$anchor_kel" --said "$icp_said" >/dev/null || {
        echo "setup_iel_identity_with_policy: kel anchor failed for icp $icp_said (anchor KEL $anchor_kel)" >&2
        return 1
    }

    # Multi-node race fix: `iel submit` triggers an IEL gossip
    # announcement that fan out to peers, who then try to verify the
    # IEL against their local KEL view of `anchor_kel`. If the anchor
    # `Ixn` hasn't propagated to those peers yet, IEL verification
    # fails permanently (IEL has no anti-entropy fallback). Wait for
    # the anchor to converge first if the caller has defined a
    # `wait_for_kel_anchor_convergence` helper (test-sadstore.sh
    # multi-node mode); otherwise (single-node tests) skip.
    if [ "$(type -t wait_for_kel_anchor_convergence)" = "function" ]; then
        wait_for_kel_anchor_convergence "$anchor_kel" "$icp_said" || {
            echo "setup_iel_identity_with_policy: KEL anchor for icp $icp_said did not converge to peers" >&2
            return 1
        }
    fi

    $cli_invocation iel submit "$icp_said" >/dev/null || {
        echo "setup_iel_identity_with_policy: iel submit failed for icp $icp_said" >&2
        return 1
    }

    local iel_prefix
    iel_prefix=$($cli_invocation sad get "$icp_said" | jq -r '.prefix') || {
        echo "setup_iel_identity_with_policy: failed to read icp $icp_said back from SAD store" >&2
        return 1
    }
    if [ -z "$iel_prefix" ] || [ "$iel_prefix" = "null" ]; then
        echo "setup_iel_identity_with_policy: icp $icp_said missing prefix in SAD payload" >&2
        return 1
    fi
    echo "$iel_prefix"
}

# Put a JSON content blob as a SAD object via `kels-cli sad put`.
# The input file should have `said: "############..."` placeholder; the
# CLI computes the SAID and posts. Echoes the resulting SAID to stdout.
# Usage: CONTENT_SAID=$(put_sad_object "$CLI_INVOCATION" "$JSON_FILE_PATH")
put_sad_object() {
    local cli_invocation="$1"
    local file="$2"
    $cli_invocation sad put "$file"
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
    kel_has_event_kind "$url" "$prefix" "kels/kel/v1/events/ror"
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

# --- KEL anchor convergence (cross-chain race resolution) ---

# Fetch the effective SAID of a KEL on a given KELS URL.
# Returns empty string on error or 404.
# Usage: get_kel_effective_said URL PREFIX
get_kel_effective_said() {
    local url="$1"
    local prefix="$2"
    curl -sf -X POST -H 'Content-Type: application/json' \
        -d "{\"prefix\":\"${prefix}\"}" \
        "${url}/api/v1/kels/kel/effective-said" | jq -r '.said // empty'
}

# Wait for `kel_prefix`'s effective SAID on every peer KELS to match the
# origin KELS's. This removes the cross-chain race from tests that anchor
# a SAID in the origin node's KEL and then submit an IEL/SEL event
# referencing it: the SAD/IEL gossip announcement can reach peers before
# the KEL `Ixn` anchor, peer verification fails the policy-anchor check,
# and the announcement is silently dropped (AE eventually reconciles
# but past test timeouts).
#
# Reads two globals (set by the calling test script):
#   KELS_ORIGIN_URL  — KELS URL where the anchor was just written.
#   KELS_PEER_URLS   — array of peer KELS URLs that need to converge.
#                      Empty/unset → no-op (single-node mode).
#
# Production gossip is deliberately offline-tolerant; this convergence
# wait lives only in the test harness — NOT on the post-#147 production
# submit path.
#
# `said_label` is informational only, surfaced in timeout messages.
# Usage: wait_for_kel_anchor_convergence KEL_PREFIX SAID_LABEL [TIMEOUT]
wait_for_kel_anchor_convergence() {
    local kel_prefix="$1"
    local said_label="$2"
    local timeout="${3:-${CONVERGENCE_TIMEOUT:-30}}"

    # Single-node mode: no peers to converge to.
    if [ -z "${KELS_PEER_URLS+x}" ] || [ "${#KELS_PEER_URLS[@]}" -eq 0 ]; then
        return 0
    fi
    if [ -z "${KELS_ORIGIN_URL:-}" ]; then
        echo "wait_for_kel_anchor_convergence: KELS_ORIGIN_URL must be set when KELS_PEER_URLS is non-empty" >&2
        return 1
    fi

    local origin_eff
    origin_eff=$(get_kel_effective_said "$KELS_ORIGIN_URL" "$kel_prefix")
    if [ -z "$origin_eff" ]; then
        echo "wait_for_kel_anchor_convergence: failed to read origin KEL effective SAID for $kel_prefix at $KELS_ORIGIN_URL" >&2
        return 1
    fi

    local peer_url
    for peer_url in "${KELS_PEER_URLS[@]}"; do
        local deadline=$((SECONDS + timeout))
        local peer_eff=""
        while [ $SECONDS -lt $deadline ]; do
            peer_eff=$(get_kel_effective_said "$peer_url" "$kel_prefix")
            if [ "$peer_eff" = "$origin_eff" ]; then
                break
            fi
            sleep 1
        done
        if [ "$peer_eff" != "$origin_eff" ]; then
            echo "wait_for_kel_anchor_convergence: $kel_prefix did not converge to $peer_url for anchor $said_label (got '$peer_eff', expected '$origin_eff')" >&2
            return 1
        fi
    done
    return 0
}

# Get KEL kel status (OK, DIVERGENT, CONTESTED, DECOMMISSIONED) from kels-cli.
# Usage: get_kel_status URL PREFIX
get_kel_status() {
    local url="$1"
    local prefix="$2"
    kels-cli --kels-url "$url" kel get "$prefix" 2>&1 | grep "Status:" | sed "s/$(printf '\033')\[[0-9;]*m//g" | awk '{print $2}'
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
