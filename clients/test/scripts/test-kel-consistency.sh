#!/usr/bin/env bash
# test-consistency.sh - Deep KEL Consistency Verification
# Compares all prefixes and KEL contents across all nodes to ensure consistency.
#
# For each node, fetches all prefixes, then for each prefix fetches the full KEL.
# Verifies:
#   1. All nodes have the same set of prefixes
#   2. All prefixes have the same number of events on each node
#   3. A SHA-256 digest of each KEL matches across all nodes
#   4. For mismatched KELs, behavioral state (normal/frozen/recovered/contested/decommissioned)
#      is consistent across nodes
#
# Usage: test-consistency.sh
#
# Environment variables:
#   NODE_A_KELS_HOST - node-a KELS hostname (default: kels)
#   NODE_B_KELS_HOST - node-b KELS hostname (default: kels.node-b.kels)
#   NODE_C_KELS_HOST - node-c KELS hostname (default: kels.node-c.kels)
#   NODE_D_KELS_HOST - node-d KELS hostname (default: kels.node-d.kels)
#   NODE_E_KELS_HOST - node-e KELS hostname (default: kels.node-e.kels)
#   NODE_F_KELS_HOST - node-f KELS hostname (default: kels.node-f.kels)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
NODE_A_KELS_HOST="${NODE_A_KELS_HOST:-kels}"
NODE_B_KELS_HOST="${NODE_B_KELS_HOST:-kels.node-b.kels}"
NODE_C_KELS_HOST="${NODE_C_KELS_HOST:-kels.node-c.kels}"
NODE_D_KELS_HOST="${NODE_D_KELS_HOST:-kels.node-d.kels}"
NODE_E_KELS_HOST="${NODE_E_KELS_HOST:-kels.node-e.kels}"
NODE_F_KELS_HOST="${NODE_F_KELS_HOST:-kels.node-f.kels}"

declare -a NODE_NAMES=(a b c d e f)
declare -a NODE_URLS=(
    "http://${NODE_A_KELS_HOST}"
    "http://${NODE_B_KELS_HOST}"
    "http://${NODE_C_KELS_HOST}"
    "http://${NODE_D_KELS_HOST}"
    "http://${NODE_E_KELS_HOST}"
    "http://${NODE_F_KELS_HOST}"
)

# Dummy CESR values for test endpoints that skip auth but still deserialize
DUMMY_PREFIX="KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
DUMMY_SIGNATURE="0CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# Nodes with KELS_TEST_ENDPOINTS enabled (unauthenticated test prefixes endpoint)
declare -a PREFIX_NODE_NAMES=(a b d)
declare -a PREFIX_NODE_URLS=(
    "http://${NODE_A_KELS_HOST}"
    "http://${NODE_B_KELS_HOST}"
    "http://${NODE_D_KELS_HOST}"
)

init_temp_dir

FAILURES=0

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  KEL Consistency Verification${NC}"
echo -e "${CYAN}========================================${NC}"
echo

# --- Step 1: Fetch all prefixes from test-endpoint nodes (a, b, d) ---
# These nodes have KELS_TEST_ENDPOINTS=true, exposing /api/test/prefixes without auth.
# We POST a mock signed request (auth is skipped on the test endpoint).
echo -e "${YELLOW}Fetching prefixes from test-endpoint nodes...${NC}"

declare -a REACHABLE_NAMES=()
declare -a REACHABLE_URLS=()

for i in "${!PREFIX_NODE_NAMES[@]}"; do
    name="${PREFIX_NODE_NAMES[$i]}"
    url="${PREFIX_NODE_URLS[$i]}"
    prefix_file="$TEMP_DIR/prefixes_${name}.txt"

    cursor=""
    > "$prefix_file"

    reachable=true
    while true; do
        # Build JSON body for signed prefixes request
        if [ -n "$cursor" ]; then
            body=$(jq -n --arg cursor "$cursor" --arg nonce "$(openssl rand -hex 32)" '{payload:{timestamp:0,nonce:$nonce,cursor:$cursor,limit:1000},prefix:"'"$DUMMY_PREFIX"'",signature:"'"$DUMMY_SIGNATURE"'"}')
        else
            body=$(jq -n --arg nonce "$(openssl rand -hex 32)" '{payload:{timestamp:0,nonce:$nonce,cursor:null,limit:1000},prefix:"'"$DUMMY_PREFIX"'",signature:"'"$DUMMY_SIGNATURE"'"}')
        fi

        response=$(curl -sf -X POST -H 'Content-Type: application/json' -d "$body" "${url}/api/test/prefixes" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo -e "  node-${name}: ${RED}unreachable${NC}"
            reachable=false
            break
        fi

        # Extract prefixes and append
        echo "$response" | jq -r '.prefixes[].prefix' >> "$prefix_file" 2>/dev/null

        # Check for next page
        cursor=$(echo "$response" | jq -r '.nextCursor // empty' 2>/dev/null)
        if [ -z "$cursor" ]; then
            break
        fi
    done

    if $reachable; then
        count=$(wc -l < "$prefix_file" | tr -d ' ')
        echo -e "  node-${name}: ${GREEN}${count} prefixes${NC}"
        REACHABLE_NAMES+=("$name")
        REACHABLE_URLS+=("$url")
    fi
done

echo

if [ ${#REACHABLE_NAMES[@]} -lt 2 ]; then
    echo -e "${RED}Fewer than 2 dev-tools nodes reachable for prefix fetching, cannot compare.${NC}"
    exit 1
fi

# Build list of all reachable nodes (all 6) for KEL comparison
declare -a ALL_REACHABLE_NAMES=()
declare -a ALL_REACHABLE_URLS=()

for i in "${!NODE_NAMES[@]}"; do
    name="${NODE_NAMES[$i]}"
    url="${NODE_URLS[$i]}"

    # Quick health check
    if curl -sf "${url}/health" > /dev/null 2>&1; then
        ALL_REACHABLE_NAMES+=("$name")
        ALL_REACHABLE_URLS+=("$url")
    fi
done

echo -e "${YELLOW}${#ALL_REACHABLE_NAMES[@]} nodes reachable for KEL comparison${NC}"
echo

# --- Step 2: Compare prefix sets (across dev-tools nodes) ---
echo -e "${YELLOW}Comparing prefix sets...${NC}"

reference_name="${REACHABLE_NAMES[0]}"
reference_file="$TEMP_DIR/prefixes_${reference_name}.txt"
sort -o "$reference_file" "$reference_file"

all_match=true
for i in "${!REACHABLE_NAMES[@]}"; do
    [ "$i" -eq 0 ] && continue
    name="${REACHABLE_NAMES[$i]}"
    other_file="$TEMP_DIR/prefixes_${name}.txt"
    sort -o "$other_file" "$other_file"

    if ! diff -q "$reference_file" "$other_file" > /dev/null 2>&1; then
        all_match=false
        echo -e "  ${RED}MISMATCH: node-${reference_name} vs node-${name}${NC}"

        only_ref=$(comm -23 "$reference_file" "$other_file" | wc -l | tr -d ' ')
        only_other=$(comm -13 "$reference_file" "$other_file" | wc -l | tr -d ' ')

        [ "$only_ref" -gt 0 ] && echo -e "    ${only_ref} prefixes only on node-${reference_name}"
        [ "$only_other" -gt 0 ] && echo -e "    ${only_other} prefixes only on node-${name}"
        ((FAILURES++))
    fi
done

if $all_match; then
    total=$(wc -l < "$reference_file" | tr -d ' ')
    echo -e "  ${GREEN}All ${#REACHABLE_NAMES[@]} nodes have the same ${total} prefixes${NC}"
fi

echo

# --- Step 3: For each prefix, compare event counts and KEL digests ---
echo -e "${YELLOW}Comparing KELs across nodes...${NC}"

# Use the union of all prefixes
cat "$TEMP_DIR"/prefixes_*.txt | sort -u > "$TEMP_DIR/all_prefixes.txt"
total_prefixes=$(wc -l < "$TEMP_DIR/all_prefixes.txt" | tr -d ' ')
checked=0
kel_mismatches=0
count_mismatches=0
state_mismatches=0
behaviorally_consistent=0

while IFS= read -r prefix; do
    ((checked++))
    printf "\r  Checking prefix %d/%d..." "$checked" "$total_prefixes"

    declare -a digests=()
    declare -a counts=()
    declare -a states=()
    declare -a digest_names=()

    for i in "${!ALL_REACHABLE_NAMES[@]}"; do
        name="${ALL_REACHABLE_NAMES[$i]}"
        url="${ALL_REACHABLE_URLS[$i]}"

        all_events=$(fetch_all_events "${url}" "${prefix}")
        if [ "$(echo "$all_events" | jq 'length')" -eq 0 ]; then
            digests+=("MISSING")
            counts+=("0")
            states+=("missing")
            digest_names+=("$name")
            continue
        fi

        event_count=$(echo "$all_events" | jq 'length' 2>/dev/null)
        digest=$(echo "$all_events" | jq -cS '[.[] | .signatures |= sort_by(.label)]' | sha256sum | awk '{print $1}')

        # Determine behavioral state from event kinds and structure
        state=$(echo "$all_events" | jq -r '
            [.[].event.kind] as $kinds |
            if ($kinds | any(. == "kels/events/v1/cnt")) then "contested"
            elif ($kinds | any(. == "kels/events/v1/dec")) then "decommissioned"
            elif ($kinds | any(. == "kels/events/v1/rec" or . == "kels/events/v1/ror")) then "recovered"
            elif ([.[].event.previous | select(. != null)] | group_by(.) | any(length > 1)) then "frozen"
            else "normal"
            end
        ' 2>/dev/null)

        digests+=("$digest")
        counts+=("$event_count")
        states+=("${state:-unknown}")
        digest_names+=("$name")
    done

    # Check if all nodes agree this KEL is contested — contested KELs may
    # have different event counts/digests depending on how far archival
    # progressed before the contest arrived, but the terminal state is
    # consistent and absolute.
    unique_states=$(printf '%s\n' "${states[@]}" | sort -u | wc -l | tr -d ' ')
    all_contested=false
    if [ "$unique_states" -eq 1 ] && [ "${states[0]}" = "contested" ]; then
        all_contested=true
    fi

    # Compare counts
    unique_counts=$(printf '%s\n' "${counts[@]}" | sort -u | wc -l | tr -d ' ')
    if [ "$unique_counts" -ne 1 ]; then
        if $all_contested; then
            echo
            echo -e "  ${YELLOW}EVENT COUNT DIFFERS for contested ${prefix} (OK — terminal state)${NC}"
        else
            echo
            echo -e "  ${RED}EVENT COUNT MISMATCH for ${prefix}:${NC}"
            for j in "${!digest_names[@]}"; do
                echo -e "    node-${digest_names[$j]}: ${counts[$j]} events"
            done
            ((count_mismatches++))
            ((FAILURES++))
        fi
    fi

    # Compare digests
    unique_digests=$(printf '%s\n' "${digests[@]}" | sort -u | wc -l | tr -d ' ')
    if [ "$unique_digests" -ne 1 ]; then
        if $all_contested; then
            echo
            echo -e "  ${YELLOW}KEL DIGEST DIFFERS for contested ${prefix} (OK — terminal state)${NC}"
            ((behaviorally_consistent++))
        else
            echo
            echo -e "  ${RED}KEL DIGEST MISMATCH for ${prefix}:${NC}"
            for j in "${!digest_names[@]}"; do
                echo -e "    node-${digest_names[$j]}: ${digests[$j]}"
            done
            ((kel_mismatches++))
            ((FAILURES++))
        fi
    fi

    # For non-contested mismatched KELs, check if behavioral state is at least consistent
    if ! $all_contested && { [ "$unique_counts" -ne 1 ] || [ "$unique_digests" -ne 1 ]; }; then
        if [ "$unique_states" -eq 1 ]; then
            echo -e "    ${YELLOW}behavioral state consistent: ${states[0]}${NC}"
            ((behaviorally_consistent++))
        else
            echo
            echo -e "  ${RED}BEHAVIORAL STATE MISMATCH for ${prefix}:${NC}"
            for j in "${!digest_names[@]}"; do
                echo -e "    node-${digest_names[$j]}: ${states[$j]}"
            done
            ((state_mismatches++))
            ((FAILURES++))
        fi
    fi

    unset digests counts states digest_names
done < "$TEMP_DIR/all_prefixes.txt"

echo
echo -e "  Checked ${total_prefixes} prefixes across ${#ALL_REACHABLE_NAMES[@]} nodes"
if [ "$count_mismatches" -eq 0 ] && [ "$kel_mismatches" -eq 0 ]; then
    echo -e "  ${GREEN}All event counts and KEL digests match${NC}"
else
    [ "$count_mismatches" -gt 0 ] && echo -e "  ${RED}${count_mismatches} event count mismatches${NC}"
    [ "$kel_mismatches" -gt 0 ] && echo -e "  ${RED}${kel_mismatches} KEL digest mismatches${NC}"
    [ "$behaviorally_consistent" -gt 0 ] && echo -e "  ${YELLOW}${behaviorally_consistent} mismatched KEL(s) with consistent behavioral state${NC}"
    [ "$state_mismatches" -gt 0 ] && echo -e "  ${RED}${state_mismatches} behavioral state mismatches${NC}"
fi

# --- Summary ---
echo
echo -e "${CYAN}========================================${NC}"
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}  All consistency checks passed${NC}"
else
    echo -e "${RED}  ${FAILURES} consistency check(s) failed${NC}"
fi
echo -e "${CYAN}========================================${NC}"

exit "$FAILURES"
