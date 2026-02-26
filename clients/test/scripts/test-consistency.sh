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
#   NODE_B_KELS_HOST - node-b KELS hostname (default: kels.kels-node-b.kels)
#   NODE_C_KELS_HOST - node-c KELS hostname (default: kels.kels-node-c.kels)
#   NODE_D_KELS_HOST - node-d KELS hostname (default: kels.kels-node-d.kels)
#   NODE_E_KELS_HOST - node-e KELS hostname (default: kels.kels-node-e.kels)
#   NODE_F_KELS_HOST - node-f KELS hostname (default: kels.kels-node-f.kels)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
NODE_A_KELS_HOST="${NODE_A_KELS_HOST:-kels}"
NODE_B_KELS_HOST="${NODE_B_KELS_HOST:-kels.kels-node-b.kels}"
NODE_C_KELS_HOST="${NODE_C_KELS_HOST:-kels.kels-node-c.kels}"
NODE_D_KELS_HOST="${NODE_D_KELS_HOST:-kels.kels-node-d.kels}"
NODE_E_KELS_HOST="${NODE_E_KELS_HOST:-kels.kels-node-e.kels}"
NODE_F_KELS_HOST="${NODE_F_KELS_HOST:-kels.kels-node-f.kels}"

declare -a NODE_NAMES=(a b c d e f)
declare -a NODE_URLS=(
    "http://${NODE_A_KELS_HOST}"
    "http://${NODE_B_KELS_HOST}"
    "http://${NODE_C_KELS_HOST}"
    "http://${NODE_D_KELS_HOST}"
    "http://${NODE_E_KELS_HOST}"
    "http://${NODE_F_KELS_HOST}"
)

# Nodes with dev-tools enabled (prefixes endpoint accessible without auth via GET)
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

# --- Step 1: Fetch all prefixes from dev-tools nodes (a, b, d) ---
# Dev-tools nodes skip signature verification on the prefixes endpoint.
# We POST a mock signed request (verification is bypassed with dev-tools).
echo -e "${YELLOW}Fetching prefixes from dev-tools nodes...${NC}"

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
            body=$(jq -n --arg since "$cursor" --arg nonce "$(openssl rand -hex 32)" '{payload:{timestamp:0,nonce:$nonce,since:$since,limit:1000},peerPrefix:"test",publicKey:"test",signature:"test"}')
        else
            body=$(jq -n --arg nonce "$(openssl rand -hex 32)" '{payload:{timestamp:0,nonce:$nonce,since:null,limit:1000},peerPrefix:"test",publicKey:"test",signature:"test"}')
        fi

        response=$(curl -sf -X POST -H 'Content-Type: application/json' -d "$body" "${url}/api/kels/prefixes" 2>/dev/null)
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

        kel_response=$(curl -sf "${url}/api/kels/kel/${prefix}" 2>/dev/null)
        if [ $? -ne 0 ]; then
            digests+=("MISSING")
            counts+=("0")
            states+=("missing")
            digest_names+=("$name")
            continue
        fi

        event_count=$(echo "$kel_response" | jq '.events | length' 2>/dev/null)
        digest=$(echo "$kel_response" | jq -cS '[.events[] | .signatures |= sort_by(.publicKey)]' | sha256sum | awk '{print $1}')

        # Determine behavioral state from event kinds and structure
        state=$(echo "$kel_response" | jq -r '
            [.events[].event.kind] as $kinds |
            if ($kinds | any(. == "kels/v1/cnt")) then "contested"
            elif ($kinds | any(. == "kels/v1/dec")) then "decommissioned"
            elif ($kinds | any(. == "kels/v1/rec" or . == "kels/v1/ror")) then "recovered"
            elif ([.events[].event.previous | select(. != null)] | group_by(.) | any(length > 1)) then "frozen"
            else "normal"
            end
        ' 2>/dev/null)

        digests+=("$digest")
        counts+=("$event_count")
        states+=("${state:-unknown}")
        digest_names+=("$name")
    done

    # Compare counts
    unique_counts=$(printf '%s\n' "${counts[@]}" | sort -u | wc -l | tr -d ' ')
    if [ "$unique_counts" -ne 1 ]; then
        echo
        echo -e "  ${RED}EVENT COUNT MISMATCH for ${prefix}:${NC}"
        for j in "${!digest_names[@]}"; do
            echo -e "    node-${digest_names[$j]}: ${counts[$j]} events"
        done
        ((count_mismatches++))
        ((FAILURES++))
    fi

    # Compare digests
    unique_digests=$(printf '%s\n' "${digests[@]}" | sort -u | wc -l | tr -d ' ')
    if [ "$unique_digests" -ne 1 ]; then
        echo
        echo -e "  ${RED}KEL DIGEST MISMATCH for ${prefix}:${NC}"
        for j in "${!digest_names[@]}"; do
            echo -e "    node-${digest_names[$j]}: ${digests[$j]}"
        done
        ((kel_mismatches++))
        ((FAILURES++))
    fi

    # For mismatched KELs, check if behavioral state is at least consistent
    if [ "$unique_counts" -ne 1 ] || [ "$unique_digests" -ne 1 ]; then
        unique_states=$(printf '%s\n' "${states[@]}" | sort -u | wc -l | tr -d ' ')
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
