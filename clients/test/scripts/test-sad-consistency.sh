#!/usr/bin/env bash
# test-sad-consistency.sh - Deep SAD Consistency Verification
# Compares all SAD Event Log prefixes, chain contents, and SAD objects across nodes.
#
# For each node with test endpoints, fetches all SEL prefixes and SAD object
# SAIDs, then for each prefix/object compares across ALL nodes. Verifies:
#   1. All nodes have the same set of SEL prefixes
#   2. All chains have the same number of events on each node
#   3. A SHA-256 digest of each chain matches across all nodes
#   4. All nodes have the same set of SAD objects
#
# Usage: test-sad-consistency.sh
#
# Environment variables:
#   NODE_A_SADSTORE_HOST - node-a SADStore hostname (default: sadstore)
#   NODE_B_SADSTORE_HOST - node-b SADStore hostname (default: sadstore.node-b.kels)
#   NODE_C_SADSTORE_HOST - node-c SADStore hostname (default: sadstore.node-c.kels)
#   NODE_D_SADSTORE_HOST - node-d SADStore hostname (default: sadstore.node-d.kels)
#   NODE_E_SADSTORE_HOST - node-e SADStore hostname (default: sadstore.node-e.kels)
#   NODE_F_SADSTORE_HOST - node-f SADStore hostname (default: sadstore.node-f.kels)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
NODE_A_SADSTORE_HOST="${NODE_A_SADSTORE_HOST:-sadstore}"
NODE_B_SADSTORE_HOST="${NODE_B_SADSTORE_HOST:-sadstore.node-b.kels}"
NODE_C_SADSTORE_HOST="${NODE_C_SADSTORE_HOST:-sadstore.node-c.kels}"
NODE_D_SADSTORE_HOST="${NODE_D_SADSTORE_HOST:-sadstore.node-d.kels}"
NODE_E_SADSTORE_HOST="${NODE_E_SADSTORE_HOST:-sadstore.node-e.kels}"
NODE_F_SADSTORE_HOST="${NODE_F_SADSTORE_HOST:-sadstore.node-f.kels}"

# Dummy CESR values for test endpoints that skip auth but still deserialize
MOCK_SAID="KMOCK_SAID__________________________________"
MOCK_PREFIX="KMOCK_PREFIX________________________________"
MOCK_SIGNATURE="0CMOCK_SIGNATURE________________________________________________________________________"
MOCK_CREATED_AT="2026-01-01T00:00:00.000000Z"

declare -a NODE_NAMES=(a b c d e f)
declare -a NODE_URLS=(
    "http://${NODE_A_SADSTORE_HOST}"
    "http://${NODE_B_SADSTORE_HOST}"
    "http://${NODE_C_SADSTORE_HOST}"
    "http://${NODE_D_SADSTORE_HOST}"
    "http://${NODE_E_SADSTORE_HOST}"
    "http://${NODE_F_SADSTORE_HOST}"
)

# Nodes with KELS_TEST_ENDPOINTS enabled (unauthenticated listing endpoints)
declare -a PREFIX_NODE_NAMES=(a b d)
declare -a PREFIX_NODE_URLS=(
    "http://${NODE_A_SADSTORE_HOST}"
    "http://${NODE_B_SADSTORE_HOST}"
    "http://${NODE_D_SADSTORE_HOST}"
)

init_temp_dir

FAILURES=0

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  SAD Consistency Verification${NC}"
echo -e "${CYAN}========================================${NC}"
echo

# --- Step 1: Fetch all SEL prefixes and SAD object SAIDs from test-endpoint nodes ---
echo -e "${YELLOW}Fetching SEL prefixes and SAD object SAIDs from test-endpoint nodes...${NC}"

declare -a REACHABLE_NAMES=()
declare -a REACHABLE_URLS=()

for i in "${!PREFIX_NODE_NAMES[@]}"; do
    name="${PREFIX_NODE_NAMES[$i]}"
    url="${PREFIX_NODE_URLS[$i]}"
    prefix_file="$TEMP_DIR/sad_prefixes_${name}.txt"
    objects_file="$TEMP_DIR/sad_objects_${name}.txt"

    > "$prefix_file"
    > "$objects_file"

    # Fetch SEL prefixes
    cursor=""
    reachable=true
    while true; do
        if [ -n "$cursor" ]; then
            body=$(jq -n --arg cursor "$cursor" --arg nonce "NA$(openssl rand -hex 21)" '{payload:{said:"'"$MOCK_SAID"'",createdAt:"'"$MOCK_CREATED_AT"'",nonce:$nonce,cursor:$cursor,limit:1000},signatures:{"'"$MOCK_PREFIX"'":"'"$MOCK_SIGNATURE"'"}}')
        else
            body=$(jq -n --arg nonce "NA$(openssl rand -hex 21)" '{payload:{said:"'"$MOCK_SAID"'",createdAt:"'"$MOCK_CREATED_AT"'",nonce:$nonce,cursor:null,limit:1000},signatures:{"'"$MOCK_PREFIX"'":"'"$MOCK_SIGNATURE"'"}}')
        fi

        response=$(curl -sf -X POST -H 'Content-Type: application/json' -d "$body" "${url}/api/test/sad/events/prefixes" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo -e "  node-${name}: ${RED}unreachable${NC}"
            reachable=false
            break
        fi

        echo "$response" | jq -r '.prefixes[].prefix' >> "$prefix_file" 2>/dev/null

        cursor=$(echo "$response" | jq -r '.nextCursor // empty' 2>/dev/null)
        if [ -z "$cursor" ]; then
            break
        fi
    done

    if ! $reachable; then
        continue
    fi

    # Fetch SAD object SAIDs
    cursor=""
    while true; do
        if [ -n "$cursor" ]; then
            body=$(jq -n --arg cursor "$cursor" --arg nonce "NA$(openssl rand -hex 21)" '{payload:{said:"'"$MOCK_SAID"'",createdAt:"'"$MOCK_CREATED_AT"'",nonce:$nonce,cursor:$cursor,limit:1000},signatures:{"'"$MOCK_PREFIX"'":"'"$MOCK_SIGNATURE"'"}}')
        else
            body=$(jq -n --arg nonce "NA$(openssl rand -hex 21)" '{payload:{said:"'"$MOCK_SAID"'",createdAt:"'"$MOCK_CREATED_AT"'",nonce:$nonce,cursor:null,limit:1000},signatures:{"'"$MOCK_PREFIX"'":"'"$MOCK_SIGNATURE"'"}}')
        fi

        response=$(curl -sf -X POST -H 'Content-Type: application/json' -d "$body" "${url}/api/test/sad/saids" 2>/dev/null)
        if [ $? -ne 0 ]; then
            break
        fi

        echo "$response" | jq -r '.saids[]' >> "$objects_file" 2>/dev/null

        cursor=$(echo "$response" | jq -r '.nextCursor // empty' 2>/dev/null)
        if [ -z "$cursor" ]; then
            break
        fi
    done

    # Deduplicate (wrapping pagination may return objects from the beginning on the last page)
    sort -u -o "$objects_file" "$objects_file"

    prefix_count=$(wc -l < "$prefix_file" | tr -d ' ')
    object_count=$(wc -l < "$objects_file" | tr -d ' ')
    echo -e "  node-${name}: ${GREEN}${prefix_count} SEL prefixes, ${object_count} SAD objects${NC}"
    REACHABLE_NAMES+=("$name")
    REACHABLE_URLS+=("$url")
done

echo

if [ ${#REACHABLE_NAMES[@]} -lt 2 ]; then
    echo -e "${RED}Fewer than 2 test-endpoint nodes reachable, cannot compare.${NC}"
    exit 1
fi

# Build list of all reachable nodes for comparison
declare -a ALL_REACHABLE_NAMES=()
declare -a ALL_REACHABLE_URLS=()

for i in "${!NODE_NAMES[@]}"; do
    name="${NODE_NAMES[$i]}"
    url="${NODE_URLS[$i]}"

    if curl -sf "${url}/health" > /dev/null 2>&1; then
        ALL_REACHABLE_NAMES+=("$name")
        ALL_REACHABLE_URLS+=("$url")
    fi
done

echo -e "${YELLOW}${#ALL_REACHABLE_NAMES[@]} nodes reachable for comparison${NC}"
echo

# --- Step 2: Compare SEL prefix sets ---
echo -e "${YELLOW}Comparing SEL prefix sets...${NC}"

reference_name="${REACHABLE_NAMES[0]}"
reference_file="$TEMP_DIR/sad_prefixes_${reference_name}.txt"
sort -o "$reference_file" "$reference_file"

all_match=true
for i in "${!REACHABLE_NAMES[@]}"; do
    [ "$i" -eq 0 ] && continue
    name="${REACHABLE_NAMES[$i]}"
    other_file="$TEMP_DIR/sad_prefixes_${name}.txt"
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
    echo -e "  ${GREEN}All ${#REACHABLE_NAMES[@]} nodes have the same ${total} SEL prefixes${NC}"
fi

echo

# --- Step 2b: Compare SAD object sets ---
echo -e "${YELLOW}Comparing SAD object sets...${NC}"

obj_reference_name="${REACHABLE_NAMES[0]}"
obj_reference_file="$TEMP_DIR/sad_objects_${obj_reference_name}.txt"
sort -o "$obj_reference_file" "$obj_reference_file"

obj_all_match=true
for i in "${!REACHABLE_NAMES[@]}"; do
    [ "$i" -eq 0 ] && continue
    name="${REACHABLE_NAMES[$i]}"
    other_file="$TEMP_DIR/sad_objects_${name}.txt"
    sort -o "$other_file" "$other_file"

    if ! diff -q "$obj_reference_file" "$other_file" > /dev/null 2>&1; then
        obj_all_match=false
        echo -e "  ${RED}MISMATCH: node-${obj_reference_name} vs node-${name}${NC}"

        only_ref=$(comm -23 "$obj_reference_file" "$other_file" | wc -l | tr -d ' ')
        only_other=$(comm -13 "$obj_reference_file" "$other_file" | wc -l | tr -d ' ')

        [ "$only_ref" -gt 0 ] && echo -e "    ${only_ref} objects only on node-${obj_reference_name}"
        [ "$only_other" -gt 0 ] && echo -e "    ${only_other} objects only on node-${name}"
        ((FAILURES++))
    fi
done

if $obj_all_match; then
    total=$(wc -l < "$obj_reference_file" | tr -d ' ')
    echo -e "  ${GREEN}All ${#REACHABLE_NAMES[@]} nodes have the same ${total} SAD objects${NC}"
fi

echo

# --- Step 3: For each prefix, compare event counts and chain digests across ALL nodes ---
echo -e "${YELLOW}Comparing SAD Event Logs across all nodes...${NC}"

cat "$TEMP_DIR"/sad_prefixes_*.txt | sort -u > "$TEMP_DIR/all_sad_prefixes.txt"
total_prefixes=$(wc -l < "$TEMP_DIR/all_sad_prefixes.txt" | tr -d ' ')
checked=0
chain_mismatches=0
count_mismatches=0
divergent_consistent=0

# Fetch all events for a SAD Event Log, paginating through all pages.
fetch_all_sad_events() {
    local url="$1"
    local prefix="$2"
    local all_events="[]"
    local since=""

    while true; do
        local body="{\"prefix\":\"${prefix}\"}"
        if [ -n "$since" ]; then
            body="{\"prefix\":\"${prefix}\",\"since\":\"${since}\"}"
        fi

        local resp
        resp=$(curl -s -f -X POST -H 'Content-Type: application/json' -d "$body" "${url}/api/v1/sad/events/fetch" 2>/dev/null) || break

        local events has_more
        events=$(echo "$resp" | jq '.events')
        has_more=$(echo "$resp" | jq '.hasMore')

        if [ "$(echo "$events" | jq 'length')" -eq 0 ]; then
            break
        fi

        all_events=$(printf '%s\n%s' "$all_events" "$events" | jq -s '.[0] + .[1]')

        if [ "$has_more" != "true" ]; then
            break
        fi

        since=$(echo "$events" | jq -r '.[-1].event.said')
    done

    echo "$all_events"
}

while IFS= read -r prefix; do
    ((checked++))
    printf "\r  Checking chain %d/%d..." "$checked" "$total_prefixes"

    declare -a digests=()
    declare -a counts=()
    declare -a states=()
    declare -a digest_names=()

    for i in "${!ALL_REACHABLE_NAMES[@]}"; do
        name="${ALL_REACHABLE_NAMES[$i]}"
        url="${ALL_REACHABLE_URLS[$i]}"

        all_events=$(fetch_all_sad_events "${url}" "${prefix}")
        if [ "$(echo "$all_events" | jq 'length')" -eq 0 ]; then
            digests+=("MISSING")
            counts+=("0")
            states+=("missing")
            digest_names+=("$name")
            continue
        fi

        event_count=$(echo "$all_events" | jq 'length' 2>/dev/null)
        digest=$(echo "$all_events" | jq -cS '.' | sha256sum | awk '{print $1}')

        # Check if divergent (multiple events at the same version)
        state=$(echo "$all_events" | jq -r '
            [.[].event.version] | group_by(.) | if any(length > 1) then "divergent" else "normal" end
        ' 2>/dev/null)

        digests+=("$digest")
        counts+=("$event_count")
        states+=("${state:-unknown}")
        digest_names+=("$name")
    done

    # Check if all nodes agree the chain is divergent
    unique_states=$(printf '%s\n' "${states[@]}" | sort -u | wc -l | tr -d ' ')
    all_divergent=false
    if [ "$unique_states" -eq 1 ] && [ "${states[0]}" = "divergent" ]; then
        all_divergent=true
    fi

    # Compare counts
    unique_counts=$(printf '%s\n' "${counts[@]}" | sort -u | wc -l | tr -d ' ')
    if [ "$unique_counts" -ne 1 ]; then
        if $all_divergent; then
            echo
            echo -e "  ${YELLOW}RECORD COUNT DIFFERS for divergent ${prefix} (OK — frozen state)${NC}"
        else
            echo
            echo -e "  ${RED}RECORD COUNT MISMATCH for ${prefix}:${NC}"
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
        if $all_divergent; then
            echo
            echo -e "  ${YELLOW}CHAIN DIGEST DIFFERS for divergent ${prefix} (OK — frozen state)${NC}"
            ((divergent_consistent++))
        else
            echo
            echo -e "  ${RED}CHAIN DIGEST MISMATCH for ${prefix}:${NC}"
            for j in "${!digest_names[@]}"; do
                echo -e "    node-${digest_names[$j]}: ${digests[$j]}"
            done
            ((chain_mismatches++))
            ((FAILURES++))
        fi
    fi

    # For non-divergent mismatched chains, check if state is at least consistent
    if ! $all_divergent && { [ "$unique_counts" -ne 1 ] || [ "$unique_digests" -ne 1 ]; }; then
        if [ "$unique_states" -eq 1 ]; then
            echo -e "    ${YELLOW}state consistent: ${states[0]}${NC}"
            ((divergent_consistent++))
        else
            echo
            echo -e "  ${RED}STATE MISMATCH for ${prefix}:${NC}"
            for j in "${!digest_names[@]}"; do
                echo -e "    node-${digest_names[$j]}: ${states[$j]}"
            done
            ((FAILURES++))
        fi
    fi

    unset digests counts states digest_names
done < "$TEMP_DIR/all_sad_prefixes.txt"

echo
echo -e "  Checked ${total_prefixes} SEL prefixes across ${#ALL_REACHABLE_NAMES[@]} nodes"
if [ "$count_mismatches" -eq 0 ] && [ "$chain_mismatches" -eq 0 ]; then
    echo -e "  ${GREEN}All event counts and chain digests match${NC}"
else
    [ "$count_mismatches" -gt 0 ] && echo -e "  ${RED}${count_mismatches} event count mismatches${NC}"
    [ "$chain_mismatches" -gt 0 ] && echo -e "  ${RED}${chain_mismatches} chain digest mismatches${NC}"
    [ "$divergent_consistent" -gt 0 ] && echo -e "  ${YELLOW}${divergent_consistent} mismatched chain(s) with consistent divergent state${NC}"
fi

# --- Step 4: Verify SAD objects exist on all nodes ---
echo
echo -e "${YELLOW}Verifying SAD objects across all nodes...${NC}"

cat "$TEMP_DIR"/sad_objects_*.txt | sort -u > "$TEMP_DIR/all_sad_objects.txt"
total_objects=$(wc -l < "$TEMP_DIR/all_sad_objects.txt" | tr -d ' ')
obj_checked=0
obj_missing=0

while IFS= read -r said; do
    ((obj_checked++))
    printf "\r  Checking object %d/%d..." "$obj_checked" "$total_objects"

    for i in "${!ALL_REACHABLE_NAMES[@]}"; do
        name="${ALL_REACHABLE_NAMES[$i]}"
        url="${ALL_REACHABLE_URLS[$i]}"

        http_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "{\"said\":\"${said}\"}" "${url}/api/v1/sad/exists")
        if [ "$http_code" != "200" ]; then
            echo
            echo -e "  ${RED}MISSING object ${said} on node-${name} (HTTP ${http_code})${NC}"
            ((obj_missing++))
            ((FAILURES++))
        fi
    done
done < "$TEMP_DIR/all_sad_objects.txt"

echo
if [ "$obj_missing" -eq 0 ]; then
    echo -e "  ${GREEN}All ${total_objects} SAD objects present on all ${#ALL_REACHABLE_NAMES[@]} nodes${NC}"
else
    echo -e "  ${RED}${obj_missing} missing object(s) across nodes${NC}"
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
