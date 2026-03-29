#!/usr/bin/env bash
# test-sad-consistency.sh - Deep SAD Chain Consistency Verification
# Compares all SAD chain prefixes and chain contents across nodes.
#
# For each node with test endpoints, fetches all chain prefixes, then for each
# prefix fetches the full chain. Verifies:
#   1. All nodes have the same set of chain prefixes
#   2. All chains have the same number of records on each node
#   3. A SHA-256 digest of each chain matches across all nodes
#   4. SAD objects referenced by chains exist on all nodes
#
# Usage: test-sad-consistency.sh
#
# Environment variables:
#   NODE_A_SADSTORE_HOST - node-a SADStore hostname (default: kels-sadstore)
#   NODE_B_SADSTORE_HOST - node-b SADStore hostname (default: kels-sadstore.kels-node-b.kels)
#   NODE_C_SADSTORE_HOST - node-c SADStore hostname (default: kels-sadstore.kels-node-c.kels)
#   NODE_D_SADSTORE_HOST - node-d SADStore hostname (default: kels-sadstore.kels-node-d.kels)
#   NODE_E_SADSTORE_HOST - node-e SADStore hostname (default: kels-sadstore.kels-node-e.kels)
#   NODE_F_SADSTORE_HOST - node-f SADStore hostname (default: kels-sadstore.kels-node-f.kels)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
NODE_A_SADSTORE_HOST="${NODE_A_SADSTORE_HOST:-kels-sadstore}"
NODE_B_SADSTORE_HOST="${NODE_B_SADSTORE_HOST:-kels-sadstore.kels-node-b.kels}"
NODE_C_SADSTORE_HOST="${NODE_C_SADSTORE_HOST:-kels-sadstore.kels-node-c.kels}"
NODE_D_SADSTORE_HOST="${NODE_D_SADSTORE_HOST:-kels-sadstore.kels-node-d.kels}"
NODE_E_SADSTORE_HOST="${NODE_E_SADSTORE_HOST:-kels-sadstore.kels-node-e.kels}"
NODE_F_SADSTORE_HOST="${NODE_F_SADSTORE_HOST:-kels-sadstore.kels-node-f.kels}"

declare -a NODE_NAMES=(a b c d e f)
declare -a NODE_URLS=(
    "http://${NODE_A_SADSTORE_HOST}"
    "http://${NODE_B_SADSTORE_HOST}"
    "http://${NODE_C_SADSTORE_HOST}"
    "http://${NODE_D_SADSTORE_HOST}"
    "http://${NODE_E_SADSTORE_HOST}"
    "http://${NODE_F_SADSTORE_HOST}"
)

# Nodes with KELS_TEST_ENDPOINTS enabled (unauthenticated test prefixes endpoint)
declare -a PREFIX_NODE_NAMES=(a b d)
declare -a PREFIX_NODE_URLS=(
    "http://${NODE_A_SADSTORE_HOST}"
    "http://${NODE_B_SADSTORE_HOST}"
    "http://${NODE_D_SADSTORE_HOST}"
)

init_temp_dir

FAILURES=0

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  SAD Chain Consistency Verification${NC}"
echo -e "${CYAN}========================================${NC}"
echo

# --- Step 1: Fetch all chain prefixes from test-endpoint nodes ---
echo -e "${YELLOW}Fetching SAD chain prefixes from test-endpoint nodes...${NC}"

declare -a REACHABLE_NAMES=()
declare -a REACHABLE_URLS=()

for i in "${!PREFIX_NODE_NAMES[@]}"; do
    name="${PREFIX_NODE_NAMES[$i]}"
    url="${PREFIX_NODE_URLS[$i]}"
    prefix_file="$TEMP_DIR/sad_prefixes_${name}.txt"

    cursor=""
    > "$prefix_file"

    reachable=true
    while true; do
        if [ -n "$cursor" ]; then
            body=$(jq -n --arg since "$cursor" --arg nonce "$(openssl rand -hex 32)" '{payload:{timestamp:0,nonce:$nonce,since:$since,limit:1000},peerPrefix:"test",signature:"test"}')
        else
            body=$(jq -n --arg nonce "$(openssl rand -hex 32)" '{payload:{timestamp:0,nonce:$nonce,since:null,limit:1000},peerPrefix:"test",signature:"test"}')
        fi

        response=$(curl -sf -X POST -H 'Content-Type: application/json' -d "$body" "${url}/api/test/sad/prefixes" 2>/dev/null)
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

    if $reachable; then
        count=$(wc -l < "$prefix_file" | tr -d ' ')
        echo -e "  node-${name}: ${GREEN}${count} chain prefixes${NC}"
        REACHABLE_NAMES+=("$name")
        REACHABLE_URLS+=("$url")
    fi
done

echo

if [ ${#REACHABLE_NAMES[@]} -lt 2 ]; then
    echo -e "${RED}Fewer than 2 test-endpoint nodes reachable, cannot compare.${NC}"
    exit 1
fi

# Build list of all reachable nodes for chain comparison
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

# --- Step 1b: Fetch all SAD object SAIDs from test-endpoint nodes ---
echo -e "${YELLOW}Fetching SAD object SAIDs from test-endpoint nodes...${NC}"

for i in "${!REACHABLE_NAMES[@]}"; do
    name="${REACHABLE_NAMES[$i]}"
    url="${REACHABLE_URLS[$i]}"
    objects_file="$TEMP_DIR/sad_objects_${name}.txt"

    cursor=""
    > "$objects_file"

    while true; do
        if [ -n "$cursor" ]; then
            body=$(jq -n --arg cursor "$cursor" --arg nonce "$(openssl rand -hex 32)" '{payload:{timestamp:0,nonce:$nonce,cursor:$cursor,limit:1000},peerPrefix:"test",signature:"test"}')
        else
            body=$(jq -n --arg nonce "$(openssl rand -hex 32)" '{payload:{timestamp:0,nonce:$nonce,cursor:null,limit:1000},peerPrefix:"test",signature:"test"}')
        fi

        response=$(curl -sf -X POST -H 'Content-Type: application/json' -d "$body" "${url}/api/test/sad/objects" 2>/dev/null)
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
    count=$(wc -l < "$objects_file" | tr -d ' ')
    echo -e "  node-${name}: ${GREEN}${count} SAD objects${NC}"
done

echo

# --- Step 2: Compare prefix sets ---
echo -e "${YELLOW}Comparing chain prefix sets...${NC}"

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
    echo -e "  ${GREEN}All ${#REACHABLE_NAMES[@]} nodes have the same ${total} chain prefixes${NC}"
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

# --- Step 2c: Verify SAD objects exist on all reachable nodes ---
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

        http_code=$(curl -s -o /dev/null -w '%{http_code}' "${url}/api/v1/sad/${said}/exists")
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

echo

# --- Step 3: For each prefix, compare record counts and chain digests ---
echo -e "${YELLOW}Comparing SAD chains across nodes...${NC}"

cat "$TEMP_DIR"/sad_prefixes_*.txt | sort -u > "$TEMP_DIR/all_sad_prefixes.txt"
total_prefixes=$(wc -l < "$TEMP_DIR/all_sad_prefixes.txt" | tr -d ' ')
checked=0
chain_mismatches=0
count_mismatches=0
divergent_consistent=0

# Fetch all records for a SAD chain, paginating through all pages.
fetch_all_sad_records() {
    local url="$1"
    local prefix="$2"
    local all_records="[]"
    local since=""

    while true; do
        local query_url="${url}/api/v1/sad/chain/${prefix}"
        if [ -n "$since" ]; then
            query_url="${query_url}?since=${since}"
        fi

        local resp
        resp=$(curl -s -f "$query_url" 2>/dev/null) || break

        local records has_more
        records=$(echo "$resp" | jq '.records')
        has_more=$(echo "$resp" | jq '.hasMore')

        if [ "$(echo "$records" | jq 'length')" -eq 0 ]; then
            break
        fi

        all_records=$(printf '%s\n%s' "$all_records" "$records" | jq -s '.[0] + .[1]')

        if [ "$has_more" != "true" ]; then
            break
        fi

        since=$(echo "$records" | jq -r '.[-1].record.said')
    done

    echo "$all_records"
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

        all_records=$(fetch_all_sad_records "${url}" "${prefix}")
        if [ "$(echo "$all_records" | jq 'length')" -eq 0 ]; then
            digests+=("MISSING")
            counts+=("0")
            states+=("missing")
            digest_names+=("$name")
            continue
        fi

        record_count=$(echo "$all_records" | jq 'length' 2>/dev/null)
        digest=$(echo "$all_records" | jq -cS '.' | sha256sum | awk '{print $1}')

        # Check if divergent (multiple records at the same version)
        state=$(echo "$all_records" | jq -r '
            [.[].record.version] | group_by(.) | if any(length > 1) then "divergent" else "normal" end
        ' 2>/dev/null)

        digests+=("$digest")
        counts+=("$record_count")
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
                echo -e "    node-${digest_names[$j]}: ${counts[$j]} records"
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
echo -e "  Checked ${total_prefixes} chain prefixes across ${#ALL_REACHABLE_NAMES[@]} nodes"
if [ "$count_mismatches" -eq 0 ] && [ "$chain_mismatches" -eq 0 ]; then
    echo -e "  ${GREEN}All record counts and chain digests match${NC}"
else
    [ "$count_mismatches" -gt 0 ] && echo -e "  ${RED}${count_mismatches} record count mismatches${NC}"
    [ "$chain_mismatches" -gt 0 ] && echo -e "  ${RED}${chain_mismatches} chain digest mismatches${NC}"
    [ "$divergent_consistent" -gt 0 ] && echo -e "  ${YELLOW}${divergent_consistent} mismatched chain(s) with consistent divergent state${NC}"
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
