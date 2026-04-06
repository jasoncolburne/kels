#!/bin/bash
# load-sads.sh - Populate a SADStore node with SAD objects and chain records
#
# For each group, creates a KEL, stores SAD objects, then creates a chain with
# a random number [1, MAX_CHAIN_VERSIONS] of versions, each referencing a
# different SAD object as content.
#
# Usage: load-sads.sh [count] [concurrency]
#   count:       number of SAD objects to create (default: 900, rounded to group size)
#   concurrency: parallel workers (default: 10)

set -e

# Unset Kubernetes-injected service environment variables
unset KELS_SADSTORE_SERVICE_HOST KELS_SADSTORE_SERVICE_PORT KELS_SADSTORE_PORT
unset KELS_SERVICE_HOST KELS_SERVICE_PORT KELS_PORT

TEST_KELS_HOST="${TEST_KELS_HOST:-kels}"
TEST_KELS_PORT="${TEST_KELS_PORT:-80}"
KELS_URL="http://${TEST_KELS_HOST}:${TEST_KELS_PORT}"

TEST_SADSTORE_HOST="${TEST_SADSTORE_HOST:-sadstore}"
TEST_SADSTORE_PORT="${TEST_SADSTORE_PORT:-80}"
SADSTORE_URL="http://${TEST_SADSTORE_HOST}:${TEST_SADSTORE_PORT}"

ALGORITHM="${ALGORITHM:-ml-dsa-65}"
KIND="${KIND:-kels/v1/test-data}"

MAX_CHAIN_VERSIONS="${MAX_CHAIN_VERSIONS:-7}"
COUNT=${1:-900}
CONCURRENCY=${2:-10}

# Round down to multiple of max chain versions
COUNT=$(( (COUNT / MAX_CHAIN_VERSIONS) * MAX_CHAIN_VERSIONS ))
GROUP_COUNT=$(( COUNT / MAX_CHAIN_VERSIONS ))

PLACEHOLDER="############################################"

echo "========================================="
echo "SADStore Load Test"
echo "========================================="
echo "SAD objects:  $COUNT (${GROUP_COUNT} groups of ${MAX_CHAIN_VERSIONS})"
echo "Chains:       $GROUP_COUNT"
echo "Concurrency:  $CONCURRENCY"
echo "KELS URL:     $KELS_URL"
echo "SADStore URL: $SADSTORE_URL"
echo "Algorithm:    $ALGORITHM"
echo "Kind:         $KIND"
echo "========================================="

# Compute a CESR Blake3 SAID from a string argument.
# Prepend 00 to hex hash, convert to binary, base64url, take last 43 chars, prepend "K".
cesr_blake3() {
    local data="$1"
    local padded
    padded=$(echo "00$(printf '%s' "$data" | b3sum --no-names)" | xxd -r -p | base64 | tr '/' '_' | tr '+' '-')
    echo "K${padded:(-43)}"
}

# Compute a SAID for a JSON object.
compute_said() {
    local json="$1"
    local with_placeholder
    with_placeholder=$(echo "$json" | jq -c --arg p "$PLACEHOLDER" '.said = $p')
    cesr_blake3 "$with_placeholder"
}

# Compute prefix for a v0 inception record (both said AND prefix are placeholders).
compute_prefix() {
    local json="$1"
    local with_placeholders
    with_placeholders=$(echo "$json" | jq -c --arg p "$PLACEHOLDER" '.said = $p | .prefix = $p')
    cesr_blake3 "$with_placeholders"
}

create_group() {
    local group=$1
    local tmpdir
    tmpdir=$(mktemp -d)

    # 1. Create a KEL
    local prefix
    prefix=$(kels-cli --kels-url "$KELS_URL" --config-dir "$tmpdir" incept --signing-algorithm "$ALGORITHM" 2>&1 | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1)
    if [ -z "$prefix" ]; then
        echo "ERROR [group $group]: KEL inception failed" >&2
        rm -rf "$tmpdir"
        return 1
    fi

    # 2. Create 9 SAD objects and collect their SAIDs
    local object_saids=()
    for i in $(seq 1 "$MAX_CHAIN_VERSIONS"); do
        local json
        json=$(jq -nc --arg p "$PLACEHOLDER" --arg v "load-test-${group}-${i}-$(date +%s%N)" \
            '{said: $p, value: $v}')
        local said
        said=$(compute_said "$json")
        json=$(echo "$json" | jq -c --arg s "$said" '.said = $s')

        local put_resp
        put_resp=$(curl -s -w "\n%{http_code}" -X POST "${SADSTORE_URL}/api/v1/sad" \
            -H 'Content-Type: application/json' \
            -d "$json")
        local put_code
        put_code=$(echo "$put_resp" | tail -1)
        if [ "$put_code" != "201" ] && [ "$put_code" != "200" ]; then
            echo "ERROR [group $group]: SAD object PUT failed (HTTP $put_code): $(echo "$put_resp" | head -1)" >&2
        fi

        object_saids+=("$said")
    done

    # 3. Compute chain prefix (use kels-cli for correctness)
    local chain_prefix
    chain_prefix=$(kels-cli sad prefix "$prefix" "$KIND" 2>&1)
    if [ -z "$chain_prefix" ]; then
        echo "ERROR [group $group]: chain prefix computation failed" >&2
        rm -rf "$tmpdir"
        return 1
    fi

    # 4. Pick random n from [1,9]
    local n=$(( (RANDOM % MAX_CHAIN_VERSIONS) + 1 ))

    # 5. Build chain records: v0 (inception, no content) then v1..vN
    # v0: deterministic inception record
    local v0_json
    v0_json=$(jq -nc --arg p "$PLACEHOLDER" --arg kp "$prefix" --arg k "$KIND" \
        '{said: $p, prefix: $p, version: 0, kelPrefix: $kp, kind: $k}')
    local v0_prefix
    v0_prefix=$(compute_prefix "$v0_json")
    v0_json=$(echo "$v0_json" | jq -c --arg pfx "$v0_prefix" '.prefix = $pfx')
    local v0_said
    v0_said=$(compute_said "$v0_json")
    v0_json=$(echo "$v0_json" | jq -c --arg s "$v0_said" '.said = $s')

    # Sign v0
    local v0_sig
    v0_sig=$(kels-cli --config-dir "$tmpdir" sign --prefix "$prefix" "$v0_said" 2>&1)
    if [ -z "$v0_sig" ] || echo "$v0_sig" | grep -qi "^error"; then
        echo "ERROR [group $group]: v0 signing failed: $v0_sig" >&2
        rm -rf "$tmpdir"
        return 1
    fi

    local records_json="[]"
    records_json=$(echo "$records_json" | jq -c --argjson r "$(echo "$v0_json")" --arg sig "$v0_sig" \
        '. + [{pointer: $r, signature: $sig, establishmentSerial: 0}]')

    local prev_said="$v0_said"

    for i in $(seq 1 "$n"); do
        local content_said="${object_saids[$((i-1))]}"
        local vi_json
        vi_json=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$v0_prefix" --arg prev "$prev_said" \
            --argjson ver "$i" --arg kp "$prefix" --arg k "$KIND" --arg cs "$content_said" \
            '{said: $p, prefix: $pfx, previous: $prev, version: $ver, kelPrefix: $kp, kind: $k, contentSaid: $cs}')
        local vi_said
        vi_said=$(compute_said "$vi_json")
        vi_json=$(echo "$vi_json" | jq -c --arg s "$vi_said" '.said = $s')

        local vi_sig
        vi_sig=$(kels-cli --config-dir "$tmpdir" sign --prefix "$prefix" "$vi_said" 2>&1)
        if [ -z "$vi_sig" ] || echo "$vi_sig" | grep -qi "^error"; then
            echo "ERROR [group $group]: v$i signing failed: $vi_sig" >&2
            break
        fi

        records_json=$(echo "$records_json" | jq -c --argjson r "$(echo "$vi_json")" --arg sig "$vi_sig" \
            '. + [{pointer: $r, signature: $sig, establishmentSerial: 0}]')

        prev_said="$vi_said"
    done

    # 6. Submit all records in one batch
    local submit_resp
    submit_resp=$(curl -s -w "\n%{http_code}" -X POST "${SADSTORE_URL}/api/v1/sad/pointers" \
        -H 'Content-Type: application/json' \
        -d "$records_json")
    local submit_code
    submit_code=$(echo "$submit_resp" | tail -1)
    if [ "$submit_code" != "201" ]; then
        echo "ERROR [group $group]: chain record submit failed (HTTP $submit_code): $(echo "$submit_resp" | head -1)" >&2
        echo "  First record: $(echo "$records_json" | jq -c '.[0]')" >&2
    fi

    rm -rf "$tmpdir"
}

export -f create_group cesr_blake3 compute_said compute_prefix
export KELS_URL SADSTORE_URL ALGORITHM KIND PLACEHOLDER MAX_CHAIN_VERSIONS

start=$(date +%s)
seq 1 "$GROUP_COUNT" | xargs -P "$CONCURRENCY" -I {} bash -c 'create_group {}'
end=$(date +%s)

elapsed=$((end - start))
echo ""
echo "Created $COUNT SAD objects + $GROUP_COUNT chains in ${elapsed}s"
echo "Rate: $(( GROUP_COUNT / (elapsed > 0 ? elapsed : 1) )) chains/s"
