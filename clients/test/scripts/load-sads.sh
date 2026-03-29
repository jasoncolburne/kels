#!/bin/bash
# load-sads.sh - Populate a SADStore node with SAD objects and chain records
#
# For every 9 SAD objects, creates a KEL, stores the objects, then creates
# a chain with a random number [1,9] of versions, each referencing a different
# SAD object as content.
#
# Usage: load-sads.sh [count] [concurrency]
#   count:       number of SAD objects to create (default: 900, rounded to multiple of 9)
#   concurrency: parallel workers (default: 10)

set -e

# Unset Kubernetes-injected service environment variables
unset KELS_SADSTORE_SERVICE_HOST KELS_SADSTORE_SERVICE_PORT KELS_SADSTORE_PORT
unset KELS_SERVICE_HOST KELS_SERVICE_PORT KELS_PORT

TEST_KELS_HOST="${TEST_KELS_HOST:-kels}"
TEST_KELS_PORT="${TEST_KELS_PORT:-80}"
KELS_URL="http://${TEST_KELS_HOST}:${TEST_KELS_PORT}"

TEST_SADSTORE_HOST="${TEST_SADSTORE_HOST:-kels-sadstore}"
TEST_SADSTORE_PORT="${TEST_SADSTORE_PORT:-80}"
SADSTORE_URL="http://${TEST_SADSTORE_HOST}:${TEST_SADSTORE_PORT}"

ALGORITHM="${ALGORITHM:-ml-dsa-65}"
KIND="${KIND:-kels/v1/test-data}"

COUNT=${1:-900}
CONCURRENCY=${2:-10}

# Round down to multiple of 9
COUNT=$(( (COUNT / 9) * 9 ))
GROUPS=$(( COUNT / 9 ))

PLACEHOLDER="############################################"

echo "========================================="
echo "SADStore Load Test"
echo "========================================="
echo "SAD objects:  $COUNT (${GROUPS} groups of 9)"
echo "Chains:       $GROUPS"
echo "Concurrency:  $CONCURRENCY"
echo "KELS URL:     $KELS_URL"
echo "SADStore URL: $SADSTORE_URL"
echo "Algorithm:    $ALGORITHM"
echo "Kind:         $KIND"
echo "========================================="

# Compute a SAID for a JSON object.
# Sets said to placeholder, hashes with blake3, prepends CESR "K" code.
compute_said() {
    local json="$1"
    local with_placeholder
    with_placeholder=$(echo "$json" | jq -c --arg p "$PLACEHOLDER" '.said = $p')
    local hash_b64
    hash_b64=$(printf '%s' "$with_placeholder" | b3sum --no-names --raw | base64 -w0 | tr '+/' '-_')
    echo "K${hash_b64}"
}

# Compute SAID for a SAD record (both said and prefix use placeholders for v0)
compute_record_said() {
    local json="$1"
    local with_placeholder
    with_placeholder=$(echo "$json" | jq -c --arg p "$PLACEHOLDER" '.said = $p')
    local hash_b64
    hash_b64=$(printf '%s' "$with_placeholder" | b3sum --no-names --raw | base64 -w0 | tr '+/' '-_')
    echo "K${hash_b64}"
}

# Compute prefix for a v0 inception record (both said AND prefix are placeholders)
compute_prefix() {
    local json="$1"
    local with_placeholders
    with_placeholders=$(echo "$json" | jq -c --arg p "$PLACEHOLDER" '.said = $p | .prefix = $p')
    local hash_b64
    hash_b64=$(printf '%s' "$with_placeholders" | b3sum --no-names --raw | base64 -w0 | tr '+/' '-_')
    echo "K${hash_b64}"
}

create_group() {
    local group=$1
    local tmpdir
    tmpdir=$(mktemp -d)

    # 1. Create a KEL
    local prefix
    prefix=$(kels-cli --kels-url "$KELS_URL" --config-dir "$tmpdir" incept --signing-algorithm "$ALGORITHM" 2>/dev/null | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1)
    if [ -z "$prefix" ]; then
        rm -rf "$tmpdir"
        return 1
    fi

    # 2. Create 9 SAD objects and collect their SAIDs
    local object_saids=()
    for i in $(seq 1 9); do
        local json
        json=$(jq -nc --arg p "$PLACEHOLDER" --arg v "load-test-${group}-${i}-$(date +%s%N)" \
            '{said: $p, value: $v}')
        local said
        said=$(compute_said "$json")
        json=$(echo "$json" | jq -c --arg s "$said" '.said = $s')

        curl -sf -X PUT "${SADSTORE_URL}/api/v1/sad/${said}" \
            -H 'Content-Type: application/json' \
            -d "$json" > /dev/null 2>&1 || true

        object_saids+=("$said")
    done

    # 3. Compute chain prefix (use kels-cli for correctness)
    local chain_prefix
    chain_prefix=$(kels-cli sad prefix "$prefix" "$KIND" 2>/dev/null)
    if [ -z "$chain_prefix" ]; then
        rm -rf "$tmpdir"
        return 1
    fi

    # 4. Pick random n from [1,9]
    local n=$(( (RANDOM % 9) + 1 ))

    # 5. Build chain records: v0 (inception, no content) then v1..vN
    # v0: deterministic inception record
    local v0_json
    v0_json=$(jq -nc --arg p "$PLACEHOLDER" --arg kp "$prefix" --arg k "$KIND" \
        '{said: $p, prefix: $p, version: 0, kelPrefix: $kp, kind: $k}')
    local v0_prefix
    v0_prefix=$(compute_prefix "$v0_json")
    v0_json=$(echo "$v0_json" | jq -c --arg pfx "$v0_prefix" '.prefix = $pfx')
    local v0_said
    v0_said=$(compute_record_said "$v0_json")
    v0_json=$(echo "$v0_json" | jq -c --arg s "$v0_said" '.said = $s')

    # Sign v0 and submit
    local v0_sig
    v0_sig=$(kels-cli --config-dir "$tmpdir" sign --prefix "$prefix" "$v0_said" 2>/dev/null)

    local records_json="[]"
    records_json=$(echo "$records_json" | jq -c --argjson r "$(echo "$v0_json")" --arg sig "$v0_sig" \
        '. + [{record: $r, signature: $sig, establishmentSerial: 0}]')

    local prev_said="$v0_said"

    for i in $(seq 1 "$n"); do
        local content_said="${object_saids[$((i-1))]}"
        local vi_json
        vi_json=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$v0_prefix" --arg prev "$prev_said" \
            --argjson ver "$i" --arg kp "$prefix" --arg k "$KIND" --arg cs "$content_said" \
            '{said: $p, prefix: $pfx, previous: $prev, version: $ver, kelPrefix: $kp, kind: $k, contentSaid: $cs}')
        local vi_said
        vi_said=$(compute_record_said "$vi_json")
        vi_json=$(echo "$vi_json" | jq -c --arg s "$vi_said" '.said = $s')

        local vi_sig
        vi_sig=$(kels-cli --config-dir "$tmpdir" sign --prefix "$prefix" "$vi_said" 2>/dev/null)

        records_json=$(echo "$records_json" | jq -c --argjson r "$(echo "$vi_json")" --arg sig "$vi_sig" \
            '. + [{record: $r, signature: $sig, establishmentSerial: 0}]')

        prev_said="$vi_said"
    done

    # 6. Submit all records in one batch
    curl -sf -X POST "${SADSTORE_URL}/api/v1/sad/records" \
        -H 'Content-Type: application/json' \
        -d "$records_json" > /dev/null 2>&1

    rm -rf "$tmpdir"
}

export -f create_group compute_said compute_record_said compute_prefix
export KELS_URL SADSTORE_URL ALGORITHM KIND PLACEHOLDER

start=$(date +%s)
seq 1 "$GROUPS" | xargs -P "$CONCURRENCY" -I {} bash -c 'create_group {}'
end=$(date +%s)

elapsed=$((end - start))
echo ""
echo "Created $COUNT SAD objects + $GROUPS chains in ${elapsed}s"
echo "Rate: $(( GROUPS / (elapsed > 0 ? elapsed : 1) )) chains/s"
