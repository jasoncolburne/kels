#!/bin/bash
# load-sad.sh - Populate a SADStore node with SAD objects and chain records
#
# For each group, creates a KEL, builds a single-endorser policy from its
# prefix (using the policy SAID as write_policy), stores SAD objects, then
# creates a pointer chain with a random number [1, MAX_CHAIN_VERSIONS] of
# versions, each referencing a different SAD object as content.
#
# Usage: load-sad.sh [count] [concurrency]
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

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

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

    # 1b. Build a real policy (single endorser) and store as SAD object
    local policy_json
    policy_json=$(jq -nc --arg p "$PLACEHOLDER" --arg expr "endorse($prefix)" \
        '{said: $p, expression: $expr}')
    local policy_said
    policy_said=$(compute_said "$policy_json")
    policy_json=$(echo "$policy_json" | jq -c --arg s "$policy_said" '.said = $s')

    local policy_resp
    policy_resp=$(curl -s -w "\n%{http_code}" -X POST "${SADSTORE_URL}/api/v1/sad" \
        -H 'Content-Type: application/json' \
        -d "$policy_json")
    local policy_code
    policy_code=$(echo "$policy_resp" | tail -1)
    if [ "$policy_code" != "201" ] && [ "$policy_code" != "200" ]; then
        echo "ERROR [group $group]: policy upload failed (HTTP $policy_code)" >&2
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
            rm -rf "$tmpdir"
            return 1
        fi

        object_saids+=("$said")
    done

    # 3. Compute chain prefix (use kels-cli for correctness)
    # kels-cli sad prefix takes (write_policy, topic) — we use the policy SAID as write_policy
    local chain_prefix
    chain_prefix=$(kels-cli sad prefix "$policy_said" "$KIND" 2>&1)
    if [ -z "$chain_prefix" ]; then
        echo "ERROR [group $group]: chain prefix computation failed" >&2
        rm -rf "$tmpdir"
        return 1
    fi

    # 4. Pick random n from [1,9]
    local n=$(( (RANDOM % MAX_CHAIN_VERSIONS) + 1 ))

    # 5. Build chain records: v0 (inception, no content) then v1..vN
    # v0: deterministic inception record (no content for v0)
    local v0_json
    v0_json=$(jq -nc --arg p "$PLACEHOLDER" --arg t "$KIND" --arg wp "$policy_said" \
        '{said: $p, prefix: $p, version: 0, topic: $t, writePolicy: $wp}')
    local v0_prefix
    v0_prefix=$(compute_prefix "$v0_json")
    v0_json=$(echo "$v0_json" | jq -c --arg pfx "$v0_prefix" '.prefix = $pfx')
    local v0_said
    v0_said=$(compute_said "$v0_json")
    v0_json=$(echo "$v0_json" | jq -c --arg s "$v0_said" '.said = $s')

    # Anchor v0 SAID in the KEL (required for write_policy authorization)
    if ! kels-cli --kels-url "$KELS_URL" --config-dir "$tmpdir" anchor --prefix "$prefix" --said "$v0_said" >/dev/null 2>&1; then
        echo "ERROR [group $group]: failed to anchor v0 SAID $v0_said" >&2
        rm -rf "$tmpdir"
        return 1
    fi

    local records_json="[]"
    records_json=$(echo "$records_json" | jq -c --argjson r "$(echo "$v0_json")" '. + [$r]')

    local prev_said="$v0_said"

    # Build a checkpoint policy for this chain
    build_checkpoint_policy "$SADSTORE_URL" "$prefix"
    local chain_cp_said="$CHECKPOINT_POLICY_SAID"

    for i in $(seq 1 "$n"); do
        local content_said="${object_saids[$((i-1))]}"
        local vi_json
        if [ "$i" -eq 1 ]; then
            # v1: first checkpoint (declares checkpoint_policy + is_checkpoint)
            vi_json=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$v0_prefix" --arg prev "$prev_said" \
                --argjson ver "$i" --arg t "$KIND" --arg cs "$content_said" --arg wp "$policy_said" \
                --arg cp "$chain_cp_said" \
                '{said: $p, prefix: $pfx, previous: $prev, version: $ver, topic: $t, content: $cs, writePolicy: $wp, checkpointPolicy: $cp, isCheckpoint: true}')
        else
            vi_json=$(jq -nc --arg p "$PLACEHOLDER" --arg pfx "$v0_prefix" --arg prev "$prev_said" \
                --argjson ver "$i" --arg t "$KIND" --arg cs "$content_said" --arg wp "$policy_said" \
                '{said: $p, prefix: $pfx, previous: $prev, version: $ver, topic: $t, content: $cs, writePolicy: $wp}')
        fi
        local vi_said
        vi_said=$(compute_said "$vi_json")
        vi_json=$(echo "$vi_json" | jq -c --arg s "$vi_said" '.said = $s')

        # Anchor each version's SAID in the KEL
        if ! kels-cli --kels-url "$KELS_URL" --config-dir "$tmpdir" anchor --prefix "$prefix" --said "$vi_said" >/dev/null 2>&1; then
            echo "ERROR [group $group]: failed to anchor v${i} SAID $vi_said" >&2
            rm -rf "$tmpdir"
            return 1
        fi

        records_json=$(echo "$records_json" | jq -c --argjson r "$(echo "$vi_json")" '. + [$r]')

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
        rm -rf "$tmpdir"
        return 1
    fi

    rm -rf "$tmpdir"
}

export -f create_group cesr_blake3 compute_said compute_prefix
export KELS_URL SADSTORE_URL ALGORITHM KIND PLACEHOLDER MAX_CHAIN_VERSIONS

start=$(date +%s)
seq 1 "$GROUP_COUNT" | xargs -P "$CONCURRENCY" -I {} bash -c 'create_group {}'
xargs_status=$?
end=$(date +%s)

elapsed=$((end - start))
echo ""
echo "Created $COUNT SAD objects + $GROUP_COUNT chains in ${elapsed}s"
echo "Rate: $(( GROUP_COUNT / (elapsed > 0 ? elapsed : 1) )) chains/s"

if [ "$xargs_status" -ne 0 ]; then
    echo "ERROR: one or more groups failed" >&2
    exit 1
fi
