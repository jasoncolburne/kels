#!/bin/bash
# load-sad.sh - Populate a SADStore node with SAD objects and SAD events
#
# For each group, creates a KEL, sets up an IEL identity (single-endorser
# immune policy bound to the KEL), publishes content SAD objects, then
# drives a SE chain via `kels sel incept` (atomic [Icp, Upd@v1]) followed
# by zero or more `kels sel update` calls. Each version references a
# different SAD object as content.
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
TOPIC="${TOPIC:-kels/sad/v1/test-data}"

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
echo "Topic:        $TOPIC"
echo "========================================="

create_group() {
    local group=$1
    local tmpdir
    tmpdir=$(mktemp -d)
    local cli_global="--kels-url $KELS_URL --sadstore-url $SADSTORE_URL --config-dir $tmpdir"

    # 1. Create a KEL.
    local prefix
    prefix=$(kels-cli $cli_global kel incept --signing-algorithm "$ALGORITHM" 2>&1 \
        | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1)
    if [ -z "$prefix" ]; then
        echo "ERROR [group $group]: KEL inception failed" >&2
        rm -rf "$tmpdir"
        return 1
    fi

    # 2. Set up an IEL identity (single-endorser immune policy bound to the KEL).
    #    The helpers need the same `kels-cli` invocation flags the rest of
    #    create_group uses — most importantly `--config-dir`, so the
    #    `kel anchor` step inside `setup_iel_identity` can find the
    #    per-group key store under `$tmpdir`. Sharing $cli_global keeps
    #    every CLI call in a group rooted in the same isolated config.
    local iel_prefix
    iel_prefix=$(setup_iel_identity "kels-cli $cli_global" "$prefix" "load-${group}-$$") || {
        echo "ERROR [group $group]: IEL identity setup failed" >&2
        rm -rf "$tmpdir"
        return 1
    }

    # 3. Publish $MAX_CHAIN_VERSIONS content SAD objects.
    local content_saids=()
    for i in $(seq 1 "$MAX_CHAIN_VERSIONS"); do
        local content_json="$tmpdir/content-${i}.json"
        jq -nc --arg p "$PLACEHOLDER" --arg v "load-test-${group}-${i}-$(date +%s%N)" \
            '{said: $p, value: $v}' > "$content_json"
        local content_said
        content_said=$(put_sad_object "kels-cli $cli_global" "$content_json") || {
            echo "ERROR [group $group]: content SAD put failed for v${i}" >&2
            rm -rf "$tmpdir"
            return 1
        }
        content_saids+=("$content_said")
    done

    # 4. Pick random n in [1, MAX_CHAIN_VERSIONS]; chain = [Icp, Upd@v1, ..., Upd@vn].
    local n=$(( (RANDOM % MAX_CHAIN_VERSIONS) + 1 ))

    # 5. Stage atomic [Icp, Upd@v1] via `sel incept`. content_saids[0] is v1.
    local incept_out
    incept_out=$(kels-cli $cli_global sel incept "$TOPIC" \
        --identity "$iel_prefix" --initial-content "${content_saids[0]}" --publish 2>&1) || {
        echo "ERROR [group $group]: sel incept failed: $incept_out" >&2
        rm -rf "$tmpdir"
        return 1
    }
    local icp_said upd1_said
    icp_said=$(echo "$incept_out" | head -1)
    upd1_said=$(echo "$incept_out" | tail -1)

    # Anchor [Icp, v1].
    if ! kels-cli $cli_global kel anchor --prefix "$prefix" --said "$icp_said" >/dev/null 2>&1; then
        echo "ERROR [group $group]: failed to anchor Icp $icp_said" >&2
        rm -rf "$tmpdir"
        return 1
    fi
    if ! kels-cli $cli_global kel anchor --prefix "$prefix" --said "$upd1_said" >/dev/null 2>&1; then
        echo "ERROR [group $group]: failed to anchor v1 $upd1_said" >&2
        rm -rf "$tmpdir"
        return 1
    fi

    # Submit the inception batch.
    if ! kels-cli $cli_global sel submit "$icp_said" "$upd1_said" >/dev/null 2>&1; then
        echo "ERROR [group $group]: failed to submit [Icp, v1]" >&2
        rm -rf "$tmpdir"
        return 1
    fi

    # 6. For i in [2, n]: stage v_i Upd via sel update with content_saids[i-1],
    #    anchor, submit.
    local sel_prefix
    sel_prefix=$(kels-cli sel prefix "$iel_prefix" "$TOPIC" 2>/dev/null)
    for i in $(seq 2 "$n"); do
        local content="${content_saids[$((i-1))]}"
        local vi_said
        vi_said=$(kels-cli $cli_global sel update "$sel_prefix" "$content" --publish 2>&1) || {
            echo "ERROR [group $group]: sel update v${i} failed: $vi_said" >&2
            rm -rf "$tmpdir"
            return 1
        }
        if ! kels-cli $cli_global kel anchor --prefix "$prefix" --said "$vi_said" >/dev/null 2>&1; then
            echo "ERROR [group $group]: failed to anchor v${i} $vi_said" >&2
            rm -rf "$tmpdir"
            return 1
        fi
        if ! kels-cli $cli_global sel submit "$vi_said" >/dev/null 2>&1; then
            echo "ERROR [group $group]: failed to submit v${i} $vi_said" >&2
            rm -rf "$tmpdir"
            return 1
        fi
    done

    rm -rf "$tmpdir"
}

export -f create_group build_immune_policy setup_iel_identity \
    setup_iel_identity_with_policy put_sad_object
export KELS_URL SADSTORE_URL ALGORITHM TOPIC PLACEHOLDER MAX_CHAIN_VERSIONS

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
