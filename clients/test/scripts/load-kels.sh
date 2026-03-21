#!/bin/bash
# load-kels.sh - Populate a KELS node with many KELs for performance testing
#
# Usage: load-kels.sh [count] [events_per_kel]
#   count:          number of KELs to create (default: 1000)
#   events_per_kel: number of interaction events per KEL (default: 5)

set -e

# Unset Kubernetes-injected service environment variables
unset KELS_SERVICE_HOST KELS_SERVICE_PORT KELS_PORT

TEST_KELS_HOST="${TEST_KELS_HOST:-kels}"
TEST_KELS_PORT="${TEST_KELS_PORT:-80}"
KELS_URL="http://${TEST_KELS_HOST}:${TEST_KELS_PORT}"

COUNT=${1:-1000}
EVENTS_PER_KEL=${2:-5}
ALGORITHM=${3:-ml-dsa-65}
CONCURRENCY=${4:-10}

echo "========================================="
echo "KELS Load Test"
echo "========================================="
echo "KELs to create:    $COUNT"
echo "Events per KEL:    $EVENTS_PER_KEL"
echo "Algorithm:         $ALGORITHM"
echo "Concurrency:       $CONCURRENCY"
echo "KELS URL:          $KELS_URL"
echo "========================================="

create_kel() {
    local i=$1
    local tmpdir
    tmpdir=$(mktemp -d)
    # Create KEL with inception + interaction events
    local prefix
    prefix=$(kels-cli --url "$KELS_URL" --config-dir "$tmpdir" incept --signing-algorithm "$ALGORITHM" 2>/dev/null | grep -oE 'K[A-Za-z0-9_-]{43}' | head -1)
    if [ -z "$prefix" ]; then
        rm -rf "$tmpdir"
        return 1
    fi
    for j in $(seq 1 "$EVENTS_PER_KEL"); do
        kels-cli --url "$KELS_URL" --config-dir "$tmpdir" interact "$prefix" --anchor "load-test-${i}-${j}" >/dev/null 2>&1 || true
    done
    rm -rf "$tmpdir"
}

export -f create_kel
export KELS_URL ALGORITHM EVENTS_PER_KEL

start=$(date +%s)
seq 1 "$COUNT" | xargs -P "$CONCURRENCY" -I {} bash -c 'create_kel {}'
end=$(date +%s)

elapsed=$((end - start))
echo ""
echo "Created $COUNT KELs with $EVENTS_PER_KEL events each in ${elapsed}s"
echo "Total events: $((COUNT * (EVENTS_PER_KEL + 1)))"
