#!/bin/bash
# kels-bench Benchmark Test
# Measures KELS server performance with concurrent load
#
# Usage: bench-kels.sh [concurrency] [duration]

set -e

# Unset Kubernetes-injected service environment variables
unset KELS_SERVICE_HOST KELS_SERVICE_PORT KELS_PORT

# Service endpoints
TEST_KELS_HOST="${TEST_KELS_HOST:-kels}"
TEST_KELS_PORT="${TEST_KELS_PORT:-80}"

KELS_URL="http://${TEST_KELS_HOST}:${TEST_KELS_PORT}"

CONCURRENCY=${1:-60}
DURATION=${2:-5}

echo "========================================="
echo "kels-bench Benchmark"
echo "========================================="
echo "Concurrency: $CONCURRENCY"
echo "Duration:    ${DURATION}s"
echo "KELS URL:    $KELS_URL"
echo "========================================="

echo ""
echo "secp256r1"
echo ""
kels-bench --algorithm secp256r1 --url "$KELS_URL" --concurrency "$CONCURRENCY" --duration "$DURATION" --throughput-only --warmup 1

echo ""
echo "ml-dsa-65"
echo ""
kels-bench --algorithm ml-dsa-65 --url "$KELS_URL" --concurrency "$CONCURRENCY" --duration "$DURATION" --throughput-only --warmup 1

echo ""
echo "ml-dsa-87"
echo ""
kels-bench --algorithm ml-dsa-87 --url "$KELS_URL" --concurrency "$CONCURRENCY" --duration "$DURATION" --throughput-only --warmup 1

echo ""
echo -e "\033[0;32m=== KELS Benchmark Complete ===\033[0m"
