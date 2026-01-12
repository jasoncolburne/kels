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

CONCURRENCY=${1:-40}
DURATION=${2:-10}

echo "========================================="
echo "kels-bench Benchmark"
echo "========================================="
echo "Concurrency: $CONCURRENCY"
echo "Duration:    ${DURATION}s"
echo "KELS URL:    $KELS_URL"
echo "========================================="
echo ""

kels-bench --url "$KELS_URL" --concurrency "$CONCURRENCY" --duration "$DURATION" --throughput-only --warmup 2

echo ""
echo -e "\033[0;32m=== KELS Benchmark Complete ===\033[0m"
