#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <PREFIX>"
  exit 1
fi

PREFIX="$1"
NODES=(a b c d e f)
LOGS_DIR="$(cd "$(dirname "$0")/.." && pwd)/logs"

mkdir -p "$LOGS_DIR/$PREFIX"

for node in "${NODES[@]}"; do
  echo "Fetching node-$node..."
  curl -s -X POST -H 'Content-Type: application/json' -d "{\"prefix\":\"$PREFIX\"}" "http://kels.node-$node.kels/api/v1/kels/kel/fetch" | jq . > "$LOGS_DIR/$PREFIX/node-$node.kel" &
done

wait
echo "Done. Files in $LOGS_DIR/"
