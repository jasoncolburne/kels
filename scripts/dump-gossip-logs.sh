#!/usr/bin/env bash
set -euo pipefail

NODES=(a b c d e f)
LOGS_DIR="$(cd "$(dirname "$0")/.." && pwd)/logs"

mkdir -p "$LOGS_DIR"

for node in "${NODES[@]}"; do
  echo "Dumping gossip logs for node-$node..."
  kubectl logs -l app=gossip --tail 10000 -n "kels-node-$node" > "$LOGS_DIR/gossip-$node.log" 2>&1 &
done

wait
echo "Done. Files in $LOGS_DIR/"
