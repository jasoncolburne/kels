#!/usr/bin/env bash
set -e

# Find the Raft federation leader by querying registry status endpoints
# from inside the cluster via the test-client pod.

REGISTRIES=(kels-registry-a kels-registry-b kels-registry-c kels-registry-d)

for ns in "${REGISTRIES[@]}"; do
    LEADER_INFO=$(kubectl exec -n kels-node-a test-client -- \
        curl -s "http://registry.${ns}.kels/api/v1/federation/status" 2>/dev/null || echo "{}")
    IS_LEADER=$(echo "$LEADER_INFO" | jq -r '.isLeader // false')

    if [ "$IS_LEADER" = "true" ]; then
        echo -n "$ns"
        exit 0
    fi
done

echo "Error: Could not find federation leader" >&2
exit 1
