#!/usr/bin/env bash
set -e

ENV_NAME="$1"

if [ -z "$ENV_NAME" ]; then
    echo "Usage: read-registry-url.sh <env-name>" >&2
    exit 1
fi

# Map node environments to their registry
case "$ENV_NAME" in
    node-a|node-d) REGISTRY_ENV="registry-a" ;;
    node-b) REGISTRY_ENV="registry-b" ;;
    node-c) REGISTRY_ENV="registry-c" ;;
    *) REGISTRY_ENV="$ENV_NAME" ;;
esac

# Output the internal cluster URL for the registry
echo "http://kels-registry.kels-${REGISTRY_ENV}.svc.cluster.local"
