#!/usr/bin/env bash
set -e

ENV_NAME="$1"

if [ -z "$ENV_NAME" ]; then
    echo "Usage: federation-read-url.sh <env-name>" >&2
    exit 1
fi

REGISTRIES_FILE=".kels/federated-registries.json"

if [ ! -f "$REGISTRIES_FILE" ]; then
    echo ""
    exit 0
fi

# Map node environments to their registry
case "$ENV_NAME" in
    node-a|node-d) REGISTRY_ENV="registry-a" ;;
    node-b|node-e) REGISTRY_ENV="registry-b" ;;
    node-c|node-f) REGISTRY_ENV="registry-c" ;;
    *) REGISTRY_ENV="$ENV_NAME" ;;
esac

jq -r --arg name "$REGISTRY_ENV" '.[] | select(.name == $name) | .url' "$REGISTRIES_FILE"
