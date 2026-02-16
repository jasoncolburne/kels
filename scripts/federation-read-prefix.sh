#!/usr/bin/env bash
set -e

REGISTRIES_FILE=".kels/federated-registries.json"

if [ ! -f "$REGISTRIES_FILE" ]; then
    echo ""
    exit 0
fi

ENV_NAME="$1"

# Map node environments to their registry
case "$ENV_NAME" in
    node-a|node-d) REGISTRY_ENV="registry-a" ;;
    node-b|node-e) REGISTRY_ENV="registry-b" ;;
    node-c|node-f) REGISTRY_ENV="registry-c" ;;
    *) REGISTRY_ENV="$ENV_NAME" ;;
esac

jq -r --arg name "$REGISTRY_ENV" '.[] | select(.name == $name) | .prefix' "$REGISTRIES_FILE"
