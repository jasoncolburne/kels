#!/usr/bin/env bash
set -e

ENV_NAME="$1"
REPO_ROOT="$2"

if [ -z "$ENV_NAME" ] || [ -z "$REPO_ROOT" ]; then
    echo "Usage: federation-deactivate.sh <env-name> <repo-root>"
    exit 1
fi

REGISTRIES_FILE="$REPO_ROOT/.kels/federated-registries.json"

if [ ! -f "$REGISTRIES_FILE" ]; then
    echo "Error: $REGISTRIES_FILE not found"
    exit 1
fi

if ! jq -e --arg name "$ENV_NAME" '.[] | select(.name == $name)' "$REGISTRIES_FILE" >/dev/null 2>&1; then
    echo "Error: Registry '$ENV_NAME' not found in $REGISTRIES_FILE"
    exit 1
fi

jq --arg name "$ENV_NAME" \
    'map(if .name == $name then .active = false else . end)' \
    "$REGISTRIES_FILE" > "$REGISTRIES_FILE.tmp"
mv "$REGISTRIES_FILE.tmp" "$REGISTRIES_FILE"

echo "Registry deactivated: $ENV_NAME"
