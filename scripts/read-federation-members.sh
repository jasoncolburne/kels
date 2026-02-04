#!/usr/bin/env bash
set -e

REGISTRIES_FILE=".kels/federated-registries.json"

if [ ! -f "$REGISTRIES_FILE" ]; then
    # File doesn't exist yet - return empty (federation not configured)
    echo ""
    exit 0
fi

ENV_NAME="$1"
MODE="${2:-prefix}"  # "prefix" (default) or "members"

# Map node environments to their registry
case "$ENV_NAME" in
    node-a|node-d) REGISTRY_ENV="registry-a" ;;
    node-b) REGISTRY_ENV="registry-b" ;;
    node-c) REGISTRY_ENV="registry-c" ;;
    *) REGISTRY_ENV="$ENV_NAME" ;;
esac

if [ "$MODE" = "members" ]; then
    # Output all prefixes as federation members: prefix1=url1,prefix2=url2,...
    jq -r 'to_entries | map("\(.value)=http://kels-registry.kels-\(.key).kels") | join(",")' "$REGISTRIES_FILE"
else
    # Output single prefix for this environment
    jq -r --arg env "$REGISTRY_ENV" '.[$env] // empty' "$REGISTRIES_FILE"
fi
