#!/usr/bin/env bash
set -e

ENV_NAME="$1"
ENV_NAMESPACE="$2"
REPO_ROOT="$3"

if [ -z "$ENV_NAME" ] || [ -z "$ENV_NAMESPACE" ] || [ -z "$REPO_ROOT" ]; then
    echo "Usage: federation-fetch.sh <env-name> <env-namespace> <repo-root>"
    exit 1
fi

mkdir -p "$REPO_ROOT/.kels"
RESPONSE=$(kubectl exec -n "$ENV_NAMESPACE" deploy/identity -c identity -- \
    /app/identity-admin -j status 2>/dev/null)
PREFIX=$(echo "$RESPONSE" | jq -r '.prefix // empty')
if [ -z "$PREFIX" ]; then
    echo "Error: Could not fetch registry prefix. Is identity service initialized?"
    echo "Response: $RESPONSE"
    exit 1
fi

REGISTRIES_FILE="$REPO_ROOT/.kels/federated-registries.json"
URL="http://registry.${ENV_NAME}.kels"

if [ -f "$REGISTRIES_FILE" ]; then
    # Auto-assign next id
    NEXT_ID=$(jq 'if length == 0 then 0 else ([.[].id] | max + 1) end' "$REGISTRIES_FILE")
    # Add new entry (skip if name already exists)
    if jq -e --arg name "$ENV_NAME" '.[] | select(.name == $name)' "$REGISTRIES_FILE" >/dev/null 2>&1; then
        # Update existing entry (preserve id)
        jq --arg name "$ENV_NAME" --arg prefix "$PREFIX" --arg url "$URL" \
            'map(if .name == $name then .prefix = $prefix | .url = $url else . end)' \
            "$REGISTRIES_FILE" > "$REGISTRIES_FILE.tmp"
    else
        jq --argjson id "$NEXT_ID" --arg name "$ENV_NAME" --arg prefix "$PREFIX" --arg url "$URL" \
            '. + [{"id": $id, "name": $name, "prefix": $prefix, "url": $url, "active": true}]' \
            "$REGISTRIES_FILE" > "$REGISTRIES_FILE.tmp"
    fi
    mv "$REGISTRIES_FILE.tmp" "$REGISTRIES_FILE"
else
    # Create new file
    jq -n --arg name "$ENV_NAME" --arg prefix "$PREFIX" --arg url "$URL" \
        '[{"id": 0, "name": $name, "prefix": $prefix, "url": $url, "active": true}]' > "$REGISTRIES_FILE"
fi

echo "Registry prefix saved for $ENV_NAME: $PREFIX"
