#!/usr/bin/env bash
set -e

ENV_NAME="$1"
ENV_NAMESPACE="$2"
REPO_ROOT="$3"

if [ -z "$ENV_NAME" ] || [ -z "$ENV_NAMESPACE" ] || [ -z "$REPO_ROOT" ]; then
    echo "Usage: fetch-registry-prefix.sh <env-name> <env-namespace> <repo-root>"
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

# Save to JSON file with environment key
REGISTRIES_FILE="$REPO_ROOT/.kels/federated-registries.json"
if [ -f "$REGISTRIES_FILE" ]; then
    # Update existing file
    jq --arg env "$ENV_NAME" --arg prefix "$PREFIX" '.[$env] = $prefix' "$REGISTRIES_FILE" > "$REGISTRIES_FILE.tmp"
    mv "$REGISTRIES_FILE.tmp" "$REGISTRIES_FILE"
else
    # Create new file
    jq -n --arg env "$ENV_NAME" --arg prefix "$PREFIX" '{($env): $prefix}' > "$REGISTRIES_FILE"
fi

echo "Registry prefix saved for $ENV_NAME: $PREFIX"
