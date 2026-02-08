#!/usr/bin/env bash
set -e

REGISTRIES_FILE=".kels/federated-registries.json"

if [ ! -f "$REGISTRIES_FILE" ]; then
    # File doesn't exist yet - return empty (bootstrap mode)
    echo ""
    exit 0
fi

# Output all prefixes as comma-separated list
jq -r '[.[] | values] | join(",")' "$REGISTRIES_FILE"
