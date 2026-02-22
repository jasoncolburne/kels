#!/usr/bin/env bash
set -e

REGISTRIES_FILE=".kels/federated-registries.json"

if [ ! -f "$REGISTRIES_FILE" ]; then
    echo ""
    exit 0
fi

jq -r '[.[] | select(.active == true) | "\(.prefix)=\(.url)"] | join(",")' "$REGISTRIES_FILE"
