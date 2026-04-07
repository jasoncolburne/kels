#!/usr/bin/env bash
# deploy-nodes.sh - Deploy nodes by name
#
# Usage: deploy-nodes.sh node-a node-b node-c ...

source "$(cd "$(dirname "$0")" && pwd)/common.sh"

deploy_nodes "$@"
