#!/usr/bin/env bash
# wait-for-gossip.sh - Wait for gossip nodes to be ready
#
# Usage: wait-for-gossip.sh <timeout> node-a node-b ...

source "$(cd "$(dirname "$0")" && pwd)/common.sh"

wait_for_gossip "$@"
