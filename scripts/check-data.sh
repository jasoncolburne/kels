#!/usr/bin/env bash
# check-data.sh — diagnostic queries against KELS / SADStore for one or more nodes.
#
# Hits the existing HTTP endpoints directly (test endpoints where unsigned, v1
# otherwise). Targets must be reachable from the host (kels.<node>.kels and
# sadstore.<node>.kels) — same DNS posture as `investigate-prefix.sh`.

set -euo pipefail

usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") <subcommand> [args...]

Subcommands:
  event-exists <said> <node>              KEL event SAID present on node's KELS?
                                          200 → exists, 404 → missing.
  sad-exists <said> <node>                SAD object SAID present on node's sadstore?
  prefix-listed <kind> <prefix> <node>    Prefix appears in node's listing? Walks all pages.
                                            kind: kel | sel | iel
  compare <kind> <node-x> <node-y>        Listing diff between two nodes (full pagination).
                                            kind: kel | sel | iel
  fetch-events <kind> <prefix> <node>     Dump events on node for a prefix.
                                            kind: kel | sel | iel

Examples:
  $(basename "$0") event-exists KLs1QBX5... node-a
  $(basename "$0") sad-exists KHLquHOV... node-a
  $(basename "$0") prefix-listed iel KIQII-h8mBPj... node-a
  $(basename "$0") compare iel node-a node-d
  $(basename "$0") fetch-events kel KCRtRuvy9... node-a
EOF
    exit 1
}

[ $# -lt 1 ] && usage

cmd="$1"; shift

# --- URL helpers ---

list_url() {
    local kind="$1" node="$2"
    case "$kind" in
        kel) echo "http://kels.${node}.kels/api/test/prefixes" ;;
        sel) echo "http://sadstore.${node}.kels/api/test/sad/events/prefixes" ;;
        iel) echo "http://sadstore.${node}.kels/api/test/iel/events/prefixes" ;;
        *) echo "kind must be kel|sel|iel (got: $kind)" >&2; exit 2 ;;
    esac
}

# Mock SignedRequest payload values — `/api/test/*` listing endpoints
# require the SignedRequest wrapper for deserialization but do not verify
# signatures. Same shape clients/test/scripts/test-sad-consistency.sh uses.
MOCK_SAID="KMOCK_SAID__________________________________"
MOCK_PREFIX="KMOCK_PREFIX________________________________"
MOCK_SIGNATURE="0CMOCK_SIGNATURE________________________________________________________________________"
MOCK_CREATED_AT="2026-01-01T00:00:00.000000Z"

# Build the JSON body for a paginated test listing request. Pass the
# cursor as $1 (empty string for first page).
listing_body() {
    local cursor="$1"
    local nonce="NA$(openssl rand -hex 21)"
    if [ -n "$cursor" ]; then
        jq -n --arg cursor "$cursor" --arg nonce "$nonce" \
            "{payload:{said:\"$MOCK_SAID\",createdAt:\"$MOCK_CREATED_AT\",nonce:\$nonce,cursor:\$cursor,limit:1000},signatures:{\"$MOCK_PREFIX\":\"$MOCK_SIGNATURE\"}}"
    else
        jq -n --arg nonce "$nonce" \
            "{payload:{said:\"$MOCK_SAID\",createdAt:\"$MOCK_CREATED_AT\",nonce:\$nonce,cursor:null,limit:1000},signatures:{\"$MOCK_PREFIX\":\"$MOCK_SIGNATURE\"}}"
    fi
}

fetch_url() {
    local kind="$1" node="$2"
    case "$kind" in
        kel) echo "http://kels.${node}.kels/api/v1/kels/kel/fetch" ;;
        sel) echo "http://sadstore.${node}.kels/api/v1/sad/events/fetch" ;;
        iel) echo "http://sadstore.${node}.kels/api/v1/iel/events/fetch" ;;
        *) echo "kind must be kel|sel|iel (got: $kind)" >&2; exit 2 ;;
    esac
}

# --- Listing pagination ---
#
# Streams one prefix entry per line as compact JSON. Cooperates with `jq -c`
# downstream for filter/sort/diff composition.
all_prefixes() {
    local url="$1"
    local cursor=""
    while :; do
        local body resp next
        body=$(listing_body "$cursor")
        resp=$(curl -sf -X POST "$url" -H 'content-type: application/json' -d "$body" 2>/dev/null) || break
        echo "$resp" | jq -c '.prefixes[]?'
        next=$(echo "$resp" | jq -r '.nextCursor // empty')
        [ -z "$next" ] && break
        cursor="$next"
    done
}

# --- Subcommands ---

cmd_event_exists() {
    [ $# -eq 2 ] || { echo "Usage: $(basename "$0") event-exists <said> <node>" >&2; exit 1; }
    local said="$1" node="$2"
    local code
    code=$(curl -sX POST "http://kels.${node}.kels/api/v1/kels/events/exists" \
        -H 'content-type: application/json' \
        -d "{\"said\":\"$said\"}" \
        -o /dev/null -w '%{http_code}')
    case "$code" in
        200) echo "EXISTS on $node ($said)" ;;
        404) echo "NOT FOUND on $node ($said)" ;;
        *)   echo "HTTP $code on $node ($said)" ;;
    esac
}

cmd_sad_exists() {
    [ $# -eq 2 ] || { echo "Usage: $(basename "$0") sad-exists <said> <node>" >&2; exit 1; }
    local said="$1" node="$2"
    local code
    code=$(curl -sX POST "http://sadstore.${node}.kels/api/v1/sad/exists" \
        -H 'content-type: application/json' \
        -d "{\"said\":\"$said\"}" \
        -o /dev/null -w '%{http_code}')
    case "$code" in
        200) echo "EXISTS on $node ($said)" ;;
        404) echo "NOT FOUND on $node ($said)" ;;
        *)   echo "HTTP $code on $node ($said)" ;;
    esac
}

cmd_prefix_listed() {
    [ $# -eq 3 ] || { echo "Usage: $(basename "$0") prefix-listed <kind> <prefix> <node>" >&2; exit 1; }
    local kind="$1" prefix="$2" node="$3"
    local match
    match=$(all_prefixes "$(list_url "$kind" "$node")" | jq -c --arg p "$prefix" 'select(.prefix == $p)' | head -n1)
    if [ -n "$match" ]; then
        echo "LISTED on $node ($kind):"
        echo "$match" | jq .
    else
        echo "NOT LISTED on $node ($kind): $prefix"
        exit 1
    fi
}

cmd_compare() {
    [ $# -eq 3 ] || { echo "Usage: $(basename "$0") compare <kind> <node-x> <node-y>" >&2; exit 1; }
    local kind="$1" nx="$2" ny="$3"
    local x_file y_file
    x_file=$(mktemp)
    y_file=$(mktemp)

    all_prefixes "$(list_url "$kind" "$nx")" | jq -r '.prefix' | sort -u > "$x_file"
    all_prefixes "$(list_url "$kind" "$ny")" | jq -r '.prefix' | sort -u > "$y_file"

    local x_count y_count x_only_count y_only_count
    x_count=$(wc -l < "$x_file" | tr -d ' ')
    y_count=$(wc -l < "$y_file" | tr -d ' ')

    echo "$nx ($kind): $x_count prefixes"
    echo "$ny ($kind): $y_count prefixes"

    x_only_count=$(comm -23 "$x_file" "$y_file" | wc -l | tr -d ' ')
    y_only_count=$(comm -13 "$x_file" "$y_file" | wc -l | tr -d ' ')

    echo
    echo "Only on $nx: $x_only_count"
    comm -23 "$x_file" "$y_file" | sed 's/^/  /'
    echo
    echo "Only on $ny: $y_only_count"
    comm -13 "$x_file" "$y_file" | sed 's/^/  /'

    rm -f "$x_file" "$y_file"
}

cmd_fetch_events() {
    [ $# -eq 3 ] || { echo "Usage: $(basename "$0") fetch-events <kind> <prefix> <node>" >&2; exit 1; }
    local kind="$1" prefix="$2" node="$3"
    curl -sX POST "$(fetch_url "$kind" "$node")" \
        -H 'content-type: application/json' \
        -d "{\"prefix\":\"$prefix\"}" \
        | jq .
}

case "$cmd" in
    event-exists)   cmd_event_exists   "$@" ;;
    sad-exists)     cmd_sad_exists     "$@" ;;
    prefix-listed)  cmd_prefix_listed  "$@" ;;
    compare)        cmd_compare        "$@" ;;
    fetch-events)   cmd_fetch_events   "$@" ;;
    -h|--help|help) usage ;;
    *) echo "Unknown subcommand: $cmd" >&2; usage ;;
esac
