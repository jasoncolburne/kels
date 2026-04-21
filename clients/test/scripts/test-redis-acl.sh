#!/usr/bin/env bash
# test-redis-acl.sh - Redis ACL Enforcement Tests
# Verifies per-service ACL users, command restrictions, key isolation, and TTLs.
#
# Environment variables:
#   REDIS_HOST          - Redis hostname (default: redis)
#   KELS_PASSWORD       - kels user password (default: kels-redis-pass)
#   GOSSIP_PASSWORD     - gossip user password (default: gossip-redis-pass)
#   SADSTORE_PASSWORD   - sadstore user password (default: sadstore-redis-pass)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
REDIS_HOST="${REDIS_HOST:-redis}"
KELS_PASSWORD="${KELS_PASSWORD:-kels-redis-pass}"
GOSSIP_PASSWORD="${GOSSIP_PASSWORD:-gossip-redis-pass}"
SADSTORE_PASSWORD="${SADSTORE_PASSWORD:-sadstore-redis-pass}"

# Redis command helpers for each user
redis_kels() {
    redis-cli -h "$REDIS_HOST" --user kels -a "$KELS_PASSWORD" --no-auth-warning "$@"
}

redis_gossip() {
    redis-cli -h "$REDIS_HOST" --user gossip -a "$GOSSIP_PASSWORD" --no-auth-warning "$@"
}

redis_sadstore() {
    redis-cli -h "$REDIS_HOST" --user sadstore -a "$SADSTORE_PASSWORD" --no-auth-warning "$@"
}

redis_noauth() {
    redis-cli -h "$REDIS_HOST" "$@" 2>&1
}

echo "========================================="
echo "Redis ACL Enforcement Tests"
echo "========================================="
echo "Redis Host: $REDIS_HOST"
echo "========================================="
echo ""

# ==========================================
# 1. Unauthenticated access rejected
# ==========================================
echo "=== 1. Unauthenticated Access ==="

run_test "Unauthenticated PING rejected" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" PING 2>&1)
    echo "  Result: $result"
    echo "$result" | grep -qi "NOAUTH\|ERR\|denied\|Authentication required"
'

echo ""

# ==========================================
# 2. Each user can authenticate and PING
# ==========================================
echo "=== 2. User Authentication ==="

run_test "kels user can PING" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user kels -a "'$KELS_PASSWORD'" --no-auth-warning PING)
    echo "  Result: $result"
    [ "$result" = "PONG" ]
'

run_test "gossip user can PING" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user gossip -a "'$GOSSIP_PASSWORD'" --no-auth-warning PING)
    echo "  Result: $result"
    [ "$result" = "PONG" ]
'

run_test "sadstore user can PING" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user sadstore -a "'$SADSTORE_PASSWORD'" --no-auth-warning PING)
    echo "  Result: $result"
    [ "$result" = "PONG" ]
'

echo ""

# ==========================================
# 3. Dangerous commands denied
# ==========================================
echo "=== 3. Command Denial ==="

run_test "gossip user cannot FLUSHALL" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user gossip -a "'$GOSSIP_PASSWORD'" --no-auth-warning FLUSHALL 2>&1)
    echo "  Result: $result"
    echo "$result" | grep -qi "NOPERM\|no permissions\|denied"
'

run_test "gossip user cannot CONFIG SET" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user gossip -a "'$GOSSIP_PASSWORD'" --no-auth-warning CONFIG SET maxmemory 100mb 2>&1)
    echo "  Result: $result"
    echo "$result" | grep -qi "NOPERM\|no permissions\|denied"
'

run_test "gossip user cannot DEBUG" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user gossip -a "'$GOSSIP_PASSWORD'" --no-auth-warning DEBUG SLEEP 0 2>&1)
    echo "  Result: $result"
    echo "$result" | grep -qi "NOPERM\|no permissions\|denied\|not allowed"
'

run_test "kels user cannot FLUSHALL" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user kels -a "'$KELS_PASSWORD'" --no-auth-warning FLUSHALL 2>&1)
    echo "  Result: $result"
    echo "$result" | grep -qi "NOPERM\|no permissions\|denied"
'

echo ""

# ==========================================
# 4. Key pattern isolation
# ==========================================
echo "=== 4. Key Pattern Isolation ==="

run_test "gossip can HSET kels:anti_entropy:stale" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user gossip -a "'$GOSSIP_PASSWORD'" --no-auth-warning HSET kels:anti_entropy:stale test_prefix test_source)
    echo "  Result: $result"
    # Clean up
    redis-cli -h "'$REDIS_HOST'" --user gossip -a "'$GOSSIP_PASSWORD'" --no-auth-warning DEL kels:anti_entropy:stale > /dev/null
    [ "$result" = "1" ] || [ "$result" = "0" ]
'

run_test "gossip cannot SET kels:kel:test" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user gossip -a "'$GOSSIP_PASSWORD'" --no-auth-warning SET kels:kel:test forbidden 2>&1)
    echo "  Result: $result"
    echo "$result" | grep -qi "NOPERM\|no permissions\|denied"
'

run_test "kels can SETEX kels:kel:test" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user kels -a "'$KELS_PASSWORD'" --no-auth-warning SETEX kels:kel:test 60 testdata)
    echo "  Result: $result"
    # Clean up
    redis-cli -h "'$REDIS_HOST'" --user kels -a "'$KELS_PASSWORD'" --no-auth-warning DEL kels:kel:test > /dev/null
    [ "$result" = "OK" ]
'

run_test "kels cannot HSET kels:anti_entropy:stale" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user kels -a "'$KELS_PASSWORD'" --no-auth-warning HSET kels:anti_entropy:stale test forbidden 2>&1)
    echo "  Result: $result"
    echo "$result" | grep -qi "NOPERM\|no permissions\|denied"
'

echo ""

# ==========================================
# 5. Cache keys have TTLs
# ==========================================
echo "=== 5. Cache Key TTLs ==="

run_test "KEL cache key expires after SETEX" bash -c '
    redis-cli -h "'$REDIS_HOST'" --user kels -a "'$KELS_PASSWORD'" --no-auth-warning SETEX kels:kel:ttl-test 1 testdata > /dev/null
    before=$(redis-cli -h "'$REDIS_HOST'" --user kels -a "'$KELS_PASSWORD'" --no-auth-warning GET kels:kel:ttl-test)
    echo "  Before expiry: $before"
    sleep 2
    after=$(redis-cli -h "'$REDIS_HOST'" --user kels -a "'$KELS_PASSWORD'" --no-auth-warning GET kels:kel:ttl-test)
    echo "  After expiry: ${after:-(nil)}"
    [ "$before" = "testdata" ] && [ -z "$after" ]
'

echo ""

# ==========================================
# 6. Operational keys have no TTL
# ==========================================
echo "=== 6. Operational Key TTLs ==="

run_test "Anti-entropy key persists (no TTL)" bash -c '
    redis-cli -h "'$REDIS_HOST'" --user gossip -a "'$GOSSIP_PASSWORD'" --no-auth-warning HSET kels:anti_entropy:acl_test ttl-test-prefix ttl-test-source > /dev/null
    sleep 2
    result=$(redis-cli -h "'$REDIS_HOST'" --user gossip -a "'$GOSSIP_PASSWORD'" --no-auth-warning HGETALL kels:anti_entropy:acl_test)
    echo "  After 2s: $result"
    # Clean up
    redis-cli -h "'$REDIS_HOST'" --user gossip -a "'$GOSSIP_PASSWORD'" --no-auth-warning DEL kels:anti_entropy:acl_test > /dev/null
    echo "$result" | grep -q "ttl-test-prefix"
'

echo ""

# ==========================================
# 7. Pub/Sub channel isolation
# ==========================================
echo "=== 7. Pub/Sub Channel Isolation ==="

run_test "kels can PUBLISH to kel_updates" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user kels -a "'$KELS_PASSWORD'" --no-auth-warning PUBLISH kel_updates test_message)
    echo "  Result: $result"
    [ "$result" -ge 0 ]
'

run_test "sadstore can PUBLISH to sad_updates" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user sadstore -a "'$SADSTORE_PASSWORD'" --no-auth-warning PUBLISH sad_updates test_message)
    echo "  Result: $result"
    [ "$result" -ge 0 ]
'

run_test "sadstore can PUBLISH to sel_updates" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user sadstore -a "'$SADSTORE_PASSWORD'" --no-auth-warning PUBLISH sel_updates test_message)
    echo "  Result: $result"
    [ "$result" -ge 0 ]
'

run_test "gossip cannot PUBLISH to kel_updates" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user gossip -a "'$GOSSIP_PASSWORD'" --no-auth-warning PUBLISH kel_updates test_message 2>&1)
    echo "  Result: $result"
    echo "$result" | grep -qi "NOPERM\|no permissions\|denied"
'

run_test "kels cannot PUBLISH to sad_updates" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user kels -a "'$KELS_PASSWORD'" --no-auth-warning PUBLISH sad_updates test_message 2>&1)
    echo "  Result: $result"
    echo "$result" | grep -qi "NOPERM\|no permissions\|denied"
'

run_test "sadstore cannot PUBLISH to kel_updates" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user sadstore -a "'$SADSTORE_PASSWORD'" --no-auth-warning PUBLISH kel_updates test_message 2>&1)
    echo "  Result: $result"
    echo "$result" | grep -qi "NOPERM\|no permissions\|denied"
'

echo ""

# ==========================================
# 8. Key pattern isolation (sadstore)
# ==========================================
echo "=== 8. SADStore Key Isolation ==="

run_test "sadstore can SET kels:sad:test" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user sadstore -a "'$SADSTORE_PASSWORD'" --no-auth-warning SETEX kels:sad:test 60 testdata)
    echo "  Result: $result"
    redis-cli -h "'$REDIS_HOST'" --user sadstore -a "'$SADSTORE_PASSWORD'" --no-auth-warning DEL kels:sad:test > /dev/null
    [ "$result" = "OK" ]
'

run_test "sadstore cannot SET kels:kel:test" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user sadstore -a "'$SADSTORE_PASSWORD'" --no-auth-warning SET kels:kel:test forbidden 2>&1)
    echo "  Result: $result"
    echo "$result" | grep -qi "NOPERM\|no permissions\|denied"
'

run_test "sadstore cannot HSET kels:anti_entropy:stale" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user sadstore -a "'$SADSTORE_PASSWORD'" --no-auth-warning HSET kels:anti_entropy:stale test forbidden 2>&1)
    echo "  Result: $result"
    echo "$result" | grep -qi "NOPERM\|no permissions\|denied"
'

echo ""

print_summary "Redis ACL Test Summary"
exit_with_result
