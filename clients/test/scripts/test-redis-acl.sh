#!/bin/bash
# test-redis-acl.sh - Redis ACL Enforcement Tests
# Verifies per-service ACL users, command restrictions, key isolation, and TTLs.
#
# Environment variables:
#   REDIS_HOST          - Redis hostname (default: redis)
#   KELS_PASSWORD       - kels user password (default: kels-redis-pass)
#   GOSSIP_PASSWORD     - gossip user password (default: gossip-redis-pass)
#   REGISTRY_PASSWORD   - registry user password (default: registry-redis-pass)

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
REDIS_HOST="${REDIS_HOST:-redis}"
KELS_PASSWORD="${KELS_PASSWORD:-kels-redis-pass}"
GOSSIP_PASSWORD="${GOSSIP_PASSWORD:-gossip-redis-pass}"
REGISTRY_PASSWORD="${REGISTRY_PASSWORD:-registry-redis-pass}"

TESTS_PASSED=0
TESTS_FAILED=0

# Test helpers
run_test() {
    local name="$1"
    shift
    echo -e "${YELLOW}Testing: ${name}${NC}"
    if "$@" 2>&1; then
        echo -e "${GREEN}PASSED: ${name}${NC}"
        ((TESTS_PASSED++)) || true
        return 0
    else
        echo -e "${RED}FAILED: ${name}${NC}"
        ((TESTS_FAILED++)) || true
        return 1
    fi
}

# Redis command helpers for each user
redis_kels() {
    redis-cli -h "$REDIS_HOST" --user kels -a "$KELS_PASSWORD" --no-auth-warning "$@"
}

redis_gossip() {
    redis-cli -h "$REDIS_HOST" --user gossip -a "$GOSSIP_PASSWORD" --no-auth-warning "$@"
}

redis_registry() {
    redis-cli -h "$REDIS_HOST" --user registry -a "$REGISTRY_PASSWORD" --no-auth-warning "$@"
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

run_test "registry user can PING" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user registry -a "'$REGISTRY_PASSWORD'" --no-auth-warning PING)
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

run_test "registry can SET kels-registry:node:test" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user registry -a "'$REGISTRY_PASSWORD'" --no-auth-warning SET kels-registry:node:test testdata)
    echo "  Result: $result"
    # Clean up
    redis-cli -h "'$REDIS_HOST'" --user registry -a "'$REGISTRY_PASSWORD'" --no-auth-warning DEL kels-registry:node:test > /dev/null
    [ "$result" = "OK" ]
'

run_test "registry cannot SET kels:kel:test" bash -c '
    result=$(redis-cli -h "'$REDIS_HOST'" --user registry -a "'$REGISTRY_PASSWORD'" --no-auth-warning SET kels:kel:test forbidden 2>&1)
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
# Summary
# ==========================================
echo "========================================="
echo "Redis ACL Test Summary"
echo "========================================="
echo -e "Passed: ${GREEN}${TESTS_PASSED}${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "Failed: ${RED}${TESTS_FAILED}${NC}"
else
    echo -e "Failed: ${GREEN}${TESTS_FAILED}${NC}"
fi
echo "========================================="

if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
fi
