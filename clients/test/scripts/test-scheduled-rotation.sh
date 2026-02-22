#!/usr/bin/env bash
# test-scheduled-rotation.sh - Identity Scheduled Rotation Tests
# Verifies KEL structure after multiple scheduled rotations.
#
# The scheduled-rotate command follows a ROT, ROT, ROR, ROT, ROT, ROR pattern.
# After 4 rotations the KEL should contain: ROT, ROT, ROR, ROT
#
# Usage: test-scheduled-rotation.sh
#
# Environment variables:
#   IDENTITY_NS - Identity service namespace (default: kels-registry-a)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/test-common.sh"

# Configuration
IDENTITY_NS="${IDENTITY_NS:-kels-registry-a}"
IDENTITY_URL="http://identity.${IDENTITY_NS}.kels"

echo "========================================="
echo "KELS Scheduled Rotation Test Suite"
echo "========================================="
echo "Identity URL: $IDENTITY_URL"
echo "========================================="
echo ""

# Wait for identity service to be ready
echo "Waiting for identity service..."
wait_for_health "$IDENTITY_URL" "Identity service" || exit 1
echo ""

# ========================================
# Fetch KEL and extract rotation event kinds
# ========================================
echo -e "${CYAN}=== Verifying KEL Structure After Rotations ===${NC}"
echo ""

KEL=$(curl -s -f "$IDENTITY_URL/api/identity/kel")
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to fetch identity KEL${NC}"
    exit 1
fi

# Extract rotation event kinds in order (rot, ror)
ROTATION_KINDS=$(echo "$KEL" | jq -r '[.[] | .event | select(.kind == "kels/v1/rot" or .kind == "kels/v1/ror") | .kind] | .[]')
echo "Rotation event kinds:"
echo "$ROTATION_KINDS" | nl
echo ""

# Convert to array for indexed access
mapfile -t KINDS <<< "$ROTATION_KINDS"
ROTATION_COUNT=${#KINDS[@]}

echo "Total rotation events: $ROTATION_COUNT"

# Verify we have at least 4 rotation events
run_test "At least 4 rotation events" [ "$ROTATION_COUNT" -ge 4 ]

# Verify 3rd rotation (index 2) is ROR
run_test "3rd rotation is ROR" [ "${KINDS[2]}" = "kels/v1/ror" ]

# Verify 4th rotation (index 3) is ROT
run_test "4th rotation is ROT" [ "${KINDS[3]}" = "kels/v1/rot" ]

# Verify 1st rotation (index 0) is ROT
run_test "1st rotation is ROT" [ "${KINDS[0]}" = "kels/v1/rot" ]

# Verify 2nd rotation (index 1) is ROT
run_test "2nd rotation is ROT" [ "${KINDS[1]}" = "kels/v1/rot" ]

echo ""

print_summary "Scheduled Rotation Test Summary"
exit_with_result
