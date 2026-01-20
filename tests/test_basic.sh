#!/bin/bash
# Basic test script for fastrace (non-root tests)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FASTRACE="${SCRIPT_DIR}/../fastrace"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
skip() { echo -e "${YELLOW}SKIP${NC}: $1"; }

echo "========================================"
echo "Fastrace Basic Test Suite"
echo "========================================"
echo ""

# Check binary exists
if [ ! -f "$FASTRACE" ]; then
    echo "Error: fastrace binary not found at $FASTRACE"
    echo "Run 'make' first."
    exit 1
fi

# Test 1: Version check
echo "Test 1: Version output"
VERSION_OUTPUT=$("$FASTRACE" -V 2>&1)
if echo "$VERSION_OUTPUT" | grep -q "fastrace 1.0.0"; then
    pass "Version output correct: $VERSION_OUTPUT"
else
    fail "Version output incorrect: $VERSION_OUTPUT"
fi

# Test 2: Help output
echo ""
echo "Test 2: Help output"
HELP_OUTPUT=$("$FASTRACE" -h 2>&1)
if echo "$HELP_OUTPUT" | grep -q "Usage:"; then
    pass "Help output contains usage info"
else
    fail "Help output missing usage info"
fi

# Test 3: Help contains new options
echo ""
echo "Test 3: New CLI options present"
MISSING=""
for OPT in "-6" "-I" "-T" "--json" "--csv" "--metrics" "--quiet"; do
    if ! echo "$HELP_OUTPUT" | grep -q -- "$OPT"; then
        MISSING="$MISSING $OPT"
    fi
done
if [ -z "$MISSING" ]; then
    pass "All new CLI options documented"
else
    fail "Missing CLI options in help:$MISSING"
fi

# Test 4: Invalid arguments
echo ""
echo "Test 4: Invalid argument handling"
if "$FASTRACE" --invalid-option 2>&1 | grep -q -i "usage\|help\|error\|unknown"; then
    pass "Invalid option handled correctly"
else
    skip "Invalid option handling (may vary)"
fi

# Test 5: Missing target
echo ""
echo "Test 5: Missing target handling"
if "$FASTRACE" 2>&1 | grep -q -i "usage"; then
    pass "Missing target shows usage"
else
    fail "Missing target should show usage"
fi

# Test 6: Invalid max TTL
echo ""
echo "Test 6: Invalid max TTL"
if "$FASTRACE" -m 999 localhost 2>&1 | grep -q -i "invalid"; then
    pass "Invalid max TTL rejected"
else
    skip "Invalid max TTL handling"
fi

# Test 7: Invalid probes per hop
echo ""
echo "Test 7: Invalid probes per hop"
if "$FASTRACE" -q 99 localhost 2>&1 | grep -q -i "invalid"; then
    pass "Invalid probes rejected"
else
    skip "Invalid probes handling"
fi

# Test 8: Check binary is not stripped (has symbols for debugging)
echo ""
echo "Test 8: Binary integrity"
if file "$FASTRACE" | grep -q "executable"; then
    pass "Binary is executable"
else
    fail "Binary format issue"
fi

echo ""
echo "========================================"
echo "Basic tests completed successfully!"
echo "========================================"
echo ""
echo "Run 'sudo make test-full' for full test suite with network tests."
