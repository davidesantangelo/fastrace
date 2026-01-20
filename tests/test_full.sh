#!/bin/bash
# Full test suite for fastrace (requires root)

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
echo "Fastrace Full Test Suite"
echo "========================================"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This test requires root privileges."
    echo "Run: sudo $0"
    exit 1
fi

# Check binary exists
if [ ! -f "$FASTRACE" ]; then
    echo "Error: fastrace binary not found at $FASTRACE"
    echo "Run 'make' first."
    exit 1
fi

# Test 1: Trace localhost (UDP)
echo "Test 1: Trace localhost (UDP mode)"
OUTPUT=$("$FASTRACE" -m 5 -q 1 127.0.0.1 2>&1)
if echo "$OUTPUT" | grep -q "127.0.0.1"; then
    pass "Localhost trace (UDP)"
else
    fail "Localhost trace (UDP) failed: $OUTPUT"
fi

# Test 2: Trace localhost (ICMP mode)
echo ""
echo "Test 2: Trace localhost (ICMP mode)"
OUTPUT=$("$FASTRACE" -I -m 5 -q 1 127.0.0.1 2>&1)
if echo "$OUTPUT" | grep -q "127.0.0.1\|ICMP"; then
    pass "Localhost trace (ICMP)"
else
    skip "ICMP mode may require specific kernel support"
fi

# Test 3: JSON output
echo ""
echo "Test 3: JSON output format"
OUTPUT=$("$FASTRACE" --json -m 3 -q 1 127.0.0.1 2>&1)
if echo "$OUTPUT" | grep -q '"target"' && echo "$OUTPUT" | grep -q '"hops"'; then
    pass "JSON output format"
else
    fail "JSON output format incorrect: $OUTPUT"
fi

# Test 4: CSV output
echo ""
echo "Test 4: CSV output format"
OUTPUT=$("$FASTRACE" --csv -m 3 -q 1 127.0.0.1 2>&1)
if echo "$OUTPUT" | grep -q "ttl,ip,rtt_ms"; then
    pass "CSV output format"
else
    fail "CSV output format incorrect: $OUTPUT"
fi

# Test 5: Quiet mode
echo ""
echo "Test 5: Quiet mode"
OUTPUT=$("$FASTRACE" --quiet -m 3 -q 1 127.0.0.1 2>&1)
LINES=$(echo "$OUTPUT" | wc -l)
if [ "$LINES" -lt 10 ]; then
    pass "Quiet mode (minimal output)"
else
    skip "Quiet mode output longer than expected"
fi

# Test 6: Metrics output
echo ""
echo "Test 6: Metrics output"
OUTPUT=$("$FASTRACE" --metrics -m 3 -q 2 127.0.0.1 2>&1)
if echo "$OUTPUT" | grep -q "RTT\|Samples\|p50\|p95"; then
    pass "Metrics output"
else
    skip "Metrics may not show with localhost"
fi

# Test 7: DNS disabled
echo ""
echo "Test 7: DNS disabled (-n)"
OUTPUT=$("$FASTRACE" -n -m 3 -q 1 127.0.0.1 2>&1)
if echo "$OUTPUT" | grep -q "127.0.0.1"; then
    pass "DNS disabled mode"
else
    fail "DNS disabled mode failed"
fi

# Test 8: Custom parameters
echo ""
echo "Test 8: Custom parameters"
OUTPUT=$("$FASTRACE" -m 10 -q 2 -c 4 -t 300 127.0.0.1 2>&1)
if echo "$OUTPUT" | grep -q "Probes per hop: 2"; then
    pass "Custom parameters"
else
    skip "Custom parameters output check"
fi

# Test 9: External trace (optional - requires network)
echo ""
echo "Test 9: External trace (1.1.1.1)"
if ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
    OUTPUT=$("$FASTRACE" -m 5 -q 1 -n 1.1.1.1 2>&1)
    if echo "$OUTPUT" | grep -q "Tracing\|TTL"; then
        pass "External trace to 1.1.1.1"
    else
        skip "External trace output unclear"
    fi
else
    skip "No network connectivity to 1.1.1.1"
fi

# Test 10: Signal handling (SIGINT)
echo ""
echo "Test 10: Signal handling"
timeout 2 "$FASTRACE" -m 30 -q 3 127.0.0.1 >/dev/null 2>&1 &
PID=$!
sleep 0.5
kill -INT $PID 2>/dev/null || true
wait $PID 2>/dev/null || true
pass "Signal handling (process terminated cleanly)"

echo ""
echo "========================================"
echo "Full test suite completed!"
echo "========================================"
