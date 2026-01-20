#!/bin/bash
# Benchmark script for fastrace

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FASTRACE="${SCRIPT_DIR}/../fastrace"

echo "========================================"
echo "Fastrace Benchmark Suite"
echo "========================================"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This benchmark requires root privileges."
    echo "Run: sudo $0"
    exit 1
fi

# Check binary exists
if [ ! -f "$FASTRACE" ]; then
    echo "Error: fastrace binary not found at $FASTRACE"
    echo "Run 'make' first."
    exit 1
fi

# Print version
"$FASTRACE" -V
echo ""

# Benchmark function
benchmark() {
    local name="$1"
    local target="$2"
    local extra_args="$3"
    
    echo "----------------------------------------"
    echo "Benchmark: $name"
    echo "Target: $target"
    echo "----------------------------------------"
    
    # Warm-up run
    "$FASTRACE" -n -m 15 -q 1 $extra_args "$target" >/dev/null 2>&1 || true
    
    # Timed runs
    local total_time=0
    local runs=3
    
    for i in $(seq 1 $runs); do
        start_time=$(date +%s.%N)
        "$FASTRACE" -n -m 20 -q 3 $extra_args "$target" >/dev/null 2>&1 || true
        end_time=$(date +%s.%N)
        run_time=$(echo "$end_time - $start_time" | bc)
        echo "  Run $i: ${run_time}s"
        total_time=$(echo "$total_time + $run_time" | bc)
    done
    
    avg_time=$(echo "scale=3; $total_time / $runs" | bc)
    echo "  Average: ${avg_time}s"
    echo ""
}

# Localhost benchmark
benchmark "Localhost (UDP)" "127.0.0.1" ""

# Localhost ICMP benchmark
benchmark "Localhost (ICMP)" "127.0.0.1" "-I"

# Check for external connectivity
if ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
    echo "External connectivity available, running network benchmarks..."
    echo ""
    
    benchmark "Cloudflare DNS" "1.1.1.1" ""
    benchmark "Google DNS" "8.8.8.8" ""
    
    if ping -c 1 -W 2 google.com >/dev/null 2>&1; then
        benchmark "google.com (with DNS resolution)" "google.com" ""
        benchmark "google.com (no DNS)" "google.com" "-n"
    fi
else
    echo "No external connectivity, skipping network benchmarks."
fi

# High concurrency benchmark
echo "----------------------------------------"
echo "Benchmark: High Concurrency"
echo "----------------------------------------"
echo "Testing with different concurrency window sizes..."

for window in 4 8 12 16; do
    start_time=$(date +%s.%N)
    "$FASTRACE" -n -m 20 -q 3 -c $window 127.0.0.1 >/dev/null 2>&1 || true
    end_time=$(date +%s.%N)
    run_time=$(echo "$end_time - $start_time" | bc)
    echo "  Window=$window: ${run_time}s"
done
echo ""

# Quiet mode benchmark
echo "----------------------------------------"
echo "Benchmark: Output Modes"
echo "----------------------------------------"

start_time=$(date +%s.%N)
"$FASTRACE" -n -m 15 -q 3 127.0.0.1 >/dev/null 2>&1 || true
end_time=$(date +%s.%N)
echo "  Normal output: $(echo "$end_time - $start_time" | bc)s"

start_time=$(date +%s.%N)
"$FASTRACE" -n -m 15 -q 3 --quiet 127.0.0.1 >/dev/null 2>&1 || true
end_time=$(date +%s.%N)
echo "  Quiet mode:    $(echo "$end_time - $start_time" | bc)s"

start_time=$(date +%s.%N)
"$FASTRACE" -n -m 15 -q 3 --json 127.0.0.1 >/dev/null 2>&1 || true
end_time=$(date +%s.%N)
echo "  JSON output:   $(echo "$end_time - $start_time" | bc)s"

echo ""
echo "========================================"
echo "Benchmark completed!"
echo "========================================"
