# Fastrace

Fast, dependency-free traceroute in pure C. Minimal syscalls, clear output, significantly faster than standard traceroute.

## Features

- **IPv4 and IPv6** dual-stack support
- **Multiple probe modes**: UDP (default), ICMP Echo, TCP SYN
- **Output formats**: Text (default), JSON, CSV
- **Performance metrics**: RTT percentiles, jitter, statistics
- **Adaptive concurrency**: Automatic window sizing based on network latency
- **Zero dependencies**: Only libc + raw sockets

## Performance

Fastrace is designed for speed. By using non-blocking sockets, batch I/O, concurrent probing, and optimized syscalls, it completes traces significantly faster than the standard `traceroute` utility.

### Benchmark: `google.com`

| Tool         | Hops | Time   | Response Rate |
| ------------ | ---- | ------ | ------------- |
| **fastrace** | 13   | ~1.5s  | 74.4% (29/39) |
| traceroute   | 11   | ~30s   | —             |

**fastrace** completes the trace **~20x faster** while providing richer output including load-balanced path detection.

<details>
<summary>Full output comparison</summary>

**fastrace:**

```
sudo ./fastrace google.com
fastrace 1.0.0
Tracing route to google.com (142.250.180.174)
Maximum hops: 30, Probes per hop: 3, Protocol: UDP
TTL │ IP Address                              (RTT ms)    Hostname
────┼────────────────────────────────────────────────────────────────
1   │ → 192.168.1.1                           (  6.15 ms)
2   │ * * * (timeout)
3   │ * * * (timeout)
4   │ → 185.89.159.5                          ( 14.77 ms)
5   │ → 37.26.80.129                          ( 14.68 ms)
6   │ → 193.77.91.225                         ( 29.88 ms) bsn-77-91-225.static.siol.net
7   │ → 193.77.107.46                         ( 31.69 ms) bsn-77-107-46.static.siol.net
8   │ * * * (timeout)
9   │ → 142.250.180.174                       ( 37.91 ms) mil04s44-in-f14.1e100.net
      └→ 142.251.235.178                       ( 39.32 ms)
      └→ 192.178.44.134                        ( 38.93 ms)
...
Trace complete in 1523.4 ms. Hops: 13, Responses: 29/39 (74.4%)
```

**Standard traceroute (~30 seconds):**

```
traceroute google.com
traceroute to google.com (142.250.180.174), 64 hops max, 40 byte packets
 1  192.168.1.1 (192.168.1.1)  3.876 ms  3.480 ms  3.633 ms
 2  * * *
 3  * * *
 ...
11  mil04s44-in-f14.1e100.net (142.250.180.174)  30.008 ms * *
```

</details>

## Quick Install

```bash
make                 # optimized build
sudo make install    # optional, installs to /usr/local/bin
```

Manual alternative:

```bash
gcc -O3 -pthread -lm -o fastrace fastrace.c
```

## Usage

```bash
sudo ./fastrace [options] <target>
```

### Basic Examples

```bash
# Standard UDP trace
sudo ./fastrace google.com

# IPv6 trace
sudo ./fastrace -6 ipv6.google.com

# ICMP Echo mode (like ping-based traceroute)
sudo ./fastrace -I 8.8.8.8

# Fast trace with no DNS
sudo ./fastrace -n -m 20 -q 2 cloudflare.com

# JSON output for scripting
sudo ./fastrace --json example.com

# Show performance metrics
sudo ./fastrace --metrics google.com
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-n` | Disable reverse DNS lookups | enabled |
| `-6` | Use IPv6 | IPv4 |
| `-I` | Use ICMP Echo instead of UDP | UDP |
| `-T` | Use TCP SYN instead of UDP | UDP |
| `-m <hops>` | Maximum hops to trace (1-128) | 30 |
| `-q <probes>` | Probes per hop (1-10) | 3 |
| `-c <count>` | Concurrent TTL window size | 8 |
| `-d <us>` | Inter-probe delay in microseconds | 100 |
| `-W <ms>` | Poll wait timeout in milliseconds | 1 |
| `-t <ms>` | Hop completion timeout in milliseconds | 500 |
| `-P <port>` | Base UDP/TCP destination port | 33434 |
| `--json` | Output results in JSON format | text |
| `--csv` | Output results in CSV format | text |
| `--metrics` | Show performance metrics (RTT p50/p95/p99, jitter) | off |
| `--quiet` | Minimal output (for benchmarking) | off |
| `--no-adaptive` | Disable adaptive concurrency window | adaptive |
| `-V` | Print version and exit | |
| `-h` | Show help message | |

### Output Formats

**JSON output** (`--json`):
```json
{
  "target": "google.com",
  "protocol": "UDP",
  "ip_version": 4,
  "probes_sent": 39,
  "responses_received": 29,
  "response_rate": 74.4,
  "hops": [
    {"ttl": 1, "results": [{"ip": "192.168.1.1", "rtt_ms": 6.150}]},
    {"ttl": 2, "results": [{"timeout": true}]},
    ...
  ]
}
```

**CSV output** (`--csv`):
```csv
ttl,ip,rtt_ms,hostname
1,192.168.1.1,6.150,router.local
2,*,0.0,
3,185.89.159.5,14.770,
...
```

**Metrics output** (`--metrics`):
```
── Performance Metrics ──────────────────────────────
  Samples:     29
  RTT min:     6.150 ms
  RTT max:     39.320 ms
  RTT mean:    24.567 ms
  RTT stddev:  10.234 ms
  RTT p50:     25.430 ms
  RTT p95:     38.120 ms
  RTT p99:     39.100 ms
  Jitter:      3.456 ms
─────────────────────────────────────────────────────
```

## Running Without sudo (Optional)

If you prefer not to type `sudo` every time:

**macOS** (setuid):
```bash
sudo chown root:wheel ./fastrace
sudo chmod u+s ./fastrace
```

**Linux** (capabilities, recommended):
```bash
sudo setcap cap_net_raw+ep ./fastrace
```

**Linux** (setuid, alternative):
```bash
sudo chown root:root ./fastrace
sudo chmod u+s ./fastrace
```

Then run directly:

```bash
./fastrace google.com
```

> **Security note**: This allows any local user to run fastrace with root privileges. Use only on personal machines.

## Testing

```bash
# Basic tests (no root required)
make test

# Full test suite (requires root)
sudo make test-full

# Performance benchmark
sudo make benchmark
```

## Technical Details

### Why is it fast?

1. **Batch I/O**: Uses `recvmmsg` on Linux for receiving multiple packets in one syscall
2. **Concurrent Probing**: Sends probes for multiple TTLs simultaneously
3. **Adaptive Window**: Automatically increases concurrency for low-latency networks
4. **Non-blocking I/O**: Uses `poll()` with tight timeouts
5. **Optimized Parsing**: Fast-path for non-matching ICMP packets
6. **Lock-free Counters**: Atomic operations for statistics

### Architecture

- **Dual socket design**: UDP/ICMP/TCP for sending, raw ICMP for receiving
- **Background DNS**: Hostname resolution runs in a separate thread
- **Monotonic timing**: Uses `CLOCK_MONOTONIC_RAW` for precise RTT measurements
- **Memory pools**: Pre-allocated buffers to avoid malloc in hot paths

### Platform Support

| Platform | UDP | ICMP | TCP | IPv6 | recvmmsg |
|----------|-----|------|-----|------|----------|
| Linux    | Yes | Yes  | Yes | Yes  | Yes      |
| macOS    | Yes | Yes  | Yes | Yes  | No*      |
| FreeBSD  | Yes | Yes  | Yes | Yes  | No*      |

*Falls back to standard `recvmsg`

## License

BSD-2-Clause. See LICENSE.
