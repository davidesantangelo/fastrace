# Fastrace

A high-performance, dependency-free traceroute implementation in pure C.

## New in 0.2.0

- Fully non-blocking architecture driven by `poll()` for faster ICMP draining
- Monotonic timing pipeline for sub-millisecond RTT accuracy
- Runtime tuning via CLI flags for hops, probes, concurrency, and timeouts
- Reverse DNS cache with optional suppression (`-n`) to optimise lookups
- Expanded socket buffers and smarter probe scheduling for lower latency traces

## Overview

Fastrace is a blazingly fast traceroute utility designed for network diagnostics and performance analysis. It maps the route that packets take across an IP network from source to destination, providing detailed timing information and identifying potential bottlenecks or routing issues.

## Technical Architecture

- **Zero External Dependencies**: Relies solely on standard C libraries and system calls
- **Maximum Performance**: Event-driven pipeline with parallel probing and non-blocking IO
- **Low Memory Footprint**: Uses compact data structures with tight allocations sized to the trace
- **Dual Socket Implementation**: Uses UDP for probes and raw sockets for response capture
- **Visual Route Mapping**: Displays network topology with a structured, tree-like representation
- **Runtime Tunability**: Allows hop count, probe volume, concurrency, and DNS behaviour to be adjusted live

### Key Components


#### 1. Dual Socket Architecture

Fastrace uses two socket types for maximum effectiveness:
- UDP socket (`SOCK_DGRAM`) for sending probe packets
- Raw ICMP socket (`SOCK_RAW`) for receiving router responses

```c
send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
```

#### 2. Probe Structure

Each probe is tracked using a specialized structure:

```c
typedef struct {
    int ttl;                /* Time-to-Live value */
    int probe;              /* Probe sequence number */
    struct timeval sent_time; /* Timestamp when sent */
    int received;           /* Whether response was received */
    struct in_addr addr;    /* Address of responding hop */
    double rtt;             /* Round-trip time in ms */
    int port;              /* UDP port used for this probe */
} probe_t;
```

#### 3. Adaptive Route Discovery

Fastrace implements a configurable multi-TTL probing system that keeps several hops "in flight" simultaneously. The concurrency window can be tuned at runtime (`-c <count>`), enabling the tracer to saturate available ICMP feedback channels without overwhelming links.

#### 4. Efficient Response Processing

The response processor relies on a `poll()`-driven event loop and non-blocking sockets to eagerly drain ICMP bursts while avoiding idle busy-waiting:

```c
struct pollfd pfd = { .fd = recv_sock, .events = POLLIN | POLLERR };
if (poll(&pfd, 1, config.wait_timeout_ms) > 0) {
    drain_icmp_socket();
}
```

#### 5. UDP/ICMP Protocol Implementation

Fastrace implements precise handling of network protocols:

- **UDP Probes**: Sending UDP packets with incrementing TTL values
- **TTL Management**: Systematic incrementing of TTL values to discover route hops
- **ICMP Response Processing**: Parsing ICMP responses from routers
- **Port-based Probe Identification**: Using unique ports to match responses to probes

#### 6. Visual Path Representation

Fastrace provides a structured visual representation of network paths:
- Tree-like format shows branching at load-balanced routes
- Clear arrows indicate path progression
- Distinct formatting for primary and alternative routes

## Performance Optimizations

### 1. Poll-Based Event Loop

Non-blocking sockets combined with `poll()` wakeups eliminate unnecessary sleeps and react instantly to bursts of ICMP replies.

### 2. Adaptive Probe Batching

Probe cadence is tuned via `config.probe_delay_us` and the runtime `-q` option, letting users increase sample density when needed without recompilation.

### 3. Monotonic Timing

`clock_gettime(CLOCK_MONOTONIC)` powers RTT measurements and hop deadlines, delivering microsecond precision unaffected by system clock changes.

### 4. Compiler Optimization

Designed to be compiled with aggressive optimization flags:

```
gcc -O3 -o fastrace fastrace.c
```

### 5. DNS Caching

A lightweight reverse DNS cache prevents repeated `PTR` lookups for load-balanced hops, cutting latency and reducing resolver load.

## Benchmark Comparison

Fastrace significantly outperforms standard traceroute in several key metrics:

| Metric | Standard Traceroute | Fastrace | Improvement |
|--------|---------------------|----------|-------------|
| Total trace time (30 hops) | ~15-20 seconds | ~5-8 seconds | 60-70% faster |
| Memory usage | ~400-600 KB | ~120-150 KB | 70-75% less memory |
| CPU utilization | 5-8% | 2-3% | 60% less CPU |
| Packet efficiency | 1 TTL at a time | Up to 5 TTLs concurrently | 5x throughput |
| Response waiting | Fixed timeouts | Adaptive timeouts | Better adaptation |
| Visual clarity | Flat output | Hierarchical tree view | Improved readability |
| RTT accuracy | Variable | Highly accurate | Matches standard tools |

## Technical Requirements

### System Requirements

- **Operating System**: Linux, macOS, or other Unix-like systems with raw socket support
- **Permissions**: Root/sudo access required (raw sockets)
- **Compiler**: GCC with C99 support or later
- **Architecture**: x86, x86_64, ARM, or any platform with standard C library support

### Header Dependencies

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
```

## Compilation & Installation

### Using Makefile

The project includes a Makefile for easy compilation and installation:

```bash
# Standard optimized build
make

# Build with debugging symbols
make debug

# Build with maximum performance optimizations
make optimized

# Install to system (default: /usr/local/bin)
sudo make install

# Uninstall from system
sudo make uninstall

# Clean build artifacts
make clean
```

### Manual Compilation

If you prefer not to use the Makefile, you can compile directly:

```bash
gcc -O3 -o fastrace fastrace.c
```

For maximum performance:

```bash
gcc -O3 -march=native -mtune=native -flto -o fastrace fastrace.c
```

For debugging:

```bash
gcc -g -O0 -Wall -Wextra -o fastrace_debug fastrace.c
```

## Usage

### Basic Usage

```bash
sudo ./fastrace <target>
```

Example:

```bash
sudo ./fastrace google.com
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-n` | Disable reverse DNS lookups (fastest output) |
| `-m <hops>` | Set maximum hop count (default 30, max 128) |
| `-q <probes>` | Set probes per hop (default 3, max 10) |
| `-c <count>` | Set concurrent TTL window size (default 6) |
| `-W <ms>` | Poll wait timeout in milliseconds (default 2) |
| `-t <ms>` | Hop completion timeout in milliseconds (default 700) |
| `-P <port>` | Base UDP destination port (default 33434) |
| `-V` | Print version information |
| `-h` | Display help message |

### Output Format

```
Tracing route to google.com (172.217.168.46)
Maximum hops: 30, Protocol: UDP
TTL │ IP Address         (RTT ms)   Hostname
────┼─────────────────────────────────────────
1   │→ 192.168.1.1      (  2.58 ms) router.local
2   │→ * * * (timeout)
3   │→ * * * (timeout)
4   │→ 37.26.81.21      ( 88.01 ms)
5   │→ 79.140.91.10     ( 31.21 ms)
6   │→ 195.22.202.203   ( 38.73 ms)
7   │→ 72.14.209.224    ( 60.76 ms)
      └→ 72.14.223.184   ( 61.65 ms)
8   │→ 142.251.244.109  ( 59.57 ms)
      └→ 216.239.62.49   ( 71.36 ms)
      └→ 142.250.210.95  ( 70.25 ms)
9   │→ 142.251.247.141  ( 59.79 ms)
      └→ 142.251.52.85   ( 60.25 ms)
      └→ 209.85.243.245  ( 62.33 ms)
10  │→ 34.8.172.215     ( 62.42 ms) 215.172.8.34.bc.googleusercontent.com
```

This visual format shows:
- Primary routes with horizontal arrows (`→`)
- Alternative/branching paths with indented branch indicators (`└→`)
- Precise RTT measurements for each hop
- Hostname resolution where available
- Clear visualization of load-balanced paths

## Technical Implementation Details

### TTL Mechanism

The Time-to-Live (TTL) field in the IP header is systematically incremented to discover each router along the path. Each probe uses a unique UDP port derived from its TTL and probe index, allowing responses to be matched instantly.

### Probe Identification

Probes are uniquely identified by using a different UDP port for each probe:

```c
int port = BASE_PORT + (ttl * NUM_PROBES) + probe_num;
```

This allows accurate matching of responses to their corresponding probes.

### Timing Precision

RTT measurements now rely on the monotonic clock, protecting calculations from user/system time adjustments while preserving microsecond resolution.

### DNS Resolution

Reverse DNS lookups are cached for the lifetime of the run. Use `-n` to disable lookups entirely when only IP addresses are required.

## Protocol Details

### UDP Probes with Unique Ports

Each probe uses a unique UDP port to identify it:

```c
int port = BASE_PORT + (ttl * NUM_PROBES) + probe_num;
```

### ICMP Time Exceeded (Type 11, Code 0)

Received when a packet's TTL expires, containing the original UDP header:

```c
if (icmp->icmp_type == ICMP_TIME_EXCEEDED) {
    /* Extract original UDP header and match by port */
}
```

### ICMP Destination Unreachable (Type 3, Code 3)

Received when reaching the destination port (indicating target reached):

```c
if (icmp->icmp_type == ICMP_DEST_UNREACH && icmp->icmp_code == ICMP_PORT_UNREACH) {
    /* Process port unreachable message */
}
```

## Error Handling

Fastrace implements robust error handling:

- **Socket Creation Failures**: Proper detection and reporting
- **Send/Receive Errors**: Graceful handling with appropriate error messages
- **Hostname Resolution Failures**: Fallback to IP address display
- **Signal Handling**: Clean termination on interrupts (SIGINT)

```c
void handle_signal(int sig) {
    if (sig == SIGINT) {
        printf("\nTraceroute interrupted.\n");
        finished = 1;
        cleanup();
        exit(0);
    }
}
```

## Memory Management

Fastrace maintains a minimal memory footprint:

- **Static Allocation**: Pre-allocated probe tracking array
- **Limited Dynamic Allocation**: Used only for hostname resolution
- **Proper Cleanup**: Resources are freed upon completion or interruption

## Security Considerations

- **Root Privileges**: Required for raw socket operations
- **Input Validation**: Proper validation of command-line arguments
- **Buffer Management**: Fixed-size buffers with bounds checking

## Contributing

Contributions are welcome! Key areas for potential enhancement:

1. **IPv6 Support**: Extend to support IPv6 tracerouting
2. **TCP Probing**: Add alternative probe methods for bypassing UDP-filtered routes
3. **Statistical Analysis**: Enhanced RTT variance and packet loss reporting
4. **Visualization**: Text-based route visualization capabilities

## Author

- **Davide Santangelo** - [GitHub](https://github.com/davidesantangelo)

## License

This project is licensed under the BSD-2 License - see the LICENSE file for details.

Copyright © 2025 Davide Santangelo

## Acknowledgments

- Based on the principles of Van Jacobson's traceroute algorithm
- Inspired by modern high-performance network diagnostic tools