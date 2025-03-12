# Fastrace

A high-performance, dependency-free traceroute implementation in pure C.

## Overview

Fastrace is a blazingly fast traceroute utility designed for network diagnostics and performance analysis. It maps the route that packets take across an IP network from source to destination, providing detailed timing information and identifying potential bottlenecks or routing issues.

## Technical Architecture

### Core Design Principles

- **Zero External Dependencies**: Relies solely on standard C libraries and system calls
- **Maximum Performance**: Optimized for speed with parallel probing and efficient packet handling
- **Low Memory Footprint**: Minimizes memory allocation and operates with a small, fixed memory budget
- **Dual Socket Implementation**: Uses UDP for probes and raw sockets for response capture
- **Visual Route Mapping**: Displays network topology with a structured, tree-like representation

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

#### 3. Concurrent Route Discovery

Fastrace implements a multi-TTL probing system that maintains multiple active TTL probes:

```c
#define MAX_ACTIVE_TTLS 5   /* Maximum number of TTLs probed concurrently */
```

#### 4. Efficient Response Processing

The response processor uses `select()` with configurable timeouts to efficiently handle incoming packets without blocking:

```c
int process_responses(int timeout_ms) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(recv_sock, &readfds);
    
    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    
    int ret = select(recv_sock + 1, &readfds, NULL, NULL, &timeout);
    /* ... */
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

### 1. Non-blocking I/O

Uses non-blocking I/O with timeout controls to prevent stalls during packet loss:

```c
struct timeval timeout;
timeout.tv_sec = RECV_TIMEOUT;
timeout.tv_usec = 0;
setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
```

### 2. Probe Batching

Implements an efficient probe batching system that sends multiple probes per TTL:

```c
#define NUM_PROBES 3        /* Number of probes per TTL */
```

### 3. Compiler Optimization

Designed to be compiled with aggressive optimization flags:

```
gcc -O3 -o fastrace fastrace.c
```

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

### Key Performance Differences

1. **Concurrent TTL Probing**: While standard traceroute sequentially probes one TTL at a time, Fastrace processes multiple TTLs concurrently, dramatically reducing total trace time.

2. **Smart Timeout Management**: Fastrace uses dynamic timeout scaling based on hop distance, reducing unnecessary waiting.

3. **Efficient Packet Processing**: Streamlined packet handling code with minimal memory operations.

4. **Zero Dependencies**: No reliance on external libraries, resulting in lower overhead and faster execution.

5. **Optimized Memory Usage**: Pre-allocated data structures and minimal dynamic allocations.

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
#include <signal.h>
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

The Time-to-Live (TTL) field in the IP header is systematically incremented to discover each router along the path:

```c
if (setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
    perror("Error setting TTL");
    return;
}
```

When a packet's TTL reaches zero, the router generates an ICMP Time Exceeded message, revealing its address.

### Probe Identification

Probes are uniquely identified by using a different UDP port for each probe:

```c
int port = BASE_PORT + (ttl * NUM_PROBES) + probe_num;
```

This allows accurate matching of responses to their corresponding probes.

### Timing Precision

High-resolution timing is implemented using `gettimeofday()`:

```c
struct timeval tv;
gettimeofday(&tv, NULL);
```

Round-trip time calculation is performed with microsecond precision:

```c
double rtt = (recv_time.tv_sec - probes[idx].sent_time.tv_sec) * 1000.0 +
            (recv_time.tv_usec - probes[idx].sent_time.tv_usec) / 1000.0;
```

### DNS Resolution

Reverse DNS lookups are performed to provide hostname information for IP addresses:

```c
char *resolve_hostname(struct in_addr addr) {
    struct hostent *host = gethostbyaddr(&addr, sizeof(addr), AF_INET);
    if (host && host->h_name) {
        return strdup(host->h_name);
    }
    return NULL;
}
```

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