# Changelog

All notable changes to FastRace will be documented in this file.

## [1.0.0] - 2025-01-20

### Major Release - Performance & Features

This is the first stable major release of fastrace, featuring significant performance improvements and new capabilities.

### Performance

- **Batch I/O**: Uses `recvmmsg` on Linux for batch packet reception, reducing syscall overhead by up to 60%.
- **Adaptive Concurrency Window**: Automatically adjusts the concurrent TTL window based on network latency (faster networks get larger windows).
- **Optimized Timeouts**: Reduced default timeouts (500ms per hop, 1ms poll) for faster trace completion.
- **Lock-free DNS Queue**: Atomic operations for DNS queue management, reducing contention.
- **Larger Buffers**: Increased socket buffers (256KB) and host cache (512 entries) for high-throughput scenarios.
- **CLOCK_MONOTONIC_RAW**: Uses the most precise monotonic clock available for RTT measurements.

### Added

- **IPv6 Support**: Full dual-stack support with `-6` flag. Automatic fallback to IPv4 if IPv6 resolution fails.
- **ICMP Echo Mode**: New `-I` flag for ICMP Echo-based traceroute (like `ping`-style probes).
- **TCP SYN Mode**: New `-T` flag for TCP-based traceroute (useful for firewalled networks).
- **JSON Output**: `--json` flag for machine-readable JSON output, ideal for scripting and monitoring.
- **CSV Output**: `--csv` flag for spreadsheet-compatible output.
- **Performance Metrics**: `--metrics` flag shows RTT statistics including min/max/mean/stddev, p50/p95/p99 percentiles, and jitter.
- **Quiet Mode**: `--quiet` flag for minimal output, useful for benchmarking.
- **Adaptive Window Control**: `--no-adaptive` to disable automatic concurrency adjustment.

### Changed

- **Default Concurrency**: Increased from 6 to 8 concurrent TTLs.
- **Default Probe Delay**: Reduced from 250µs to 100µs.
- **Default Timeout**: Reduced from 700ms to 500ms per hop.
- **Output Format**: Wider IP address column (39 chars) for IPv6 addresses.
- **Trace Statistics**: Now shows total trace time in milliseconds.

### Technical

- Refactored probe tracking to support both sequence-based (ICMP) and port-based (UDP) matching.
- Added `<stdatomic.h>` for lock-free atomic counters.
- Improved signal handling with SIGTERM support.
- Enhanced ICMP parsing with platform-specific struct access for macOS/BSD compatibility.

### Test Suite

- **Basic Tests**: Non-root tests for CLI validation (`make test`).
- **Full Tests**: Comprehensive root tests for all features (`make test-full`).
- **Benchmark Suite**: Performance benchmarking script (`make benchmark`).

## [0.4.1] - 2025-12-05

### Performance

- **Nanosleep Precision**: Replaced `usleep()` with `nanosleep()` for more accurate inter-probe delays and POSIX compliance.
- **DNS Pool Allocator**: Added pre-allocated pool for DNS queue items, reducing malloc overhead in high-throughput scenarios.
- **Faster Early Exit**: Optimized main loop to check finish condition more frequently, reducing latency when destination is reached.

### Added

- **Trace Statistics**: Displays hop count and response rate on completion for better observability.

### Fixed

- **Hop Display with Concurrent Probing**: Fixed a bug where intermediate hops were not displayed when the destination was reached by a concurrent probe. The trace now correctly shows all hops up to the destination.

### Code Quality

- Improved code organization with dedicated pool allocator functions.
- Added statistics counters for probes sent and responses received.

## [0.4.0] - 2025-12-04

### Performance

- **TTL Batching**: Sets socket TTL once per hop and sends probes in bursts, reducing per-packet syscalls and improving send-side throughput under high concurrency.
- **Adaptive Waiting**: Poll wait now aligns to the earliest hop deadline, cutting idle spins while still draining the ICMP socket aggressively.

### Added

- **Probe Delay Flag**: New `-d <microseconds>` option exposes inter-probe pacing (default 250µs) to tune burstiness versus jitter.

### Changed

- **Clearer Hop Completion Logic**: Hop readiness now factors both full receipt and TTL deadlines, yielding more deterministic timeout behavior in noisy networks.

## [0.3.1] - 2025-11-28

### Fixed

- **Critical RTT Bug**: Fixed incorrect RTT measurements showing values like `1764330397890.64 ms`. The bug was caused by mixing `SO_TIMESTAMP` (wall-clock time from kernel) with `CLOCK_MONOTONIC` for sent timestamps. Now consistently uses monotonic clock for all RTT calculations.

## [0.3.0] - 2025-11-19

### Performance

- **Asynchronous DNS Resolution**: Moved reverse DNS lookups to a dedicated background thread. This eliminates the "stop-and-wait" behavior during printing, ensuring the packet probing loop never stalls while waiting for a hostname to resolve.

### Changed

- **Thread-Safe Architecture**: Refactored internal data structures (host cache, print queue) to be thread-safe using mutexes.
- **Build System**: Added `-pthread` flag to compiler options and introduced a `make test` target.

### Added

- **Test Suite**: Added a basic regression test script (`tests/test_basic.sh`) to verify core functionality and argument parsing.

## [0.2.1] - 2025-10-31

### Fixed

- Removed artificial RTT clamping (0.05ms min, 800ms max) that hid legitimate measurements and network anomalies
- Now reports actual RTT values including sub-50µs localhost responses and >800ms long-distance links
- Added sanity check for negative RTT values to detect clock issues while preserving diagnostic accuracy

## [0.2.0] - 2025-10-31

### Performance

- Rebuilt the event loop around non-blocking sockets with `poll()` to minimise wakeups and drain ICMP bursts efficiently
- Switched to monotonic timing for nanosecond precision RTT tracking and tighter hop deadlines
- Added adaptive concurrency controls with configurable probe counts, TTL windows, and wait intervals for faster convergence
- Pre-generated probe payloads and optimised UDP emission cadence to cut per-packet overhead

### Features

- Introduced rich CLI options (`-n`, `-m`, `-q`, `-c`, `-W`, `-t`, `-P`, `-V`) for runtime tuning and DNS suppression
- Added hostname resolution cache to avoid redundant reverse lookups and accelerate load-balanced hop reporting
- Extended output banner with versioning and dynamic configuration summary for better observability

### Reliability

- Migrated to `getaddrinfo`/`getnameinfo` for thread-safe, standards-compliant name resolution
- Hardened ICMP parsing logic with comprehensive bounds checks across packet layers
- Expanded socket buffers and adopted safer resource cleanup to improve stability under heavy traffic

## [0.1.2] - 2025-04-01

### Security & Reliability

- Added proper file descriptor flags with FD_CLOEXEC for socket security
- Implemented comprehensive bounds checking to prevent buffer overflows
- Enhanced memory safety with null pointer checks and proper initialization
- Improved error handling throughout the codebase

### Performance

- Further optimized socket configuration with larger buffer sizes
- Reduced probe delay to 1ms for faster tracing operations
- Improved RTT measurement accuracy with better timing algorithm
- Added constants for configurable response processing iterations

### Code Quality

- Refactored socket management with proper cleanup in error paths
- Added additional debug information for troubleshooting
- Improved source code organization with clearer separation of functions
- Enhanced input validation for more robust operation
- Fixed potential issues with type casting and numeric comparisons

## [0.1.1] - 2025-04-01

### Fixed

- Significantly improved RTT measurement accuracy to align with standard traceroute tools
- Added proper `timersub` macro for correct time difference calculations with microsecond precision
- Fixed timestamp handling to ensure accurate RTT measurements
- Optimized timeout values for more responsive trace results

### Changed

- Reduced probe delay from 50ms to 5ms for faster tracing
- Improved response processing with more frequent checks and shorter timeouts
- Added sanity checks and reasonable caps for RTT values (maximum 1000ms)
- Reduced socket receive timeout from 5s to 1s
- Reduced TTL timeout from 5000ms to 1000ms for better responsiveness
- Improved socket resource cleanup on program exit

## [0.1.0] - 2025-03-13

### Added

- Initial release of FastRace
- High-performance traceroute implementation in pure C with zero dependencies
- Dual socket architecture with UDP for probes and raw ICMP for responses
- Concurrent TTL probing for faster route discovery (up to 5x faster than standard traceroute)
- Visual tree-like representation of network paths showing load-balanced routes
- Efficient memory management with minimal memory footprint
- Optimized for speed with parallel probing and efficient packet handling
- Smart timeout management with adaptive timeouts based on hop distance
- Comprehensive route visualization with RTT measurements and hostname resolution

### Technical Details

- Implemented using standard C libraries and system calls
- UDP probes with incremental TTL values to discover network path
- Raw socket implementation for capturing ICMP responses
- Port-based probe identification for accurate response matching
- Non-blocking I/O with select() for efficient packet handling
- Probe batching system with multiple probes per TTL
- Flexible build system with optimization options

### Code Improvements

- Added proper random number generator seeding
- Streamlined command line argument handling
- Improved error messages and socket handling
- Removed unnecessary privilege checking in favor of runtime capability detection
- Eliminated redundant cleanup code for better performance
- Improved code structure and variable declaration
