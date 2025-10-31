# Changelog
All notable changes to FastRace will be documented in this file.

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

### Known Issues
- IPv6 support not yet implemented
- Limited support for non-POSIX systems
- May require elevated privileges depending on system configuration