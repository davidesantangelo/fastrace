# Changelog
All notable changes to FastRace will be documented in this file.

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