# Fastrace

Fast, dependency-free traceroute in pure C. Minimal syscalls, clear output.

## Why

- Non-blocking sockets with poll; DNS runs on a separate thread.
- Zero external deps: libc + raw sockets.
- Tunable on the fly: hops, probes, concurrency window, wait, per-probe delay, DNS on/off.
- Readable tree output: branches for load-balanced paths, precise RTTs.

## Quick install

```bash
make                 # optimized build
sudo make install    # optional, installs to /usr/local/bin
```

Manual alternative:

```bash
gcc -O3 -pthread -o fastrace fastrace.c
```

## Minimal use

```bash
sudo ./fastrace <target>
```

Key flags:

- `-n` disable DNS
- `-m <hops>` max hops (default 30, max 128)
- `-q <probes>` probes per hop (default 3, max 10)
- `-c <count>` concurrent TTLs (default 6)
- `-d <us>` inter-probe delay in microseconds (default 250)
- `-W <ms>` poll wait (default 2)
- `-t <ms>` hop timeout (default 700)
- `-P <port>` base UDP port (default 33434)
- `-V` version, `-h` help

Quick example:

```bash
sudo ./fastrace -n -m 20 -q 2 example.com
```

Sample output:

```
sudo ./fastrace google.com
Tracing route to google.com (142.250.180.174)
Maximum hops: 30, Probes per hop: 3, Protocol: UDP
TTL | IP Address         (RTT ms)    Hostname
----+-----------------------------------------
1   | -> 192.168.1.1     (  2.60 ms)
2   | * * * (timeout)
3   | * * * (timeout)
4   | -> 185.89.159.5    (  6.81 ms)
5   | -> 37.26.80.129    (  9.22 ms)
6   | -> 193.77.91.225   ( 29.88 ms) bsn-77-91-225.static.siol.net
7   | -> 193.77.107.46   ( 33.62 ms) bsn-77-107-46.static.siol.net
```

## Notes

- Requires root/sudo for raw ICMP.
- RTTs use monotonic clock; no wall-clock mixing.
- Batches probes per TTL with one `setsockopt` call.
- Adaptive wait: aligns polling to the next hop deadline.

## License

BSD-2-Clause. See LICENSE.