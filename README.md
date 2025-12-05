# Fastrace

⚡ **Fast, dependency-free traceroute in pure C.** Minimal syscalls, clear output, significantly faster than standard traceroute.

## Performance

Fastrace is designed for speed. By using non-blocking sockets, concurrent probing, and optimized syscalls, it completes traces significantly faster than the standard `traceroute` utility.

### Benchmark: `google.com`

| Tool         | Hops | Time | Response Rate |
| ------------ | ---- | ---- | ------------- |
| **fastrace** | 13   | ~2s  | 74.4% (29/39) |
| traceroute   | 11   | ~30s | —             |

**fastrace** completes the trace **~15x faster** while providing richer output including load-balanced path detection.

<details>
<summary>📊 Full output comparison</summary>

**fastrace:**

```
sudo ./fastrace google.com
fastrace 0.4.1
Tracing route to google.com (142.250.180.174)
Maximum hops: 30, Probes per hop: 3, Protocol: UDP
TTL │ IP Address         (RTT ms)    Hostname
────┼───────────────────────────────────────────
1   │ → 192.168.1.1     (  6.15 ms)
2   │ * * * (timeout)
3   │ * * * (timeout)
4   │ → 185.89.159.5    ( 14.77 ms)
5   │ → 37.26.80.129    ( 14.68 ms)
6   │ → 193.77.91.225   ( 29.88 ms) bsn-77-91-225.static.siol.net
7   │ → 193.77.107.46   ( 31.69 ms) bsn-77-107-46.static.siol.net
8   │ * * * (timeout)
9   │ → 142.250.180.174 ( 37.91 ms) mil04s44-in-f14.1e100.net
      └→ 142.251.235.178 ( 39.32 ms)
      └→ 192.178.44.134  ( 38.93 ms)
...
Trace complete. Hops: 13, Responses: 29/39 (74.4%)
```

**Standard traceroute (~30 seconds):**

```
traceroute google.com
traceroute to google.com (142.250.180.174), 64 hops max, 40 byte packets
 1  192.168.1.1 (192.168.1.1)  3.876 ms  3.480 ms  3.633 ms
 2  * * *
 3  * * *
 4  185.89.159.5 (185.89.159.5)  8.114 ms  5.154 ms  5.630 ms
 5  37.26.80.129 (37.26.80.129)  7.029 ms  10.697 ms  6.448 ms
 6  bsn-77-91-225.static.siol.net (193.77.91.225)  25.419 ms  24.929 ms  25.954 ms
 7  bsn-77-107-46.static.siol.net (193.77.107.46)  29.024 ms  30.893 ms  32.847 ms
 8  * * *
 9  142.251.235.174 (142.251.235.174)  32.945 ms
    108.170.233.96 (108.170.233.96)  31.500 ms  34.309 ms
10  142.250.211.21 (142.250.211.21)  33.097 ms  28.131 ms
    142.250.211.23 (142.250.211.23)  32.650 ms
11  mil04s44-in-f14.1e100.net (142.250.180.174)  30.008 ms * *
```

</details>

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

## Running without sudo (optional)

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

> ⚠️ **Security note**: This allows any local user to run fastrace with root privileges. Use only on personal machines.

## Notes

- Requires root/sudo for raw ICMP.
- RTTs use monotonic clock; no wall-clock mixing.
- Batches probes per TTL with one `setsockopt` call.
- Adaptive wait: aligns polling to the next hop deadline.
- Displays trace statistics (hops, response rate) on completion.

## License

BSD-2-Clause. See LICENSE.
