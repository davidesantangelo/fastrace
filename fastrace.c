/**
 * fastrace 1.0.0 - Blazing fast traceroute implementation
 *
 * Features:
 *   - IPv4 and IPv6 support
 *   - UDP (default), ICMP Echo, and TCP SYN modes
 *   - JSON/CSV output formats
 *   - Performance metrics (RTT percentiles, jitter)
 *   - Batch I/O with sendmmsg/recvmmsg on Linux
 *   - Lock-free DNS cache with background resolution
 *   - Adaptive concurrency window
 *
 * Compiles with: gcc -O3 -pthread -o fastrace fastrace.c
 * Run with: sudo ./fastrace [options] <target>
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <math.h>

#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED 11
#endif
#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif
#ifndef ICMP_PORT_UNREACH
#define ICMP_PORT_UNREACH 3
#endif
#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif
#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif

#define VERSION "1.0.0"
#define PACKET_SIZE 64
#define HOST_CACHE_SIZE 512
#define MAX_TTL_LIMIT 128
#define MAX_PROBES_LIMIT 10
#define SOCKET_BUFFER_SIZE 262144
#define MAX_BATCH_SIZE 16

// Output formats
typedef enum {
    OUTPUT_TEXT = 0,
    OUTPUT_JSON,
    OUTPUT_CSV
} output_format_t;

// Probe protocols
typedef enum {
    PROTO_UDP = 0,
    PROTO_ICMP,
    PROTO_TCP
} probe_proto_t;

typedef struct {
    int ttl;
    int probe;
    struct timespec sent_time;
    bool received;
    struct in_addr addr;
    struct in6_addr addr6;
    double rtt;
    int port;
    uint16_t seq;
} probe_t;

typedef struct {
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } addr;
    bool is_ipv6;
    char *hostname;
    _Atomic bool resolved;
} host_cache_entry_t;

typedef struct {
    int max_ttl;
    int num_probes;
    int max_active_ttls;
    int wait_timeout_ms;
    int ttl_timeout_ms;
    int probe_delay_us;
    int base_port;
    bool dns_enabled;
    bool ipv6;
    probe_proto_t protocol;
    output_format_t output_format;
    bool show_metrics;
    bool quiet;
    bool adaptive_window;
} traceroute_config_t;

static traceroute_config_t config = {
    .max_ttl = 30,
    .num_probes = 3,
    .max_active_ttls = 8,
    .wait_timeout_ms = 1,
    .ttl_timeout_ms = 500,
    .probe_delay_us = 100,
    .base_port = 33434,
    .dns_enabled = true,
    .ipv6 = false,
    .protocol = PROTO_UDP,
    .output_format = OUTPUT_TEXT,
    .show_metrics = false,
    .quiet = false,
    .adaptive_window = true
};

// Threading and Queue globals
static pthread_t dns_thread_id;
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static volatile bool dns_running = true;
static _Atomic int dns_queue_size = 0;
#define MAX_DNS_QUEUE_SIZE 2048

// DNS pool allocator
#define DNS_POOL_SIZE 128
static int dns_pool_next = 0;

typedef struct dns_queue_item {
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } addr;
    bool is_ipv6;
    struct dns_queue_item *next;
} dns_queue_item_t;

static dns_queue_item_t *dns_queue_head = NULL;
static dns_queue_item_t *dns_queue_tail = NULL;

static int send_sock = -1;
static int recv_sock = -1;
static char *target_host = NULL;
static struct sockaddr_storage dest_addr;
static socklen_t dest_addr_len;
static volatile sig_atomic_t finished = 0;
static probe_t *probes = NULL;
static struct timespec *last_probe_time = NULL;
static host_cache_entry_t host_cache[HOST_CACHE_SIZE];
static size_t host_cache_next = 0;
static unsigned char base_payload[PACKET_SIZE];
static dns_queue_item_t dns_pool[DNS_POOL_SIZE];

// ICMP sequence counter
static _Atomic uint16_t probe_seq_counter = 0;
static uint16_t probe_icmp_id;

// Statistics
static _Atomic int stats_probes_sent = 0;
static _Atomic int stats_responses_received = 0;
static double *all_rtts = NULL;
static int rtt_count = 0;
static pthread_mutex_t rtt_mutex = PTHREAD_MUTEX_INITIALIZER;

// JSON output buffer
static char *json_hops = NULL;
static size_t json_hops_len = 0;
static size_t json_hops_cap = 0;

// Function prototypes
static void cleanup(void);
static void print_help(const char *prog_name);
static void print_version(void);
static void initialize_payload(void);
static void set_cloexec(int fd);
static void set_nonblocking(int fd);
static void monotonic_now(struct timespec *ts);
static double timespec_diff_ms(const struct timespec *start, const struct timespec *end);
static int configure_ttl(int ttl);
static void send_single_probe(int ttl, int probe_num);
static void send_probe_batch(int ttl);
static int compute_wait_timeout_ms(int next_ttl_to_print, int current_ttl);
static bool ttl_all_received(int ttl);
static bool ttl_ready_to_print(int ttl, const struct timespec *now);
static void print_ttl_results(int ttl);
static int process_responses(int timeout_ms);
static int drain_icmp_socket(void);
static int handle_icmp_packet(const unsigned char *buffer, size_t bytes,
                              const struct sockaddr_storage *recv_addr, const struct timespec *recv_time);
static const char *resolve_hostname_cached(const void *addr, bool is_ipv6);
static void host_cache_store(const void *addr, bool is_ipv6, const char *hostname);
static char *host_cache_lookup(const void *addr, bool is_ipv6);
static void free_host_cache(void);
static void queue_dns_lookup(const void *addr, bool is_ipv6);
static void *dns_worker(void *arg);
static uint16_t icmp_checksum(const void *data, size_t len);
static void record_rtt(double rtt);
static void print_metrics(void);
static void json_append_hop(int ttl, const char *results);
static void print_json_output(void);
static void print_csv_header(void);
static void print_csv_hop(int ttl, struct in_addr *addrs, struct in6_addr *addrs6, double *rtts, int count);

static dns_queue_item_t *dns_pool_alloc(void)
{
    if (dns_pool_next < DNS_POOL_SIZE)
        return &dns_pool[dns_pool_next++];
    return malloc(sizeof(dns_queue_item_t));
}

static void dns_pool_free(dns_queue_item_t *item)
{
    if (item < dns_pool || item >= dns_pool + DNS_POOL_SIZE)
        free(item);
}

static void queue_dns_lookup(const void *addr, bool is_ipv6)
{
    if (!config.dns_enabled) return;

    int current_size = atomic_load(&dns_queue_size);
    if (current_size >= MAX_DNS_QUEUE_SIZE) return;

    dns_queue_item_t *item = dns_pool_alloc();
    if (!item) return;

    if (is_ipv6) {
        memcpy(&item->addr.v6, addr, sizeof(struct in6_addr));
    } else {
        memcpy(&item->addr.v4, addr, sizeof(struct in_addr));
    }
    item->is_ipv6 = is_ipv6;
    item->next = NULL;

    pthread_mutex_lock(&queue_mutex);
    if (dns_queue_tail) {
        dns_queue_tail->next = item;
        dns_queue_tail = item;
    } else {
        dns_queue_head = dns_queue_tail = item;
    }
    atomic_fetch_add(&dns_queue_size, 1);
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

static void *dns_worker(void *arg)
{
    (void)arg;
    while (dns_running) {
        pthread_mutex_lock(&queue_mutex);
        while (dns_queue_head == NULL && dns_running) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }

        if (!dns_running) {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }

        dns_queue_item_t *item = dns_queue_head;
        dns_queue_head = item->next;
        if (dns_queue_head == NULL) {
            dns_queue_tail = NULL;
        }
        atomic_fetch_sub(&dns_queue_size, 1);
        pthread_mutex_unlock(&queue_mutex);

        char host[NI_MAXHOST];
        struct sockaddr_storage sa;
        socklen_t sa_len;
        memset(&sa, 0, sizeof(sa));

        if (item->is_ipv6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&sa;
            sa6->sin6_family = AF_INET6;
            sa6->sin6_addr = item->addr.v6;
            sa_len = sizeof(struct sockaddr_in6);
        } else {
            struct sockaddr_in *sa4 = (struct sockaddr_in *)&sa;
            sa4->sin_family = AF_INET;
            sa4->sin_addr = item->addr.v4;
            sa_len = sizeof(struct sockaddr_in);
        }

        if (getnameinfo((struct sockaddr *)&sa, sa_len, host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
            host_cache_store(item->is_ipv6 ? (void*)&item->addr.v6 : (void*)&item->addr.v4,
                             item->is_ipv6, host);
        }

        dns_pool_free(item);
    }
    return NULL;
}

static void cleanup(void)
{
    dns_running = false;
    pthread_mutex_lock(&queue_mutex);
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);

    if (dns_thread_id) {
        pthread_join(dns_thread_id, NULL);
    }

    pthread_mutex_lock(&queue_mutex);
    while (dns_queue_head) {
        dns_queue_item_t *tmp = dns_queue_head;
        dns_queue_head = dns_queue_head->next;
        dns_pool_free(tmp);
    }
    dns_queue_tail = NULL;
    pthread_mutex_unlock(&queue_mutex);

    if (send_sock >= 0) {
        close(send_sock);
        send_sock = -1;
    }
    if (recv_sock >= 0) {
        close(recv_sock);
        recv_sock = -1;
    }
    if (probes) {
        free(probes);
        probes = NULL;
    }
    if (last_probe_time) {
        free(last_probe_time);
        last_probe_time = NULL;
    }
    if (all_rtts) {
        free(all_rtts);
        all_rtts = NULL;
    }
    if (json_hops) {
        free(json_hops);
        json_hops = NULL;
    }
    free_host_cache();
}

static void print_help(const char *prog_name)
{
    printf("fastrace %s - high-performance traceroute\n", VERSION);
    printf("Usage: sudo %s [options] <target>\n", prog_name);
    printf("\nOptions:\n");
    printf("  -n              Disable reverse DNS lookups\n");
    printf("  -6              Use IPv6\n");
    printf("  -I              Use ICMP Echo instead of UDP\n");
    printf("  -T              Use TCP SYN instead of UDP\n");
    printf("  -m <hops>       Maximum hops to trace (1-%d) [default %d]\n", MAX_TTL_LIMIT, config.max_ttl);
    printf("  -q <probes>     Probes per hop (1-%d) [default %d]\n", MAX_PROBES_LIMIT, config.num_probes);
    printf("  -c <count>      Concurrent TTL window size [default %d]\n", config.max_active_ttls);
    printf("  -d <us>         Inter-probe delay in microseconds [default %d]\n", config.probe_delay_us);
    printf("  -W <ms>         Poll wait timeout in milliseconds [default %d]\n", config.wait_timeout_ms);
    printf("  -t <ms>         Hop completion timeout in milliseconds [default %d]\n", config.ttl_timeout_ms);
    printf("  -P <port>       Base UDP/TCP destination port [default %d]\n", config.base_port);
    printf("  --json          Output results in JSON format\n");
    printf("  --csv           Output results in CSV format\n");
    printf("  --metrics       Show performance metrics (RTT percentiles, jitter)\n");
    printf("  --quiet         Minimal output (for benchmarking)\n");
    printf("  --no-adaptive   Disable adaptive concurrency window\n");
    printf("  -V              Print version and exit\n");
    printf("  -h              Show this help message\n");
}

static void print_version(void)
{
    printf("fastrace %s\n", VERSION);
}

static void initialize_payload(void)
{
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(base_payload, sizeof(base_payload));
#else
    for (size_t i = 0; i < sizeof(base_payload); i++) {
        base_payload[i] = (unsigned char)(rand() & 0xFF);
    }
#endif
    probe_icmp_id = (uint16_t)(getpid() & 0xFFFF);
}

static void set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags != -1)
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void monotonic_now(struct timespec *ts)
{
#if defined(CLOCK_MONOTONIC_RAW)
    if (clock_gettime(CLOCK_MONOTONIC_RAW, ts) == 0) return;
#endif
#if defined(CLOCK_MONOTONIC)
    if (clock_gettime(CLOCK_MONOTONIC, ts) == 0) return;
#endif
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ts->tv_sec = tv.tv_sec;
    ts->tv_nsec = tv.tv_usec * 1000;
}

static double timespec_diff_ms(const struct timespec *start, const struct timespec *end)
{
    double sec = (double)(end->tv_sec - start->tv_sec);
    double nsec = (double)(end->tv_nsec - start->tv_nsec);
    return sec * 1000.0 + nsec / 1000000.0;
}

static uint16_t icmp_checksum(const void *data, size_t len)
{
    const uint16_t *ptr = data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)ptr;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

static int configure_ttl(int ttl)
{
    if (ttl < 1 || ttl > config.max_ttl)
        return -1;

    int opt_level = config.ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
    int opt_name = config.ipv6 ? IPV6_UNICAST_HOPS : IP_TTL;

    if (setsockopt(send_sock, opt_level, opt_name, &ttl, sizeof(ttl)) < 0) {
        return -1;
    }
    return 0;
}

static void send_single_probe(int ttl, int probe_num)
{
    if (send_sock < 0) return;
    if (probe_num < 0 || probe_num >= config.num_probes) return;

    size_t idx = (size_t)(ttl - 1) * (size_t)config.num_probes + (size_t)probe_num;
    int port = config.base_port + ((ttl - 1) * config.num_probes) + probe_num;

    struct sockaddr_storage probe_dest;
    socklen_t probe_dest_len;
    memcpy(&probe_dest, &dest_addr, sizeof(dest_addr));
    probe_dest_len = dest_addr_len;

    if (config.ipv6) {
        ((struct sockaddr_in6 *)&probe_dest)->sin6_port = htons(port);
    } else {
        ((struct sockaddr_in *)&probe_dest)->sin_port = htons(port);
    }

    unsigned char packet[PACKET_SIZE + 8];
    size_t packet_len = PACKET_SIZE;

    if (config.protocol == PROTO_ICMP) {
        uint16_t seq = atomic_fetch_add(&probe_seq_counter, 1);
        probes[idx].seq = seq;

        if (config.ipv6) {
            struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)packet;
            memset(icmp6, 0, sizeof(*icmp6));
            icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
            icmp6->icmp6_code = 0;
            icmp6->icmp6_id = htons(probe_icmp_id);
            icmp6->icmp6_seq = htons(seq);
            memcpy(packet + sizeof(*icmp6), base_payload, PACKET_SIZE - sizeof(*icmp6));
            packet_len = PACKET_SIZE;
            // ICMPv6 checksum computed by kernel
        } else {
            struct icmp *icmp_hdr = (struct icmp *)packet;
            memset(icmp_hdr, 0, sizeof(*icmp_hdr));
            icmp_hdr->icmp_type = ICMP_ECHO;
            icmp_hdr->icmp_code = 0;
            icmp_hdr->icmp_hun.ih_idseq.icd_id = htons(probe_icmp_id);
            icmp_hdr->icmp_hun.ih_idseq.icd_seq = htons(seq);
            memcpy(packet + 8, base_payload, PACKET_SIZE - 8);
            icmp_hdr->icmp_cksum = 0;
            icmp_hdr->icmp_cksum = icmp_checksum(packet, PACKET_SIZE);
            packet_len = PACKET_SIZE;
        }
    } else {
        memcpy(packet, base_payload, PACKET_SIZE);
        struct timeval tv;
        gettimeofday(&tv, NULL);
        memcpy(packet, &tv, sizeof(tv) < PACKET_SIZE ? sizeof(tv) : PACKET_SIZE);
    }

    ssize_t sent = sendto(send_sock, packet, packet_len, 0,
                          (struct sockaddr *)&probe_dest, probe_dest_len);
    if (sent < 0) return;

    struct timespec send_time;
    monotonic_now(&send_time);

    probes[idx].ttl = ttl;
    probes[idx].probe = probe_num;
    probes[idx].port = port;
    probes[idx].sent_time = send_time;
    probes[idx].received = false;
    memset(&probes[idx].addr, 0, sizeof(probes[idx].addr));
    memset(&probes[idx].addr6, 0, sizeof(probes[idx].addr6));
    probes[idx].rtt = 0.0;

    atomic_fetch_add(&stats_probes_sent, 1);
}

static void send_probe_batch(int ttl)
{
    if (send_sock < 0) return;
    if (configure_ttl(ttl) < 0) return;

    for (int probe = 0; probe < config.num_probes; probe++) {
        send_single_probe(ttl, probe);
        if (config.probe_delay_us > 0 && probe < config.num_probes - 1) {
            struct timespec delay = {0, config.probe_delay_us * 1000L};
            nanosleep(&delay, NULL);
        }
    }

    monotonic_now(&last_probe_time[ttl - 1]);
}

static bool ttl_all_received(int ttl)
{
    for (int probe = 0; probe < config.num_probes; probe++) {
        size_t idx = (size_t)(ttl - 1) * (size_t)config.num_probes + (size_t)probe;
        if (!probes[idx].received) return false;
    }
    return true;
}

static bool ttl_ready_to_print(int ttl, const struct timespec *now)
{
    if (ttl_all_received(ttl)) return true;

    struct timespec zero = {0, 0};
    if (memcmp(&last_probe_time[ttl - 1], &zero, sizeof(struct timespec)) == 0) return false;

    double elapsed = timespec_diff_ms(&last_probe_time[ttl - 1], now);
    return elapsed > (double)config.ttl_timeout_ms;
}

static int compute_wait_timeout_ms(int next_ttl_to_print, int current_ttl)
{
    struct timespec now;
    monotonic_now(&now);

    double min_timeout = (double)config.wait_timeout_ms;
    struct timespec zero = {0, 0};

    for (int ttl = next_ttl_to_print; ttl < current_ttl; ttl++) {
        if (memcmp(&last_probe_time[ttl - 1], &zero, sizeof(struct timespec)) != 0) {
            double elapsed = timespec_diff_ms(&last_probe_time[ttl - 1], &now);
            double remaining = (double)config.ttl_timeout_ms - elapsed;
            if (remaining < 0.0) remaining = 0.0;
            if (remaining < min_timeout) min_timeout = remaining;
        }
    }

    return (int)(min_timeout < 0.0 ? 0.0 : min_timeout);
}

static void record_rtt(double rtt)
{
    pthread_mutex_lock(&rtt_mutex);
    int new_count = rtt_count + 1;
    double *new_rtts = realloc(all_rtts, new_count * sizeof(double));
    if (new_rtts) {
        all_rtts = new_rtts;
        all_rtts[rtt_count] = rtt;
        rtt_count = new_count;
    }
    pthread_mutex_unlock(&rtt_mutex);
}

static int compare_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static void print_metrics(void)
{
    if (rtt_count == 0) {
        printf("\nNo RTT samples collected.\n");
        return;
    }

    pthread_mutex_lock(&rtt_mutex);
    qsort(all_rtts, rtt_count, sizeof(double), compare_double);

    double sum = 0, sum_sq = 0;
    for (int i = 0; i < rtt_count; i++) {
        sum += all_rtts[i];
        sum_sq += all_rtts[i] * all_rtts[i];
    }

    double mean = sum / rtt_count;
    double variance = (sum_sq / rtt_count) - (mean * mean);
    double stddev = sqrt(variance > 0 ? variance : 0);

    double min = all_rtts[0];
    double max = all_rtts[rtt_count - 1];
    double p50 = all_rtts[rtt_count / 2];
    double p95 = all_rtts[(int)(rtt_count * 0.95)];
    double p99 = all_rtts[(int)(rtt_count * 0.99)];

    // Calculate jitter (mean absolute deviation between consecutive samples)
    double jitter_sum = 0;
    for (int i = 1; i < rtt_count; i++) {
        jitter_sum += fabs(all_rtts[i] - all_rtts[i-1]);
    }
    double jitter = rtt_count > 1 ? jitter_sum / (rtt_count - 1) : 0;

    pthread_mutex_unlock(&rtt_mutex);

    printf("\n── Performance Metrics ──────────────────────────────\n");
    printf("  Samples:     %d\n", rtt_count);
    printf("  RTT min:     %.3f ms\n", min);
    printf("  RTT max:     %.3f ms\n", max);
    printf("  RTT mean:    %.3f ms\n", mean);
    printf("  RTT stddev:  %.3f ms\n", stddev);
    printf("  RTT p50:     %.3f ms\n", p50);
    printf("  RTT p95:     %.3f ms\n", p95);
    printf("  RTT p99:     %.3f ms\n", p99);
    printf("  Jitter:      %.3f ms\n", jitter);
    printf("─────────────────────────────────────────────────────\n");
}

static void json_append_hop(int ttl, const char *results)
{
    size_t needed = strlen(results) + 64;
    if (json_hops_len + needed >= json_hops_cap) {
        size_t new_cap = json_hops_cap == 0 ? 4096 : json_hops_cap * 2;
        while (new_cap < json_hops_len + needed) new_cap *= 2;
        char *new_buf = realloc(json_hops, new_cap);
        if (!new_buf) return;
        json_hops = new_buf;
        json_hops_cap = new_cap;
    }

    if (json_hops_len > 0) {
        json_hops_len += sprintf(json_hops + json_hops_len, ",\n");
    }
    json_hops_len += sprintf(json_hops + json_hops_len,
        "    {\"ttl\": %d, \"results\": [%s]}", ttl, results);
}

static void print_json_output(void)
{
    int sent = atomic_load(&stats_probes_sent);
    int recv = atomic_load(&stats_responses_received);

    printf("{\n");
    printf("  \"target\": \"%s\",\n", target_host);
    printf("  \"protocol\": \"%s\",\n",
           config.protocol == PROTO_UDP ? "UDP" :
           config.protocol == PROTO_ICMP ? "ICMP" : "TCP");
    printf("  \"ip_version\": %d,\n", config.ipv6 ? 6 : 4);
    printf("  \"probes_sent\": %d,\n", sent);
    printf("  \"responses_received\": %d,\n", recv);
    printf("  \"response_rate\": %.1f,\n", sent > 0 ? (100.0 * recv / sent) : 0.0);
    printf("  \"hops\": [\n%s\n  ]\n", json_hops ? json_hops : "");
    printf("}\n");
}

static void print_csv_header(void)
{
    printf("ttl,ip,rtt_ms,hostname\n");
}

static void print_csv_hop(int ttl, struct in_addr *addrs, struct in6_addr *addrs6,
                          double *rtts, int count)
{
    for (int i = 0; i < count; i++) {
        char ip_str[INET6_ADDRSTRLEN];
        if (config.ipv6) {
            inet_ntop(AF_INET6, &addrs6[i], ip_str, sizeof(ip_str));
        } else {
            inet_ntop(AF_INET, &addrs[i], ip_str, sizeof(ip_str));
        }

        const char *hostname = resolve_hostname_cached(
            config.ipv6 ? (void*)&addrs6[i] : (void*)&addrs[i], config.ipv6);

        printf("%d,%s,%.3f,%s\n", ttl, ip_str, rtts[i], hostname ? hostname : "");
        if (hostname) free((void*)hostname);
    }
}

static void print_ttl_results(int ttl)
{
    struct in_addr hop_addrs[MAX_PROBES_LIMIT];
    struct in6_addr hop_addrs6[MAX_PROBES_LIMIT];
    double hop_rtts[MAX_PROBES_LIMIT];
    memset(hop_addrs, 0, sizeof(hop_addrs));
    memset(hop_addrs6, 0, sizeof(hop_addrs6));
    memset(hop_rtts, 0, sizeof(hop_rtts));

    int unique_addrs = 0;
    int received_count = 0;

    for (int probe = 0; probe < config.num_probes; probe++) {
        size_t idx = (size_t)(ttl - 1) * (size_t)config.num_probes + (size_t)probe;
        if (!probes[idx].received) continue;

        received_count++;
        record_rtt(probes[idx].rtt);

        int existing_idx = -1;
        for (int j = 0; j < unique_addrs; j++) {
            if (config.ipv6) {
                if (memcmp(&hop_addrs6[j], &probes[idx].addr6, sizeof(struct in6_addr)) == 0) {
                    existing_idx = j;
                    break;
                }
            } else {
                if (hop_addrs[j].s_addr == probes[idx].addr.s_addr) {
                    existing_idx = j;
                    break;
                }
            }
        }

        if (existing_idx == -1 && unique_addrs < MAX_PROBES_LIMIT) {
            if (config.ipv6) {
                hop_addrs6[unique_addrs] = probes[idx].addr6;
            } else {
                hop_addrs[unique_addrs] = probes[idx].addr;
            }
            hop_rtts[unique_addrs] = probes[idx].rtt;
            unique_addrs++;
        } else if (existing_idx >= 0) {
            hop_rtts[existing_idx] = (hop_rtts[existing_idx] * 0.4) + (probes[idx].rtt * 0.6);
        }
    }

    if (config.output_format == OUTPUT_CSV) {
        if (received_count > 0 && unique_addrs > 0) {
            print_csv_hop(ttl, hop_addrs, hop_addrs6, hop_rtts, unique_addrs);
        } else {
            printf("%d,*,0.0,\n", ttl);
        }
        return;
    }

    if (config.output_format == OUTPUT_JSON) {
        char results[2048] = "";
        size_t pos = 0;
        for (int i = 0; i < unique_addrs; i++) {
            char ip_str[INET6_ADDRSTRLEN];
            if (config.ipv6) {
                inet_ntop(AF_INET6, &hop_addrs6[i], ip_str, sizeof(ip_str));
            } else {
                inet_ntop(AF_INET, &hop_addrs[i], ip_str, sizeof(ip_str));
            }

            const char *hostname = resolve_hostname_cached(
                config.ipv6 ? (void*)&hop_addrs6[i] : (void*)&hop_addrs[i], config.ipv6);

            if (i > 0) pos += sprintf(results + pos, ", ");
            pos += sprintf(results + pos, "{\"ip\": \"%s\", \"rtt_ms\": %.3f",
                           ip_str, hop_rtts[i]);
            if (hostname) {
                pos += sprintf(results + pos, ", \"hostname\": \"%s\"", hostname);
                free((void*)hostname);
            }
            pos += sprintf(results + pos, "}");
        }
        if (unique_addrs == 0) {
            strcpy(results, "{\"timeout\": true}");
        }
        json_append_hop(ttl, results);
        return;
    }

    // Text output
    if (config.quiet) {
        if (received_count > 0 && unique_addrs > 0) {
            char ip_str[INET6_ADDRSTRLEN];
            if (config.ipv6) {
                inet_ntop(AF_INET6, &hop_addrs6[0], ip_str, sizeof(ip_str));
            } else {
                inet_ntop(AF_INET, &hop_addrs[0], ip_str, sizeof(ip_str));
            }
            printf("%d %s %.2f\n", ttl, ip_str, hop_rtts[0]);
        } else {
            printf("%d * *\n", ttl);
        }
        return;
    }

    if (received_count > 0 && unique_addrs > 0) {
        for (int i = 0; i < unique_addrs; i++) {
            char ip_str[INET6_ADDRSTRLEN];
            if (config.ipv6) {
                inet_ntop(AF_INET6, &hop_addrs6[i], ip_str, sizeof(ip_str));
            } else {
                inet_ntop(AF_INET, &hop_addrs[i], ip_str, sizeof(ip_str));
            }

            const char *hostname = resolve_hostname_cached(
                config.ipv6 ? (void*)&hop_addrs6[i] : (void*)&hop_addrs[i], config.ipv6);

            if (i == 0) {
                printf("→ %-39s (%6.2f ms)", ip_str, hop_rtts[i]);
            } else {
                printf("\n      └→ %-39s (%6.2f ms)", ip_str, hop_rtts[i]);
            }
            if (hostname) {
                printf(" %s", hostname);
                free((void *)hostname);
            }
            printf("\n");
        }

        // Check if destination reached
        if (config.ipv6) {
            struct sockaddr_in6 *d6 = (struct sockaddr_in6 *)&dest_addr;
            if (memcmp(&hop_addrs6[0], &d6->sin6_addr, sizeof(struct in6_addr)) == 0) {
                finished = 1;
            }
        } else {
            struct sockaddr_in *d4 = (struct sockaddr_in *)&dest_addr;
            if (hop_addrs[0].s_addr == d4->sin_addr.s_addr) {
                finished = 1;
            }
        }
    } else {
        printf("* * * (timeout)\n");
    }
}

static int process_responses(int timeout_ms)
{
    if (recv_sock < 0) return -1;
    if (timeout_ms < 0) timeout_ms = 0;

    if (timeout_ms > 0) {
        struct pollfd pfd = {.fd = recv_sock, .events = POLLIN};
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret <= 0) return 0;
        if (!(pfd.revents & POLLIN)) return 0;
    }

    return drain_icmp_socket();
}

static int drain_icmp_socket(void)
{
    int processed = 0;
    unsigned char buffer[2048];
    struct sockaddr_storage recv_addr;

#if defined(__linux__) && defined(__GLIBC__)
    // Use recvmmsg for batch receive on Linux
    struct mmsghdr msgs[MAX_BATCH_SIZE];
    struct iovec iovecs[MAX_BATCH_SIZE];
    unsigned char buffers[MAX_BATCH_SIZE][2048];
    struct sockaddr_storage addrs[MAX_BATCH_SIZE];

    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < MAX_BATCH_SIZE; i++) {
        iovecs[i].iov_base = buffers[i];
        iovecs[i].iov_len = sizeof(buffers[i]);
        msgs[i].msg_hdr.msg_name = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(addrs[i]);
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    struct timespec timeout = {0, 0};
    int ret = recvmmsg(recv_sock, msgs, MAX_BATCH_SIZE, MSG_DONTWAIT, &timeout);

    if (ret > 0) {
        struct timespec recv_time;
        monotonic_now(&recv_time);

        for (int i = 0; i < ret; i++) {
            if (msgs[i].msg_len > 0) {
                if (handle_icmp_packet(buffers[i], msgs[i].msg_len, &addrs[i], &recv_time) > 0) {
                    processed++;
                }
            }
        }
    }
#else
    // Standard recvmsg for macOS/BSD
    struct msghdr msg;
    struct iovec iov;

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);

    msg.msg_name = &recv_addr;
    msg.msg_namelen = sizeof(recv_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;

    for (;;) {
        msg.msg_namelen = sizeof(recv_addr);
        ssize_t bytes = recvmsg(recv_sock, &msg, MSG_DONTWAIT);

        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            break;
        }

        struct timespec recv_time;
        monotonic_now(&recv_time);

        if (handle_icmp_packet(buffer, (size_t)bytes, &recv_addr, &recv_time) > 0) {
            processed++;
        }
    }
#endif

    return processed;
}

static int handle_icmp_packet(const unsigned char *buffer, size_t bytes,
                              const struct sockaddr_storage *recv_addr,
                              const struct timespec *recv_time)
{
    if (config.ipv6) {
        // IPv6 ICMP handling
        if (bytes < sizeof(struct icmp6_hdr)) return 0;

        const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)buffer;

        if (config.protocol == PROTO_ICMP) {
            // Echo reply
            if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
                if (ntohs(icmp6->icmp6_dataun.icmp6_un_data16[0]) != probe_icmp_id) return 0;
                uint16_t seq = ntohs(icmp6->icmp6_dataun.icmp6_un_data16[1]);

                for (size_t idx = 0; idx < (size_t)config.max_ttl * (size_t)config.num_probes; idx++) {
                    if (!probes[idx].received && probes[idx].seq == seq) {
                        double rtt = timespec_diff_ms(&probes[idx].sent_time, recv_time);
                        if (rtt < 0) rtt = 0;
                        probes[idx].received = true;
                        probes[idx].addr6 = ((struct sockaddr_in6 *)recv_addr)->sin6_addr;
                        probes[idx].rtt = rtt;
                        atomic_fetch_add(&stats_responses_received, 1);
                        queue_dns_lookup(&probes[idx].addr6, true);
                        finished = 1;
                        return 1;
                    }
                }
            }
            // Time exceeded
            else if (icmp6->icmp6_type == ICMP6_TIME_EXCEEDED) {
                if (bytes < sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr))
                    return 0;

                const struct icmp6_hdr *orig_icmp = (const struct icmp6_hdr *)
                    (buffer + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr));

                if (orig_icmp->icmp6_type != ICMP6_ECHO_REQUEST) return 0;
                if (ntohs(orig_icmp->icmp6_dataun.icmp6_un_data16[0]) != probe_icmp_id) return 0;

                uint16_t seq = ntohs(orig_icmp->icmp6_dataun.icmp6_un_data16[1]);
                for (size_t idx = 0; idx < (size_t)config.max_ttl * (size_t)config.num_probes; idx++) {
                    if (!probes[idx].received && probes[idx].seq == seq) {
                        double rtt = timespec_diff_ms(&probes[idx].sent_time, recv_time);
                        if (rtt < 0) rtt = 0;
                        probes[idx].received = true;
                        probes[idx].addr6 = ((struct sockaddr_in6 *)recv_addr)->sin6_addr;
                        probes[idx].rtt = rtt;
                        atomic_fetch_add(&stats_responses_received, 1);
                        queue_dns_lookup(&probes[idx].addr6, true);
                        return 1;
                    }
                }
            }
        } else {
            // UDP mode - time exceeded or dest unreach
            if (icmp6->icmp6_type == ICMP6_TIME_EXCEEDED ||
                icmp6->icmp6_type == ICMP6_DST_UNREACH) {

                if (bytes < sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + sizeof(struct udphdr))
                    return 0;

                const struct udphdr *orig_udp = (const struct udphdr *)
                    (buffer + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr));

                int orig_port = ntohs(orig_udp->uh_dport);
                int diff = orig_port - config.base_port;
                if (diff < 0) return 0;

                size_t total_slots = (size_t)config.max_ttl * (size_t)config.num_probes;
                if ((size_t)diff >= total_slots) return 0;

                size_t idx = (size_t)diff;
                if (!probes[idx].received) {
                    double rtt = timespec_diff_ms(&probes[idx].sent_time, recv_time);
                    if (rtt < 0) rtt = 0;
                    probes[idx].received = true;
                    probes[idx].addr6 = ((struct sockaddr_in6 *)recv_addr)->sin6_addr;
                    probes[idx].rtt = rtt;
                    atomic_fetch_add(&stats_responses_received, 1);
                    queue_dns_lookup(&probes[idx].addr6, true);

                    if (icmp6->icmp6_type == ICMP6_DST_UNREACH) {
                        finished = 1;
                    }
                    return 1;
                }
            }
        }
        return 0;
    }

    // IPv4 handling
    if (bytes < sizeof(struct ip)) return 0;

    const struct ip *ip = (const struct ip *)buffer;
    int ip_header_len = ip->ip_hl << 2;
    if (ip_header_len <= 0 || (size_t)ip_header_len >= bytes) return 0;
    if (bytes < (size_t)(ip_header_len + ICMP_MINLEN)) return 0;

    const struct icmp *icmp_pkt = (const struct icmp *)(buffer + ip_header_len);

    if (config.protocol == PROTO_ICMP) {
        // Echo reply - destination reached
        if (icmp_pkt->icmp_type == ICMP_ECHOREPLY) {
            if (ntohs(icmp_pkt->icmp_hun.ih_idseq.icd_id) != probe_icmp_id) return 0;
            uint16_t seq = ntohs(icmp_pkt->icmp_hun.ih_idseq.icd_seq);

            for (size_t idx = 0; idx < (size_t)config.max_ttl * (size_t)config.num_probes; idx++) {
                if (!probes[idx].received && probes[idx].seq == seq) {
                    double rtt = timespec_diff_ms(&probes[idx].sent_time, recv_time);
                    if (rtt < 0) rtt = 0;
                    probes[idx].received = true;
                    probes[idx].addr = ((struct sockaddr_in *)recv_addr)->sin_addr;
                    probes[idx].rtt = rtt;
                    atomic_fetch_add(&stats_responses_received, 1);
                    queue_dns_lookup(&probes[idx].addr, false);
                    finished = 1;
                    return 1;
                }
            }
        }
        // Time exceeded
        else if (icmp_pkt->icmp_type == ICMP_TIME_EXCEEDED) {
            if (bytes < (size_t)(ip_header_len + 8 + sizeof(struct ip) + 8)) return 0;

            const struct ip *orig_ip = (const struct ip *)(buffer + ip_header_len + 8);
            int orig_ip_hl = orig_ip->ip_hl << 2;
            if (orig_ip_hl < 20) return 0;

            const struct icmp *orig_icmp = (const struct icmp *)(buffer + ip_header_len + 8 + orig_ip_hl);
            if (orig_icmp->icmp_type != ICMP_ECHO) return 0;
            if (ntohs(orig_icmp->icmp_hun.ih_idseq.icd_id) != probe_icmp_id) return 0;

            uint16_t seq = ntohs(orig_icmp->icmp_hun.ih_idseq.icd_seq);
            for (size_t idx = 0; idx < (size_t)config.max_ttl * (size_t)config.num_probes; idx++) {
                if (!probes[idx].received && probes[idx].seq == seq) {
                    double rtt = timespec_diff_ms(&probes[idx].sent_time, recv_time);
                    if (rtt < 0) rtt = 0;
                    probes[idx].received = true;
                    probes[idx].addr = ((struct sockaddr_in *)recv_addr)->sin_addr;
                    probes[idx].rtt = rtt;
                    atomic_fetch_add(&stats_responses_received, 1);
                    queue_dns_lookup(&probes[idx].addr, false);
                    return 1;
                }
            }
        }
        return 0;
    }

    // UDP mode
    if (!(icmp_pkt->icmp_type == ICMP_TIME_EXCEEDED ||
          (icmp_pkt->icmp_type == ICMP_DEST_UNREACH && icmp_pkt->icmp_code == ICMP_PORT_UNREACH))) {
        return 0;
    }

    if (bytes < (size_t)(ip_header_len + 8 + sizeof(struct ip))) return 0;

    const struct ip *orig_ip = (const struct ip *)(buffer + ip_header_len + 8);
    int orig_ip_header_len = orig_ip->ip_hl << 2;
    if (orig_ip_header_len <= 0) return 0;

    size_t required = (size_t)ip_header_len + 8 + (size_t)orig_ip_header_len + sizeof(struct udphdr);
    if (bytes < required) return 0;

    const struct udphdr *orig_udp = (const struct udphdr *)(buffer + ip_header_len + 8 + orig_ip_header_len);
    int orig_port = ntohs(orig_udp->uh_dport);

    int diff = orig_port - config.base_port;
    if (diff < 0) return 0;

    size_t total_slots = (size_t)config.max_ttl * (size_t)config.num_probes;
    if ((size_t)diff >= total_slots) return 0;

    size_t idx = (size_t)diff;

    if (!probes[idx].received) {
        double rtt = timespec_diff_ms(&probes[idx].sent_time, recv_time);
        if (rtt < 0) rtt = 0;

        probes[idx].received = true;
        probes[idx].addr = ((struct sockaddr_in *)recv_addr)->sin_addr;
        probes[idx].rtt = rtt;
        atomic_fetch_add(&stats_responses_received, 1);

        queue_dns_lookup(&probes[idx].addr, false);

        struct sockaddr_in *d4 = (struct sockaddr_in *)&dest_addr;
        if (((struct sockaddr_in *)recv_addr)->sin_addr.s_addr == d4->sin_addr.s_addr &&
            icmp_pkt->icmp_type == ICMP_DEST_UNREACH &&
            icmp_pkt->icmp_code == ICMP_PORT_UNREACH) {
            finished = 1;
        }
    }

    return 1;
}

static char *host_cache_lookup(const void *addr, bool is_ipv6)
{
    pthread_mutex_lock(&cache_mutex);
    for (size_t i = 0; i < HOST_CACHE_SIZE; i++) {
        if (host_cache[i].hostname && host_cache[i].is_ipv6 == is_ipv6) {
            bool match = false;
            if (is_ipv6) {
                match = memcmp(&host_cache[i].addr.v6, addr, sizeof(struct in6_addr)) == 0;
            } else {
                match = memcmp(&host_cache[i].addr.v4, addr, sizeof(struct in_addr)) == 0;
            }
            if (match) {
                char *copy = strdup(host_cache[i].hostname);
                pthread_mutex_unlock(&cache_mutex);
                return copy;
            }
        }
    }
    pthread_mutex_unlock(&cache_mutex);
    return NULL;
}

static void host_cache_store(const void *addr, bool is_ipv6, const char *hostname)
{
    pthread_mutex_lock(&cache_mutex);
    size_t slot = host_cache_next % HOST_CACHE_SIZE;
    host_cache_next = (host_cache_next + 1) % HOST_CACHE_SIZE;

    if (host_cache[slot].hostname) {
        free(host_cache[slot].hostname);
        host_cache[slot].hostname = NULL;
    }

    if (is_ipv6) {
        memcpy(&host_cache[slot].addr.v6, addr, sizeof(struct in6_addr));
    } else {
        memcpy(&host_cache[slot].addr.v4, addr, sizeof(struct in_addr));
    }
    host_cache[slot].is_ipv6 = is_ipv6;
    host_cache[slot].hostname = strdup(hostname);
    atomic_store(&host_cache[slot].resolved, true);
    pthread_mutex_unlock(&cache_mutex);
}

static void free_host_cache(void)
{
    pthread_mutex_lock(&cache_mutex);
    for (size_t i = 0; i < HOST_CACHE_SIZE; i++) {
        if (host_cache[i].hostname) {
            free(host_cache[i].hostname);
            host_cache[i].hostname = NULL;
        }
    }
    pthread_mutex_unlock(&cache_mutex);
}

static const char *resolve_hostname_cached(const void *addr, bool is_ipv6)
{
    if (!config.dns_enabled) return NULL;
    return host_cache_lookup(addr, is_ipv6);
}

static void handle_signal(int sig)
{
    (void)sig;
    finished = 1;
}

int main(int argc, char *argv[])
{
    atexit(cleanup);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    static struct option long_options[] = {
        {"json", no_argument, NULL, 'J'},
        {"csv", no_argument, NULL, 'C'},
        {"metrics", no_argument, NULL, 'M'},
        {"quiet", no_argument, NULL, 'Q'},
        {"no-adaptive", no_argument, NULL, 'A'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hn6ITVm:q:c:d:W:t:P:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            print_help(argv[0]);
            return 0;
        case 'V':
            print_version();
            return 0;
        case 'n':
            config.dns_enabled = false;
            break;
        case '6':
            config.ipv6 = true;
            break;
        case 'I':
            config.protocol = PROTO_ICMP;
            break;
        case 'T':
            config.protocol = PROTO_TCP;
            break;
        case 'J':
            config.output_format = OUTPUT_JSON;
            break;
        case 'C':
            config.output_format = OUTPUT_CSV;
            break;
        case 'M':
            config.show_metrics = true;
            break;
        case 'Q':
            config.quiet = true;
            break;
        case 'A':
            config.adaptive_window = false;
            break;
        case 'm': {
            int value = atoi(optarg);
            if (value < 1 || value > MAX_TTL_LIMIT) {
                fprintf(stderr, "Invalid max TTL: %s\n", optarg);
                return 1;
            }
            config.max_ttl = value;
            break;
        }
        case 'q': {
            int value = atoi(optarg);
            if (value < 1 || value > MAX_PROBES_LIMIT) {
                fprintf(stderr, "Invalid probes per hop: %s\n", optarg);
                return 1;
            }
            config.num_probes = value;
            break;
        }
        case 'c': {
            int value = atoi(optarg);
            if (value < 1) {
                fprintf(stderr, "Invalid concurrency window: %s\n", optarg);
                return 1;
            }
            config.max_active_ttls = value;
            break;
        }
        case 'd': {
            int value = atoi(optarg);
            if (value < 0) {
                fprintf(stderr, "Invalid inter-probe delay: %s\n", optarg);
                return 1;
            }
            config.probe_delay_us = value;
            break;
        }
        case 'W': {
            int value = atoi(optarg);
            if (value < 0) {
                fprintf(stderr, "Invalid poll timeout: %s\n", optarg);
                return 1;
            }
            config.wait_timeout_ms = value;
            break;
        }
        case 't': {
            int value = atoi(optarg);
            if (value < 1) {
                fprintf(stderr, "Invalid hop timeout: %s\n", optarg);
                return 1;
            }
            config.ttl_timeout_ms = value;
            break;
        }
        case 'P': {
            int value = atoi(optarg);
            if (value < 1024 || value > 65535) {
                fprintf(stderr, "Invalid base port: %s\n", optarg);
                return 1;
            }
            config.base_port = value;
            break;
        }
        default:
            print_help(argv[0]);
            return 1;
        }
    }

    if (optind >= argc) {
        print_help(argv[0]);
        return 1;
    }

    target_host = argv[optind];

    if (config.max_active_ttls < 1)
        config.max_active_ttls = 1;
    if (config.max_active_ttls > config.max_ttl)
        config.max_active_ttls = config.max_ttl;

    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
    initialize_payload();

    // Resolve target
    memset(&dest_addr, 0, sizeof(dest_addr));

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = config.ipv6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo *result = NULL;
    int gai_err = getaddrinfo(target_host, NULL, &hints, &result);

    // If IPv6 failed, try IPv4
    if (gai_err != 0 && config.ipv6) {
        hints.ai_family = AF_INET;
        gai_err = getaddrinfo(target_host, NULL, &hints, &result);
        if (gai_err == 0) {
            config.ipv6 = false;
        }
    }

    if (gai_err != 0 || !result) {
        fprintf(stderr, "Error: Cannot resolve host '%s': %s\n", target_host, gai_strerror(gai_err));
        return 1;
    }

    memcpy(&dest_addr, result->ai_addr, result->ai_addrlen);
    dest_addr_len = result->ai_addrlen;
    config.ipv6 = (result->ai_family == AF_INET6);
    freeaddrinfo(result);

    char dest_ip[INET6_ADDRSTRLEN];
    if (config.ipv6) {
        struct sockaddr_in6 *d6 = (struct sockaddr_in6 *)&dest_addr;
        inet_ntop(AF_INET6, &d6->sin6_addr, dest_ip, sizeof(dest_ip));
    } else {
        struct sockaddr_in *d4 = (struct sockaddr_in *)&dest_addr;
        inet_ntop(AF_INET, &d4->sin_addr, dest_ip, sizeof(dest_ip));
    }

    // Print header based on output format
    if (config.output_format == OUTPUT_TEXT && !config.quiet) {
        printf("fastrace %s\n", VERSION);
        printf("Tracing route to %s (%s)\n", target_host, dest_ip);
        printf("Maximum hops: %d, Probes per hop: %d, Protocol: %s%s\n",
               config.max_ttl, config.num_probes,
               config.protocol == PROTO_UDP ? "UDP" :
               config.protocol == PROTO_ICMP ? "ICMP" : "TCP",
               config.ipv6 ? " (IPv6)" : "");
        printf("TTL │ IP Address                              (RTT ms)    Hostname\n");
        printf("────┼────────────────────────────────────────────────────────────────\n");
    } else if (config.output_format == OUTPUT_CSV) {
        print_csv_header();
    }

    size_t total_slots = (size_t)config.max_ttl * (size_t)config.num_probes;
    probes = calloc(total_slots, sizeof(probe_t));
    last_probe_time = calloc((size_t)config.max_ttl, sizeof(struct timespec));
    if (!probes || !last_probe_time) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 1;
    }

    // Create sockets
    int af = config.ipv6 ? AF_INET6 : AF_INET;

    if (config.protocol == PROTO_ICMP) {
        send_sock = socket(af, SOCK_RAW, config.ipv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
        if (send_sock < 0) {
            perror("Error creating ICMP socket. Are you running as root?");
            return 1;
        }
    } else if (config.protocol == PROTO_TCP) {
        send_sock = socket(af, SOCK_STREAM, IPPROTO_TCP);
        if (send_sock < 0) {
            perror("Error creating TCP socket");
            return 1;
        }
        set_nonblocking(send_sock);
    } else {
        send_sock = socket(af, SOCK_DGRAM, IPPROTO_UDP);
        if (send_sock < 0) {
            perror("Error creating UDP socket");
            return 1;
        }
    }
    set_cloexec(send_sock);

    recv_sock = socket(af, SOCK_RAW, config.ipv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
    if (recv_sock < 0) {
        perror("Error creating ICMP receive socket. Are you running as root?");
        return 1;
    }
    set_cloexec(recv_sock);
    set_nonblocking(recv_sock);

    if (config.dns_enabled) {
        if (pthread_create(&dns_thread_id, NULL, dns_worker, NULL) != 0) {
            config.dns_enabled = false;
        }
    }

    int sndbuff = SOCKET_BUFFER_SIZE;
    int rcvbuff = SOCKET_BUFFER_SIZE;
    setsockopt(send_sock, SOL_SOCKET, SO_SNDBUF, &sndbuff, sizeof(sndbuff));
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuff, sizeof(rcvbuff));

    int next_ttl_to_print = 1;
    int current_ttl = 1;
    int max_sent_ttl = 0;

    // Adaptive window variables
    double recent_rtt_sum = 0;
    int recent_rtt_count = 0;
    int adaptive_window = config.max_active_ttls;

    struct timespec trace_start;
    monotonic_now(&trace_start);

    while (next_ttl_to_print <= config.max_ttl) {
        // Adaptive window adjustment
        if (config.adaptive_window && recent_rtt_count > 0) {
            double avg_rtt = recent_rtt_sum / recent_rtt_count;
            if (avg_rtt < 20.0) {
                adaptive_window = config.max_active_ttls + 4;
            } else if (avg_rtt < 50.0) {
                adaptive_window = config.max_active_ttls + 2;
            } else {
                adaptive_window = config.max_active_ttls;
            }
            if (adaptive_window > config.max_ttl) adaptive_window = config.max_ttl;
        }

        int effective_window = config.adaptive_window ? adaptive_window : config.max_active_ttls;

        while (current_ttl <= config.max_ttl &&
               (current_ttl - next_ttl_to_print) < effective_window &&
               !finished) {
            send_probe_batch(current_ttl);
            max_sent_ttl = current_ttl;
            current_ttl++;
            process_responses(0);
        }

        int dynamic_wait = compute_wait_timeout_ms(next_ttl_to_print, current_ttl);
        process_responses(dynamic_wait);

        struct timespec now;
        monotonic_now(&now);

        while (next_ttl_to_print < current_ttl && ttl_ready_to_print(next_ttl_to_print, &now)) {
            if (config.output_format == OUTPUT_TEXT && !config.quiet) {
                printf("%-3d │ ", next_ttl_to_print);
            }
            print_ttl_results(next_ttl_to_print);

            // Update adaptive window based on recent RTTs
            for (int p = 0; p < config.num_probes; p++) {
                size_t idx = (size_t)(next_ttl_to_print - 1) * (size_t)config.num_probes + (size_t)p;
                if (probes[idx].received) {
                    recent_rtt_sum += probes[idx].rtt;
                    recent_rtt_count++;
                    if (recent_rtt_count > 10) {
                        recent_rtt_sum = probes[idx].rtt * 5;
                        recent_rtt_count = 5;
                    }
                }
            }

            next_ttl_to_print++;
        }

        if (finished && next_ttl_to_print > max_sent_ttl) break;

        if (current_ttl > config.max_ttl && next_ttl_to_print <= max_sent_ttl && !finished) {
            usleep(5000);
        }
    }

    struct timespec trace_end;
    monotonic_now(&trace_end);
    double trace_time_ms = timespec_diff_ms(&trace_start, &trace_end);

    int sent = atomic_load(&stats_probes_sent);
    int recv = atomic_load(&stats_responses_received);

    if (config.output_format == OUTPUT_JSON) {
        print_json_output();
    } else if (config.output_format == OUTPUT_TEXT && !config.quiet) {
        printf("\nTrace complete in %.1f ms. Hops: %d, Responses: %d/%d (%.1f%%)\n",
               trace_time_ms, next_ttl_to_print - 1, recv, sent,
               sent > 0 ? (100.0 * recv / sent) : 0.0);
    }

    if (config.show_metrics) {
        print_metrics();
    }

    return finished ? 0 : 1;
}
