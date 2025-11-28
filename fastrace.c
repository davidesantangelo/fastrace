/**
 * fastrace - Blazing fast traceroute implementation with no dependencies
 *
 * Compiles with: gcc -O3 -o fastrace fastrace.c
 * Run with: sudo ./fastrace [target]
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
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

#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED 11
#endif
#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif
#ifndef ICMP_PORT_UNREACH
#define ICMP_PORT_UNREACH 3
#endif

#define VERSION "0.3.1"
#define PACKET_SIZE 60
#define HOST_CACHE_SIZE 256
#define MAX_TTL_LIMIT 128
#define MAX_PROBES_LIMIT 10
#define SOCKET_BUFFER_SIZE 131072

typedef struct
{
    int ttl;
    int probe;
    struct timespec sent_time;
    bool received;
    struct in_addr addr;
    double rtt;
    int port;
} probe_t;

typedef struct
{
    struct in_addr addr;
    char *hostname;
} host_cache_entry_t;

typedef struct
{
    int max_ttl;
    int num_probes;
    int max_active_ttls;
    int wait_timeout_ms;
    int ttl_timeout_ms;
    int probe_delay_us;
    int base_port;
    bool dns_enabled;
} traceroute_config_t;

static traceroute_config_t config = {
    .max_ttl = 30,
    .num_probes = 3,
    .max_active_ttls = 6,
    .wait_timeout_ms = 2,
    .ttl_timeout_ms = 700,
    .probe_delay_us = 250,
    .base_port = 33434,
    .dns_enabled = true};

// Threading and Queue globals
static pthread_t dns_thread_id;
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static volatile bool dns_running = true;
static int dns_queue_size = 0;
#define MAX_DNS_QUEUE_SIZE 1024

typedef struct dns_queue_item {
    struct in_addr addr;
    struct dns_queue_item *next;
} dns_queue_item_t;

static dns_queue_item_t *dns_queue_head = NULL;
static dns_queue_item_t *dns_queue_tail = NULL;

static int send_sock = -1;
static int recv_sock = -1;
static char *target_host = NULL;
static struct sockaddr_in dest_addr;
static volatile sig_atomic_t finished = 0;
static probe_t *probes = NULL;
static struct timespec *last_probe_time = NULL;
static host_cache_entry_t host_cache[HOST_CACHE_SIZE];
static size_t host_cache_next = 0;
static unsigned char base_payload[PACKET_SIZE];

static void cleanup(void);
static void print_help(const char *prog_name);
static void print_version(void);
static void initialize_payload(void);
static void set_cloexec(int fd);
static void set_nonblocking(int fd);
static void monotonic_now(struct timespec *ts);
static double timespec_diff_ms(const struct timespec *start, const struct timespec *end);
static void send_probe(int ttl, int probe_num);
static int process_responses(int timeout_ms);
static int drain_icmp_socket(void);
static int handle_icmp_packet(const unsigned char *buffer, size_t bytes, const struct sockaddr_in *recv_addr, const struct timespec *recv_time);
static const char *resolve_hostname_cached(struct in_addr addr);
static void host_cache_store(struct in_addr addr, const char *hostname);
static char *host_cache_lookup(struct in_addr addr);
static void free_host_cache(void);

static void queue_dns_lookup(struct in_addr addr);
static void *dns_worker(void *arg);

static void queue_dns_lookup(struct in_addr addr)
{
    if (!config.dns_enabled) return;

    pthread_mutex_lock(&queue_mutex);
    if (dns_queue_size >= MAX_DNS_QUEUE_SIZE) {
        pthread_mutex_unlock(&queue_mutex);
        return;
    }
    pthread_mutex_unlock(&queue_mutex);

    dns_queue_item_t *item = malloc(sizeof(dns_queue_item_t));
    if (!item) return;
    item->addr = addr;
    item->next = NULL;

    pthread_mutex_lock(&queue_mutex);
    if (dns_queue_tail) {
        dns_queue_tail->next = item;
        dns_queue_tail = item;
    } else {
        dns_queue_head = dns_queue_tail = item;
    }
    dns_queue_size++;
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
        dns_queue_size--;
        pthread_mutex_unlock(&queue_mutex);

        char host[NI_MAXHOST];
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr = item->addr;

        if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0)
        {
            host_cache_store(item->addr, host);
        }
        
        free(item);
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

    // Clear remaining queue
    pthread_mutex_lock(&queue_mutex);
    while (dns_queue_head) {
        dns_queue_item_t *tmp = dns_queue_head;
        dns_queue_head = dns_queue_head->next;
        free(tmp);
    }
    dns_queue_tail = NULL;
    pthread_mutex_unlock(&queue_mutex);

    if (send_sock >= 0)
    {
        close(send_sock);
        send_sock = -1;
    }
    if (recv_sock >= 0)
    {
        close(recv_sock);
        recv_sock = -1;
    }
    if (probes)
    {
        free(probes);
        probes = NULL;
    }
    if (last_probe_time)
    {
        free(last_probe_time);
        last_probe_time = NULL;
    }
    free_host_cache();
}

static void print_help(const char *prog_name)
{
    printf("fastrace %s - high-performance traceroute\n", VERSION);
    printf("Usage: sudo %s [options] <target>\n", prog_name);
    printf("\nOptions:\n");
    printf("  -n            Disable reverse DNS lookups\n");
    printf("  -m <hops>     Maximum hops to trace (1-%d) [default %d]\n", MAX_TTL_LIMIT, config.max_ttl);
    printf("  -q <probes>   Probes per hop (1-%d) [default %d]\n", MAX_PROBES_LIMIT, config.num_probes);
    printf("  -c <count>    Concurrent TTL window size [default %d]\n", config.max_active_ttls);
    printf("  -W <ms>       Poll wait timeout in milliseconds [default %d]\n", config.wait_timeout_ms);
    printf("  -t <ms>       Hop completion timeout in milliseconds [default %d]\n", config.ttl_timeout_ms);
    printf("  -P <port>     Base UDP destination port [default %d]\n", config.base_port);
    printf("  -V            Print version and exit\n");
    printf("  -h            Show this help message\n");
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
    for (size_t i = 0; i < sizeof(base_payload); i++)
    {
        base_payload[i] = (unsigned char)(rand() & 0xFF);
    }
#endif
}

static void set_cloexec(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags == -1)
        return;
    fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return;
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void monotonic_now(struct timespec *ts)
{
#if defined(CLOCK_MONOTONIC)
    if (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
    {
        return;
    }
#endif
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ts->tv_sec = tv.tv_sec;
    ts->tv_nsec = tv.tv_usec * 1000;
}

static double timespec_diff_ms(const struct timespec *start, const struct timespec *end)
{
    time_t sec = end->tv_sec - start->tv_sec;
    long nsec = end->tv_nsec - start->tv_nsec;
    if (nsec < 0)
    {
        sec -= 1;
        nsec += 1000000000L;
    }
    return (double)sec * 1000.0 + (double)nsec / 1000000.0;
}

static void send_probe(int ttl, int probe_num)
{
    if (send_sock < 0)
        return;
    if (ttl < 1 || ttl > config.max_ttl)
        return;
    if (probe_num < 0 || probe_num >= config.num_probes)
        return;

    if (setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
    {
        perror("Error setting TTL");
        return;
    }

    int port = config.base_port + ((ttl - 1) * config.num_probes) + probe_num;
    struct sockaddr_in probe_dest = dest_addr;
    probe_dest.sin_port = htons(port);

    struct timeval tv;
    gettimeofday(&tv, NULL);

    unsigned char payload[PACKET_SIZE];
    memcpy(payload, base_payload, sizeof(payload));
    memcpy(payload, &tv, sizeof(tv));

    if (sendto(send_sock, payload, sizeof(payload), 0, (struct sockaddr *)&probe_dest, sizeof(probe_dest)) < 0)
    {
        return;
    }

    struct timespec send_time;
    monotonic_now(&send_time);

    size_t idx = (size_t)(ttl - 1) * (size_t)config.num_probes + (size_t)probe_num;
    probes[idx].ttl = ttl;
    probes[idx].probe = probe_num;
    probes[idx].port = port;
    probes[idx].sent_time = send_time;
    probes[idx].received = false;
    probes[idx].addr.s_addr = 0;
    probes[idx].rtt = 0.0;
}

static int process_responses(int timeout_ms)
{
    if (recv_sock < 0)
        return -1;

    if (timeout_ms < 0)
        timeout_ms = 0;

    if (timeout_ms > 0)
    {
        struct pollfd pfd = {.fd = recv_sock, .events = POLLIN | POLLERR | POLLHUP};
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret < 0)
        {
            if (errno == EINTR)
                return 0;
            perror("poll error");
            return -1;
        }
        if (ret == 0)
            return 0;
        if (!(pfd.revents & (POLLIN | POLLERR | POLLHUP)))
            return 0;
    }

    return drain_icmp_socket();
}

static int drain_icmp_socket(void)
{
    int processed = 0;
    struct msghdr msg;
    struct iovec iov;
    unsigned char buffer[2048];
    char control[1024];
    struct sockaddr_in recv_addr;

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);

    msg.msg_name = &recv_addr;
    msg.msg_namelen = sizeof(recv_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    for (;;)
    {
        msg.msg_namelen = sizeof(recv_addr);
        msg.msg_controllen = sizeof(control);
        
        ssize_t bytes = recvmsg(recv_sock, &msg, MSG_DONTWAIT);

        if (bytes < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            perror("recvmsg error");
            break;
        }

        struct timespec recv_time;
        
        // Always use monotonic clock for RTT calculations.
        // SO_TIMESTAMP provides wall-clock time which cannot be compared
        // with monotonic sent_time, causing huge incorrect RTT values.
        monotonic_now(&recv_time);

        if (handle_icmp_packet(buffer, (size_t)bytes, &recv_addr, &recv_time) > 0)
        {
            processed++;
        }
    }

    return processed;
}

static int handle_icmp_packet(const unsigned char *buffer, size_t bytes, const struct sockaddr_in *recv_addr, const struct timespec *recv_time)
{
    if (bytes < sizeof(struct ip))
        return 0;

    const struct ip *ip = (const struct ip *)buffer;
    int ip_header_len = ip->ip_hl << 2;
    if (ip_header_len <= 0 || (size_t)ip_header_len >= bytes)
        return 0;

    if (bytes < (size_t)(ip_header_len + ICMP_MINLEN))
        return 0;

    const struct icmp *icmp = (const struct icmp *)(buffer + ip_header_len);
    if (!(icmp->icmp_type == ICMP_TIME_EXCEEDED ||
          (icmp->icmp_type == ICMP_DEST_UNREACH && icmp->icmp_code == ICMP_PORT_UNREACH)))
    {
        return 1;
    }

    if (bytes < (size_t)(ip_header_len + 8 + sizeof(struct ip)))
        return 1;

    const struct ip *orig_ip = (const struct ip *)(buffer + ip_header_len + 8);
    int orig_ip_header_len = orig_ip->ip_hl << 2;
    if (orig_ip_header_len <= 0)
        return 1;

    size_t required = (size_t)ip_header_len + 8 + (size_t)orig_ip_header_len + sizeof(struct udphdr);
    if (bytes < required)
        return 1;

    const struct udphdr *orig_udp = (const struct udphdr *)(buffer + ip_header_len + 8 + orig_ip_header_len);
    int orig_port = ntohs(orig_udp->uh_dport);

    // Calculate probe index directly from port
    int diff = orig_port - config.base_port;
    if (diff < 0) return 1;

    size_t total_slots = (size_t)config.max_ttl * (size_t)config.num_probes;
    if ((size_t)diff >= total_slots) return 1;

    size_t idx = (size_t)diff;

    if (!probes[idx].received)
    {
        double rtt = timespec_diff_ms(&probes[idx].sent_time, recv_time);
        if (rtt < 0.0)
        {
            fprintf(stderr, "Warning: Negative RTT detected (%.3f ms) - clock issue?\n", rtt);
            rtt = 0.0;
        }

        probes[idx].received = true;
        probes[idx].addr = recv_addr->sin_addr;
        probes[idx].rtt = rtt;

        queue_dns_lookup(recv_addr->sin_addr);

        if (recv_addr->sin_addr.s_addr == dest_addr.sin_addr.s_addr &&
            icmp->icmp_type == ICMP_DEST_UNREACH &&
            icmp->icmp_code == ICMP_PORT_UNREACH)
        {
            finished = 1;
        }
    }

    return 1;
}

// Returns a copy that must be freed by caller
static char *host_cache_lookup(struct in_addr addr)
{
    pthread_mutex_lock(&cache_mutex);
    for (size_t i = 0; i < HOST_CACHE_SIZE; i++)
    {
        if (host_cache[i].hostname && host_cache[i].addr.s_addr == addr.s_addr)
        {
            char *copy = strdup(host_cache[i].hostname);
            pthread_mutex_unlock(&cache_mutex);
            return copy;
        }
    }
    pthread_mutex_unlock(&cache_mutex);
    return NULL;
}

static void host_cache_store(struct in_addr addr, const char *hostname)
{
    pthread_mutex_lock(&cache_mutex);
    size_t slot = host_cache_next % HOST_CACHE_SIZE;
    host_cache_next = (host_cache_next + 1) % HOST_CACHE_SIZE;

    if (host_cache[slot].hostname)
    {
        free(host_cache[slot].hostname);
        host_cache[slot].hostname = NULL;
    }

    host_cache[slot].addr = addr;
    host_cache[slot].hostname = strdup(hostname);
    pthread_mutex_unlock(&cache_mutex);
}

static void free_host_cache(void)
{
    pthread_mutex_lock(&cache_mutex);
    for (size_t i = 0; i < HOST_CACHE_SIZE; i++)
    {
        if (host_cache[i].hostname)
        {
            free(host_cache[i].hostname);
            host_cache[i].hostname = NULL;
        }
    }
    pthread_mutex_unlock(&cache_mutex);
}

static const char *resolve_hostname_cached(struct in_addr addr)
{
    if (!config.dns_enabled)
        return NULL;

    return host_cache_lookup(addr);
}

static void handle_signal(int sig)
{
    (void)sig;
    exit(0);
}

int main(int argc, char *argv[])
{
    atexit(cleanup);
    signal(SIGINT, handle_signal);

    int opt;
    while ((opt = getopt(argc, argv, "hnVm:q:c:W:t:P:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            print_help(argv[0]);
            return 0;
        case 'V':
            print_version();
            return 0;
        case 'n':
            config.dns_enabled = false;
            break;
        case 'm':
        {
            int value = atoi(optarg);
            if (value < 1 || value > MAX_TTL_LIMIT)
            {
                fprintf(stderr, "Invalid max TTL: %s\n", optarg);
                return 1;
            }
            config.max_ttl = value;
            break;
        }
        case 'q':
        {
            int value = atoi(optarg);
            if (value < 1 || value > MAX_PROBES_LIMIT)
            {
                fprintf(stderr, "Invalid probes per hop: %s\n", optarg);
                return 1;
            }
            config.num_probes = value;
            break;
        }
        case 'c':
        {
            int value = atoi(optarg);
            if (value < 1)
            {
                fprintf(stderr, "Invalid concurrency window: %s\n", optarg);
                return 1;
            }
            config.max_active_ttls = value;
            break;
        }
        case 'W':
        {
            int value = atoi(optarg);
            if (value < 0)
            {
                fprintf(stderr, "Invalid poll timeout: %s\n", optarg);
                return 1;
            }
            config.wait_timeout_ms = value;
            break;
        }
        case 't':
        {
            int value = atoi(optarg);
            if (value < 1)
            {
                fprintf(stderr, "Invalid hop timeout: %s\n", optarg);
                return 1;
            }
            config.ttl_timeout_ms = value;
            break;
        }
        case 'P':
        {
            int value = atoi(optarg);
            if (value < 1024 || value > 65535)
            {
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

    if (optind >= argc)
    {
        print_help(argv[0]);
        return 1;
    }

    target_host = argv[optind];

    if (config.max_active_ttls < 1)
        config.max_active_ttls = 1;
    if (config.max_active_ttls > config.max_ttl)
        config.max_active_ttls = config.max_ttl;

    srand((unsigned int)time(NULL));
    initialize_payload();

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo *result = NULL;
    int gai_err = getaddrinfo(target_host, NULL, &hints, &result);
    if (gai_err != 0 || !result)
    {
        fprintf(stderr, "Error: Cannot resolve host '%s': %s\n", target_host, gai_strerror(gai_err));
        return 1;
    }

    memcpy(&dest_addr, result->ai_addr, sizeof(struct sockaddr_in));
    freeaddrinfo(result);

    char dest_ip[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &dest_addr.sin_addr, dest_ip, sizeof(dest_ip)))
    {
        strncpy(dest_ip, "<unknown>", sizeof(dest_ip));
        dest_ip[sizeof(dest_ip) - 1] = '\0';
    }

    printf("fastrace %s\n", VERSION);
    printf("Tracing route to %s (%s)\n", target_host, dest_ip);
    printf("Maximum hops: %d, Probes per hop: %d, Protocol: UDP\n", config.max_ttl, config.num_probes);
    printf("TTL │ IP Address         (RTT ms)    Hostname\n");
    printf("────┼───────────────────────────────────────────\n");

    size_t total_slots = (size_t)config.max_ttl * (size_t)config.num_probes;
    probes = calloc(total_slots, sizeof(probe_t));
    last_probe_time = calloc((size_t)config.max_ttl, sizeof(struct timespec));
    if (!probes || !last_probe_time)
    {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 1;
    }

    send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (send_sock < 0)
    {
        perror("Error creating UDP socket");
        return 1;
    }
    set_cloexec(send_sock);

    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_sock < 0)
    {
        perror("Error creating ICMP socket. Are you running as root?");
        return 1;
    }
    set_cloexec(recv_sock);
    set_nonblocking(recv_sock);

    if (config.dns_enabled) {
        if (pthread_create(&dns_thread_id, NULL, dns_worker, NULL) != 0) {
            fprintf(stderr, "Warning: Failed to create DNS thread. DNS resolution disabled.\n");
            config.dns_enabled = false;
        }
    }

    int sndbuff = SOCKET_BUFFER_SIZE;
    int rcvbuff = SOCKET_BUFFER_SIZE;
    setsockopt(send_sock, SOL_SOCKET, SO_SNDBUF, &sndbuff, sizeof(sndbuff));
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuff, sizeof(rcvbuff));

    int next_ttl_to_print = 1;
    int current_ttl = 1;

    while (next_ttl_to_print <= config.max_ttl && !finished)
    {
        while (current_ttl <= config.max_ttl &&
               (current_ttl - next_ttl_to_print) < config.max_active_ttls &&
               !finished)
        {
            for (int probe = 0; probe < config.num_probes; probe++)
            {
                send_probe(current_ttl, probe);
                if (config.probe_delay_us > 0)
                    usleep((useconds_t)config.probe_delay_us);
            }
            monotonic_now(&last_probe_time[current_ttl - 1]);
            current_ttl++;
            process_responses(0);
        }

        process_responses(config.wait_timeout_ms);

        int ttl = next_ttl_to_print;
        struct timespec zero = {0, 0};
        double time_elapsed = 0.0;

        if (memcmp(&last_probe_time[ttl - 1], &zero, sizeof(struct timespec)) != 0)
        {
            struct timespec now;
            monotonic_now(&now);
            time_elapsed = timespec_diff_ms(&last_probe_time[ttl - 1], &now);
        }

        bool all_received = true;
        for (int probe = 0; probe < config.num_probes; probe++)
        {
            size_t idx = (size_t)(ttl - 1) * (size_t)config.num_probes + (size_t)probe;
            if (!probes[idx].received)
            {
                all_received = false;
                break;
            }
        }

        if (all_received ||
            (time_elapsed > (double)config.ttl_timeout_ms &&
             memcmp(&last_probe_time[ttl - 1], &zero, sizeof(struct timespec)) != 0))
        {
            printf("%-3d │ ", ttl);

            struct in_addr hop_addrs[MAX_PROBES_LIMIT];
            double hop_rtts[MAX_PROBES_LIMIT];
            memset(hop_addrs, 0, sizeof(hop_addrs));
            memset(hop_rtts, 0, sizeof(hop_rtts));

            int unique_addrs = 0;
            int received_count = 0;

            for (int probe = 0; probe < config.num_probes; probe++)
            {
                size_t idx = (size_t)(ttl - 1) * (size_t)config.num_probes + (size_t)probe;
                if (!probes[idx].received)
                    continue;

                received_count++;
                int existing_idx = -1;
                for (int j = 0; j < unique_addrs; j++)
                {
                    if (hop_addrs[j].s_addr == probes[idx].addr.s_addr)
                    {
                        existing_idx = j;
                        break;
                    }
                }

                if (existing_idx == -1 && unique_addrs < MAX_PROBES_LIMIT)
                {
                    hop_addrs[unique_addrs] = probes[idx].addr;
                    hop_rtts[unique_addrs] = probes[idx].rtt;
                    unique_addrs++;
                }
                else if (existing_idx >= 0)
                {
                    double prev = hop_rtts[existing_idx];
                    hop_rtts[existing_idx] = (prev * 0.4) + (probes[idx].rtt * 0.6);
                }
            }

            if (received_count > 0 && unique_addrs > 0)
            {
                for (int i = 0; i < unique_addrs; i++)
                {
                    const char *hostname = resolve_hostname_cached(hop_addrs[i]);
                    if (i == 0)
                    {
                        printf("→ %-15s (%6.2f ms)", inet_ntoa(hop_addrs[i]), hop_rtts[i]);
                    }
                    else
                    {
                        printf("\n      └→ %-15s (%6.2f ms)", inet_ntoa(hop_addrs[i]), hop_rtts[i]);
                    }
                    if (hostname)
                    {
                        printf(" %s", hostname);
                        free((void*)hostname);
                    }
                    printf("\n");
                }

                if (hop_addrs[0].s_addr != 0 && hop_addrs[0].s_addr == dest_addr.sin_addr.s_addr)
                {
                    finished = 1;
                }
            }
            else
            {
                printf("* * * (timeout)\n");
            }

            next_ttl_to_print++;
        }
        else if (current_ttl > config.max_ttl && next_ttl_to_print <= config.max_ttl)
        {
            usleep(10000);
        }
    }

    return finished ? 0 : 1;
}
