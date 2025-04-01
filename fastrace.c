/**
 * fastrace - Blazing fast traceroute implementation with no dependencies
 *
 * Compiles with: gcc -O3 -o fastrace fastrace.c
 * Run with: sudo ./fastrace [target]
 */

#define _GNU_SOURCE // Define before including headers to potentially get SOCK_CLOEXEC etc.
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
#include <fcntl.h>  // Needed for fcntl, F_SETFD, FD_CLOEXEC
#include <stdarg.h> // Used by debug_print

#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED 11
#endif
#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif
#ifndef ICMP_PORT_UNREACH
#define ICMP_PORT_UNREACH 3
#endif

#define MAX_TTL 30
#define PACKET_SIZE 60
#define NUM_PROBES 3
#define RECV_TIMEOUT 1
#define MAX_ACTIVE_TTLS 5
#define DEBUG 0
#define WAIT_TIMEOUT_MS 1
#define TTL_TIMEOUT 800
#define BASE_PORT 33434
#define PROBE_DELAY 1000
#define MAX_RTT 1000.0
#define MIN_RTT 0.1
#define INITIAL_RESP_CHECKS 10
#define LATER_RESP_CHECKS 40
#define SOCKET_BUFFER_SIZE 65536

typedef struct
{
    int ttl;
    int probe;
    struct timeval sent_time;
    int received;
    struct in_addr addr;
    double rtt;
    int port;
} probe_t;

int send_sock = -1;
int recv_sock = -1;
char *target_host = NULL;
struct sockaddr_in dest_addr;
int finished = 0;
probe_t probes[MAX_TTL * NUM_PROBES];
struct timeval last_probe_time[MAX_TTL];

void send_probe(int ttl, int probe_num);
int process_responses(int timeout_ms);
char *resolve_hostname(struct in_addr addr);
void print_help(void);
void debug_print(const char *fmt, ...);

#ifndef timersub
#define timersub(a, b, result)                           \
    do                                                   \
    {                                                    \
        (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;    \
        (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
        if ((result)->tv_usec < 0)                       \
        {                                                \
            --(result)->tv_sec;                          \
            (result)->tv_usec += 1000000;                \
        }                                                \
    } while (0)
#endif

void debug_print(const char *fmt, ...)
{
    if (!DEBUG)
        return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

char *resolve_hostname(struct in_addr addr)
{
    struct hostent *host = gethostbyaddr(&addr, sizeof(addr), AF_INET);
    if (host && host->h_name)
    {
        char *name_copy = strdup(host->h_name);
        if (!name_copy)
        {
            perror("strdup failed in resolve_hostname");
            // Return NULL if strdup fails
            return NULL;
        }
        return name_copy; // Return allocated copy
    }
    return NULL;
}

void print_help(void)
{
    printf("Usage: sudo ./fastrace <target>\n");
    printf("\nOptions:\n");
    printf("  <target>    Target hostname or IP address\n");
    printf("\nExample:\n");
    printf("  sudo ./fastrace google.com\n");
}

void send_probe(int ttl, int probe_num)
{
    if (send_sock < 0)
        return; // Check if socket is valid

    if (setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
    {
        perror("Error setting TTL");
        return;
    }

    int port = BASE_PORT + (ttl * NUM_PROBES) + probe_num;
    struct sockaddr_in probe_dest = dest_addr;
    probe_dest.sin_port = htons(port);

    char payload[PACKET_SIZE];
    memset(payload, 0, sizeof(payload));

    struct timeval tv;

    // Fill payload *after* tv struct size offset
    for (size_t i = sizeof(tv); i < sizeof(payload); i++)
    {
        payload[i] = rand() % 256;
    }

    gettimeofday(&tv, NULL);
    memcpy(payload, &tv, sizeof(tv)); // Embed timestamp

    if (sendto(send_sock, payload, sizeof(payload), 0,
               (struct sockaddr *)&probe_dest, sizeof(probe_dest)) < 0)
    {
        // Avoid flooding stderr if destination is unreachable quickly
        // Consider adding rate limiting or smarter error handling if needed
        // perror("Error sending packet");
        return;
    }

    int idx = (ttl - 1) * NUM_PROBES + probe_num;
    if (idx >= 0 && idx < MAX_TTL * NUM_PROBES)
    {
        probes[idx].ttl = ttl;
        probes[idx].probe = probe_num;
        probes[idx].port = port;
        probes[idx].sent_time = tv; // Store the exact time sent
        probes[idx].received = 0;
        probes[idx].rtt = 0.0; // Initialize RTT
    }
    else
    {
        fprintf(stderr, "Warning: Probe index %d out of bounds (TTL: %d, Probe: %d)\n", idx, ttl, probe_num);
    }
}

int process_responses(int timeout_ms)
{
    fd_set readfds;
    FD_ZERO(&readfds);
    if (recv_sock < 0)
        return -1; // Socket not open
    FD_SET(recv_sock, &readfds);

    struct timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    int ret = select(recv_sock + 1, &readfds, NULL, NULL, &timeout);
    if (ret < 0)
    {
        if (errno == EINTR)
            return 0; // Interrupted, try again
        perror("select error");
        return -1; // Indicate error
    }
    if (ret == 0)
    {
        return 0; // Timeout
    }

    if (!FD_ISSET(recv_sock, &readfds))
    {
        return 0; // Should not happen if select returned > 0
    }

    char buffer[1500];
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);

    // Use ssize_t for recvfrom return value
    ssize_t bytes = recvfrom(recv_sock, buffer, sizeof(buffer), 0,
                             (struct sockaddr *)&recv_addr, &addr_len);

    if (bytes <= 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0; // No data available right now
        perror("recvfrom error");
        return 0; // Treat other errors as no response received for now
    }

    struct timeval recv_time;
    gettimeofday(&recv_time, NULL);

    struct ip *ip = (struct ip *)buffer;
    int ip_header_len = ip->ip_hl << 2;
    // Use size_t for comparison with bytes
    if ((size_t)bytes < (size_t)(ip_header_len + ICMP_MINLEN))
    {
        debug_print("Packet too small: %zd bytes\n", bytes);
        return 0;
    }

    struct icmp *icmp = (struct icmp *)(buffer + ip_header_len);
    debug_print("Received ICMP type: %d, code: %d from %s\n",
                icmp->icmp_type, icmp->icmp_code, inet_ntoa(recv_addr.sin_addr));

    if (icmp->icmp_type == ICMP_TIME_EXCEEDED ||
        (icmp->icmp_type == ICMP_DEST_UNREACH && icmp->icmp_code == ICMP_PORT_UNREACH))
    {
        // ICMP header + original IP header + 8 bytes of original UDP header
        const size_t min_payload_size = 8 + sizeof(struct ip) + 8; // Use size_t
        // Fix warning: Cast bytes to size_t for comparison
        if ((size_t)bytes < (size_t)(ip_header_len + min_payload_size))
        {
            debug_print("  ICMP payload too small for original headers\n");
            return 1; // Processed this packet, even if invalid
        }

        struct ip *orig_ip = (struct ip *)(buffer + ip_header_len + 8);
        int orig_ip_header_len = orig_ip->ip_hl << 2;

        // Check if enough data for original UDP header
        // Fix warning: Cast bytes to size_t for comparison
        if ((size_t)bytes < (size_t)(ip_header_len + 8 + orig_ip_header_len + sizeof(struct udphdr)))
        {
            debug_print("  Not enough data for original UDP header\n");
            return 1;
        }

        struct udphdr *orig_udp = (struct udphdr *)(buffer + ip_header_len + 8 + orig_ip_header_len);
        int orig_port = ntohs(orig_udp->uh_dport);

        // Find matching probe based on original destination port
        for (int ttl = 1; ttl <= MAX_TTL; ttl++)
        {
            for (int i = 0; i < NUM_PROBES; i++)
            {
                int idx = (ttl - 1) * NUM_PROBES + i;
                if (idx < 0 || idx >= MAX_TTL * NUM_PROBES)
                    continue; // Bounds check

                if (!probes[idx].received && probes[idx].port == orig_port)
                {
                    probes[idx].received = 1;
                    probes[idx].addr = recv_addr.sin_addr;

                    struct timeval diff;
                    timersub(&recv_time, &probes[idx].sent_time, &diff);

                    double rtt = ((double)diff.tv_sec * 1000.0) +
                                 ((double)diff.tv_usec / 1000.0);

                    if (rtt < MIN_RTT)
                        rtt = MIN_RTT;
                    else if (rtt > MAX_RTT)
                        rtt = MAX_RTT;

                    probes[idx].rtt = rtt;

                    debug_print("  Matched probe idx=%d (TTL=%d, probe=%d), rtt=%.2fms\n",
                                idx, ttl, i, rtt);
                    return 1; // Found match
                }
            }
        }
        debug_print("  No matching probe found for port %d\n", orig_port);
    }
    return 1; // Processed ICMP packet, even if not matched
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        print_help();
        return 1;
    }

    srand((unsigned int)time(NULL));
    target_host = argv[1];

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    struct hostent *host = gethostbyname(target_host);
    if (!host)
    {
        if (inet_pton(AF_INET, target_host, &dest_addr.sin_addr) <= 0)
        {
            fprintf(stderr, "Error: Could not resolve host '%s'\n", target_host);
            return 1;
        }
    }
    else
    {
        // Ensure host->h_addr_list[0] is not NULL before dereferencing
        if (host->h_addr_list && host->h_addr_list[0])
        {
            memcpy(&dest_addr.sin_addr, host->h_addr_list[0], host->h_length);
        }
        else
        {
            fprintf(stderr, "Error: Could not get address from resolved host '%s'\n", target_host);
            return 1;
        }
    }

    printf("Tracing route to %s (%s)\n",
           target_host,
           inet_ntoa(dest_addr.sin_addr));
    printf("Maximum hops: %d, Protocol: UDP\n", MAX_TTL);
    printf("TTL │ IP Address         (RTT ms)    Hostname\n");
    printf("────┼───────────────────────────────────────────\n");

    // Create sockets without SOCK_CLOEXEC initially
    send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (send_sock < 0)
    {
        perror("Error creating UDP socket");
        return 1;
    }
    // Set FD_CLOEXEC manually
    if (fcntl(send_sock, F_SETFD, FD_CLOEXEC) == -1)
    {
        perror("Warning: Failed to set FD_CLOEXEC on send socket");
        // Non-fatal, continue
    }

    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_sock < 0)
    {
        perror("Error creating ICMP socket. Are you running as root?");
        close(send_sock); // Close already opened socket
        return 1;
    }
    // Set FD_CLOEXEC manually
    if (fcntl(recv_sock, F_SETFD, FD_CLOEXEC) == -1)
    {
        perror("Warning: Failed to set FD_CLOEXEC on receive socket");
        // Non-fatal, continue
    }

    struct timeval timeout;
    timeout.tv_sec = RECV_TIMEOUT;
    timeout.tv_usec = 0;
    if (setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("Error setting receive timeout");
        close(send_sock);
        close(recv_sock);
        return 1;
    }

    memset(probes, 0, sizeof(probes));
    memset(last_probe_time, 0, sizeof(last_probe_time));

    int sndbuff = SOCKET_BUFFER_SIZE;
    int rcvbuff = SOCKET_BUFFER_SIZE;
    // Ignore errors for buffer size setting, not critical
    setsockopt(send_sock, SOL_SOCKET, SO_SNDBUF, &sndbuff, sizeof(sndbuff));
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuff, sizeof(rcvbuff));

    int next_ttl_to_print = 1;
    int current_ttl = 1;

    while (next_ttl_to_print <= MAX_TTL && !finished)
    {
        while (current_ttl <= MAX_TTL &&
               (current_ttl - next_ttl_to_print) < MAX_ACTIVE_TTLS)
        {
            debug_print("Sending probes for TTL %d\n", current_ttl);
            for (int i = 0; i < NUM_PROBES; i++)
            {
                send_probe(current_ttl, i);
                usleep(PROBE_DELAY);
            }
            gettimeofday(&last_probe_time[current_ttl - 1], NULL);
            current_ttl++;

            for (int i = 0; i < INITIAL_RESP_CHECKS; i++)
            {
                if (process_responses(WAIT_TIMEOUT_MS) < 0)
                    goto cleanup; // Handle select error
            }
        }

        for (int i = 0; i < LATER_RESP_CHECKS; i++)
        {
            if (process_responses(WAIT_TIMEOUT_MS) < 0)
                goto cleanup; // Handle select error
        }

        struct timeval now;
        gettimeofday(&now, NULL);
        int ttl = next_ttl_to_print;

        // Check if last probe time is valid before calculating elapsed time
        double time_elapsed = 0;
        if (last_probe_time[ttl - 1].tv_sec != 0 || last_probe_time[ttl - 1].tv_usec != 0)
        {
            struct timeval elapsed_diff;
            timersub(&now, &last_probe_time[ttl - 1], &elapsed_diff);
            time_elapsed = (double)elapsed_diff.tv_sec * 1000.0 + (double)elapsed_diff.tv_usec / 1000.0;
        }

        int all_received = 1;
        for (int i = 0; i < NUM_PROBES; i++)
        {
            int idx = (ttl - 1) * NUM_PROBES + i;
            if (idx < 0 || idx >= MAX_TTL * NUM_PROBES)
            {                     // Bounds check
                all_received = 0; // Should not happen if ttl is valid
                break;
            }
            if (!probes[idx].received)
            {
                all_received = 0;
                break;
            }
        }

        // Check if ready to print: all probes received OR timeout occurred after sending
        if (all_received || (time_elapsed > TTL_TIMEOUT && (last_probe_time[ttl - 1].tv_sec != 0 || last_probe_time[ttl - 1].tv_usec != 0)))
        {
            printf("%-3d │ ", ttl);

            struct in_addr hop_addrs[NUM_PROBES] = {0}; // Initialize
            double hop_rtts[NUM_PROBES] = {0.0};
            int unique_addrs = 0;
            int received_count = 0;

            for (int i = 0; i < NUM_PROBES; i++)
            {
                int idx = (ttl - 1) * NUM_PROBES + i;
                if (idx < 0 || idx >= MAX_TTL * NUM_PROBES)
                    continue; // Bounds check

                if (probes[idx].received)
                {
                    received_count++;
                    int is_unique = 1;
                    int existing_idx = -1;
                    for (int j = 0; j < unique_addrs; j++)
                    {
                        if (hop_addrs[j].s_addr == probes[idx].addr.s_addr)
                        {
                            is_unique = 0;
                            existing_idx = j;
                            break;
                        }
                    }

                    if (is_unique)
                    {
                        if (unique_addrs < NUM_PROBES)
                        { // Prevent overflow
                            hop_addrs[unique_addrs] = probes[idx].addr;
                            hop_rtts[unique_addrs] = probes[idx].rtt;
                            unique_addrs++;
                        }
                    }
                    else if (existing_idx >= 0)
                    {
                        double new_rtt = probes[idx].rtt;
                        double old_rtt = hop_rtts[existing_idx];
                        // Weighted average favoring lower RTTs
                        hop_rtts[existing_idx] = (old_rtt * 0.4 + new_rtt * 0.6);
                    }
                }
            }

            if (received_count > 0)
            {
                int first_addr_printed = 0; // Flag to track if the first IP was printed
                for (int i = 0; i < unique_addrs; i++)
                {
                    char *hostname = resolve_hostname(hop_addrs[i]);
                    if (i == 0)
                    {
                        printf("→ %-15s (%6.2f ms)", inet_ntoa(hop_addrs[i]), hop_rtts[i]);
                        first_addr_printed = 1;
                    }
                    else
                    {
                        // Indent subsequent unique IPs for the same TTL
                        printf("\n      └→ %-15s (%6.2f ms)", inet_ntoa(hop_addrs[i]), hop_rtts[i]);
                    }
                    if (hostname)
                    {
                        printf(" %s", hostname);
                        free(hostname); // Free the duplicated string
                    }
                    // Add newline after the first IP line only if there are more IPs for this TTL
                    // or if it's the only IP for this TTL. Add newline always after subsequent IPs.
                    if (i == 0 && unique_addrs > 1)
                        printf("\n");
                    else if (i > 0)
                        printf("\n");
                }
                // Handle case where probes received but somehow unique_addrs is 0
                if (unique_addrs == 0 && received_count > 0)
                {
                    printf("? ? ? (Error processing hops)\n");
                }
                else if (first_addr_printed && unique_addrs == 1)
                {
                    printf("\n"); // Ensure newline even if only one unique IP printed
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
        // Add a small sleep if no TTL was printed to prevent busy-waiting excessively
        else if (current_ttl > MAX_TTL && next_ttl_to_print <= MAX_TTL)
        {
            usleep(10000); // Sleep 10ms if waiting for final TTL timeouts
        }
    }

cleanup:
    if (send_sock >= 0)
        close(send_sock);
    if (recv_sock >= 0)
        close(recv_sock);

    return finished ? 0 : 1; // Return 0 if target reached, 1 otherwise
}
