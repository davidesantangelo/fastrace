/**
 * fastrace - Blazing fast traceroute implementation with no dependencies
 * 
 * Compiles with: gcc -O3 -o fastrace fastrace.c
 * Run with: sudo ./fastrace [target]
 */

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
 
 /* Define ICMP constants if not available in system headers */
 #ifndef ICMP_TIME_EXCEEDED
 #define ICMP_TIME_EXCEEDED 11
 #endif
 #ifndef ICMP_DEST_UNREACH
 #define ICMP_DEST_UNREACH 3
 #endif
 #ifndef ICMP_PORT_UNREACH
 #define ICMP_PORT_UNREACH 3
 #endif
 
 /* Configuration */
 #define MAX_TTL 30          /* Maximum number of hops */
 #define PACKET_SIZE 60      /* Size of packet to send */
 #define NUM_PROBES 3        /* Number of probes per TTL */
 #define RECV_TIMEOUT 5      /* Socket receive timeout in seconds */
 #define MAX_ACTIVE_TTLS 5   /* Maximum number of TTLs probed concurrently */
 #define DEBUG 0             /* Set to 1 to enable debug output */
 #define WAIT_TIMEOUT_MS 50  /* Moderate timeout for better responsiveness */
 #define TTL_TIMEOUT 5000    /* Timeout per TTL in ms */
 #define BASE_PORT 33434     /* Starting UDP port for probes */
 
 /* Probe tracking */
 typedef struct {
     int ttl;
     int probe;
     struct timeval sent_time;
     int received;
     struct in_addr addr;
     double rtt;
     int port;              /* UDP port used for this probe */
 } probe_t;
 
 /* Global variables */
 int send_sock = -1;         /* Socket for sending UDP packets */
 int recv_sock = -1;         /* Socket for receiving ICMP responses */
 char target_host[256];
 struct sockaddr_in dest_addr;
 int finished = 0;
 probe_t probes[MAX_TTL * NUM_PROBES];
 struct timeval last_probe_time[MAX_TTL]; /* Time when last probe for each TTL was sent */
 
 /* Function prototypes */
 void cleanup(void);
 void handle_signal(int sig);
 void send_probe(int ttl, int probe_num);
 int process_responses(int timeout_ms);
 char *resolve_hostname(struct in_addr addr);
 void print_help(void);
 void debug_print(const char *fmt, ...);
 
 int main(int argc, char *argv[]) {
     /* Check arguments */
     if (argc != 2) {
         print_help();
         return 1;
     }
     
     /* Save target hostname */
     strncpy(target_host, argv[1], sizeof(target_host) - 1);
     target_host[sizeof(target_host) - 1] = '\0';
     
     /* Setup signal handlers */
     signal(SIGINT, handle_signal);
     
     /* Setup destination address */
     memset(&dest_addr, 0, sizeof(dest_addr));
     dest_addr.sin_family = AF_INET;
     
     /* Try to resolve hostname to IP */
     struct hostent *host = gethostbyname(target_host);
     if (!host) {
         if (inet_pton(AF_INET, target_host, &dest_addr.sin_addr) <= 0) {
             fprintf(stderr, "Error: Could not resolve host '%s'\n", target_host);
             return 1;
         }
     } else {
         memcpy(&dest_addr.sin_addr, host->h_addr_list[0], host->h_length);
     }
     
     printf("Tracing route to %s (%s)\n", 
            target_host, 
            inet_ntoa(dest_addr.sin_addr));
     printf("Maximum hops: %d, Protocol: UDP\n", MAX_TTL);
     printf("TTL │ IP Address         (RTT ms)    Hostname\n");
     printf("────┼───────────────────────────────────────────\n");
     
     /* Create UDP socket for sending packets */
     send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
     if (send_sock < 0) {
         perror("Error creating UDP socket");
         return 1;
     }
     
     /* Create raw ICMP socket for receiving responses */
     recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
     if (recv_sock < 0) {
         perror("Error creating ICMP socket. Are you running as root?");
         cleanup();
         return 1;
     }
     
     /* Set receive timeout */
     struct timeval timeout;
     timeout.tv_sec = RECV_TIMEOUT;
     timeout.tv_usec = 0;
     if (setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
         perror("Error setting receive timeout");
         cleanup();
         return 1;
     }
     
     /* Initialize probes array and last_probe_time */
     memset(probes, 0, sizeof(probes));
     memset(last_probe_time, 0, sizeof(last_probe_time));
     
     /* Start traceroute with concurrent TTL probing */
     int next_ttl_to_print = 1;  /* Next TTL to display results for */
     int current_ttl = 1;        /* Next TTL to start probing */
 
     while (next_ttl_to_print <= MAX_TTL && !finished) {
         /* Send probes for up to MAX_ACTIVE_TTLS TTLs */
         while (current_ttl <= MAX_TTL && 
                (current_ttl - next_ttl_to_print) < MAX_ACTIVE_TTLS) {
             debug_print("Sending probes for TTL %d\n", current_ttl);
             for (int i = 0; i < NUM_PROBES; i++) {
                 send_probe(current_ttl, i);
                 usleep(50000); // 50ms between probes
             }
             /* Record time after sending all probes for this TTL */
             gettimeofday(&last_probe_time[current_ttl - 1], NULL);
             current_ttl++;
         }
         
         /* Process responses in a tight loop */
         for (int i = 0; i < 10; i++) {
             process_responses(WAIT_TIMEOUT_MS);
         }
         
         /* Check if we can print the next TTL */
         struct timeval now;
         gettimeofday(&now, NULL);
         int ttl = next_ttl_to_print;
         double time_elapsed = (now.tv_sec - last_probe_time[ttl - 1].tv_sec) * 1000.0 +
                              (now.tv_usec - last_probe_time[ttl - 1].tv_usec) / 1000.0;
         
         int all_received = 1;
         for (int i = 0; i < NUM_PROBES; i++) {
             int idx = (ttl - 1) * NUM_PROBES + i;
             if (!probes[idx].received) {
                 all_received = 0;
                 break;
             }
         }
         
         /* Print result if all probes received or timeout exceeded */
         if (all_received || (time_elapsed > TTL_TIMEOUT && last_probe_time[ttl - 1].tv_sec != 0)) {
             printf("%-3d │ ", ttl);  // Added space after vertical bar
             
             struct in_addr hop_addr = {0};
             double total_rtt = 0;
             int count = 0;
             struct in_addr hop_addrs[NUM_PROBES];
             double hop_rtts[NUM_PROBES];
             int unique_addrs = 0;
             
             // Collect unique addresses and RTTs
             for (int i = 0; i < NUM_PROBES; i++) {
                 int idx = (ttl - 1) * NUM_PROBES + i;
                 if (probes[idx].received) {
                     int is_unique = 1;
                     int existing_idx = -1;
                     for (int j = 0; j < unique_addrs; j++) {
                         if (hop_addrs[j].s_addr == probes[idx].addr.s_addr) {
                             is_unique = 0;
                             existing_idx = j;
                             break;
                         }
                     }
                     if (is_unique) {
                         hop_addrs[unique_addrs] = probes[idx].addr;
                         hop_rtts[unique_addrs] = probes[idx].rtt;
                         unique_addrs++;
                     } else if (existing_idx >= 0) {
                         // Average RTTs for same IP
                         hop_rtts[existing_idx] = (hop_rtts[existing_idx] + probes[idx].rtt) / 2;
                     }
                     
                     if (hop_addr.s_addr == 0) hop_addr = probes[idx].addr;
                     total_rtt += probes[idx].rtt;
                     count++;
                 }
             }
             
             if (count > 0) {
                 // Print first address with hostname
                 char *hostname = resolve_hostname(hop_addrs[0]);
                 // Add a space after the arrow for better alignment
                 printf("→ %-15s (%6.2f ms)", inet_ntoa(hop_addrs[0]), hop_rtts[0]);
                 if (hostname) {
                     printf(" %s", hostname);
                     free(hostname);
                 }
                 printf("\n");
                 
                 // Print additional addresses if any
                 for (int i = 1; i < unique_addrs; i++) {
                     // Use simpler arrow character with consistent spacing
                     printf("      └→ %-15s (%6.2f ms)", inet_ntoa(hop_addrs[i]), hop_rtts[i]);
                     char *alt_hostname = resolve_hostname(hop_addrs[i]);
                     if (alt_hostname) {
                         printf(" %s", alt_hostname);
                         free(alt_hostname);
                     }
                     printf("\n");
                 }
                 
                 /* Check if target reached */
                 if (hop_addr.s_addr == dest_addr.sin_addr.s_addr) {
                     finished = 1;
                 }
             } else {
                 printf("* * * (timeout)\n");
             }
             next_ttl_to_print++;
         }
     }
     
     cleanup();
     return 0;
 }
 
 /* Unchanged functions below */
 void cleanup(void) {
     if (send_sock >= 0) {
         close(send_sock);
         send_sock = -1;
     }
     if (recv_sock >= 0) {
         close(recv_sock);
         recv_sock = -1;
     }
 }
 
 void handle_signal(int sig) {
     if (sig == SIGINT) {
         printf("\nTraceroute interrupted.\n");
         finished = 1;
         cleanup();
         exit(0);
     }
 }
 
 void send_probe(int ttl, int probe_num) {
     if (setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
         perror("Error setting TTL");
         return;
     }
     
     int port = BASE_PORT + (ttl * NUM_PROBES) + probe_num;
     struct sockaddr_in probe_dest = dest_addr;
     probe_dest.sin_port = htons(port);
     
     char payload[PACKET_SIZE];
     memset(payload, 0, sizeof(payload));
     struct timeval tv;
     gettimeofday(&tv, NULL);
     memcpy(payload, &tv, sizeof(tv));
     for (int i = sizeof(tv); i < sizeof(payload); i++) {
         payload[i] = rand() % 256;
     }
     
     if (sendto(send_sock, payload, sizeof(payload), 0, 
                (struct sockaddr *)&probe_dest, sizeof(probe_dest)) < 0) {
         perror("Error sending packet");
         return;
     }
     
     int idx = (ttl - 1) * NUM_PROBES + probe_num;
     if (idx < MAX_TTL * NUM_PROBES) {
         probes[idx].ttl = ttl;
         probes[idx].probe = probe_num;
         probes[idx].port = port;
         gettimeofday(&probes[idx].sent_time, NULL);
         probes[idx].received = 0;
     }
 }
 
 int process_responses(int timeout_ms) {
     fd_set readfds;
     FD_ZERO(&readfds);
     FD_SET(recv_sock, &readfds);
     
     struct timeval timeout;
     timeout.tv_sec = timeout_ms / 1000;
     timeout.tv_usec = (timeout_ms % 1000) * 1000;
     
     int ret = select(recv_sock + 1, &readfds, NULL, NULL, &timeout);
     if (ret <= 0) return ret;
     
     char buffer[1500];
     struct sockaddr_in recv_addr;
     socklen_t addr_len = sizeof(recv_addr);
     
     int bytes = recvfrom(recv_sock, buffer, sizeof(buffer), 0, 
                         (struct sockaddr *)&recv_addr, &addr_len);
     if (bytes <= 0) return 0;
     
     struct timeval recv_time;
     gettimeofday(&recv_time, NULL);
     
     struct ip *ip = (struct ip *)buffer;
     int ip_header_len = ip->ip_hl << 2;
     if (bytes < ip_header_len + ICMP_MINLEN) {
         debug_print("Packet too small: %d bytes\n", bytes);
         return 0;
     }
     
     struct icmp *icmp = (struct icmp *)(buffer + ip_header_len);
     debug_print("Received ICMP type: %d, code: %d from %s\n", 
                icmp->icmp_type, icmp->icmp_code, inet_ntoa(recv_addr.sin_addr));
     
     if (icmp->icmp_type == ICMP_TIME_EXCEEDED || 
         (icmp->icmp_type == ICMP_DEST_UNREACH && icmp->icmp_code == ICMP_PORT_UNREACH)) {
         struct ip *orig_ip = (struct ip *)(buffer + ip_header_len + 8);
         int orig_ip_header_len = orig_ip->ip_hl << 2;
         
         if (bytes < ip_header_len + 8 + orig_ip_header_len + 8) {
             debug_print("  Not enough data for original header\n");
             return 1;
         }
         
         struct udphdr *orig_udp = (struct udphdr *)(buffer + ip_header_len + 8 + orig_ip_header_len);
         int orig_port = ntohs(orig_udp->uh_dport);
         
         for (int ttl = 1; ttl <= MAX_TTL; ttl++) {
             for (int i = 0; i < NUM_PROBES; i++) {
                 int idx = (ttl - 1) * NUM_PROBES + i;
                 if (idx >= MAX_TTL * NUM_PROBES) continue;
                 
                 if (!probes[idx].received && probes[idx].port == orig_port) {
                     probes[idx].received = 1;
                     probes[idx].addr = recv_addr.sin_addr;
                     double rtt = (recv_time.tv_sec - probes[idx].sent_time.tv_sec) * 1000.0 +
                                 (recv_time.tv_usec - probes[idx].sent_time.tv_usec) / 1000.0;
                     probes[idx].rtt = rtt;
                     debug_print("  Matched probe idx=%d (TTL=%d, probe=%d), rtt=%.2fms\n", 
                                idx, ttl, i, rtt);
                     return 1;
                 }
             }
         }
     }
     return 1;
 }
 
 void debug_print(const char *fmt, ...) {
     if (!DEBUG) return;
     va_list args;
     va_start(args, fmt);
     vfprintf(stderr, fmt, args);
     va_end(args);
 }
 
 char *resolve_hostname(struct in_addr addr) {
     struct hostent *host = gethostbyaddr(&addr, sizeof(addr), AF_INET);
     if (host && host->h_name) return strdup(host->h_name);
     return NULL;
 }
 
 void print_help(void) {
     printf("Usage: sudo ./fastrace <target>\n");
     printf("\nOptions:\n");
     printf("  <target>    Target hostname or IP address\n");
     printf("\nExample:\n");
     printf("  sudo ./fastrace google.com\n");
 }