#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

// DNS header structure
struct dns_header {
    uint16_t id;        // Identification number
    uint16_t flags;     // DNS flags
    uint16_t qdcount;   // Question count
    uint16_t ancount;   // Answer count
    uint16_t nscount;   // Authority count
    uint16_t arcount;   // Additional count
};

int craft_dns_buffer(char* buffer, uint sz, const char* query) {
    struct dns_header *dns = (struct dns_header *)buffer;
    memset(buffer, 0, sz);

    // Fill DNS header
    dns->id = htons(1234);           // Random ID
    dns->flags = htons(0x0100);      // Standard query
    dns->qdcount = htons(1);         // One question
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    // Add question section
    char *qname = (char *)&buffer[sizeof(struct dns_header)];

    // Convert domain name to DNS format
    int idx = 0;
    const char *label = query;
    while (*label) {
        int len = 0;
        while (label[len] && label[len] != '.') len++;
        qname[idx++] = len;
        memcpy(&qname[idx], label, len);
        idx += len;
        label += len;
        if (*label == '.') label++;
    }
    qname[idx++] = 0;  // Terminal length byte

    // Add QTYPE and QCLASS
    uint16_t *qtype = (uint16_t *)&buffer[sizeof(struct dns_header) + idx];
    *qtype = htons(1);    // A record
    uint16_t *qclass = (uint16_t *)&buffer[sizeof(struct dns_header) + idx + 2];
    *qclass = htons(1);   // IN class

    int total_len = sizeof(struct dns_header) + idx + 4;
    return total_len;
}

uint64_t test_udp_latency(int nbruns, int ommit, char *addr, int port, const char* query) {
    int sock_dest, sock_send;
    struct sockaddr_in addr_dest;
    char sendbuffer[1024];
    char recvbuffer[1024];
    struct timespec start, end;
    uint64_t *results;
    uint64_t min, max, avg;

    uint dns_len = craft_dns_buffer(sendbuffer, sizeof(sendbuffer), query);
    
    // Create two UDP sockets
    sock_dest = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sock_send = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_dest < 0 || sock_send < 0) {
        perror("socket");
        return (0);
    }

    // Setup first socket address
    memset(&addr_dest, 0, sizeof(addr_dest));
    addr_dest.sin_family = AF_INET;
    if (addr != NULL) {
        addr_dest.sin_addr.s_addr = inet_addr(addr);
    } else {
        addr_dest.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    addr_dest.sin_port = htons(port);

    // Bind first socket
    if (bind(sock_dest, (struct sockaddr*)&addr_dest, sizeof(addr_dest)) < 0) {
        close(sock_dest);
        close(sock_send);
        perror("bind");
        return (0);
    }

    // Connect second socket to first
    if (connect(sock_send, (struct sockaddr*)&addr_dest, sizeof(addr_dest)) < 0) {
        close(sock_dest);
        close(sock_send);
        perror("connec");
        return (0);
    }

    results = malloc(sizeof(*results) * (nbruns - ommit));
    if (results == NULL) {
        close(sock_dest);
        close(sock_send);
        perror("malloc");
        return (0);
    }

    max = avg = 0;
    min = UINT64_MAX;
    for (int i = 0; i < nbruns; i++) {

        // Get start time
        if (clock_gettime(CLOCK_MONOTONIC_RAW, &start) < 0) {
            close(sock_dest);
            close(sock_send);
            perror("clock_gettime start");
            return (0);
        }

        // Send message from socket2
        if (send(sock_send, sendbuffer, dns_len, 0) < 0) {
            close(sock_dest);
            close(sock_send);
            perror("send");
            return (0);
        }

        // Get end time
        if (clock_gettime(CLOCK_MONOTONIC_RAW, &end) < 0) {
            close(sock_dest);
            close(sock_send);
            perror("clock_gettime end");
            return (0);
        }

        // Receive on socket1
        int ret = recvfrom(sock_dest, recvbuffer, sizeof(recvbuffer), 0, NULL, NULL);
        if (ret < 0) {
            close(sock_dest);
            close(sock_send);
            perror("recvfrom");
            return (0);
        }

        if (i >= ommit) {
            // Calculate time difference in nanoseconds
            results[i - ommit] = (end.tv_sec - start.tv_sec) * 1000000000ULL +
                (end.tv_nsec - start.tv_nsec);
            // update min and max results
            if (results[i - ommit] < min) {
                min = results[i - ommit];
            }
            if (results[i - ommit] > max) {
                max = results[i - ommit];
            }
            avg += results[i - ommit];
        }
    }

    close(sock_dest);
    close(sock_send);

    avg /= (nbruns - ommit);
    printf("latency min: %lu\n", min);
    printf("latency max: %lu\n", max);
    return avg;
}

int main(int ac, char** av) {
    /* long latency = test_udp_latency(4096*4096, 4096*32, 4679, "perdu.com"); */

    long latency = test_udp_latency(1, 0, NULL, 53, "perdu.com");
    if (latency == 0) {
        fprintf(stderr, "error");
        return (-1);
    }
    printf("Average latency: %lu\n", latency);
    return (0);
}
