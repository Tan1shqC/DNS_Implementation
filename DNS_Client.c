#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <sys/types.h>
#include <errno.h>

#define IPPROTO_SDNS 254

struct dns_packet {
    uint16_t id;

    uint8_t type : 1;   // 0 for query, 1 for response
    uint8_t n : 3;      // number of responses or queries

    /* 
        if query then after the struct there will n variable length bits
        each one be a integer describing the length of the domain name
        followed by the domain name
    */

    /*
        if response then after the struct there will be n 33 bits.
        first bit describing wether query was successful
        following 32 bits describing ip addresses for query
    */
};

int main() {
    int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_SDNS);
    if (sock_fd < 0) {
        perror("socket");
        exit(1);
    }
    int hdrincl_opt = 1;
    if (setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &hdrincl_opt, sizeof(hdrincl_opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr("127.0.0.1");


    char data[2048];

    // construct ip header
    struct iphdr* ip = (struct iphdr*)data;
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct dns_packet) + (10 + 4) + (12 + 4) + (9 + 4);
    ip->id = 62500;
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_SDNS;
    ip->check = 0;
    ip->saddr = inet_addr("127.0.0.1"); 
    ip->daddr = inet_addr("127.0.0.1");


    // append SDNS header
    struct dns_packet* header = (struct dns_packet*)(data + sizeof(struct iphdr));
    header->id = 0x00;
    header->type = 0;
    header->n = 3;

    // append query
    int* ptr = (int*)(data + sizeof(struct dns_packet) + sizeof(struct iphdr));
    *ptr = 10;
    ptr += 1;
    char* domain = (char *)ptr;
    strcpy(domain, "google.com");

    ptr = (int *) (domain + strlen(domain));
    *ptr = 12;
    ptr += 1;
    domain = (char *)ptr;
    strcpy(domain, "facebook.com");

    ptr = (int *) (domain + strlen(domain));
    *ptr = 9;
    ptr += 1;
    domain = (char *)ptr;
    strcpy(domain, "yahoo.com");

    fprintf(stderr, "Sending packet of length %d\n", ip->tot_len);
    if(sendto(sock_fd, data, ip->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        exit(1);
    }
    fprintf(stderr, "Errno: %d\n", errno);
    fprintf(stderr, "Packet sent\n");

    char Res[2048];
    while(1) {
        fprintf(stderr, "Waiting for response\n");
        recv(sock_fd, Res, 2048, 0);
        fprintf(stderr, "Response received\n");

        // remove ip header
        struct iphdr* ip = (struct iphdr*)Res;

        // log ip header
        fprintf(stderr, "************************************\n");
        fprintf(stderr, "IP Header\n");
        fprintf(stderr, "Version: %d\n", ip->version);
        fprintf(stderr, "IHL: %d\n", ip->ihl);
        fprintf(stderr, "TOS: %d\n", ip->tos);
        fprintf(stderr, "Total Length: %d\n", ip->tot_len);
        fprintf(stderr, "ID: %d\n", ip->id);
        fprintf(stderr, "Frag Offset: %d\n", ip->frag_off);
        fprintf(stderr, "TTL: %d\n", ip->ttl);
        fprintf(stderr, "Protocol: %d\n", ip->protocol);
        fprintf(stderr, "Checksum: %d\n", ip->check);
        fprintf(stderr, "Source IP: %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr));
        fprintf(stderr, "Destination IP: %s\n", inet_ntoa(*(struct in_addr*)&ip->daddr));
        fprintf(stderr, "************************************\n");

        if(ip->protocol == IPPROTO_SDNS) {
            char* res = Res + sizeof(struct iphdr);
            // print the response
            printf("Test response\n");
            struct dns_packet* res_header = (struct dns_packet*) res;
            printf("ID: %d\tType: %d\tN: %d\n", res_header->id, res_header->type, res_header->n);

            char* ptr_res = res + sizeof(struct dns_packet);
            for(int i = 0; i < res_header->n; ++i) {
                for(int j = 0; j < 33; ++j) {
                    if(j % 8 == 1) {
                        printf(" ");
                    }

                    int k = 33 * i + j;
                    int curr_word = k / 32;
                    int bit = k % 32;

                    int* ptr = (int *)(ptr_res) + curr_word;
                    printf("%d", (*ptr >> (31 - bit)) & 1);
                    
                }
                printf("\n");
            }
            // break;
        }
        else {
            fprintf(stderr, "Received From IP: %s", inet_ntoa(*(struct in_addr*)&ip->saddr));
        }
    }
    // recv(sock_fd, res, 2048, 0);
}