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
#include <linux/if_packet.h>
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

/*
    Return total bytes written into ptr
    -1 for errors
*/
int read_from_file(const char* filepath, char* ptr, size_t size, int* nlines);

// utility functions
void print_ip_header(struct iphdr* hdr);
void test_req(char* req);
void test_res(char* res);

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

    // append query
    char* ptr = data + sizeof(struct dns_packet) + sizeof(struct iphdr);
    int nlines = 0;
    read_from_file("domains.txt", ptr, 2048, &nlines);
    header->n = nlines;

    test_req((char*) header);
    if(sendto(sock_fd, data, ip->tot_len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        exit(1);
    }

    char Res[2048];
    while(1) {
        recv(sock_fd, Res, 2048, 0);

        // remove ip header
        struct iphdr* ip = (struct iphdr*)Res;
        print_ip_header(ip);

        if(ip->protocol == IPPROTO_SDNS) {

            char* res = Res + sizeof(struct iphdr);
            // print the response
            struct dns_packet* res_header = (struct dns_packet*) res;
            if(res_header->type == 1 && res_header->id == header->id) {
                test_res(res);
                break;
            }
        }
    }
}

int read_from_file(const char* filepath, char* ptr, size_t size, int* nlines) {
    FILE* file = fopen(filepath, "r");
    if(file == NULL) {
        perror("fopen");
        return -1;
    }

    // read line by line until EOF or bytes read exceed size
    int offset = 0;
    char line[64];

    while(fgets(line, sizeof(line), file) != NULL) {
        int line_len = strlen(line);

        if(line[line_len - 1] == '\n') {
            line[line_len - 1] = '\0'; // remove newline character
            line_len -= 1;
        }

        if(line_len + sizeof(int) > (size - 1) - offset + 1) {
            return -1;
        }

        *(int*)(ptr) = line_len; // append length of line at the end
        ptr += sizeof(int);

        for(int i = 0; i < line_len; ++i) {
            *ptr = line[i];
            ptr++;
        }

        offset += line_len + sizeof(int);
        *nlines += 1;
    }

    return offset;
}

void print_ip_header(struct iphdr* hdr) {
    printf("**********IP Header**********\n\n");
    printf("Version: %d\n", hdr->version);
    printf("IHL: %d\n", hdr->ihl);
    printf("TOS: %d\n", hdr->tos);
    printf("Total Length: %d\n", hdr->tot_len);
    printf("Identification: %d\n", hdr->id);
    printf("Fragment Offset: %d\n", hdr->frag_off);
    printf("TTL: %d\n", hdr->ttl);
    printf("Protocol: %d\n", hdr->protocol);
    printf("Checksum: %d\n", hdr->check);
    printf("Source IP: %s\n", inet_ntoa(*(struct in_addr*)&hdr->saddr));
    printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr*)&hdr->daddr));
    printf("\n******************************\n");
}

void test_res(char* res) {
    printf("*****SDNS Response Packet*****\n\n");
    struct dns_packet* res_header = (struct dns_packet*) res;
    fprintf(stderr, "ID: %d\nType: %d\nN: %d\n\n", res_header->id, res_header->type, res_header->n);

    char* ptr_res = res + sizeof(struct dns_packet);
    for(int i = 0; i < res_header->n; ++i) {
        uint32_t num = 0;
        for(int j = 0; j < 33; ++j) {
            if(j % 8 == 1) {
                printf(" ");
            }

            int k = 33 * i + j;
            int curr_word = k / 32;
            int bit = k % 32;

            int* ptr = (int *)(ptr_res) + curr_word;
            printf("%d", (*ptr >> (31 - bit)) & 1);
            if(j != 0) {
                num = (num << 1) | ((*ptr >> (31 - bit)) & 1);
            }
        }
        printf("\t%d.%d.%d.%d\n", num >> 24, (num >> 16) & 255, (num >> 8) & 255, num & 255);
        printf("\n");
    }
    printf("******************************\n");
}

void test_req(char* req) {
    printf("******SDNS Request packet******\n\n");
    struct dns_packet* req_header = (struct dns_packet*)req;
    printf("ID: %d\nType: %d\nN: %d\n\n", req_header->id, req_header->type, req_header->n);

    char* ptr_req = req + sizeof(struct dns_packet);
    for(int i = 0; i < req_header->n; ++i) {
        int domain_len = *(int*)ptr_req;
        ptr_req += sizeof(int);
        char *domain = (char *)malloc(sizeof(char) * domain_len + 1);

        for(int j = 0; j < domain_len; ++j) {
            domain[j] = *ptr_req;
            ptr_req++;
        }
        domain[domain_len] = '\0';
        printf("Domain: %s\n", domain);
        free(domain);
    }
    printf("\n******************************\n");
}