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
    checks if the packet is a SDNS packet
    If so creates a copy of the packet in data
    up to user to free the data
*/
int check_packet(int fd, char** data_addr);

/*
    recieves a SDNS request packet
    sends SDNS response packet along with IP header to file descriptor fd
*/ 
int handle_request(int fd, char* data);

/*
    converts hostname to ip
    return -1 for errors
*/
int hostname_to_ip(char * hostname , uint32_t* ip);

// utility functions
void print_ip_header(struct iphdr* hdr);
void test_req(char* req);
void test_res(char* res);
void clear_bits(int *num, int r);

int main(int argc, char* argv[]) {
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

    while(1) {
        char* frame;
        if(check_packet(sock_fd, &frame) == 0) {
            // further process the SDNS packet
            char* data = frame + sizeof(struct iphdr);
            handle_request(sock_fd, data);
            free(frame);
        }
    }
}

int check_packet(int fd, char** data_addr) {
    char* buf = (char*)malloc(2048 * sizeof(char));

    if(recv(fd, buf, 2048, 0) < 0) {
        perror("recv");
        exit(1);
    }

    struct iphdr* ip = (struct iphdr*)(buf);
    struct dns_packet* dns = (struct dns_packet*)(buf + sizeof(struct iphdr));
    if(ip->protocol == IPPROTO_SDNS && dns->type == 0) {
        printf("SDNS Request packet received\n");
        print_ip_header(ip);
        *data_addr = buf;
        return 0;
    }
    return -1;
}

int handle_request(int fd, char* data) {
    test_req(data);
    struct dns_packet* req_header = (struct dns_packet*)data;

    if(req_header->type == 1) {
        // response packet
        return -1;
    }

    char* res = (char*)malloc(sizeof(struct iphdr) + sizeof(struct dns_packet) + ((33 * req_header->n + (8 - 1)) / 8));
    struct iphdr* ip = (struct iphdr*)(res);

    // construct ip header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct dns_packet) + ((33 * req_header->n + (8 - 1)) / 8);
    ip->id = 62501;
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_SDNS;
    ip->check = 0;              // doesn't really matter as the we are the ones responsible for checking it and we won't
    ip->saddr = inet_addr("127.0.0.1");
    ip->daddr = inet_addr("127.0.0.1");

    struct dns_packet* res_header = (struct dns_packet*) (res + sizeof(struct iphdr));

    res_header->id = req_header->id;
    res_header->type = 1;
    res_header->n = req_header->n;

    // query
    char* ptr_req = data + sizeof(struct dns_packet);
    char* ptr_res = res + sizeof(struct dns_packet) + sizeof(struct iphdr);
    int offset = 0;

    for(int i = 0; i < req_header->n; ++i) {
        int domain_len = *(int*)ptr_req;
        ptr_req += sizeof(int);
        char *domain = (char *)malloc(sizeof(char) * domain_len + 1);

        for(int j = 0; j < domain_len; ++j) {
            domain[j] = *ptr_req;
            ptr_req++;
        }
        domain[domain_len] = '\0';

        // query the domain
        uint32_t ip;
        int status = hostname_to_ip(domain, &ip);

        if(status == 0) {
            // successful query
            // now write to res
            int curr_word = (offset) / 32; // 0 based indexing
            int inital_bits = 32 - (offset % 32);

            int* ptr = (int *)(ptr_res) + curr_word;
            clear_bits(ptr, inital_bits);

            int first_number = 1;
            first_number = (first_number << (inital_bits - 1)) | (ip >> (32 - (inital_bits - 1)));
            *ptr = *ptr | first_number;

            ptr += 1;
            *ptr = 0;
            int second_number = (ip << (inital_bits - 1));
            *ptr = *ptr | second_number;
        }
        else {
            int curr_word = (offset) / 32; // 0 based indexing
            int inital_bits = 32 - (offset % 32);

            int* ptr = (int *)(ptr_res) + curr_word;
            clear_bits(ptr, inital_bits);

            int first_number = 0;
            first_number = (first_number << (inital_bits - 1)) | (ip >> (32 - (inital_bits - 1)));
            *ptr = *ptr | first_number;

            ptr += 1;
            *ptr = 0;
        }

        offset += 33;
        free(domain);
    }

    // send the response
    test_res((char *) res_header);

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr("127.0.0.1");

    if(sendto(fd, res, sizeof(struct iphdr) + sizeof(struct dns_packet) + ((33 * req_header->n + (8 - 1)) / 8), 0, (struct sockaddr*) &dest, sizeof(dest)) < 0) {
        perror("send");
        exit(1);
    }
    free(res);
}

int hostname_to_ip(char * hostname , uint32_t* ip) {
	struct hostent *he;
	struct in_addr **addr_list;

	if ( (he = gethostbyname( hostname ) ) == NULL)  {
		// get the host info
		herror("gethostbyname");
		return -1;
	}

	addr_list = (struct in_addr **) he->h_addr_list;
	
	for(int i = 0; addr_list[i] != NULL; i++)  {
		//Return the first one;
        *ip = addr_list[i]->s_addr;
		return EXIT_SUCCESS;
	}
	
	return 0;
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

// clears the last r bits from right
void clear_bits(int *num, int r) {
    unsigned int mask = ~0;
    mask = (mask >> r) << r;
    *num &= mask;
}