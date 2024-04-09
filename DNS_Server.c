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
int check_packet(int fd, char** _data);

// handles the SDNS packet
int handle_request(char** _data, int fd);

// converts hostname to ip
int hostname_to_ip(char * hostname , uint32_t* ip);

// utility functions
void print_ethernet_header(struct ethhdr* hdr);
void print_ip_header(struct iphdr* hdr);
void test_res(char* res);
void clear_bits(int *num, int r);

int main(int argc, char* argv[]) {
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        perror("socket");
        exit(1);
    }

    while(1) {
        char* data;
        char** _data = &data;
        if(check_packet(sock_fd, _data) == 0) {
            // further process the SDNS packet
            handle_request(_data, sock_fd);
            fprintf(stderr, "LINE(%d) Handled Request\n", __LINE__);
            free(*_data);
        }
    }
}

int check_packet(int fd, char** _data) {
    char* buf = (char*)malloc(2048 * sizeof(char));
    recv(fd, buf, 2048, 0);

    struct ethhdr* eth = (struct ethhdr*)buf;
    struct iphdr* ip = (struct iphdr*)(buf + sizeof(struct ethhdr));
    // print_ethernet_header(eth);
    // print_ip_header(ip);

    char* data = buf + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if(ip->protocol == IPPROTO_SDNS) {
        print_ethernet_header(eth);
        print_ip_header(ip);
        struct dns_packet* dns = (struct dns_packet*)data;
        printf("ID: %d\tType: %d\tN: %d\n", dns->id, dns->type, dns->n);
        printf("SDNS packet received\n");
        *_data = data;
        return 0;
    }
    return -1;
}

int handle_request(char** _data, int fd) {
    char* data = *_data;
    test_res(data);
    struct dns_packet* req_header = (struct dns_packet*)data;

    if(req_header->type == 1) {
        // response packet
        return -1;
    }

    char* res = (char*)malloc(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct dns_packet) + ((33 * req_header->n + (8 - 1)) / 8));
    struct ethhdr* eth = (struct ethhdr*)res;
    struct iphdr* ip = (struct iphdr*)(res + sizeof(struct ethhdr));

    // construct ethernet header
    eth->h_dest[0] = 0x00; eth->h_dest[1] = 0x00; eth->h_dest[2] = 0x00; eth->h_dest[3] = 0x00; eth->h_dest[4] = 0x00; eth->h_dest[5] = 0x00;
    eth->h_source[0] = 0x00; eth->h_source[1] = 0x00; eth->h_source[2] = 0x00; eth->h_source[3] = 0x00; eth->h_source[4] = 0x00; eth->h_source[5] = 0x00;
    eth->h_proto = 8;

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

    struct dns_packet* res_header = (struct dns_packet*) (res + sizeof(struct ethhdr) + sizeof(struct iphdr));

    res_header->id = req_header->id;
    res_header->type = 1;
    res_header->n = req_header->n;

    // query
    char* ptr_req = data + sizeof(struct dns_packet);
    char* ptr_res = res + sizeof(struct dns_packet) + sizeof(struct ethhdr) + sizeof(struct iphdr);
    int offset = 0;

    fprintf(stderr, "LINE(%d): Working here\n", __LINE__);
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
    fprintf(stderr, "LINE(%d): Sending response\n", __LINE__);

    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(struct sockaddr_ll));
    dest.sll_family = AF_PACKET;
    dest.sll_protocol = 8;
    dest.sll_ifindex = if_nametoindex("lo");
    dest.sll_halen = ETH_ALEN;
    dest.sll_addr[0] = 0x00; dest.sll_addr[1] = 0x00; dest.sll_addr[2] = 0x00; dest.sll_addr[3] = 0x00; dest.sll_addr[4] = 0x00; dest.sll_addr[5] = 0x00;

    if(sendto(fd, res, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct dns_packet) + ((33 * req_header->n + (8 - 1)) / 8), 0, (struct sockaddr*) &dest, sizeof(dest)) < 0) {
        perror("send");
        exit(1);
    }
    fprintf(stderr, "LINE(%d): Response sent\n", __LINE__);
    free(res);
    fprintf(stderr, "LINE(%d): Response freed\n", __LINE__);
}

int hostname_to_ip(char * hostname , uint32_t* ip)
{
	struct hostent *he;
	struct in_addr **addr_list;
		
	if ( (he = gethostbyname( hostname ) ) == NULL) 
	{
		// get the host info
		herror("gethostbyname");
		return -1;
	}

	addr_list = (struct in_addr **) he->h_addr_list;
	
	for(int i = 0; addr_list[i] != NULL; i++) 
	{
		//Return the first one;
        *ip = addr_list[i]->s_addr;
		return EXIT_SUCCESS;
	}
	
	return 0;
}

void print_ethernet_header(struct ethhdr* hdr) {
    printf("**********Ethernet Header**********\n");
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           hdr->h_dest[0], hdr->h_dest[1], hdr->h_dest[2],
           hdr->h_dest[3], hdr->h_dest[4], hdr->h_dest[5]);
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           hdr->h_source[0], hdr->h_source[1], hdr->h_source[2],
           hdr->h_source[3], hdr->h_source[4], hdr->h_source[5]);
    printf("Protocol: %d\n", hdr->h_proto);
    printf("************************************\n");
}

void print_ip_header(struct iphdr* hdr) {
    printf("**********IP Header**********\n");
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
    printf("******************************\n");
}

void test_res(char* res) {
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
}


// clears the last r bits from right
void clear_bits(int *num, int r) {
    unsigned int mask = ~0;
    mask = (mask >> r) << r;
    *num &= mask;
}