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

// struct dns_packet {
//     uint16_t id;

//     uint8_t type : 1;   // 0 for query, 1 for response
//     uint8_t n : 3;      // number of responses or queries
// };

// int handle_request(char* data, int fd);
// void test_res(char* res);
// int hostname_to_ip(char * hostname , uint32_t* ip);
// void clear_bits(int *num, int r);
// void print_bits(int num);

// int main() {


//     char data[2048];

//     // append SDNS header
//     struct dns_packet* header = (struct dns_packet*)data;
//     header->id = 0x00;
//     header->type = 0;
//     header->n = 3;

//     // append query
//     int* ptr = (int*)(data + sizeof(struct dns_packet));
//     *ptr = 10;
//     ptr += 1;
//     char* domain = (char *)ptr;
//     strcpy(domain, "google.com");

//     ptr = (int *) (domain + strlen(domain));
//     *ptr = 12;
//     ptr += 1;
//     domain = (char *)ptr;
//     strcpy(domain, "facebook.com");

//     ptr = (int *) (domain + strlen(domain));
//     *ptr = 9;
//     ptr += 1;
//     domain = (char *)ptr;
//     strcpy(domain, "yahoo.com");

//     handle_request(data, 0);
// }

// int handle_request(char* data, int fd) {
//     struct dns_packet* req_header = (struct dns_packet*)data;

//     if(req_header->type == 1) {
//         // response packet
//         return -1;
//     }

//     char* res = (char*)malloc(sizeof(struct dns_packet) + ((33 * req_header->n + (8 - 1)) / 8));
//     struct dns_packet* res_header = (struct dns_packet*) res;

//     res_header->id = req_header->id;
//     res_header->type = 1;
//     res_header->n = req_header->n;

//     // query
//     char* ptr_req = data + sizeof(struct dns_packet);
//     char* ptr_res = res + sizeof(struct dns_packet);
//     int offset = 0;

//     for(int i = 0; i < req_header->n; ++i) {
//         int domain_len = *(int*)ptr_req;
//         ptr_req += sizeof(int);
//         char *domain = (char *)malloc(sizeof(char) * domain_len + 1);

//         for(int j = 0; j < domain_len; ++j) {
//             domain[j] = *ptr_req;
//             ptr_req++;
//         }
//         domain[domain_len] = '\0';

//         // query the domain
//         uint32_t ip;
//         int status = hostname_to_ip(domain, &ip);
//         print_bits(ip);

//         if(status == 0) {
//             // successful query
//             // now write to res
//             int curr_word = (offset) / 32; // 0 based indexing
//             int inital_bits = 32 - (offset % 32);

//             int* ptr = (int *)(ptr_res) + curr_word;
//             clear_bits(ptr, inital_bits);

//             int first_number = 1;
//             first_number = (first_number << (inital_bits - 1)) | (ip >> (32 - (inital_bits - 1)));
//             *ptr = *ptr | first_number;

//             ptr += 1;
//             *ptr = 0;
//             int second_number = (ip << (inital_bits - 1));
//             *ptr = *ptr | second_number;
//         }
//         else {
//             int curr_word = (offset) / 32; // 0 based indexing
//             int inital_bits = 32 - (offset % 32);

//             int* ptr = (int *)(ptr_res) + curr_word;
//             clear_bits(ptr, inital_bits);

//             int first_number = 0;
//             first_number = (first_number << (inital_bits - 1)) | (ip >> (32 - (inital_bits - 1)));
//             *ptr = *ptr | first_number;

//             ptr += 1;
//             *ptr = 0;
//         }

//         offset += 33;
//         free(domain);
//     }

//     // send the response
//     // send(fd, res, sizeof(struct dns_packet) + ((33 * req_header->n + (8 - 1)) / 8), 0);
//     test_res(res);
//     free(res);
// }

// void test_res(char* res) {
//     printf("Test response\n");
//     struct dns_packet* res_header = (struct dns_packet*) res;
//     printf("ID: %d\tType: %d\tN: %d\n", res_header->id, res_header->type, res_header->n);

//     char* ptr_res = res + sizeof(struct dns_packet);
//     for(int i = 0; i < res_header->n; ++i) {
//         for(int j = 0; j < 33; ++j) {
//             if(j % 8 == 1) {
//                 printf(" ");
//             }

//             int k = 33 * i + j;
//             int curr_word = k / 32;
//             int bit = k % 32;

//             int* ptr = (int *)(ptr_res) + curr_word;
//             printf("%d", (*ptr >> (31 - bit)) & 1);
            
//         }
//         printf("\n");
//     }
// }

// int hostname_to_ip(char * hostname , uint32_t* ip)
// {
// 	struct hostent *he;
// 	struct in_addr **addr_list;
		
// 	if ( (he = gethostbyname( hostname ) ) == NULL) 
// 	{
// 		// get the host info
// 		herror("gethostbyname");
// 		return -1;
// 	}

// 	addr_list = (struct in_addr **) he->h_addr_list;
	
// 	for(int i = 0; addr_list[i] != NULL; i++) 
// 	{
// 		//Return the first one;
//         *ip = addr_list[i]->s_addr;
//         printf("hostname: %s\n", hostname);
//         print_bits(*ip);
// 		// return EXIT_SUCCESS;
// 	}
	
// 	return 0;
// }

// // clears the last r bits from right
// void clear_bits(int *num, int r) {
//     unsigned int mask = ~0;
//     mask = (mask >> r) << r;
//     *num &= mask;
// }

// void print_bits(int num) {
//     for(int i = 31; i >= 0; --i) {
//         printf("%d", (num >> i) & 1);
//         if(i % 8 == 0) {
//             printf(" ");
//         }
//     }
//     printf("\n");
// }

// int hostname_to_ip(char * hostname , uint32_t* ip)
// {
// 	struct hostent *he;
// 	struct in_addr **addr_list;
		
// 	if ( (he = gethostbyname( hostname ) ) == NULL) 
// 	{
// 		// get the host info
// 		herror("gethostbyname");
// 		return -1;
// 	}

// 	addr_list = (struct in_addr **) he->h_addr_list;
	
// 	for(int i = 0; addr_list[i] != NULL; i++) 
// 	{
// 		//Return the first one;
//         *ip = addr_list[i]->s_addr;
//         printf("hostname: %s\n", hostname);
//         print_bits(*ip);
// 		// return EXIT_SUCCESS;
// 	}
	
// 	return 0;
// }

// int main() {
//     char* domain = "google.com";
//     uint32_t ip;
//     hostname_to_ip(domain, &ip);

//     for(int i = 4; i > 1; --i) {
//         int l = i * 8;
//         int r = (i - 1) * 8;

//         printf("%d.", (ip >> r) & 0xFF);
//     }
//     printf("%d\n", ip & 0xFF);
// }

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

int main() {
    char* ptr = (char*)malloc(1024);
    int nlines = 0;
    int offset = read_from_file("domains.txt", ptr, 1024, &nlines);
    if(offset == -1) {
        printf("Buffer overflow\n");
        return 1;
    }

    char* ptr_req = ptr;
    for(int i = 0; i < nlines; ++i) {
        int domain_len = *(int*)ptr_req;
        ptr_req += sizeof(int);
        char *domain = (char *)malloc(sizeof(char) * domain_len + 1);
        // printf("%d\n%s\n", domain_len, ptr_req);

        for(int j = 0; j < domain_len; ++j) {
            domain[j] = *ptr_req;
            ptr_req++;
        }
        domain[domain_len] = '\0';
        printf("Domain: %s\n", domain);
        free(domain);
    }

    free(ptr);
    return 0;
}
