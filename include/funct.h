
// CONSTANTS
// values for ethertypes
#define IPv4 0x0800
#define ARP 0x0806

// max size for the route table
#define ROUTE_TABLE_SIZE 100000
#define ARP_TABLE_SIZE 100 // maybe modify

#define MAC_ADDR_SIZE 6 * sizeof(uint8_t)
// END CONSTANTS

#ifndef _FUNCT_H_
#define _FUNCT_H_

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "trie.h"

// define structure for queue
struct queue_data {
    int interface;
    int len;
    char *data;
};

// the root node of the tree
extern struct node *trie;

// function used to sort the route table
extern int compareTo(const void *a, const void *b);
extern struct route_table_entry* LPM(size_t route_table_size,
                                     uint32_t ip_addr);

// function that sends an ICMP package
extern int send_ICMP(char *data, int type, int code, size_t data_len);

// 
/*
 * function that checks if the router is the final destination
 *  return 1 if true
*/
extern int check_dest(uint32_t daddr);

/*
 * function that searches in the arp table for the mac address
 * returns NULL if it isn t in the table
 */
extern struct arp_table_entry *find_mac_address(struct arp_table_entry *arp_table, 
                                                size_t arp_table_size, 
                                                uint32_t ip_addr);

// function that creates and sends an ARP request
extern int send_ARP_request(char *data, size_t len, uint32_t target_ip, 
                    int interface, uint32_t source_ip);

// function that checks if an ARP request is for this router 
extern void for_router_ARP(uint8_t *mac_dest, uint32_t ip_dest);

// function that adds an element into the arp cache
extern struct arp_table_entry *add_into_arp_table(struct arp_table_entry *arp_table,
                                                    u_int32_t *arp_table_size,
                                                    struct arp_table_entry entry);

#endif /* _FUNCT_H_ */
