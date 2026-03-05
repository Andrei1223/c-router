#include "funct.h"
#include <stdlib.h>

// route table of the router
extern struct route_table_entry *route_table;
extern unsigned int route_table_size;

// function that is passed to qsort
int compareTo(const void *a, const void *b)
{
    struct route_table_entry rtable1 = *((struct route_table_entry *) a);
    struct route_table_entry rtable2 = *((struct route_table_entry *) b);

    // check for the prefix with the bigger value
    if (rtable1.prefix == rtable2.prefix) {
        // sort by mask length
        return ntohl(rtable1.mask) - ntohl(rtable2.mask); // the ip addresses are reversed
    }

    return ntohl(rtable1.prefix) - ntohl(rtable2.prefix);
}

// converts a string into an ipv4 addr
uint32_t string2ip(char *string)
{
    uint32_t ip = 0;
    char *p;

    p = strtok(string, " .");
	int i = 0;
	while (p != NULL) {
		if (i < 4)
		    *(((unsigned char *)&ip)  + i % 4) = (unsigned char)atoi(p);

		p = strtok(NULL, " .");
		i++;
	}

    return ip;
}

// returns '1' if the daddr is one of the router s
int check_dest(uint32_t daddr)
{
    int i;

    for (i = 0; i < ROUTER_NUM_INTERFACES; i++) {
        uint32_t my_ip = string2ip(get_interface_ip(i));

        printf("interface %d ip %s\n\n", i, get_interface_ip(i));

        if (my_ip == daddr)
            return 1; // true
    }

    return 0; // false
}

// function that performs LPM on the route table
struct route_table_entry* LPM(size_t route_table_size,
                              uint32_t ip_addr)
{
    return search_entry(trie, ip_addr);
}


// function thath copies the data for an ICMP err response
void ICMP_err_payload(char *data, char *copy_to, int type, size_t *len)
{
    if (type != 11 && type != 3) {
        printf("ICMP response unsupported type: %d\n\n", type);
        return ;
    }
    *len = 0;

    // copy the old IPv4 header
    memcpy(copy_to, data, sizeof(struct iphdr));

    *len += sizeof(struct iphdr);

    // copy the first 64 bits after the ipv4 header
    memcpy(copy_to + sizeof(struct iphdr), data + sizeof(struct iphdr), 8 * sizeof(uint8_t));

    *len += 8 * sizeof(uint8_t);
}

// function that sends an ICMP header
int send_ICMP(char *data, int type, int code, size_t data_len)
{
    struct ether_header *eth_hdr = (struct ether_header *) data;
    char icmp_err_data[MAX_PACKET_LEN];
    size_t icmp_err_data_len = 0;

    // reverse the mac addresses
    uint8_t aux_mac[6];

    // swap the mac addresses
    memcpy(aux_mac, eth_hdr->ether_dhost, MAC_ADDR_SIZE);
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_ADDR_SIZE);
    memcpy(eth_hdr->ether_shost, aux_mac, MAC_ADDR_SIZE);

    // get the ipv4 header
    struct iphdr *ip_hdr = (struct iphdr *)(data + sizeof(struct ether_header));

    // search in the route table for the souce addr
    struct route_table_entry *entry = LPM(route_table_size, ip_hdr->saddr);

    if (entry == NULL) {
        printf("No return route found.\n\n");
        return -1;
    }

    if (type != 8) {
        // get the data after the IPv4 header
        ICMP_err_payload((char *)ip_hdr, icmp_err_data, type, &icmp_err_data_len);

        // update the total length of the packet
        data_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)
                 + sizeof(struct iphdr) + 8 * sizeof(uint8_t);

        // update the total length for the IPv4 packet
        ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) 
                        + sizeof(struct iphdr) + 8 * sizeof(uint8_t));
    }

    // swap the ip addresses
    ip_hdr->daddr = ip_hdr->saddr;

    // the srting2ip return in hton format
    ip_hdr->saddr = string2ip(get_interface_ip(entry->interface));

    // reset the TTL field
    ip_hdr->ttl = 64;

    ip_hdr->protocol = 1;

    // recompute the checksum
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));


    // echo request message
    if (type == 8 && code == 0) {
        // get the ICMP header
        struct icmphdr *icmp_hdr = (struct icmphdr *)(data + sizeof(struct ether_header) 
                                                        + sizeof(struct iphdr));

        // change the type of the icmp file
        icmp_hdr->type = 0;// echo reply 

        // recompute checksum for icmp header
        icmp_hdr->checksum = 0;
        icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

    } // destination unreachable
    else if (code == 0) {
        // make the icmp header
        struct icmphdr icmp_hdr;
        memset(&icmp_hdr, 0, sizeof(struct icmphdr));
        
        icmp_hdr.type = type;
        icmp_hdr.code = code;

        // address after the ipv4 header
        char *ptr = data + sizeof(struct ether_header) + sizeof(struct iphdr);

        // copy the ICMP header
        memcpy(ptr, &icmp_hdr, sizeof(struct icmphdr));

        // copy the old ipv4 header and the 64 bits
        memcpy(ptr + sizeof(struct icmphdr), icmp_err_data, icmp_err_data_len); 

        // compute the checksum for the icmp header with the data at the end
        struct icmphdr *aux_ptr = (struct icmphdr *)ptr;
        aux_ptr->checksum = htons(checksum((uint16_t *)ptr, sizeof(struct icmphdr) + icmp_err_data_len));
    }
    else {
        printf("Unsupported ICMP code: %d\n\n", code);
        return -1;
    }

    // send the data buffer
    send_to_link(entry->interface, data, data_len);
    return 1;
}

// return a pointer to the entry that has the certain ip addr or NULL
struct arp_table_entry *find_mac_address(struct arp_table_entry *arp_table, 
                                        size_t arp_table_size, 
                                        uint32_t ip_addr)
{
    int i;

    // search the table
    for (i = 0; i < arp_table_size; i++) {
        if (ip_addr == arp_table[i].ip)
            return &arp_table[i];
    }

    return NULL;
}

// function that adds an element into the arp table
struct arp_table_entry *add_into_arp_table(struct arp_table_entry *arp_table,
                        u_int32_t *arp_table_size,
                        struct arp_table_entry entry)
{

    // check if the total size has been reached
    if (*arp_table_size == ARP_TABLE_SIZE) {
        printf("ARP table max size reached\n\n");
        return NULL;
    }

    arp_table[*arp_table_size] = entry;

    *arp_table_size += 1;

    return arp_table;
}

// function that broadcasts an ARP packet
int send_ARP_request(char *data, size_t len, uint32_t target_ip, int interface, uint32_t source_ip)
{
    // moke the ethernet header
    struct ether_header *eth_hdr = (struct ether_header *)data;

    // set the type
    eth_hdr->ether_type = htons(ARP);

    // the source mac address is already in the header

    // add the broadcast MAC address
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(eth_hdr->ether_dhost, broadcast, MAC_ADDR_SIZE);

    // compute the length of the file
    len = sizeof(struct ether_header) + sizeof(struct arp_header);

    // add the arp header
    struct arp_header arp_hdr;
    memset(&arp_hdr, 0, sizeof(struct arp_header));

    // add the data
    arp_hdr.hlen = 6; // mac length
    arp_hdr.plen = 4; // ip length

    arp_hdr.htype = htons(1); // hardware type = ethernet
    arp_hdr.ptype = htons(IPv4); // protocol type = ipv4
    arp_hdr.op = htons(1); // operation = request

    memcpy(arp_hdr.sha, eth_hdr->ether_shost, MAC_ADDR_SIZE); // set the sender mac address
    arp_hdr.spa = source_ip;

    arp_hdr.tpa = target_ip;

    // copy the arp header
    memcpy(data + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));

    send_to_link(interface, data, len);

    return 0;
}

// returns the mac address for the specific interface if the ARP packet is for this router
// and if not returns NULL
void for_router_ARP(uint8_t *mac_dest, uint32_t ip_dest)
{
    // check if the mac address is boradcast
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    
    // check if the mac address is one of the router s interfaces
    uint8_t aux_mac[6];
    int i;
    for (i = 0; i < ROUTER_NUM_INTERFACES; i++) {
        // get the mac address for each interface
        get_interface_mac(i, aux_mac);

        if (memcmp(aux_mac, mac_dest, MAC_ADDR_SIZE) == 0) {
            memcpy(mac_dest, aux_mac, MAC_ADDR_SIZE);
            return ;
        }
            
    }

    // if a broadcast destination
    if (memcmp(mac_dest, broadcast, MAC_ADDR_SIZE) == 0) {
        // check each interface 
        for (i = 0; i < ROUTER_NUM_INTERFACES; i++) {
            // get the ip address
            uint32_t ip =  string2ip(get_interface_ip(i));

            if (ip == ip_dest) {
                get_interface_mac(i, aux_mac);
                memcpy(mac_dest, aux_mac, MAC_ADDR_SIZE);
                return ;
            }
        }
    }

    mac_dest = NULL;

    return ;
}
