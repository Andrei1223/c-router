#include "queue.h"
#include "lib.h"
#include "funct.h"

// route table of the router
struct route_table_entry *route_table;
unsigned int route_table_size;

// arp table of the router
struct arp_table_entry *arp_table;
unsigned int arp_table_size;

struct node *trie;

// function that populates tables with data from the files
void read_data(char *rtable_path)
{
    route_table = malloc(ROUTE_TABLE_SIZE * sizeof(struct route_table_entry)); 
    DIE(route_table == NULL, "malloc");

    // populate the route table
    route_table_size = read_rtable(rtable_path, route_table);

    // create the trie
    trie = make_trie(route_table, route_table_size);

    arp_table = malloc(ARP_TABLE_SIZE * sizeof(struct arp_table_entry));
    DIE(arp_table == NULL, "malloc");

    // set the initial size of the arp table
    arp_table_size = 0;
}

int main(int argc, char *argv[])
{
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argc - 2, argv + 2);

    // read the route table and the arp table
    read_data(argv[1]); // pass the path to the route table

    // queue for ARP
    queue q = queue_create();

    while (1) {

        int interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_header *eth_hdr = (struct ether_header *) buf;

        // check for approved ether_type
        u_int16_t ether_type = ntohs(eth_hdr->ether_type);

        // skip the package
        if (ether_type != IPv4 && ether_type != ARP) {
            printf("unknown type\n\n");
            continue;
        }
            

        // Ipv4 file
        if (ether_type == IPv4) {
            // get the ipv4 package
            struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));

            // check for wrong checksum
            if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
                printf("wrong checksum\n\n");
                continue;
            }

            // check for TTL
            if (ip_hdr->ttl <= 1) {
                printf("TTL exceeded\n\n");
                // make a time exceeded ICMP package
                send_ICMP(buf, 11, 0, len);
                continue;
            }

            // check the destination ip address is mine
            if (check_dest(ip_hdr->daddr) == 1) {
                // send the ICMP response
                send_ICMP(buf, 8, 0, len);
                continue;
            }

            // get the old ttl
            uint8_t old_ttl = ip_hdr->ttl;

            ip_hdr->ttl -= 1;

            // recompute the checksum
            u_int16_t checksum = ~(~ip_hdr->check + ~((uint16_t)old_ttl) + (u_int16_t)ip_hdr->ttl) - 1;
            ip_hdr->check = checksum;

            // search in the route table for the dest addr
            struct route_table_entry *entry = LPM(route_table_size, ip_hdr->daddr);

            if (entry == NULL) {
                printf("Destination unreachable\n\n");
                // make and send "Destination unreachable" IMCP package
                send_ICMP(buf, 3, 0, len);
                continue;
            }
            // from here no ICMP packet is sent

            // get the mac address
            struct arp_table_entry *mac = find_mac_address(arp_table, arp_table_size, entry->next_hop);

            uint8_t router_mac[6];

            get_interface_mac(entry->interface, router_mac);

            // put the source mac address
            memcpy(eth_hdr->ether_shost, router_mac, MAC_ADDR_SIZE);
            
            // check in the arp table
            if (mac == NULL) {
                struct queue_data *q_data = malloc(sizeof(struct queue_data));

                // allocate memory for the package
                q_data->data = malloc(len);
                q_data->interface = entry->interface;
                q_data->len = len;

                memcpy(q_data->data, buf, len); // copy the data

                printf("send ARP on interface %d\n\n", entry->interface);

                send_ARP_request(buf, len, entry->next_hop, entry->interface, ip_hdr->saddr);
                // add the package into a queue
                queue_enq(q, q_data);
                continue;
            }

            // add the mac address of the destination
            memcpy(eth_hdr->ether_dhost, mac->mac, MAC_ADDR_SIZE);
            printf("send data on interface:%d \n\n", interface);

            send_to_link(entry->interface, buf, len);
        } else if (ether_type == ARP) {
            // get the arp header
            struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

            // check the type of arp packet
            if (ntohs(arp_hdr->op) == 2) { // reply
                // get the mac address
                uint8_t mac[6];

                memcpy(mac, arp_hdr->sha, MAC_ADDR_SIZE);

                // dequeue
                if (queue_empty(q) == 1)
                    continue;
                    
                struct queue_data *data = (struct queue_data *)queue_deq(q);

                // add the mac address into the arp table
                struct arp_table_entry elem;
                elem.ip = arp_hdr->spa;
                memcpy(&elem.mac, arp_hdr->sha, MAC_ADDR_SIZE);
                arp_table = add_into_arp_table(arp_table, &arp_table_size, elem);

                // update the dequeued packet with the destination mac address
                struct ether_header *aux_ether = (struct ether_header *)data->data;
                memcpy(aux_ether->ether_dhost, arp_hdr->sha, MAC_ADDR_SIZE);

                // send the packet
                send_to_link(data->interface, data->data, data->len);
                
                // free the buffer from the queue
                free(data->data);
                free(data);
            } else if (ntohs(arp_hdr->op) == 1) { // request
                // check if the packet is for this router
                // the destination mac addr is in eth_hdr->ether_dhost
                for_router_ARP(eth_hdr->ether_dhost, arp_hdr->tpa);
                if (eth_hdr->ether_dhost == NULL)
                    continue;

                // complete the ether header by reversing the source with the dest
                uint8_t mac_aux[6];
                memcpy(mac_aux, eth_hdr->ether_shost, MAC_ADDR_SIZE);
                memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, MAC_ADDR_SIZE);
                memcpy(eth_hdr->ether_dhost, mac_aux, MAC_ADDR_SIZE);

                // change the op code
                arp_hdr->op = htons(2); // reply

                // reverse the ip address
                uint32_t ip_aux;
                ip_aux = arp_hdr->spa;
                arp_hdr->spa = arp_hdr->tpa;
                arp_hdr->tpa = ip_aux;

                // add the wanted mac address
                memcpy(arp_hdr->tha, eth_hdr->ether_shost, MAC_ADDR_SIZE);

                // reverse the mac addresses
                memcpy(mac_aux, arp_hdr->sha, MAC_ADDR_SIZE);
                memcpy(arp_hdr->sha, arp_hdr->tha, MAC_ADDR_SIZE);
                memcpy(arp_hdr->tha, mac_aux, MAC_ADDR_SIZE);

                // send the arp reply
                // get the route entry
                struct route_table_entry *entry = LPM(route_table_size, arp_hdr->tpa);

                if (entry == NULL) {
                    printf("unknown sender ARP packet\n\n");
                    continue;
                }

                send_to_link(entry->interface, buf, len);
            }
        }
    }
}
