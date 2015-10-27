/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    /* Packet is ARP */
    if (ethertype(packet) == ethertype_arp) {
        Debug("\nHandling ARP packet\n\n");
        print_hdrs(packet, len);
        /* Initialize packet size var */
        size_t pkt_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        /* Check if packet is of minimum length */
        if (len < pkt_size) {
            return;
        }

        /* Get the packet's ethernet and arp headers */
        sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
        sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

        /* ARP packet is a request */
        if (arp_hdr->ar_op == htons(arp_op_request)) {
            /* Get the router interface record for target ip */
            struct sr_if * iface = sr_get_interface_by_ip(sr, arp_hdr->ar_tip);
            if (iface) {
                /* Prepare ARP reply */
                uint8_t *buf = malloc(len);
                memcpy(buf, packet, len);

                /* Modify existing packet for reply */
                sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) buf;
                sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));

                /* Construct new ethernet headers */
                memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                memcpy(new_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

                /* Construct new arp headers */
                new_arp_hdr->ar_op = htons(arp_op_reply);
                new_arp_hdr->ar_tip = arp_hdr->ar_sip;
                new_arp_hdr->ar_sip = arp_hdr->ar_tip;
                memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                memcpy(new_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);

                /* Send the ARP reply */
                sr_send_packet(sr, buf, len, interface);
                /* free memory for reply */
                free(buf);
            }
        }
        /* ARP packet is a reply */
        else if (arp_hdr->ar_op == htons(arp_op_reply)) {
            /* Cache the response MAC address */
            struct sr_arpreq * req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

            /* Do nothing if there's no entry */
            if (!req) {
                return;
            }

            /* Iterate through request packet queue and send each of them */
            struct sr_packet * pkt = req->packets;
            while (pkt) {
                /* Prepare ICMP echo reply */
                uint8_t * buf = malloc(pkt->len);
                memcpy(buf, pkt->buf, pkt->len);

                /* Get the headers for the original IP packet */
                sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
                sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (pkt->buf + sizeof(sr_ethernet_hdr_t));

                /* Modify existing packet for reply */
                sr_ethernet_hdr_t * new_eth_hdr = (sr_ethernet_hdr_t *) buf;
                sr_ip_hdr_t * new_ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
                sr_icmp_hdr_t * new_icmp_hdr = (sr_icmp_hdr_t *)
                        (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                /* Construct new ethernet headers */
                memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                memcpy(new_eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);

                struct sr_if * iface = sr_get_interface_by_ip(sr, ip_hdr->ip_dst);
                /* IP destination is router interface so construct echo reply */
                if (iface) {
                    /* Construct new ip headers */
                    new_ip_hdr->ip_src = ip_hdr->ip_dst;
                    new_ip_hdr->ip_dst = ip_hdr->ip_src;

                    /* Construct new icmp headers */
                    new_icmp_hdr->icmp_type = 0;
                    new_icmp_hdr->icmp_code = 0;
                    new_icmp_hdr->icmp_sum = 0;
                    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_hdr_t));
                }

                /* Decrement the TTL by 1 */
                new_ip_hdr->ip_ttl--;

                /* Recompute the packet checksum */
                new_ip_hdr->ip_sum = 0;
                new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);

                /* Send ping response */
                sr_send_packet(sr, buf, pkt->len, interface);
                /* free memory for reply */
                free(buf);

                pkt = pkt->next;
            }
        }
    }
    /* Packet is IP */
    else if (ethertype(packet) == ethertype_ip) {
        Debug("\nHandling IP packet\n\n");
        print_hdrs(packet, len);
        size_t pkt_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
        /* Check if packet is of minimum length */
        if (len < pkt_size) {
            return;
        }

        /* Get the packet's ethernet and ip headers */
        sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
        sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
        /* Verify checksum by ensuring that the computed cksum is zero */
        uint16_t verify_sum = ~cksum(ip_hdr, ip_hdr->ip_hl * 4);

        /* Checksums don't match so ignore packet */
        if (verify_sum) {
            return;
        }

        /* Checksums match so continue forwarding packet */
        struct sr_if * iface = sr_get_interface_by_ip(sr, ip_hdr->ip_dst);
        /* Pinging one of router's interfaces */
        if (iface) {
            /* Do cache lookup */
            struct sr_arpentry * entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_src);

            /* If cache entry exists then send an echo reply to the corresponding MAC */
            if (entry) {
                /* Prepare ICMP echo reply */
                uint8_t * buf = malloc(len);
                memcpy(buf, packet, len);

                /* Modify existing packet for reply */
                sr_ethernet_hdr_t * new_eth_hdr = (sr_ethernet_hdr_t *) buf;
                sr_ip_hdr_t * new_ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
                sr_icmp_hdr_t * new_icmp_hdr = (sr_icmp_hdr_t *)
                        (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                /* Construct new ethernet headers */
                memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                memcpy(new_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

                /* Construct new ip headers */
                new_ip_hdr->ip_src = ip_hdr->ip_dst;
                new_ip_hdr->ip_dst = ip_hdr->ip_src;

                /* Decrement the TTL by 1 */
                new_ip_hdr->ip_ttl--;

                /* Recompute the packet checksum */
                new_ip_hdr->ip_sum = 0;
                new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);

                /* Construct new icmp headers */
                new_icmp_hdr->icmp_type = 0;
                new_icmp_hdr->icmp_code = 0;
                new_icmp_hdr->icmp_sum = 0;
                new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_hdr_t));

                /* Send ping response */
                sr_send_packet(sr, buf, len, interface);
                /* free memory for reply */
                free(buf);
            }

            /* Otherwise queue packet on cache requests */
            else {
                sr_arpcache_queuereq(&(sr->cache), ip_hdr->ip_src, packet, len, iface->name);
            }
        }
        /* Otherwise ip is not router interface so do longest prefix match */
        else {
            /* Perform longest prefix match for destination ip */
            struct sr_rt * match = sr_lpm(sr, ip_hdr->ip_dst);
            /* There's a longest prefix match so use that hop ip */
            if (match) {
                /* Do cache lookup */
                struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), match->dest.s_addr);
                /* If cache entry exists then return the corresponding MAC */
                if (entry) {
                    /* Modify the packet to construct reply */
                    uint8_t *buf = malloc(len);
                    memcpy(buf, packet, len);

                    /* Modify existing packet for reply */
                    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) buf;
                    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));

                    /* Construct new ethernet headers */
                    memcpy(new_eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);

                    /* Construct new ip headers */
                    new_ip_hdr->ip_src = ip_hdr->ip_dst;
                    new_ip_hdr->ip_dst = ip_hdr->ip_src;

                    /* Decrement the TTL by 1 */
                    new_ip_hdr->ip_ttl--;

                    /* Recompute the packet checksum */
                    new_ip_hdr->ip_sum = 0;
                    new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);

                    /* Send ping response */
                    sr_send_packet(sr, buf, len, interface);
                    /* free memory for reply */
                    free(buf);
                }
                /* No cache entry so queue ARP request */
                else {
                    /* Find the routing table entry that corresponds to the gateway */
                    struct sr_rt * entry = sr_find_rt_by_ip(sr, match->gw.s_addr);
                    sr_arpcache_queuereq(&(sr->cache), match->gw.s_addr, packet, len, entry->interface);
                }
            }
            /* No match so send icmp error response */
            else {
                /* Prepare ICMP error response */
                uint8_t *buf = malloc(len);
                memcpy(buf, packet, len);

                /* Modify existing packet for reply */
                sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) buf;
                sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
                sr_icmp_hdr_t *new_icmp_hdr = (sr_icmp_hdr_t *)
                        (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                /* Construct new ethernet headers */
                memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                memcpy(new_eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);

                /* Construct new ip headers */
                new_ip_hdr->ip_src = ip_hdr->ip_dst;
                new_ip_hdr->ip_dst = ip_hdr->ip_src;

                /* Decrement the TTL by 1 */
                new_ip_hdr->ip_ttl--;

                /* Recompute the packet checksum */
                new_ip_hdr->ip_sum = 0;
                new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);

                /* Construct new icmp headers */
                new_icmp_hdr->icmp_type = 3;
                new_icmp_hdr->icmp_code = 0;
                new_icmp_hdr->icmp_sum = 0;
                new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_hdr_t));

                /* Send ping response */
                sr_send_packet(sr, buf, len, interface);
                /* free memory for reply */
                free(buf);

                return;
            }
        }
    }

    return;

}/* end sr_ForwardPacket */

