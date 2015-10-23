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
        /* Initialize packet size var */
        size_t pkt_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        /* Check if packet is of minimum length */
        if (len < pkt_size) {
            return;
        }

        /* Get the packet's ethernet and arp headers */
        sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
        sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

        /* Do cache lookup */
        struct sr_arpentry * entry = sr_arpcache_lookup(&(sr->cache), arp_hdr->ar_tip);
        /* If cache entry exists then return the corresponding MAC */
        if (entry) {
            /* Modify the packet to construct reply */
            sr_send_packet(sr, packet, len, interface);

            /*TODO: Refactor this code block into a func*/
            /* Prepare ARP reply */
            uint8_t * buf = malloc(pkt_size);
            memcpy(buf, packet, pkt_size);
            /* Modify existing packet for reply */
            sr_ethernet_hdr_t * new_eth_hdr = (sr_ethernet_hdr_t *) buf;
            sr_arp_hdr_t * new_arp_hdr = (sr_arp_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
            /* Constuct new ethernet headers */
            memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(new_eth_hdr->ether_shost, entry->mac, ETHER_ADDR_LEN);
            /* Construct new arp headers */
            new_arp_hdr->ar_op = htons(arp_op_reply);
            new_arp_hdr->ar_tip = arp_hdr->ar_sip;
            new_arp_hdr->ar_sip = arp_hdr->ar_tip;
            memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            memcpy(new_arp_hdr->ar_sha, arp_hdr->ar_tha, ETHER_ADDR_LEN);

            /* Send the ARP reply */
            sr_send_packet(sr, buf, pkt_size, interface);
            /* free memory for reply */
            free(buf);
        }

        /* ARP packet is a request */
        if (arp_hdr->ar_op == htons(arp_op_request)) {
            /* Get the router interface record for target ip */
            struct sr_if * iface = sr_get_interface_by_ip(sr, arp_hdr->ar_tip);
            if (iface) {
                /*TODO: Refactor this code block into a func*/
                /* Prepare ARP reply */
                uint8_t * buf = malloc(pkt_size);
                memcpy(buf, packet, pkt_size);
                /* Modify existing packet for reply */
                sr_ethernet_hdr_t * new_eth_hdr = (sr_ethernet_hdr_t *) buf;
                sr_arp_hdr_t * new_arp_hdr = (sr_arp_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
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
                sr_send_packet(sr, buf, pkt_size, interface);
                /* free memory for reply */
                free(buf);
            }

            return;
        }
        /* ARP packet is a reply */
        else if (arp_hdr->ar_op == htons(arp_op_reply)) {
            /* TODO: Implement ARP reply */
            /* Add packet to ARP queue */
            sr_arpcache_queuereq(
                    &(sr->cache),
                    arp_hdr->ar_tip,
                    packet,
                    len,
                    interface
            );

        }
        /* Otherwise invalid op code so ignore packet */
        else {
            return;
        }
    }
    /* Packet is IP */
    else if (ethertype(packet) == ethertype_ip) {
        /* Check if packet is of minimum length */
        if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
            return;
        }
        /* Get the packet's ip header */
        sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
        /* Verify checksum by ensuring that the computed cksum is zero */
        uint16_t verify_sum = ~cksum(ip_hdr, ip_hdr->ip_hl * 4);
        /* Reject packet if checksums don't match */
        if (verify_sum) {
            /* TODO: Send ICMP message about incorrect checksum */
            return;
        /* Otherwise try to forward IP packet */
        } else {
            /* TODO: Implement IP packet handling */
        }
    }

}/* end sr_ForwardPacket */

