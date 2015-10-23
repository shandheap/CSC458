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
        /* Check if packet is of minimum length */
        if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t) ) {
            return;
        }

        /* Get the packet's arp header */
        sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

        /* Check if ARP packet is a request */
        if (arp_hdr->ar_op == htons(arp_op_request)) {
            /* Get the router interface record for target ip */
            struct sr_if * iface = sr_get_interface_by_ip(sr, arp_hdr->ar_tip);
            if (iface) {
                print_addr_eth(iface->addr);
            }
            /* Otherwise arp packet was not for us */
            else {
                return;
            }
        }
        /* Otherwise check if ARP packet is a reply */
        else if (arp_hdr->ar_op == htons(arp_op_reply)) {
            /* TODO: Implement ARP reply */
            /* Do cache lookup */
            struct sr_arpentry * entry = sr_arpcache_lookup(&(sr->cache), arp_hdr->ar_tip);
            /* If cache entry exists then return the corresponding MAC */
            if (entry) {
                /* Modify the packet to construct reply */
                sr_send_packet(sr, packet, len, interface);
                entry->mac;
            }

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

        print_hdr_arp(packet);
    }
    /* Packet is IP */
    else if (ethertype(packet) == ethertype_ip) {
        /* TODO: Implement IP packet handling */
        /* Do sanity check for packet */
        /* Check if packet is of minimum length */
        if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) ) {
            return;
        }
        /* Get the packet's ip header */
        sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
        /* Reject packet if checksums don't match */
        if (cksum(packet, len) != ip_hdr->ip_sum) {

        }
    }

}/* end sr_ForwardPacket */

