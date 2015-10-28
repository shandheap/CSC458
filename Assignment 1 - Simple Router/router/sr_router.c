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
    sr_arpcache_init(&sr->cache);

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

void modify_eth_header(sr_ethernet_hdr_t * eth_hdr,  /* Ethernet header to modify */
                          uint8_t * ether_dhost,        /* destination ethernet address */
                          uint8_t * ether_shost,        /* source ethernet address */
                          uint16_t ether_type           /* packet type ID */
)
{
    /* Construct Ethernet headers */
    memcpy(eth_hdr->ether_dhost, ether_dhost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, ether_shost, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ether_type);

    return;
}

void modify_arp_header(sr_arp_hdr_t * arp_hdr,            /* ARP header pointer to modify */
                      unsigned short  ar_hrd,             /* format of hardware address   */
                      unsigned short  ar_pro,             /* format of protocol address   */
                      unsigned char   ar_hln,             /* length of hardware address   */
                      unsigned char   ar_pln,             /* length of protocol address   */
                      unsigned short  ar_op,              /* ARP opcode (command)         */
                      unsigned char   ar_sha[ETHER_ADDR_LEN],   /* sender hardware address      */
                      uint32_t        ar_sip,             /* sender IP address            */
                      unsigned char   ar_tha[ETHER_ADDR_LEN],   /* target hardware address      */
                      uint32_t        ar_tip             /* target IP address            */
)
{
    /* Construct the ARP headers */
    arp_hdr->ar_hrd = htons(ar_hrd);
    arp_hdr->ar_pro = htons(ar_pro);
    arp_hdr->ar_hln = ar_hln;
    arp_hdr->ar_pln = ar_pln;
    arp_hdr->ar_op = htons(ar_op);
    arp_hdr->ar_tip = ar_tip;
    arp_hdr->ar_sip = ar_sip;
    memcpy(arp_hdr->ar_sha, ar_sha, ETHER_ADDR_LEN);
    memcpy(arp_hdr->ar_tha, ar_tha, ETHER_ADDR_LEN);

    return;
}

void modify_icmp_header(sr_icmp_hdr_t * icmp_hdr,    /* ICMP header to modify */
                           uint8_t icmp_type,            /* ICMP type */
                           uint8_t icmp_code             /* ICMP code */
)
{
    /* Construct Ethernet headers */
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_sum = 0;

    /* Recompute checksum */
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));

    return;
}

void sr_handle_arp_packet(struct sr_instance* sr,
                          uint8_t * packet/* lent */,
                          unsigned int len,
                          char* interface/* lent */)
{
    /* Initialize packet size var */
    size_t pkt_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    /* Check if packet is of minimum length */
    if (len < pkt_size) {
        return;
    }

    /* Get the packet's ethernet and arp headers */
    sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
    sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    switch (ntohs(arp_hdr->ar_op))
    {
        /* ARP packet is a request */
        case arp_op_request:
            Debug("Received ARP request, length(%d)\n", len);
            print_hdr_arp((uint8_t *) arp_hdr);
            /* Get the router interface record for target ip */
            struct sr_if *iface = sr_get_interface_by_ip(sr, arp_hdr->ar_tip);
            if (iface) {
                /* Prepare ARP reply */
                uint8_t *buf = malloc(len);

                /* Modify new packet for reply */
                sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) buf;
                sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));

                /* Modify new ethernet headers */
                modify_eth_header(
                        new_eth_hdr,
                        eth_hdr->ether_shost,
                        iface->addr,
                        ethertype_arp
                );

                /* Modify new arp headers */
                modify_arp_header(
                        new_arp_hdr,
                        arp_hrd_ethernet,
                        ethertype_ip,
                        ETHER_ADDR_LEN,
                        IP_PROTO_LEN,
                        arp_op_reply,
                        iface->addr,
                        arp_hdr->ar_tip,
                        arp_hdr->ar_sha,
                        arp_hdr->ar_sip
                );

                Debug("Send ARP reply, length(%d)\n", len);
                print_hdr_arp((uint8_t *) new_arp_hdr);
                /* Send the ARP reply */
                sr_send_packet(sr, buf, len, interface);
                /* free memory for reply */
                free(buf);
            }

        /* ARP packet is a reply */
        case arp_op_reply:
            Debug("Received ARP reply, length(%d)\n", len);
            print_hdr_arp((uint8_t *) arp_hdr);
            Debug("Caching ARP response for IP and MAC:\n");
            print_addr_ip_int(ntohl(arp_hdr->ar_sip));
            print_addr_eth(arp_hdr->ar_sha);
            /* Cache the response MAC address */
            struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

            /* Do nothing if there's no entry */
            if (!req) {
                return;
            }

            /* Send all packets waiting on this ARP request */
            struct sr_packet *pkt = req->packets;
            while (pkt)
            {
                uint8_t *buf = malloc(pkt->len);
                memcpy(buf, pkt->buf, pkt->len);

                /* Get the headers for the original IP packet */
                sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (pkt->buf + sizeof(sr_ethernet_hdr_t));

                /* Modify new packet for reply */
                sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) buf;
                sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
                sr_icmp_hdr_t *new_icmp_hdr = (sr_icmp_hdr_t *)
                        (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                /* Decrement the TTL by 1 */
                new_ip_hdr->ip_ttl--;
                /* Send ICMP error response if ttl is zero */
                if (new_ip_hdr->ip_ttl == 0) {
                    Debug("Time-to-live exceeded\n");
                    /* Get router's interface */
                    struct sr_if *iface = sr_get_interface(sr, pkt->iface);

                    /* Modify new ethernet headers */
                    modify_eth_header(new_eth_hdr, new_eth_hdr->ether_shost, iface->addr, ethertype_ip);

                    /* Modify new ip headers */
                    new_ip_hdr->ip_src = ip_hdr->ip_dst;
                    new_ip_hdr->ip_dst = ip_hdr->ip_src;

                    /* Modify new icmp headers */
                    modify_icmp_header(new_icmp_hdr, 11, 0);
                }

                /* Otherwise just forward the packet */
                else {
                    Debug("Forward IP packet, length(%d)\n", pkt->len);
                    struct sr_if *iface = sr_get_interface(sr, interface);

                    /* Modify new ethernet headers */
                    modify_eth_header(new_eth_hdr, arp_hdr->ar_sha, iface->addr, ethertype_ip);

                    iface = sr_get_interface_by_ip(sr, ip_hdr->ip_dst);
                    /* IP destination is router interface so construct echo reply */
                    if (iface) {
                        /* Construct new ip headers */
                        new_ip_hdr->ip_src = ip_hdr->ip_dst;
                        new_ip_hdr->ip_dst = ip_hdr->ip_src;

                        /* Set TTL to 100 for echo reply */
                        new_ip_hdr->ip_ttl = 100;

                        /* Modify new icmp headers */
                        modify_icmp_header(new_icmp_hdr, 0, 0);
                    }
                }

                /* Recompute the packet checksum */
                new_ip_hdr->ip_sum = 0;
                new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);

                print_hdr_ip((uint8_t *) new_ip_hdr);
                print_hdr_icmp((uint8_t *) new_icmp_hdr);
                /* Send ping response */
                sr_send_packet(sr, buf, pkt->len, interface);
                /* free memory for reply */
                free(buf);

                pkt = pkt->next;
            }
    }
}

void sr_handle_ip_packet(struct sr_instance* sr,
                         uint8_t * packet/* lent */,
                         unsigned int len,
                         char* interface/* lent */)
{
    size_t pkt_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    /* Ignore packets that have invalid length */
    if (len < pkt_size || len > IP_MAXPACKET) {
        return;
    }

    /* Get the packet's ip headers */
    sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /* Verify checksum by ensuring that the computed cksum is zero */
    uint16_t verify_sum = ~cksum(ip_hdr, ip_hdr->ip_hl * 4);

    /* Checksums don't match so ignore packet */
    if (verify_sum) {
        return;
    }

    Debug("Received IP packet, length(%d)\n", len);
    print_hdr_ip((uint8_t *) ip_hdr);

    /* Checksums match so continue forwarding packet */
    struct sr_if * iface = sr_get_interface_by_ip(sr, ip_hdr->ip_dst);
    /* Pinging one of router's interfaces */
    if (iface)
    {
        /* Do cache lookup */
        struct sr_arpentry * entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_src);

        /* If cache entry exists then send an echo reply to the corresponding MAC */
        if (entry)
        {
            Debug("Found cache entry for IP:\n");
            print_addr_ip_int(ntohl(ip_hdr->ip_src));
            /* Prepare ICMP echo reply */
            uint8_t * buf = malloc(len);
            memcpy(buf, packet, len);

            /* Get new packet headers */
            sr_ethernet_hdr_t * new_eth_hdr = (sr_ethernet_hdr_t *) buf;
            sr_ip_hdr_t * new_ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
            sr_icmp_hdr_t * new_icmp_hdr = (sr_icmp_hdr_t *)
                    (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            /* Modify new ip headers */
            new_ip_hdr->ip_src = ip_hdr->ip_dst;
            new_ip_hdr->ip_dst = ip_hdr->ip_src;

            /* Decrement the TTL by 1 */
            new_ip_hdr->ip_ttl--;

            /* Send ICMP error response if ttl is zero */
            if (new_ip_hdr->ip_ttl == 0)
            {
                Debug("Time-to-live exceeded\n");
                /* Get router's interface */
                iface = sr_get_interface(sr, interface);

                /* Construct new ethernet headers */
                modify_eth_header(new_eth_hdr, entry->mac, iface->addr, ethertype_ip);

                /* Construct new icmp headers */
                modify_icmp_header(new_icmp_hdr, 11, 0);
            }

                /* Check if packet is TCP or UDP payload */
            else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp)
            {
                Debug("Packet was TCP or UDP payload for router interface\n");

                /* Get interface for incoming packet */
                iface = sr_get_interface(sr, interface);

                /* Construct new ethernet headers */
                modify_eth_header(new_eth_hdr, entry->mac, iface->addr, ethertype_ip);

                /* Construct icmp error response */
                modify_icmp_header(new_icmp_hdr, 11, 0);

                print_addr_eth(new_eth_hdr->ether_dhost);
                print_addr_eth(new_eth_hdr->ether_shost);
                Debug("Interface is %s\n", iface->name);

                print_addr_ip_int(ntohl(new_ip_hdr->ip_dst));
                print_addr_ip_int(ntohl(new_ip_hdr->ip_src));
            }

                /* Otherwise construct echo reply */
            else
            {
                Debug("Echo reply to IP packet, length(%d)\n", len);
                /* Construct new ethernet headers */
                modify_eth_header(new_eth_hdr, entry->mac, iface->addr, ethertype_ip);

                /* Construct new icmp headers */
                modify_icmp_header(new_icmp_hdr, 0, 0);
            }

            /* Recompute the packet checksum */
            new_ip_hdr->ip_sum = 0;
            new_ip_hdr->ip_sum = cksum(new_ip_hdr, IP_PROTO_LEN * 4);

            print_hdr_ip((uint8_t *) new_ip_hdr);
            print_hdr_icmp((uint8_t *) new_icmp_hdr);
            /* Send ping response */
            sr_send_packet(sr, buf, len, iface->name);
            /* free memory for reply */
            free(buf);
        }

            /* Otherwise queue packet on cache requests */
        else
        {
            Debug("Cache miss for IP:\n");
            print_addr_ip_int(ntohl(ip_hdr->ip_src));
            sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_src, packet, len, iface->name);
        }
    }
    /* Otherwise ip is not router interface so do longest prefix match */
    else
    {
        /* Perform longest prefix match for destination ip */
        struct sr_rt * match = sr_lpm(sr, ip_hdr->ip_dst);
        /* There's a longest prefix match so use that hop ip */
        if (match)
        {
            /* Do cache lookup */
            struct sr_arpentry * entry = sr_arpcache_lookup(&sr->cache, match->gw.s_addr);
            /* If cache entry exists then return the corresponding MAC */
            if (entry) {
                Debug("Found cache entry for IP:\n");
                print_addr_ip_int(ntohl(match->gw.s_addr));
                /* Get corresponding router interface */
                struct sr_if * iface = sr_get_interface(sr, match->interface);

                /* Modify the packet to construct reply */
                uint8_t * buf = malloc(len);
                memcpy(buf, packet, len);

                /* Modify new packet for reply */
                sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) buf;
                sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
                sr_icmp_hdr_t *new_icmp_hdr = (sr_icmp_hdr_t *)
                        (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

                /* Decrement the TTL by 1 */
                new_ip_hdr->ip_ttl--;
                /* Send ICMP error response if ttl is zero */
                if (!new_ip_hdr->ip_ttl) {
                    /* Get router's interface */
                    struct sr_if * iface = sr_get_interface(sr, interface);

                    /* Construct new ethernet headers */
                    memcpy(new_eth_hdr->ether_dhost, new_eth_hdr->ether_shost, ETHER_ADDR_LEN);
                    memcpy(new_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

                    /* Construct new icmp headers */
                    new_icmp_hdr->icmp_type = 11;
                    new_icmp_hdr->icmp_code = 0;
                    new_icmp_hdr->icmp_sum = 0;
                    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_hdr_t));
                    Debug("Time-to-live exceeded 3\n");
                }
                    /* Otherwise just forward the packet */
                else {
                    /* Construct new ethernet headers */
                    memcpy(new_eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                    memcpy(new_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
                    Debug("Forward IP packet, length(%d)\n", len);
                }

                /* Recompute the packet checksum */
                new_ip_hdr->ip_sum = 0;
                new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);

                print_hdr_ip((uint8_t *) new_ip_hdr);
                print_hdr_icmp((uint8_t *) new_icmp_hdr);
                /* Send ping response */
                sr_send_packet(sr, buf, len, iface->name);
                /* free memory for reply */
                free(buf);
            }
                /* No cache entry so queue ARP request */
            else {
                Debug("Cache miss for IP:\n");
                print_addr_ip_int(ntohl(match->gw.s_addr));
                sr_arpcache_queuereq(&sr->cache, match->gw.s_addr, packet, len, match->interface);
            }
        }
            /* TODO: This must be queued not echo replied directly */
            /* No match so send icmp error response */
        else {
            Debug("Longest Prefix Match returned no results\n");
            /* Prepare ICMP error response */
            uint8_t * buf = malloc(len);
            memcpy(buf, packet, len);

            /* Modify new packet for reply */
            sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) buf;
            sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
            sr_icmp_hdr_t *new_icmp_hdr = (sr_icmp_hdr_t *)
                    (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            /* Get router's interface */
            struct sr_if * iface = sr_get_interface(sr, interface);

            /* Construct new ip headers using the router's interface */
            new_ip_hdr->ip_src = iface->ip;
            new_ip_hdr->ip_dst = ip_hdr->ip_src;

            /* Decrement the TTL by 1 */
            new_ip_hdr->ip_ttl--;
            /* Send ICMP error response if ttl is zero */
            if (!new_ip_hdr->ip_ttl) {
                /* Construct new icmp headers */
                new_icmp_hdr->icmp_type = 11;
                new_icmp_hdr->icmp_code = 0;
                new_icmp_hdr->icmp_sum = 0;
                new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_hdr_t));
                Debug("Time-to-live exceeded 4\n");
            }
                /* Otherwise construct reply as needed */
            else {
                new_ip_hdr->ip_src = ip_hdr->ip_dst;
                new_icmp_hdr->icmp_type = 3;
                new_icmp_hdr->icmp_code = 0;
                new_icmp_hdr->icmp_sum = 0;
                new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_hdr_t));
                Debug("Destination net unreachable\n");
            }

            /* Recompute the packet checksum */
            new_ip_hdr->ip_sum = 0;
            new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);


            print_hdr_ip((uint8_t *) new_ip_hdr);
            print_hdr_icmp((uint8_t *) new_icmp_hdr);
            /* Do cache lookup */
            struct sr_arpentry * entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_src);
            if (entry) {
                Debug("Found cache entry for IP:\n");
                print_addr_ip_int(ntohl(ip_hdr->ip_src));
                /* Construct new ethernet headers */
                memcpy(new_eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                memcpy(new_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
                /* Send error response back */
                sr_send_packet(sr, buf, len, interface);
            } else {
                Debug("Cache miss for IP:\n");
                print_addr_ip_int(ntohl(ip_hdr->ip_src));
                sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_src, buf, len, interface);
            }
            /* free memory for reply */
            free(buf);

            return;
        }
    }
}


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

    switch (ethertype(packet)) {
        /* ARP packet */
        case ethertype_arp:
            sr_handle_arp_packet(sr, packet, len, interface);
            break;

        /* IP packet */
        case ethertype_ip:
            sr_handle_ip_packet(sr, packet, len, interface);
            break;
    }

    return;

}/* end sr_ForwardPacket */

