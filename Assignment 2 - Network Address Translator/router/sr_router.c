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

void modify_icmp_t3_header(sr_icmp_t3_hdr_t * icmp_hdr,     /* ICMP header to modify */
                        uint8_t icmp_type,                  /* ICMP type */
                        uint8_t icmp_code,                  /* ICMP code */
                        uint16_t unused,                    /* Unused bytes */
                        uint16_t next_mtu,                  /* Next MTU */
                        uint8_t data[ICMP_DATA_SIZE]        /* Original IP header and first 8 bytes of data */
)
{
    /* Construct ICMP headers */
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->unused = unused;
    icmp_hdr->next_mtu = next_mtu;
    memcpy(icmp_hdr->data, data, ICMP_DATA_SIZE);
    icmp_hdr->icmp_sum = 0;

    /* Recompute checksum */
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

    return;
}

void construct_icmp_error(struct sr_instance* sr,
                          sr_ip_hdr_t * ip_hdr,  /* Original IP header */
                          uint8_t * packet /* lent */,
                          char* interface, /* lent */
                          uint8_t icmp_type, /* ICMP type */
                          uint8_t icmp_code /* ICMP code */
)
{
    /* Prepare ICMP error response */
    size_t old_pkt_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    size_t new_pkt_size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t * buf = malloc(new_pkt_size);
    memcpy(buf, packet, old_pkt_size);

    /* Get old icmp header */
    sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Modify new packet for reply */
    sr_ethernet_hdr_t * new_eth_hdr = (sr_ethernet_hdr_t *) buf;
    sr_ip_hdr_t * new_ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t * new_icmp_hdr = (sr_icmp_t3_hdr_t *)
            (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Get router's interface */
    struct sr_if * iface = sr_get_interface(sr, interface);

    /* Modify new ip headers using the router's interface */
    new_ip_hdr->ip_dst = iface->ip;

    /* Reset Identification */
    new_ip_hdr->ip_id = 0;

    /* Construct reply as needed */
    uint8_t * data = malloc(ICMP_DATA_SIZE);
    memcpy(data, ip_hdr, sizeof(sr_ip_hdr_t));
    memcpy(data + sizeof(sr_ip_hdr_t), icmp_hdr, sizeof(sr_icmp_hdr_t) + 4);
    modify_icmp_t3_header(new_icmp_hdr, icmp_type, icmp_code, 0, 0, data);

    /* Reset the packet length */
    new_ip_hdr->ip_len = htons(new_pkt_size - sizeof(sr_ethernet_hdr_t));

    /* Check if packet is TCP or UDP payload */
    if (new_ip_hdr->ip_p == ip_protocol_tcp || new_ip_hdr->ip_p == ip_protocol_udp)
    {
        /* Change protocol to icmp */
        new_ip_hdr->ip_p = ip_protocol_icmp;
    }

    /* Do cache lookup */
    struct sr_arpentry * entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_src);
    if (entry) {
        /* Modify new ethernet headers */
        modify_eth_header(new_eth_hdr, entry->mac, iface->addr, ethertype_ip);
        /* Modify new ip headers using the router's interface */
        new_ip_hdr->ip_src = iface->ip;
        new_ip_hdr->ip_dst = ip_hdr->ip_src;

        /* Set return TTL */
        new_ip_hdr->ip_ttl = 100;

        /* Recompute the packet checksum */
        new_ip_hdr->ip_sum = 0;
        new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);



        /* Send error response back */
        sr_send_packet(sr, buf, new_pkt_size, interface);
    } else {

        /* Modify new ip headers using the router's interface */
        new_ip_hdr->ip_dst = iface->ip;

        /* Recompute the packet checksum */
        new_ip_hdr->ip_sum = 0;
        new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);

        sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_src, buf, new_pkt_size, interface);
    }
    /* free memory for reply */
    free(buf);

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

                /* Send the ARP reply */
                sr_send_packet(sr, buf, len, interface);
                /* free memory for reply */
                free(buf);
            }

            break;

        /* ARP packet is a reply */
        case arp_op_reply:
            Debug("Received ARP reply, length(%d)\n", len);
            /* Cache the response MAC address */
            struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

            /* Do nothing if there's no entry */
            if (!req) {
                return;
            }

            /* Send all packets waiting on this ARP request */
            struct sr_packet * pkt = req->packets;
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
                    if (new_icmp_hdr->icmp_type == 8) {
                        size_t icmp_hdr_len = pkt->len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
                        new_icmp_hdr->icmp_type = 0;
                        new_icmp_hdr->icmp_code = 0;

                        new_icmp_hdr->icmp_sum = 0;

                        /* Recompute checksum */
                        new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, icmp_hdr_len);
                    }
                }

                /* Recompute the packet checksum */
                new_ip_hdr->ip_sum = 0;
                new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);

                /* Send ping response */
                sr_send_packet(sr, buf, pkt->len, pkt->iface);

                /* free memory for reply */
                free(buf);

                pkt = pkt->next;
            }

            /* Destroy the request */
            sr_arpreq_destroy(&sr->cache, req);

            break;
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

    printf("Receive IP packet, length(%d)\n", len);
    print_hdr_ip((uint8_t *) ip_hdr);

    /* Verify checksum by ensuring that the computed cksum is zero */
    uint16_t verify_sum = ~cksum(ip_hdr, ip_hdr->ip_hl * 4);

    /* Checksums don't match so ignore packet */
    if (verify_sum) {
        return;
    }


    /* Checksums match so continue forwarding packet */
    struct sr_if * iface = sr_get_interface_by_ip(sr, ip_hdr->ip_dst);
    /* Pinging one of router's interfaces */
    if (iface)
    {
        /* Check if packet is TCP or UDP payload */
        if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp)
        {

            /* Construct ICMP error response */
            construct_icmp_error(sr, ip_hdr, packet, interface, 3, 3);
            return;
        }

        /* Do cache lookup */
        struct sr_arpentry * entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_src);

        /* If cache entry exists then send an echo reply to the corresponding MAC */
        if (entry)
        {
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

            /* Construct echo reply */

            /* Get the incoming interface */
            iface = sr_get_interface(sr, interface);

            /* Construct new ethernet headers */
            modify_eth_header(new_eth_hdr, entry->mac, iface->addr, ethertype_ip);

            /* Construct new icmp headers */
            size_t icmp_hdr_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
            new_icmp_hdr->icmp_type = 0;
            new_icmp_hdr->icmp_code = 0;

            new_icmp_hdr->icmp_sum = 0;

            /* Recompute checksum */
            new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, icmp_hdr_len);

            /* Set TTL to 100 for echo reply */
            new_ip_hdr->ip_ttl = 100;

            /* Recompute the packet checksum */
            new_ip_hdr->ip_sum = 0;
            new_ip_hdr->ip_sum = cksum(new_ip_hdr, ip_hdr->ip_hl * 4);

            /* Send ping response */
            sr_send_packet(sr, buf, len, interface);
            /* free memory for reply */
            free(buf);
        }

        /* Otherwise queue packet on cache requests */
        else
        {
            sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_src, packet, len, interface);
        }
    }
    /* Otherwise ip is not router interface so do longest prefix match */
    else
    {
        /* Decrement the TTL by 1 */
        ip_hdr->ip_ttl--;
        /* Send ICMP error response if ttl is 0 */
        if (ip_hdr->ip_ttl == 0)
        {
            /* Get the source IP routing table entry */
            struct sr_rt * source_rt = sr_find_rt_by_ip(sr, ip_hdr->ip_src);

            /* Change TTL back to original */
            ip_hdr->ip_ttl++;
            /* Construct ICMP error response */
            construct_icmp_error(sr, ip_hdr, packet, source_rt->interface, 11, 0);
            return;
        }

        /* Perform longest prefix match for destination ip */
        struct sr_rt * match = sr_lpm(sr, ip_hdr->ip_dst);
        /* There's a longest prefix match so use that hop ip */
        if (match)
        {
            /* Do cache lookup */
            struct sr_arpentry * entry = sr_arpcache_lookup(&sr->cache, match->gw.s_addr);
            /* If cache entry exists then return the corresponding MAC */
            if (entry) {
                /* Get corresponding router interface */
                struct sr_if * iface = sr_get_interface(sr, match->interface);

                /* Modify the packet to construct reply */
                uint8_t * buf = malloc(len);
                memcpy(buf, packet, len);

                /* Modify new packet for reply */
                sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) buf;
                sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));

                /* Modify new ethernet headers */
                modify_eth_header(new_eth_hdr, entry->mac, iface->addr, ethertype_ip);

                /* Recompute the packet checksum */
                new_ip_hdr->ip_sum = 0;
                new_ip_hdr->ip_sum = cksum(new_ip_hdr, new_ip_hdr->ip_hl * 4);

                /* Send ping response */
                sr_send_packet(sr, buf, len, iface->name);
                /* free memory for reply */
                free(buf);
            }
                /* No cache entry so queue ARP request */
            else {
                sr_arpcache_queuereq(&sr->cache, match->gw.s_addr, packet, len, match->interface);
            }
        }
        /* No match so send icmp error response */
        else {
            /* Construct ICMP error response */
            construct_icmp_error(sr, ip_hdr, packet, interface, 3, 0);

            return;
        }
    }

    printf("Modified IP packet, length(%d)\n", len);
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

