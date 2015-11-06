Code Structure & Design Decisions
=================================

Most of the code to handle packets is located in sr_router.c. No new files were added, only modifications and additions to existing files.

The initial approach was to get ARP working and then focus on packet routing. The following is a breakdown of the functions and code added in each file to implement the solution:

sr_arpcache.c
-------------

We added a new function sr_handle_arpreq to handle arp requests in the arp cache requests queue.

Since sr_arpcache_sweepreqs is run every second by the existing code, we filled in this function to call sr_handle_arpreq for each request in queue. While iterating through the requests we make sure to make a copy of the next request before handling the current one, as sr_handle_arpreq could destroy the current request pointer.

sr_handle_arpreq sends ARP requests for each request in the queue. If the outstanding ARP request has been sent more than 5 times already, we send an ICMP error destination host unreachable to all waiting packets on this request, and then destroy the request after we're done sending ICMP errors. Otherwise, we send an ARP request on the request packet's interface to the broadcast MAC address.

sr_router.c
-----------

This file contains the bulk of our code. We have modification functions for each type of header (ethernet, arp, icmp type 3) which take a header pointer and then fill the struct fields with the function parameters. We also made a icmp type 3 error construction function to construct ICMP errors and send them back to their origin.

For sr_handlepacket, we used a switch statement to handle ARP and IP packets seperately. We defined sr_handle_arp_packet and sr_handle_ip_packet to handle ARP and IP packets.

sr_handle_arp_packet takes care of both ARP requests and replies. For both ARP packets, it checks if they meet the required minimum length. For requests, we first check if a router interface exists for the destination ip. If it does, then we respond, otherwise we ignore the ARP request because it's not for us. For replies we cache the source hardware address to the source IP. Then, we get an outstanding request for that IP. If there's a request waiting on that response, then we go through all waiting packets and forward them. We destroy the request after we're done sending all packets.

sr_handle_ip_packet takes care of IP packets coming to the router. The router first checks that the packet meets minimum length and does not exceed maximum length. Then we calculate the checksum, which should be 0 because the checksum field is a 1s complement of the sum of the other fields. If the checksum is correct, then we handle the packet.

If the packet is for a router interface, then we handle the ICMP echo reply or port unreachable error (for udp and tcp). Otherwise, we decrement the ttl and check if ttl exceeded (ttl is 0). If ttl is ok then we perform longest prefix match on the destination IP. If we don't have a match, then we construct an ICMP destination unreachable error. If we have a match, then we forward the packet to the next hop IP match.

sr_rt.c
-------

We've implemented two functions sr_find_rt_by_ip and sr_lpm.

sr_find_rt_by_ip was defined to find a routing table entry that corresponds to the ip argument passed into the function. The function iterates through all the routing table entries until it finds a match, otherwise it returns NULL.

sr_lpm was defined to perform longest prefix match against routing table entries. Longest prefix match is done by first trying to match the full ip against routing table entries. If there's no match, then we repeat matching against each entry except now we shift the IP, incrementing the shift each time. If there's no match, return NULL.

sr_if.c
-------

We implemented a function sr_get_interface_by_ip that gets the router interface record for the specified IP. If there was no interface then return NULL.


sr_utils.c
----------

We implemented a dummy function called set_breakpoint for gdb to break on to simply debugging.

sr_protocol.h
-------------

We defined the protocols that were necessary for our code such as the default IP protocol length and the ip protocols for TCP and UDP. 