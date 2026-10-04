/* userspace/net/stack.h - Net stack stub API. Userspace only.
 * The kernel never includes this. RX-from-wire and sockets are future
 * work; classify() is the fail-closed parse used by tests and the stub. */
#ifndef NET_STACK_H
#define NET_STACK_H

#include "eth.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "arp.h"
#include "icmp.h"
#include "ipv6.h"

#define NET_CLASS_DROP 0
#define NET_CLASS_ARP 1
#define NET_CLASS_ICMP 2
#define NET_CLASS_UDP 3
#define NET_CLASS_TCP 4
#define NET_CLASS_IPV4 5
#define NET_CLASS_IPV6 6

static inline int net_classify(const uint8_t *f, unsigned long len)
{
    uint16_t t;
    unsigned p;
    if (!eth_hdr_ok(f, len))
        return NET_CLASS_DROP;
    t = eth_type(f, len);
    if (t == ETH_TYPE_ARP)
        return arp_hdr_ok(f, len) ? NET_CLASS_ARP : NET_CLASS_DROP;
    if (t == ETH_TYPE_IPV6)
        return ipv6_hdr_ok(f, len) ? NET_CLASS_IPV6 : NET_CLASS_DROP;
    if (t != ETH_TYPE_IPV4)
        return NET_CLASS_DROP;
    if (!ip_hdr_ok(f, len))
        return NET_CLASS_DROP;
    p = ip_proto(f, len);
    if (p == IP_PROTO_ICMP)
        return icmp_hdr_ok(f, len) ? NET_CLASS_ICMP : NET_CLASS_DROP;
    if (p == IP_PROTO_UDP)
        return udp_hdr_ok(f, len) ? NET_CLASS_UDP : NET_CLASS_DROP;
    if (p == IP_PROTO_TCP)
        return tcp_hdr_ok(f, len) ? NET_CLASS_TCP : NET_CLASS_DROP;
    return NET_CLASS_IPV4;
}

int net_stack_init(void);
int net_stack_rx(const uint8_t *f, unsigned long len);

#endif /* NET_STACK_H */
