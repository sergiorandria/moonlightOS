/* userspace/net/stack.h - Net stack stub API. Userspace only.
 * The kernel never includes this. RX-from-wire and sockets are future
 * work; classify() is the fail-closed parse used by tests and the stub. */
#ifndef NET_STACK_H
#define NET_STACK_H

#include "arp.h"
#include "eth.h"
#include "icmp.h"
#include "ip.h"
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"

#define NET_CLASS_DROP 0
#define NET_CLASS_ARP 1
#define NET_CLASS_ICMP 2
#define NET_CLASS_UDP 3
#define NET_CLASS_TCP 4
#define NET_CLASS_IPV4 5
#define NET_CLASS_IPV6 6

#define NET_ERR_EMPTY 1
#define NET_ERR_TRUNC 2

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
int net_stack_udp_send(uint32_t dst_ip, uint16_t dst_port, uint16_t src_port,
                       const uint8_t *payload, unsigned long len, uint8_t *frame_out,
                       unsigned long *frame_len);
int net_udp_recv(uint8_t *buf, unsigned long cap, uint32_t *src_ip, uint16_t *src_port, int *trunc);
int net_udp_recv_from(uint16_t dport, uint8_t *buf, unsigned long cap, uint32_t *src_ip,
                      uint16_t *src_port, int *trunc);
void net_udp_drop_if(int (*drop)(uint16_t dport));

#endif /* NET_STACK_H */
