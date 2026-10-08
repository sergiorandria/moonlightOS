/* userspace/net/arp.h - ARP header view. Parse only, no replies. */
#ifndef NET_ARP_H
#define NET_ARP_H

#include <stdint.h>
#include "eth.h"

#define ARP_HDR_LEN 28u
#define ARP_HTYPE_ETH 1u
#define ARP_PTYPE_IPV4 0x0800u
#define ARP_OP_REQUEST 1u
#define ARP_OP_REPLY 2u

static inline int arp_hdr_ok(const uint8_t *f, unsigned long len)
{
    uint16_t ht, pt, op;
    if (!eth_hdr_ok(f, len) || eth_type(f, len) != ETH_TYPE_ARP)
        return 0;
    if (len < (unsigned long)ETH_HDR_LEN + ARP_HDR_LEN)
        return 0;
    ht = (uint16_t)(((unsigned)f[ETH_HDR_LEN] << 8) | (unsigned)f[ETH_HDR_LEN + 1]);
    pt = (uint16_t)(((unsigned)f[ETH_HDR_LEN + 2] << 8) | (unsigned)f[ETH_HDR_LEN + 3]);
    if (ht != ARP_HTYPE_ETH || pt != ARP_PTYPE_IPV4)
        return 0;
    if (f[ETH_HDR_LEN + 4] != ETH_ADDR_LEN || f[ETH_HDR_LEN + 5] != 4u)
        return 0;
    op = (uint16_t)(((unsigned)f[ETH_HDR_LEN + 6] << 8) | (unsigned)f[ETH_HDR_LEN + 7]);
    if (op != ARP_OP_REQUEST && op != ARP_OP_REPLY)
        return 0;
    return 1;
}

#endif /* NET_ARP_H */
