/* userspace/net/ipv6.h - IPv6 ethernet payload. Stub: version+len only. */
#ifndef NET_IPV6_H
#define NET_IPV6_H

#include <stdint.h>
#include "eth.h"

#define IPV6_HDR_LEN 40u

static inline int ipv6_hdr_ok(const uint8_t *f, unsigned long len)
{
    uint16_t plen;
    if (!eth_hdr_ok(f, len) || eth_type(f, len) != ETH_TYPE_IPV6)
        return 0;
    if (len < (unsigned long)ETH_HDR_LEN + IPV6_HDR_LEN)
        return 0;
    if ((f[ETH_HDR_LEN] >> 4) != 6u)
        return 0;
    plen = (uint16_t)(((unsigned)f[ETH_HDR_LEN + 4] << 8) | (unsigned)f[ETH_HDR_LEN + 5]);
    if ((unsigned long)ETH_HDR_LEN + IPV6_HDR_LEN + plen > len)
        return 0;
    return 1;
}

#endif /* NET_IPV6_H */
