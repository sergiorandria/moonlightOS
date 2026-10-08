/* userspace/net/udp.h - UDP header view. Stub: parse only, no sockets. */
#ifndef NET_UDP_H
#define NET_UDP_H

#include <stdint.h>
#include "ip.h"

#define UDP_HDR_LEN 8u

static inline int udp_hdr_ok(const uint8_t *f, unsigned long len)
{
    unsigned ihl, off;
    uint16_t ulen;
    if (!ip_hdr_ok(f, len) || ip_proto(f, len) != IP_PROTO_UDP)
        return 0;
    ihl = ip_ihl_bytes(f, len);
    off = ETH_HDR_LEN + ihl;
    if (len < (unsigned long)off + UDP_HDR_LEN)
        return 0;
    ulen = (uint16_t)(((unsigned)f[off + 4] << 8) | (unsigned)f[off + 5]);
    if (ulen < UDP_HDR_LEN)
        return 0;
    if ((unsigned long)off + ulen > len)
        return 0;
    return 1;
}

static inline uint16_t udp_dport(const uint8_t *f, unsigned long len)
{
    unsigned ihl, off;
    if (!udp_hdr_ok(f, len))
        return 0;
    ihl = ip_ihl_bytes(f, len);
    off = ETH_HDR_LEN + ihl;
    return (uint16_t)(((unsigned)f[off + 2] << 8) | (unsigned)f[off + 3]);
}

#endif /* NET_UDP_H */
