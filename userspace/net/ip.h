/* userspace/net/ip.h - IPv4 header checks. Pure C, host-testable.
 * Payload is never interpreted here; ports live in udp.h/tcp.h. */
#ifndef NET_IP_H
#define NET_IP_H

#include <stdint.h>
#include "eth.h"

#define IP_MIN 20u
#define IP_PROTO_ICMP 1u
#define IP_PROTO_TCP 6u
#define IP_PROTO_UDP 17u

static inline unsigned ip_ihl_bytes(const uint8_t *f, unsigned long len)
{
    unsigned ihl;
    if (!f || len < (unsigned long)(ETH_HDR_LEN + IP_MIN))
        return 0;
    if ((f[ETH_HDR_LEN] >> 4) != 4u)
        return 0;
    ihl = (unsigned)(f[ETH_HDR_LEN] & 0x0Fu) * 4u;
    if (ihl < IP_MIN)
        return 0;
    if (len < (unsigned long)ETH_HDR_LEN + ihl)
        return 0;
    return ihl;
}

static inline unsigned ip_proto(const uint8_t *f, unsigned long len)
{
    if (!ip_ihl_bytes(f, len))
        return 0;
    return f[ETH_HDR_LEN + 9];
}

static inline int ip_hdr_ok(const uint8_t *f, unsigned long len)
{
    unsigned ihl = ip_ihl_bytes(f, len);
    uint16_t tot;
    if (!ihl)
        return 0;
    tot = (uint16_t)(((unsigned)f[ETH_HDR_LEN + 2] << 8) | (unsigned)f[ETH_HDR_LEN + 3]);
    if (tot < ihl)
        return 0;
    if ((unsigned long)ETH_HDR_LEN + tot > len)
        return 0;
    return 1;
}

#endif /* NET_IP_H */
