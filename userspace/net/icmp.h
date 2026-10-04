/* userspace/net/icmp.h - ICMPv4 echo header. Parse only. */
#ifndef NET_ICMP_H
#define NET_ICMP_H

#include <stdint.h>
#include "ip.h"

#define ICMP_HDR_MIN 8u
#define ICMP_ECHO_REPLY 0u
#define ICMP_ECHO_REQUEST 8u

static inline int icmp_hdr_ok(const uint8_t *f, unsigned long len)
{
    unsigned ihl, off;
    unsigned type;
    if (!ip_hdr_ok(f, len) || ip_proto(f, len) != IP_PROTO_ICMP)
        return 0;
    ihl = ip_ihl_bytes(f, len);
    off = ETH_HDR_LEN + ihl;
    if (len < (unsigned long)off + ICMP_HDR_MIN)
        return 0;
    type = f[off];
    if (type != ICMP_ECHO_REQUEST && type != ICMP_ECHO_REPLY)
        return 0;
    return 1;
}

#endif /* NET_ICMP_H */
