/* userspace/net/tcp.h - TCP header view. Stub: parse only, no handshake. */
#ifndef NET_TCP_H
#define NET_TCP_H

#include <stdint.h>
#include "ip.h"

#define TCP_HDR_MIN 20u
#define TCP_FIN 0x01u
#define TCP_SYN 0x02u
#define TCP_RST 0x04u
#define TCP_PSH 0x08u
#define TCP_ACK 0x10u

static inline int tcp_hdr_ok(const uint8_t *f, unsigned long len)
{
    unsigned ihl, off, doff;
    if (!ip_hdr_ok(f, len) || ip_proto(f, len) != IP_PROTO_TCP)
        return 0;
    ihl = ip_ihl_bytes(f, len);
    off = ETH_HDR_LEN + ihl;
    if (len < (unsigned long)off + TCP_HDR_MIN)
        return 0;
    doff = (unsigned)(f[off + 12] >> 4) * 4u;
    if (doff < TCP_HDR_MIN)
        return 0;
    if (len < (unsigned long)off + doff)
        return 0;
    return 1;
}

static inline uint16_t tcp_dport(const uint8_t *f, unsigned long len)
{
    unsigned ihl, off;
    if (!tcp_hdr_ok(f, len))
        return 0;
    ihl = ip_ihl_bytes(f, len);
    off = ETH_HDR_LEN + ihl;
    return (uint16_t)(((unsigned)f[off + 2] << 8) | (unsigned)f[off + 3]);
}

static inline unsigned tcp_flags(const uint8_t *f, unsigned long len)
{
    unsigned ihl, off;
    if (!tcp_hdr_ok(f, len))
        return 0;
    ihl = ip_ihl_bytes(f, len);
    off = ETH_HDR_LEN + ihl;
    return (unsigned)(f[off + 13] & 0x3Fu);
}

#endif /* NET_TCP_H */
