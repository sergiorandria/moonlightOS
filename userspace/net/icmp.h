/* userspace/net/icmp.h - ICMPv4 echo header. Parse + build (RFC 792).
 * Pure C, host-testable, libc-free (stdint.h only) for freestanding use. */
#ifndef NET_ICMP_H
#define NET_ICMP_H

#include <stdint.h>

#include "arp_cache.h"
#include "cksum.h"
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

/* Checksum over ICMP message bytes (same one's complement as IP). */
static inline uint16_t net_icmp_checksum(const uint8_t *msg, unsigned mlen)
{
    return net_ip_checksum(msg, mlen);
}

static inline uint16_t net_icmp_id(const uint8_t *f, unsigned long len)
{
    unsigned ihl, off;
    if (!icmp_hdr_ok(f, len))
        return 0;
    ihl = ip_ihl_bytes(f, len);
    off = ETH_HDR_LEN + ihl;
    return (uint16_t)(((unsigned)f[off + 4] << 8) | (unsigned)f[off + 5]);
}

static inline uint16_t net_icmp_seq(const uint8_t *f, unsigned long len)
{
    unsigned ihl, off;
    if (!icmp_hdr_ok(f, len))
        return 0;
    ihl = ip_ihl_bytes(f, len);
    off = ETH_HDR_LEN + ihl;
    return (uint16_t)(((unsigned)f[off + 6] << 8) | (unsigned)f[off + 7]);
}

/* Build an echo request frame (dst MAC from ARP lookup by caller).
 * Returns 0 with *outlen set, or -1 (bad args / too big for 1514B MTU). */
static inline int net_icmp_build_request(const uint8_t *dmac, uint32_t dst_ip, uint16_t id,
                                         uint16_t seq, const uint8_t *payload, unsigned long plen,
                                         uint8_t *out, unsigned long *outlen)
{
    unsigned i;
    uint16_t ck;
    unsigned long total;
    if (!dmac || !out || !outlen || (!payload && plen))
        return -1;
    total = (unsigned long)ETH_HDR_LEN + (unsigned long)IP_MIN + (unsigned long)ICMP_HDR_MIN + plen;
    if (total > 1514UL)
        return -1;
    for (i = 0; i < 6u; i++)
    {
        out[i] = dmac[i];
        out[6 + i] = NET_MAC_SELF[i];
    }
    out[12] = 0x08u;
    out[13] = 0x00u;
    out[14] = 0x45u;
    out[15] = 0x00u;
    total = 20u + 8u + plen;
    out[16] = (uint8_t)(total >> 8);
    out[17] = (uint8_t)total;
    out[18] = 0x12u;
    out[19] = 0x34u; /* fixed id, like the UDP builder */
    out[20] = 0x40u;
    out[21] = 0x00u;
    out[22] = 64u; /* TTL */
    out[23] = IP_PROTO_ICMP;
    out[24] = 0u;
    out[25] = 0u;
    out[26] = (uint8_t)(NET_IP_SELF >> 24);
    out[27] = (uint8_t)(NET_IP_SELF >> 16);
    out[28] = (uint8_t)(NET_IP_SELF >> 8);
    out[29] = (uint8_t)NET_IP_SELF;
    out[30] = (uint8_t)(dst_ip >> 24);
    out[31] = (uint8_t)(dst_ip >> 16);
    out[32] = (uint8_t)(dst_ip >> 8);
    out[33] = (uint8_t)dst_ip;
    ck = net_ip_checksum(out + ETH_HDR_LEN, IP_MIN);
    out[24] = (uint8_t)(ck >> 8);
    out[25] = (uint8_t)(ck & 0xFFu);
    out[34] = ICMP_ECHO_REQUEST;
    out[35] = 0u;
    out[36] = 0u;
    out[37] = 0u;
    out[38] = (uint8_t)(id >> 8);
    out[39] = (uint8_t)id;
    out[40] = (uint8_t)(seq >> 8);
    out[41] = (uint8_t)seq;
    for (i = 0; i < plen; i++)
        out[42 + i] = payload[i];
    ck = net_icmp_checksum(out + ETH_HDR_LEN + IP_MIN, (unsigned)(ICMP_HDR_MIN + plen));
    out[36] = (uint8_t)(ck >> 8);
    out[37] = (uint8_t)(ck & 0xFFu);
    *outlen = (unsigned long)ETH_HDR_LEN + 20u + 8u + plen;
    return 0;
}

/* True iff f is an echo REPLY whose id/seq match (caller compares TXID). */
static inline int net_ping_match(const uint8_t *f, unsigned long len, uint16_t id, uint16_t seq)
{
    unsigned ihl, off;
    if (!icmp_hdr_ok(f, len))
        return -1;
    ihl = ip_ihl_bytes(f, len);
    off = ETH_HDR_LEN + ihl;
    if (f[off] != ICMP_ECHO_REPLY)
        return -1;
    if (net_icmp_id(f, len) != id || net_icmp_seq(f, len) != seq)
        return -1;
    return 0;
}

#endif /* NET_ICMP_H */
