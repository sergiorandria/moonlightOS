/* userspace/net/tcp.h - TCP handshake + active close (RFC 793, lwIP-grounded:
 * single TCB, active open, RST abort, FIN_WAIT). Pure C, libc-free for
 * freestanding use. Data/stream support is explicitly out of scope for
 * this slice. */
#ifndef NET_TCP_H
#define NET_TCP_H

#include <stdint.h>

#include "arp_cache.h"
#include "cksum.h"
#include "ip.h"
#define TCP_HDR_MIN 20u
#define TCP_FIN 0x01u
#define TCP_SYN 0x02u
#define TCP_RST 0x04u
#define TCP_PSH 0x08u
#define TCP_ACK 0x10u
#define TCP_OPT_MSS 2u
#define TCP_MSS_DEFAULT 536u
#define TCP_SYN_HDR_OPT 4u /* MSS kind+len+value */

#define NET_TCP_CLOSED 0
#define NET_TCP_SYN_SENT 1
#define NET_TCP_ESTABLISHED 2
#define NET_TCP_FIN_WAIT 3 /* active close: our FIN sent, peer ACK pending */

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

/* TCP checksum: same one's complement over the pseudo-header as UDP
 * (cksum.h hardcodes proto 17, so TCP carries its own with proto 6). */
static inline uint16_t net_tcp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint8_t *seg,
                                        unsigned slen)
{
    uint32_t sum;
    unsigned i;
    if (!seg)
        return 0;
    sum = ((src_ip >> 16) & 0xFFFFu) + (src_ip & 0xFFFFu) + ((dst_ip >> 16) & 0xFFFFu) +
          (dst_ip & 0xFFFFu) + 6u + (uint32_t)(uint16_t)slen;
    for (i = 0; i + 1 < slen; i += 2)
        sum += (uint32_t)(((uint16_t)seg[i] << 8) | (uint16_t)seg[i + 1]);
    if (i < slen)
        sum += (uint32_t)((uint16_t)seg[i] << 8);
    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}

struct net_tcp_conn
{
    int state;
    uint32_t iss;
    uint32_t irs;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;
    uint16_t lport;
    uint16_t rport;
    uint32_t rip;
    uint64_t retry_deadline; /* rdtime ticks; 0 = unarmed (TX pass arms it) */
    unsigned retry_count;    /* bounded retransmits used (cap owned by retry loop) */
};

/* Active open: init TCB + build SYN with MSS option. */
static inline int net_tcp_syn(struct net_tcp_conn *c, const uint8_t *dmac, uint32_t rip,
                              uint16_t rport, uint16_t lport, uint32_t iss, uint8_t *out,
                              unsigned long *outlen)
{
    unsigned i;
    uint16_t ck;
    unsigned long total;
    if (!c || !dmac || !out || !outlen || rip == 0u || rport == 0u || lport == 0u)
        return -1;
    c->state = NET_TCP_SYN_SENT;
    c->iss = iss;
    c->irs = 0u;
    c->snd_nxt = iss + 1u;
    c->rcv_nxt = 0u;
    c->lport = lport;
    c->rport = rport;
    c->rip = rip;
    c->retry_deadline = 0u;
    c->retry_count = 0u;
    total = (unsigned long)ETH_HDR_LEN + 20u + (unsigned long)TCP_HDR_MIN +
            (unsigned long)TCP_SYN_HDR_OPT;
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
    out[16] = 0u;
    out[17] = (uint8_t)(20u + TCP_HDR_MIN + TCP_SYN_HDR_OPT);
    out[18] = 0x12u;
    out[19] = 0x34u;
    out[20] = 0x40u;
    out[21] = 0x00u;
    out[22] = 64u;
    out[23] = IP_PROTO_TCP;
    out[24] = 0u;
    out[25] = 0u;
    out[26] = (uint8_t)(NET_IP_SELF >> 24);
    out[27] = (uint8_t)(NET_IP_SELF >> 16);
    out[28] = (uint8_t)(NET_IP_SELF >> 8);
    out[29] = (uint8_t)NET_IP_SELF;
    out[30] = (uint8_t)(rip >> 24);
    out[31] = (uint8_t)(rip >> 16);
    out[32] = (uint8_t)(rip >> 8);
    out[33] = (uint8_t)rip;
    ck = net_ip_checksum(out + ETH_HDR_LEN, IP_MIN);
    out[24] = (uint8_t)(ck >> 8);
    out[25] = (uint8_t)(ck & 0xFFu);
    out[34] = (uint8_t)(lport >> 8);
    out[35] = (uint8_t)lport;
    out[36] = (uint8_t)(rport >> 8);
    out[37] = (uint8_t)rport;
    out[38] = (uint8_t)(iss >> 24);
    out[39] = (uint8_t)(iss >> 16);
    out[40] = (uint8_t)(iss >> 8);
    out[41] = (uint8_t)iss;
    out[42] = 0u;
    out[43] = 0u;
    out[44] = 0u;
    out[45] = 0u;
    out[46] = (uint8_t)(6u << 4);
    out[47] = (uint8_t)TCP_SYN;
    out[48] = 0x08u;
    out[49] = 0x00u; /* window 2048 */
    out[50] = 0u;
    out[51] = 0u;
    out[52] = 0u;
    out[53] = 0u;
    out[54] = (uint8_t)TCP_OPT_MSS;
    out[55] = 4u;
    out[56] = (uint8_t)(TCP_MSS_DEFAULT >> 8);
    out[57] = (uint8_t)TCP_MSS_DEFAULT;
    ck = net_tcp_checksum(NET_IP_SELF, rip, out + ETH_HDR_LEN + IP_MIN,
                          (unsigned)(TCP_HDR_MIN + TCP_SYN_HDR_OPT));
    out[50] = (uint8_t)(ck >> 8);
    out[51] = (uint8_t)(ck & 0xFFu);
    *outlen = total;
    return 0;
}

/* SYN_SENT input: RST aborts to CLOSED; matching SYN-ACK advances to
 * ESTABLISHED with a pure ACK in out (returns 1). RST at any live state
 * (RFC 793 section 3.5: the FIN_WAIT active-close leg included) aborts
 * to CLOSED and zeroes the retry state; the sock seam disarms the
 * waiter. Anything else drops (returns 0). ESTABLISHED/FIN_WAIT non-RST
 * input drops here: stream RX lives in stack.c, peer-ACK close is a
 * later slice. CLOSED input drops. */
static inline int net_tcp_input(struct net_tcp_conn *c, const uint8_t *f, unsigned long len,
                                uint8_t *out, unsigned long *outlen)
{
    unsigned ihl, off, i;
    uint32_t sip, seq, ack;
    unsigned flags;
    uint16_t ck;
    unsigned long total;
    if (!c || !f || !out || !outlen)
        return -1;
    if (c->state == NET_TCP_CLOSED)
        return 0;
    if (!tcp_hdr_ok(f, len))
        return 0;
    ihl = ip_ihl_bytes(f, len);
    off = ETH_HDR_LEN + ihl;
    sip = (uint32_t)(((uint32_t)f[ETH_HDR_LEN + 12] << 24) | ((uint32_t)f[ETH_HDR_LEN + 13] << 16) |
                     ((uint32_t)f[ETH_HDR_LEN + 14] << 8) | (uint32_t)f[ETH_HDR_LEN + 15]);
    if (sip != c->rip)
        return 0;
    if (f[off] != (uint8_t)(c->rport >> 8) || f[off + 1] != (uint8_t)c->rport)
        return 0;
    if (f[off + 2] != (uint8_t)(c->lport >> 8) || f[off + 3] != (uint8_t)c->lport)
        return 0;
    if (net_ip_checksum(f + ETH_HDR_LEN, ihl) != 0)
        return 0;
    if (net_tcp_checksum(sip, (uint32_t)NET_IP_SELF, f + off,
                         (unsigned)(len - (unsigned long)off)) != 0)
        return 0;
    flags = (unsigned)f[off + 13];
    if (flags & (unsigned)TCP_RST)
    {
        c->state = NET_TCP_CLOSED;
        c->retry_deadline = 0u;
        c->retry_count = 0u;
        return 0;
    }
    if (c->state != NET_TCP_SYN_SENT)
        return 0;
    if (!(flags & (unsigned)TCP_SYN) || !(flags & (unsigned)TCP_ACK))
        return 0;
    seq = (uint32_t)(((uint32_t)f[off + 4] << 24) | ((uint32_t)f[off + 5] << 16) |
                     ((uint32_t)f[off + 6] << 8) | (uint32_t)f[off + 7]);
    ack = (uint32_t)(((uint32_t)f[off + 8] << 24) | ((uint32_t)f[off + 9] << 16) |
                     ((uint32_t)f[off + 10] << 8) | (uint32_t)f[off + 11]);
    if (ack != c->snd_nxt)
        return 0;
    c->irs = seq;
    c->rcv_nxt = seq + 1u;
    c->state = NET_TCP_ESTABLISHED;
    total = (unsigned long)ETH_HDR_LEN + 20u + (unsigned long)TCP_HDR_MIN;
    for (i = 0; i < 6u; i++)
    {
        out[i] = f[6 + i];
        out[6 + i] = NET_MAC_SELF[i];
    }
    out[12] = 0x08u;
    out[13] = 0x00u;
    out[14] = 0x45u;
    out[15] = 0x00u;
    out[16] = 0u;
    out[17] = 40u;
    out[18] = 0x12u;
    out[19] = 0x34u;
    out[20] = 0x40u;
    out[21] = 0x00u;
    out[22] = 64u;
    out[23] = IP_PROTO_TCP;
    out[24] = 0u;
    out[25] = 0u;
    out[26] = (uint8_t)(NET_IP_SELF >> 24);
    out[27] = (uint8_t)(NET_IP_SELF >> 16);
    out[28] = (uint8_t)(NET_IP_SELF >> 8);
    out[29] = (uint8_t)NET_IP_SELF;
    out[30] = (uint8_t)(sip >> 24);
    out[31] = (uint8_t)(sip >> 16);
    out[32] = (uint8_t)(sip >> 8);
    out[33] = (uint8_t)sip;
    ck = net_ip_checksum(out + ETH_HDR_LEN, IP_MIN);
    out[24] = (uint8_t)(ck >> 8);
    out[25] = (uint8_t)(ck & 0xFFu);
    out[34] = (uint8_t)(c->lport >> 8);
    out[35] = (uint8_t)c->lport;
    out[36] = (uint8_t)(c->rport >> 8);
    out[37] = (uint8_t)c->rport;
    out[38] = (uint8_t)(c->snd_nxt >> 24);
    out[39] = (uint8_t)(c->snd_nxt >> 16);
    out[40] = (uint8_t)(c->snd_nxt >> 8);
    out[41] = (uint8_t)c->snd_nxt;
    out[42] = (uint8_t)(c->rcv_nxt >> 24);
    out[43] = (uint8_t)(c->rcv_nxt >> 16);
    out[44] = (uint8_t)(c->rcv_nxt >> 8);
    out[45] = (uint8_t)c->rcv_nxt;
    out[46] = (uint8_t)(5u << 4);
    out[47] = (uint8_t)TCP_ACK;
    out[48] = 0x08u;
    out[49] = 0x00u;
    out[50] = 0u;
    out[51] = 0u;
    out[52] = 0u;
    out[53] = 0u;
    ck = net_tcp_checksum((uint32_t)NET_IP_SELF, sip, out + ETH_HDR_LEN + IP_MIN,
                          (unsigned)TCP_HDR_MIN);
    out[50] = (uint8_t)(ck >> 8);
    out[51] = (uint8_t)(ck & 0xFFu);
    *outlen = total;
    return 1;
}

#endif /* NET_TCP_H */
