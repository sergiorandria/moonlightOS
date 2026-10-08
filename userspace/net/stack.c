/* userspace/net/stack.c - Net stack: UDP send builder + RX queue + dispatch.
 * Pure C, host-testable, libc-free (stdint.h only, byte loops) so the
 * freestanding net ELF may share it. Canonical addrs/ARP via arp_cache.h,
 * checksums via cksum.h. */
#include "stack.h"

#include "arp_cache.h"
#include "cksum.h"
#include "eth.h"

#define NET_UDP_QDEPTH 4u
#define NET_UDP_MAX_PAYLOAD (ETH_FRAME_MAX - ETH_HDR_LEN - IP_MIN - UDP_HDR_LEN)

struct udp_slot
{
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t dst_port;
    unsigned long len;
    uint8_t payload[ETH_FRAME_MAX - ETH_HDR_LEN - IP_MIN - UDP_HDR_LEN];
};

static int net_stack_up;
static struct udp_slot s_q[NET_UDP_QDEPTH];
static unsigned s_qhead;
static unsigned s_qcount;

/* Byte-loop slot copy: struct assignment lowers to memcpy, which the
 * freestanding net ELF (-nostdlib) cannot link. Field-wise scalars plus
 * a payload byte loop (the established libc-free pattern). */
static void udp_slot_copy(struct udp_slot *d, const struct udp_slot *s)
{
    unsigned i;
    d->src_ip = s->src_ip;
    d->src_port = s->src_port;
    d->dst_port = s->dst_port;
    d->len = s->len;
    for (i = 0; i < (unsigned)sizeof(d->payload); i++) /* bound: 1472 */
        d->payload[i] = s->payload[i];
}

int net_stack_init(void)
{
    net_stack_up = 1;
    s_qhead = 0;
    s_qcount = 0;
    net_arp_init();
    return 0;
}

static uint32_t stack_ip_at(const uint8_t *f, unsigned o)
{
    return (uint32_t)(((uint32_t)f[o] << 24) | ((uint32_t)f[o + 1] << 16) |
                      ((uint32_t)f[o + 2] << 8) | (uint32_t)f[o + 3]);
}

static void stack_ip_put(uint8_t *f, unsigned o, uint32_t ip)
{
    f[o] = (uint8_t)(ip >> 24);
    f[o + 1] = (uint8_t)(ip >> 16);
    f[o + 2] = (uint8_t)(ip >> 8);
    f[o + 3] = (uint8_t)ip;
}

int net_stack_udp_send(uint32_t dst_ip, uint16_t dst_port, uint16_t src_port,
                       const uint8_t *payload, unsigned long len, uint8_t *frame_out,
                       unsigned long *frame_len)
{
    uint8_t dmac[6];
    unsigned long total;
    unsigned long ip_len;
    unsigned ulen;
    unsigned i;
    uint16_t ck;
    uint32_t sip = NET_IP_SELF;
    if (!frame_out || !frame_len)
        return -2;
    if (len > 0 && !payload)
        return -2;
    total = (unsigned long)ETH_HDR_LEN + IP_MIN + (unsigned long)UDP_HDR_LEN + len;
    if (total > (unsigned long)ETH_FRAME_MAX)
        return -2;
    if (net_arp_lookup(dst_ip, dmac) != 0)
        return -1;
    for (i = 0; i < ETH_ADDR_LEN; i++)
    {
        frame_out[i] = dmac[i];
        frame_out[6 + i] = NET_MAC_SELF[i];
    }
    frame_out[12] = 0x08;
    frame_out[13] = 0x00;
    ip_len = IP_MIN + (unsigned long)UDP_HDR_LEN + len;
    frame_out[14] = 0x45;
    frame_out[15] = 0x00;
    frame_out[16] = (uint8_t)(ip_len >> 8);
    frame_out[17] = (uint8_t)(ip_len & 0xFFu);
    frame_out[18] = 0x12;
    frame_out[19] = 0x34;
    frame_out[20] = 0x40;
    frame_out[21] = 0x00;
    frame_out[22] = 64;
    frame_out[23] = IP_PROTO_UDP;
    frame_out[24] = 0;
    frame_out[25] = 0;
    stack_ip_put(frame_out, 26, sip);
    stack_ip_put(frame_out, 30, dst_ip);
    ck = net_ip_checksum(frame_out + ETH_HDR_LEN, IP_MIN);
    frame_out[24] = (uint8_t)(ck >> 8);
    frame_out[25] = (uint8_t)(ck & 0xFFu);
    ulen = UDP_HDR_LEN + (unsigned)len;
    frame_out[34] = (uint8_t)(src_port >> 8);
    frame_out[35] = (uint8_t)(src_port & 0xFFu);
    frame_out[36] = (uint8_t)(dst_port >> 8);
    frame_out[37] = (uint8_t)(dst_port & 0xFFu);
    frame_out[38] = (uint8_t)(ulen >> 8);
    frame_out[39] = (uint8_t)(ulen & 0xFFu);
    frame_out[40] = 0;
    frame_out[41] = 0;
    for (i = 0; i < (unsigned)len; i++)
        frame_out[42 + i] = payload[i];
    ck = net_udp_checksum(sip, dst_ip, frame_out + ETH_HDR_LEN + IP_MIN, ulen);
    frame_out[40] = (uint8_t)(ck >> 8);
    frame_out[41] = (uint8_t)(ck & 0xFFu);
    *frame_len = total;
    return 0;
}

int net_stack_rx(const uint8_t *f, unsigned long len)
{
    int c;
    unsigned ihl, off;
    uint16_t tot, ulen;
    uint32_t sip, dip;
    unsigned long plen;
    unsigned idx, i;
    if (!net_stack_up)
        return NET_CLASS_DROP;
    if (!f)
        return NET_CLASS_DROP;
    if (len > (unsigned long)ETH_FRAME_MAX)
        return NET_CLASS_DROP;
    c = net_classify(f, len);
    if (c == NET_CLASS_ARP)
    {
        net_arp_learn(f, len);
        return c;
    }
    if (c != NET_CLASS_UDP)
        return c;
    ihl = ip_ihl_bytes(f, len);
    if (!ihl)
        return NET_CLASS_DROP;
    off = ETH_HDR_LEN + ihl;
    tot = (uint16_t)(((unsigned)f[ETH_HDR_LEN + 2] << 8) | (unsigned)f[ETH_HDR_LEN + 3]);
    if ((unsigned long)ETH_HDR_LEN + (unsigned long)tot > len)
        return NET_CLASS_DROP;
    if (tot < ihl)
        return NET_CLASS_DROP;
    ulen = (uint16_t)(((unsigned)f[off + 4] << 8) | (unsigned)f[off + 5]);
    if (ulen < UDP_HDR_LEN)
        return NET_CLASS_DROP;
    if ((unsigned long)off + (unsigned long)ulen > len)
        return NET_CLASS_DROP;
    if ((unsigned)tot - ihl < (unsigned)ulen)
        return NET_CLASS_DROP;
    if (net_ip_checksum(f + ETH_HDR_LEN, ihl) != 0)
        return NET_CLASS_DROP;
    sip = stack_ip_at(f, ETH_HDR_LEN + 12);
    dip = stack_ip_at(f, ETH_HDR_LEN + 16);
    if (net_udp_checksum(sip, dip, f + off, ulen) != 0)
        return NET_CLASS_DROP;
    plen = (unsigned long)ulen - (unsigned long)UDP_HDR_LEN;
    if (plen > (unsigned long)NET_UDP_MAX_PAYLOAD)
        return NET_CLASS_DROP;
    if (s_qcount >= NET_UDP_QDEPTH)
        return NET_CLASS_UDP;
    idx = (s_qhead + s_qcount) % NET_UDP_QDEPTH;
    s_q[idx].src_ip = sip;
    s_q[idx].src_port = (uint16_t)(((unsigned)f[off] << 8) | (unsigned)f[off + 1]);
    s_q[idx].dst_port = (uint16_t)(((unsigned)f[off + 2] << 8) | (unsigned)f[off + 3]);
    s_q[idx].len = plen;
    for (i = 0; i < (unsigned)plen; i++)
        s_q[idx].payload[i] = f[off + UDP_HDR_LEN + i];
    s_qcount++;
    return NET_CLASS_UDP;
}

/* Build an echo reply for an inbound request to self (caller transmits).
 * Returns 0 with *outlen set, or -1 (not a for-self request). */
int net_stack_icmp_reply(const uint8_t *f, unsigned long len, uint8_t *out, unsigned long *outlen)
{
    unsigned ihl, off, i;
    uint16_t tot, ck;
    uint8_t m[6];
    if (!f || !out || !outlen || !icmp_hdr_ok(f, len))
        return -1;
    ihl = ip_ihl_bytes(f, len);
    off = ETH_HDR_LEN + ihl;
    if (f[off] != ICMP_ECHO_REQUEST)
        return -1;
    if (len > (unsigned long)ETH_FRAME_MAX)
        return -1;
    tot = (uint16_t)(((unsigned)f[ETH_HDR_LEN + 2] << 8) | (unsigned)f[ETH_HDR_LEN + 3]);
    if ((unsigned long)ETH_HDR_LEN + (unsigned long)tot > len)
        return -1;
    if (stack_ip_at(f, ETH_HDR_LEN + 16) != (uint32_t)NET_IP_SELF)
        return -1;
    for (i = 0; i < (unsigned)(ETH_HDR_LEN + tot); i++)
        out[i] = f[i];
    for (i = 0; i < 6u; i++)
    {
        m[i] = out[i];
        out[i] = out[6 + i];
        out[6 + i] = m[i];
    }
    for (i = 0; i < 4u; i++)
    {
        m[i] = out[ETH_HDR_LEN + 12 + i];
        out[ETH_HDR_LEN + 12 + i] = out[ETH_HDR_LEN + 16 + i];
        out[ETH_HDR_LEN + 16 + i] = m[i];
    }
    out[off] = ICMP_ECHO_REPLY;
    out[ETH_HDR_LEN + 10] = 0u;
    out[ETH_HDR_LEN + 11] = 0u;
    ck = net_ip_checksum(out + ETH_HDR_LEN, ihl);
    out[ETH_HDR_LEN + 10] = (uint8_t)(ck >> 8);
    out[ETH_HDR_LEN + 11] = (uint8_t)(ck & 0xFFu);
    out[off + 2] = 0u;
    out[off + 3] = 0u;
    ck = net_icmp_checksum(out + off, (unsigned)((unsigned long)tot - (unsigned long)ihl));
    out[off + 2] = (uint8_t)(ck >> 8);
    out[off + 3] = (uint8_t)(ck & 0xFFu);
    *outlen = (unsigned long)ETH_HDR_LEN + (unsigned long)tot;
    return 0;
}

static int udp_emit(const struct udp_slot *s, uint8_t *buf, unsigned long cap, uint32_t *src_ip,
                    uint16_t *src_port, int *trunc)
{
    unsigned i;
    unsigned long n;
    if (cap < s->len)
    {
        n = cap;
        if (buf)
        {
            for (i = 0; i < (unsigned)n; i++)
                buf[i] = s->payload[i];
        }
        if (src_ip)
            *src_ip = s->src_ip;
        if (src_port)
            *src_port = s->src_port;
        if (trunc)
            *trunc = 1;
        return -(NET_ERR_TRUNC);
    }
    if (s->len > 0 && !buf)
    {
        if (src_ip)
            *src_ip = s->src_ip;
        if (src_port)
            *src_port = s->src_port;
        if (trunc)
            *trunc = 1;
        return -(NET_ERR_TRUNC);
    }
    if (buf)
    {
        for (i = 0; i < (unsigned)s->len; i++)
            buf[i] = s->payload[i];
    }
    if (src_ip)
        *src_ip = s->src_ip;
    if (src_port)
        *src_port = s->src_port;
    if (trunc)
        *trunc = 0;
    n = s->len;
    return (int)n;
}

int net_udp_recv(uint8_t *buf, unsigned long cap, uint32_t *src_ip, uint16_t *src_port, int *trunc)
{
    struct udp_slot s;
    if (s_qcount == 0)
    {
        if (trunc)
            *trunc = 0;
        return -(NET_ERR_EMPTY);
    }
    udp_slot_copy(&s, &s_q[s_qhead]);
    s_qhead = (s_qhead + 1u) % NET_UDP_QDEPTH;
    s_qcount--;
    return udp_emit(&s, buf, cap, src_ip, src_port, trunc);
}

int net_udp_recv_from(uint16_t dport, uint8_t *buf, unsigned long cap, uint32_t *src_ip,
                      uint16_t *src_port, int *trunc)
{
    unsigned k, j;
    struct udp_slot s;
    for (k = 0; k < s_qcount; k++)
    {
        unsigned idx = (s_qhead + k) % NET_UDP_QDEPTH;
        if (s_q[idx].dst_port != dport)
            continue;
        udp_slot_copy(&s, &s_q[idx]);
        for (j = k; j + 1u < s_qcount; j++)
            udp_slot_copy(&s_q[(s_qhead + j) % NET_UDP_QDEPTH],
                          &s_q[(s_qhead + j + 1u) % NET_UDP_QDEPTH]);
        s_qcount--;
        return udp_emit(&s, buf, cap, src_ip, src_port, trunc);
    }
    if (trunc)
        *trunc = 0;
    return -(NET_ERR_EMPTY);
}

void net_udp_drop_if(int (*drop)(uint16_t dport))
{
    unsigned rd, wr = 0;
    unsigned total;
    if (!drop)
        return;
    total = s_qcount;
    for (rd = 0; rd < total; rd++)
    {
        unsigned ridx = (s_qhead + rd) % NET_UDP_QDEPTH;
        if (drop(s_q[ridx].dst_port))
            continue;
        if (wr != rd)
            udp_slot_copy(&s_q[(s_qhead + wr) % NET_UDP_QDEPTH], &s_q[ridx]);
        wr++;
    }
    s_qcount = wr;
}
