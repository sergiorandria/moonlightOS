/* userspace/net/stack.c - Net stack: UDP send builder + RX queue + dispatch.
 * Pure C, host-testable, libc-free (stdint.h only, byte loops) so the
 * freestanding net ELF may share it. Canonical addrs/ARP via arp_cache.h,
 * checksums via cksum.h. */
#include "stack.h"

#include "arp_cache.h"
#include "cksum.h"
#include "eth.h"
#include "sock.h" /* TCP demux: net_sock_demux (bound-socket gate) */

/* sock.c owns the single TCB; sock.h intentionally omits the bind API
 * (Task 2 single-TU rationale: both consumers include sock.c), so the
 * one accessor used here is declared locally. */
struct net_tcp_conn *net_sock_tcp(int id);

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

/* ---- TCP RX demux (seam Task 3, spec Sec 4) ----
 * Single-TCB shape: a segment enters the stream queue only when it is
 * addressed to the bound socket (dport demux + TCB holder), the TCB is
 * ESTABLISHED, no control flag the seam owns is set (SYN/RST/FIN), and
 * the peer (sport/sip) matches the open. Anything else returns
 * NET_CLASS_TCP without queueing: silent drop, same as the UDP carve.
 * In-order PSH/ACK (seq == rcv_nxt, payload <= TCP_MSS_DEFAULT 536)
 * enqueues, advances rcv_nxt, and parks a pure ACK (seq = snd_nxt,
 * ack = new rcv_nxt). OOO, duplicate, oversize, and queue-full arrivals
 * drop the payload but still park the duplicate ACK (current rcv_nxt),
 * prompting the peer's retransmit. No reassembly buffer in this slice:
 * a dropped segment stalls until the peer retransmits. snd_nxt advances
 * on TX only (RFC 793: RX advances rcv_nxt; the Task 2 send seam owns
 * snd_nxt); pure ACKs (no payload) are accepted with no queue change. */
#define NET_TCP_QDEPTH 4u

struct tcp_slot
{
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t dst_port;
    unsigned long len;
    uint8_t payload[TCP_MSS_DEFAULT];
};

static struct tcp_slot s_tq[NET_TCP_QDEPTH];
static unsigned s_tqhead;
static unsigned s_tqcount;

/* Parked pure ACK for the last ESTABLISHED data decision (in-order ACK
 * or duplicate ACK; v2_main transmits then clears, exactly once). The
 * builder mirrors the tcp.h pure-ACK bytes (IP id 0x12/0x34, TTL 64,
 * window 2048). net_stack_rx has no frame out-param, so the frame parks
 * here like the net_sock_tcp_tx seam. */
/* Per-dport parked ACKs (back-to-back arrivals for different ports must
 * not clobber each other; Ref: RFC 793 duplicate-ACK duty). 4 slots
 * mirror NET_TCP_QDEPTH; same-dport parks overwrite. */
#define NET_TCP_ACK_SLOTS 4u
struct tcp_ack_slot
{
    uint16_t dport;
    unsigned long len;
    uint8_t frame[ETH_HDR_LEN + IP_MIN + TCP_HDR_MIN];
    int used;
};
static struct tcp_ack_slot s_tack[NET_TCP_ACK_SLOTS];

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
    s_tqhead = 0;
    s_tqcount = 0;
    {
        unsigned qi;
        for (qi = 0; qi < NET_TCP_ACK_SLOTS; qi++) /* bound: 4 */
            s_tack[qi].used = 0;
    }
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

/* Byte-loop slot copy: same libc-free discipline as udp_slot_copy. */
static void tcp_slot_copy(struct tcp_slot *d, const struct tcp_slot *s)
{
    unsigned i;
    d->src_ip = s->src_ip;
    d->src_port = s->src_port;
    d->dst_port = s->dst_port;
    d->len = s->len;
    for (i = 0; i < (unsigned)sizeof(d->payload); i++) /* bound: 536 */
        d->payload[i] = s->payload[i];
}

/* Park one pure ACK (seq = snd_nxt, ack = rcv_nxt) for the bound TCB.
 * Byte-mirrors the tcp.h pure-ACK reply (same IP id/TTL/window). */
static void tcp_ack_park_dport(uint16_t dport, const uint8_t *frame, unsigned long flen)
{
    unsigned i, k;
    for (i = 0; i < NET_TCP_ACK_SLOTS; i++) /* bound: 4 */
    {
        if (s_tack[i].used && s_tack[i].dport == dport)
            break;
    }
    if (i >= NET_TCP_ACK_SLOTS)
    {
        for (k = 0; k < NET_TCP_ACK_SLOTS; k++) /* bound: 4 */
        {
            if (!s_tack[k].used)
                break;
        }
        i = (k < NET_TCP_ACK_SLOTS) ? k : 0u; /* full: overwrite oldest */
    }
    s_tack[i].dport = dport;
    s_tack[i].len = flen;
    for (k = 0; k < (unsigned)sizeof(s_tack[i].frame); k++) /* bound: 54 */
        s_tack[i].frame[k] = frame[k];
    s_tack[i].used = 1;
}

static void tcp_ack_build(const struct net_tcp_conn *c, const uint8_t *f, uint16_t dport)
{
    unsigned i;
    uint16_t ck;
    uint8_t fr[ETH_HDR_LEN + IP_MIN + TCP_HDR_MIN];
    uint32_t sip = stack_ip_at(f, ETH_HDR_LEN + 12);
    for (i = 0; i < 6u; i++) /* bound: 6 */
    {
        fr[i] = f[6 + i];
        fr[6 + i] = NET_MAC_SELF[i];
    }
    fr[12] = 0x08u;
    fr[13] = 0x00u;
    fr[14] = 0x45u;
    fr[15] = 0x00u;
    fr[16] = 0u;
    fr[17] = 40u;
    fr[18] = 0x12u;
    fr[19] = 0x34u;
    fr[20] = 0x40u;
    fr[21] = 0x00u;
    fr[22] = 64u;
    fr[23] = IP_PROTO_TCP;
    fr[24] = 0u;
    fr[25] = 0u;
    stack_ip_put(fr, 26, (uint32_t)NET_IP_SELF);
    stack_ip_put(fr, 30, sip);
    ck = net_ip_checksum(fr + ETH_HDR_LEN, IP_MIN);
    fr[24] = (uint8_t)(ck >> 8);
    fr[25] = (uint8_t)(ck & 0xFFu);
    fr[34] = (uint8_t)(c->lport >> 8);
    fr[35] = (uint8_t)c->lport;
    fr[36] = (uint8_t)(c->rport >> 8);
    fr[37] = (uint8_t)c->rport;
    fr[38] = (uint8_t)(c->snd_nxt >> 24);
    fr[39] = (uint8_t)(c->snd_nxt >> 16);
    fr[40] = (uint8_t)(c->snd_nxt >> 8);
    fr[41] = (uint8_t)c->snd_nxt;
    fr[42] = (uint8_t)(c->rcv_nxt >> 24);
    fr[43] = (uint8_t)(c->rcv_nxt >> 16);
    fr[44] = (uint8_t)(c->rcv_nxt >> 8);
    fr[45] = (uint8_t)c->rcv_nxt;
    fr[46] = (uint8_t)(5u << 4);
    fr[47] = (uint8_t)TCP_ACK;
    fr[48] = 0x08u;
    fr[49] = 0x00u;
    fr[50] = 0u;
    fr[51] = 0u;
    fr[52] = 0u;
    fr[53] = 0u;
    ck = net_tcp_checksum((uint32_t)NET_IP_SELF, sip, fr + ETH_HDR_LEN + IP_MIN,
                          (unsigned)TCP_HDR_MIN);
    fr[50] = (uint8_t)(ck >> 8);
    fr[51] = (uint8_t)(ck & 0xFFu);
    tcp_ack_park_dport(dport, fr, sizeof(fr));
}

/* TCP branch of net_stack_rx: validate, demux by dport, and queue
 * in-order stream bytes (see the state comment above). The TCP segment
 * length comes from the IP total (tot - ihl), not the wire length, so
 * Ethernet-padded frames (e.g. 54B pure ACKs padded to 60B) still
 * checksum over exactly the bytes the peer sent. */
static int tcp_rx_demux(const uint8_t *f, unsigned long len)
{
    unsigned ihl, off, doff;
    uint16_t tot;
    uint32_t sip, dip;
    unsigned long seglen, plen;
    uint16_t sport, dport;
    unsigned flags;
    uint32_t seq;
    int sid;
    struct net_tcp_conn *t;
    unsigned idx, i;
    ihl = ip_ihl_bytes(f, len);
    if (!ihl)
        return NET_CLASS_DROP;
    off = ETH_HDR_LEN + ihl;
    tot = (uint16_t)(((unsigned)f[ETH_HDR_LEN + 2] << 8) | (unsigned)f[ETH_HDR_LEN + 3]);
    if ((unsigned long)ETH_HDR_LEN + (unsigned long)tot > len)
        return NET_CLASS_DROP;
    if (tot < ihl)
        return NET_CLASS_DROP;
    doff = (unsigned)(f[off + 12] >> 4) * 4u;
    if (doff < TCP_HDR_MIN)
        return NET_CLASS_DROP;
    if ((unsigned long)off + (unsigned long)doff > len)
        return NET_CLASS_DROP;
    if ((unsigned)tot - ihl < doff)
        return NET_CLASS_DROP;
    if (net_ip_checksum(f + ETH_HDR_LEN, ihl) != 0)
        return NET_CLASS_DROP;
    sip = stack_ip_at(f, ETH_HDR_LEN + 12);
    dip = stack_ip_at(f, ETH_HDR_LEN + 16);
    seglen = (unsigned long)tot - (unsigned long)ihl;
    if ((unsigned long)off + seglen > len)
        return NET_CLASS_DROP;
    if (net_tcp_checksum(sip, dip, f + off, (unsigned)seglen) != 0)
        return NET_CLASS_DROP;
    sport = (uint16_t)(((unsigned)f[off] << 8) | (unsigned)f[off + 1]);
    dport = (uint16_t)(((unsigned)f[off + 2] << 8) | (unsigned)f[off + 3]);
    flags = (unsigned)(f[off + 13] & 0x3Fu);
    seq = (uint32_t)(((uint32_t)f[off + 4] << 24) | ((uint32_t)f[off + 5] << 16) |
                     ((uint32_t)f[off + 6] << 8) | (uint32_t)f[off + 7]);
    sid = net_sock_demux(dport);
    t = net_sock_tcp(sid);
    if (!t)
        return NET_CLASS_TCP; /* unbound port: silent drop */
    if (t->state != NET_TCP_ESTABLISHED)
        return NET_CLASS_TCP; /* handshake/RST leg owns it (seam) */
    if (flags & (unsigned)(TCP_SYN | TCP_RST | TCP_FIN))
        return NET_CLASS_TCP; /* seam owns control flags (no FIN support) */
    if (sport != t->rport || sip != t->rip)
        return NET_CLASS_TCP; /* spoof/foreign: silent drop */
    plen = seglen - (unsigned long)doff;
    if (plen == 0)
        return NET_CLASS_TCP; /* pure ACK: accepted, nothing queued */
    if (seq != t->rcv_nxt || plen > (unsigned long)TCP_MSS_DEFAULT)
    {
        tcp_ack_build(t, f, dport); /* OOO/dup/oversize: duplicate ACK */
        return NET_CLASS_TCP;
    }
    if (s_tqcount >= NET_TCP_QDEPTH)
    {
        tcp_ack_build(t, f, dport); /* full: drop newest, still ACK */
        return NET_CLASS_TCP;
    }
    idx = (s_tqhead + s_tqcount) % NET_TCP_QDEPTH;
    /* Fill slot atomically before incrementing count (same
     * defense-in-depth as the UDP path). */
    s_tq[idx].src_ip = sip;
    s_tq[idx].src_port = sport;
    s_tq[idx].dst_port = dport;
    s_tq[idx].len = plen;
    for (i = 0; i < (unsigned)plen; i++) /* bound: 536 */
        s_tq[idx].payload[i] = f[off + doff + i];
    /* Memory barrier to ensure slot is visible before count increment */
    __asm__ volatile("" ::: "memory");
    s_tqcount++;
    t->rcv_nxt += (uint32_t)plen;
    tcp_ack_build(t, f, dport); /* in-order ACK (ack = new rcv_nxt) */
    return NET_CLASS_TCP;
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
    frame_out[14] = IP_VER_IHL;
    frame_out[15] = IP_TOS_DSCP;
    frame_out[16] = (uint8_t)(ip_len >> 8);
    frame_out[17] = (uint8_t)(ip_len & 0xFFu);
    frame_out[18] = 0x12;
    frame_out[19] = 0x34;
    frame_out[20] = IP_TTL_DEFAULT;
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
    /* UDP header: offset 34 = ETH_HDR_LEN(14) + IP_MIN(20) + UDP_OFF_SRC(0) */
    frame_out[34] = (uint8_t)(src_port >> 8);
    frame_out[35] = (uint8_t)(src_port & 0xFFu);
    frame_out[36] = (uint8_t)(dst_port >> 8);
    frame_out[37] = (uint8_t)(dst_port & 0xFFu);
    frame_out[38] = (uint8_t)(ulen >> 8);
    frame_out[39] = (uint8_t)(ulen & 0xFFu);
    frame_out[40] = 0; /* UDP checksum placeholder */
    frame_out[41] = 0;
    for (i = 0; i < (unsigned)len; i++)
        frame_out[42 + i] = payload[i]; /* Payload starts at offset 42 */
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
    if (c == NET_CLASS_TCP)
        return tcp_rx_demux(f, len);
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
    /* Fill slot atomically before incrementing count to avoid race
     * with concurrent net_udp_recv_from shifts (single-threaded
     * net ELF, but defense-in-depth for future expansion). */
    s_q[idx].src_ip = sip;
    s_q[idx].src_port = (uint16_t)(((unsigned)f[off] << 8) | (unsigned)f[off + 1]);
    s_q[idx].dst_port = (uint16_t)(((unsigned)f[off + 2] << 8) | (unsigned)f[off + 3]);
    s_q[idx].len = plen;
    for (i = 0; i < (unsigned)plen; i++)
        s_q[idx].payload[i] = f[off + UDP_HDR_LEN + i];
    /* Memory barrier to ensure slot is visible before count increment */
    __asm__ volatile("" ::: "memory");
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
        {
            unsigned src_idx = (s_qhead + j) % NET_UDP_QDEPTH;
            unsigned dst_idx = (s_qhead + j + 1u) % NET_UDP_QDEPTH;
            udp_slot_copy(&s_q[dst_idx], &s_q[src_idx]);
        }
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

/* Per-socket stream carve: dequeue bytes for dport (FIFO). Same
 * EMPTY/TRUNC contract as net_udp_recv_from. Removal left-compacts the
 * tail over the hole so order is preserved. */
int net_tcp_recv_from(uint16_t dport, uint8_t *buf, unsigned long cap, uint32_t *src_ip,
                      uint16_t *src_port, int *trunc)
{
    unsigned k, j;
    struct tcp_slot s;
    for (k = 0; k < s_tqcount; k++) /* bound: 4 */
    {
        unsigned idx = (s_tqhead + k) % NET_TCP_QDEPTH;
        if (s_tq[idx].dst_port != dport)
            continue;
        tcp_slot_copy(&s, &s_tq[idx]);
        for (j = k; j + 1u < s_tqcount; j++) /* bound: 4 */
        {
            unsigned dst_idx = (s_tqhead + j) % NET_TCP_QDEPTH;
            unsigned src_idx = (s_tqhead + j + 1u) % NET_TCP_QDEPTH;
            tcp_slot_copy(&s_tq[dst_idx], &s_tq[src_idx]);
        }
        s_tqcount--;
        if (cap < s.len)
        {
            unsigned m;
            unsigned long n = cap;
            if (buf)
            {
                for (m = 0; m < (unsigned)n; m++) /* bound: 536 */
                    buf[m] = s.payload[m];
            }
            if (src_ip)
                *src_ip = s.src_ip;
            if (src_port)
                *src_port = s.src_port;
            if (trunc)
                *trunc = 1;
            return -(NET_ERR_TRUNC);
        }
        if (s.len > 0 && !buf)
        {
            if (src_ip)
                *src_ip = s.src_ip;
            if (src_port)
                *src_port = s.src_port;
            if (trunc)
                *trunc = 1;
            return -(NET_ERR_TRUNC);
        }
        if (buf)
        {
            for (j = 0; j < (unsigned)s.len; j++) /* bound: 536 */
                buf[j] = s.payload[j];
        }
        if (src_ip)
            *src_ip = s.src_ip;
        if (src_port)
            *src_port = s.src_port;
        if (trunc)
            *trunc = 0;
        return (int)s.len;
    }
    if (trunc)
        *trunc = 0;
    return -(NET_ERR_EMPTY);
}

/* Drop queued stream bytes selected by the predicate (S_CLOSE drain). */
void net_tcp_drop_if(int (*drop)(uint16_t dport))
{
    unsigned rd, wr = 0;
    unsigned total;
    if (!drop)
        return;
    total = s_tqcount;
    for (rd = 0; rd < total; rd++) /* bound: 4 */
    {
        unsigned ridx = (s_tqhead + rd) % NET_TCP_QDEPTH;
        if (drop(s_tq[ridx].dst_port))
            continue;
        if (wr != rd)
            tcp_slot_copy(&s_tq[(s_tqhead + wr) % NET_TCP_QDEPTH], &s_tq[ridx]);
        wr++;
    }
    s_tqcount = wr;
}

/* Legacy global readout removed: use net_tcp_ack_tx_for/clear_for. */

/* Per-dport parked-ACK readout (back-to-back arrivals for different ports
 * must not clobber each other). Returns frame bytes + len, or 0/0. */
const uint8_t *net_tcp_ack_tx_for(uint16_t dport, unsigned long *len_out)
{
    unsigned i;
    for (i = 0; i < NET_TCP_ACK_SLOTS; i++) /* bound: 4 */
    {
        if (s_tack[i].used && s_tack[i].dport == dport)
        {
            if (len_out)
                *len_out = s_tack[i].len;
            return s_tack[i].frame;
        }
    }
    if (len_out)
        *len_out = 0;
    return 0;
}

/* Release one port's parked ACK without transmitting. */
void net_tcp_ack_clear_for(uint16_t dport)
{
    unsigned i;
    for (i = 0; i < NET_TCP_ACK_SLOTS; i++) /* bound: 4 */
    {
        if (s_tack[i].used && s_tack[i].dport == dport)
            s_tack[i].used = 0;
    }
}
