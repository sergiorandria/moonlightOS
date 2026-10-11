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
#define NET_TCP_FIN_WAIT 3   /* active close: our FIN sent, peer ACK pending */
#define NET_TCP_CLOSE_WAIT 4 /* passive close: peer FIN seen+ACKed, our FIN pending */
#define NET_TCP_LAST_ACK 5   /* passive close: our FIN sent, peer ACK pending */
#define NET_TCP_TIME_WAIT 6  /* linger (RFC 793 section 3.5): both closes park here for 2MSL */
/* 2MSL linger, rdtime ticks (~60s at the 10MHz timebase shared with
 * NET_IRQ_TIMEOUT_TICKS). Entry stamps now + this; RST skips it. */
#define NET_TCP_TIME_WAIT_TICKS 600000000UL

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
static inline uint16_t net_tcp_checksum(uint32_t src_ip, uint32_t dst_ip, const uint8_t *seg, unsigned slen)
{
    uint32_t sum;
    unsigned i;
    if (!seg)
        return 0;
    sum = ((src_ip >> 16) & 0xFFFFu) + (src_ip & 0xFFFFu) + ((dst_ip >> 16) & 0xFFFFu) + (dst_ip & 0xFFFFu) + 6u +
          (uint32_t)(uint16_t)slen;
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
static inline int net_tcp_syn(struct net_tcp_conn *c, const uint8_t *dmac, uint32_t rip, uint16_t rport, uint16_t lport,
                              uint32_t iss, uint8_t *out, unsigned long *outlen)
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
    total = (unsigned long)ETH_HDR_LEN + 20u + (unsigned long)TCP_HDR_MIN + (unsigned long)TCP_SYN_HDR_OPT;
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
    ck = net_tcp_checksum(NET_IP_SELF, rip, out + ETH_HDR_LEN + IP_MIN, (unsigned)(TCP_HDR_MIN + TCP_SYN_HDR_OPT));
    out[50] = (uint8_t)(ck >> 8);
    out[51] = (uint8_t)(ck & 0xFFu);
    *outlen = total;
    return 0;
}

/* SYN_SENT input: RST aborts to CLOSED; matching SYN-ACK advances to
 * ESTABLISHED with a pure ACK in out (returns 1). ESTABLISHED input: a
 * peer FIN enters CLOSE_WAIT (RFC 793 section 3.5 passive close) with a
 * pure ACK in out (returns 1); the FIN consumes rcv_nxt + 1 and is never
 * queued as data, so bytes queued before the FIN stay deliverable. Strict
 * in-order: only a FIN with seq == rcv_nxt closes; an off-window FIN
 * drops with ESTABLISHED held (no state change, no reply), so a spoofed
 * FIN cannot tear the connection down or solicit a wrong ACK. Out of
 * scope (Task 1 ruling): a FIN segment's own payload is not queued by
 * this seam -- vectors queue PSH bytes first, then send a header-only
 * FIN -- so rcv_nxt advances by exactly 1 on entry. The retry budget is
 * untouched (an outstanding segment stays armed under the single-flight
 * poll). FIN_WAIT input: the peer's ACK covering our FIN
 * (ack == snd_nxt: FIN consumed one sequence
 * number at build) or any peer FIN (including an early FIN-ACK sent
 * before our FIN was ACKed: simultaneous close) completes the close
 * exactly once to TIME_WAIT (RFC 793 section 3.5 linger: retry_deadline
 * = now + NET_TCP_TIME_WAIT_TICKS, retry disarmed, no reply parked);
 * the sock seam holds the waiter armed across entry (the loop wakes it
 * once, Task 3). Anything else in
 * FIN_WAIT (stale ACK, stray data-shaped segment) drops with FIN_WAIT
 * held, so the FIN retry keeps running. No reply frame is ever parked
 * on the FIN_WAIT close: a bare close needs no wire answer, and
 * duplicate peer FINs arriving after the linger (CLOSED) drop at the top. LAST_ACK
 * input closes exactly once on the covering ACK of our FIN
 * (ack == snd_nxt) to TIME_WAIT (same linger stamp as the FIN_WAIT
 * leg); a duplicate peer FIN parks a re-ACK and holds
 * LAST_ACK (Task 3 ruling, detailed below); a stale ACK holds LAST_ACK
 * with the FIN retry untouched. TIME_WAIT input holds (drops with no
 * reply: duplicate-ACK replies are Task 2). RST at any live state
 * (RFC 793 section 3.5: the FIN_WAIT active-close leg included) aborts
 * to CLOSED and zeroes the retry state (RST skips the linger); the
 * sock seam disarms the
 * waiter. ESTABLISHED non-FIN input
 * drops here: stream RX lives in stack.c. CLOSED input drops.
 *
 * Passive-close duplicates (Task 3 ruling, RFC 793 section 3.5): a
 * retransmitted peer FIN in CLOSE_WAIT or LAST_ACK (seq == rcv_nxt - 1:
 * the entry already consumed one sequence number) parks a pure re-ACK
 * (returns 1, byte-identical to the entry ACK via tcp_park_ack) and holds
 * state -- never a second close. A premature close would drop the
 * duplicate-ACK obligation and (in LAST_ACK) disarm the FIN retry the
 * close still needs; holding keeps the retry alive, so a combined FIN +
 * covering ACK still converges via the retry's plain ACK. Anything else
 * in CLOSE_WAIT/LAST_ACK (stale ACK, stray data-shaped segment,
 * off-window FIN) drops with the state held. */
static inline void tcp_park_ack(const struct net_tcp_conn *c, const uint8_t *f, uint32_t sip, uint8_t *out,
                                unsigned long *outlen)
{
    unsigned i;
    uint16_t ck;
    unsigned long total = (unsigned long)ETH_HDR_LEN + 20u + (unsigned long)TCP_HDR_MIN;
    for (i = 0; i < 6u; i++) /* bound: 6 */
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
    ck = net_tcp_checksum((uint32_t)NET_IP_SELF, sip, out + ETH_HDR_LEN + IP_MIN, (unsigned)TCP_HDR_MIN);
    out[50] = (uint8_t)(ck >> 8);
    out[51] = (uint8_t)(ck & 0xFFu);
    *outlen = total;
}

/* Clock-threading input: now stamps the TIME_WAIT linger (now +
 * NET_TCP_TIME_WAIT_TICKS) on both graceful completions. The legacy
 * net_tcp_input wrapper below passes now = 0 (test-pinned baseline);
 * the loop passes u_rdtime() once it migrates (Task 2). */
static inline int net_tcp_input_at(struct net_tcp_conn *c, const uint8_t *f, unsigned long len, uint8_t *out,
                                   unsigned long *outlen, uint64_t now)
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
    if (net_tcp_checksum(sip, (uint32_t)NET_IP_SELF, f + off, (unsigned)(len - (unsigned long)off)) != 0)
        return 0;
    flags = (unsigned)f[off + 13];
    if (flags & (unsigned)TCP_RST)
    {
        c->state = NET_TCP_CLOSED;
        c->retry_deadline = 0u;
        c->retry_count = 0u;
        return 0;
    }
    if (c->state == NET_TCP_FIN_WAIT)
    {
        /* Active-close completion (RFC 793 section 3.5 FIN-WAIT-1/2):
         * ack parses like the SYN_SENT leg below (same offsets). */
        ack = (uint32_t)(((uint32_t)f[off + 8] << 24) | ((uint32_t)f[off + 9] << 16) | ((uint32_t)f[off + 10] << 8) |
                         (uint32_t)f[off + 11]);
        if (((flags & (unsigned)TCP_ACK) && ack == c->snd_nxt) || (flags & (unsigned)TCP_FIN))
        {
            c->state = NET_TCP_TIME_WAIT;
            c->retry_deadline = now + NET_TCP_TIME_WAIT_TICKS;
            c->retry_count = 0u;
        }
        return 0;
    }
    if (c->state == NET_TCP_CLOSE_WAIT)
    {
        /* Passive-close duplicate FIN (Task 3 ruling, detailed above):
         * the retransmit carries the consumed sequence number, so only
         * seq == rcv_nxt - 1 re-ACKs (returns 1) with CLOSE_WAIT held;
         * anything else (stray data-shaped segment, off-window FIN) drops
         * with CLOSE_WAIT held, so the app's S_CLOSE still owns our FIN.
         * No reply frame is ever parked on a drop. */
        if (!(flags & (unsigned)TCP_FIN))
            return 0;
        seq = (uint32_t)(((uint32_t)f[off + 4] << 24) | ((uint32_t)f[off + 5] << 16) | ((uint32_t)f[off + 6] << 8) |
                         (uint32_t)f[off + 7]);
        if (seq != c->rcv_nxt - 1u)
            return 0;
        tcp_park_ack(c, f, sip, out, outlen);
        return 1;
    }
    if (c->state == NET_TCP_LAST_ACK)
    {
        /* Passive-close completion (RFC 793 section 3.5 LAST-ACK): the
         * peer ACK covering our FIN (ack == snd_nxt: FIN consumed one
         * sequence number at build, same as the FIN_WAIT leg) closes
         * exactly once to TIME_WAIT (linger: retry_deadline = now +
         * NET_TCP_TIME_WAIT_TICKS, retry disarmed, no reply frame); the
         * sock seam holds the waiter armed across entry (the loop wakes
         * it once, Task 3). A duplicate
         * peer FIN (Task 3 ruling) parks a re-ACK (returns 1) and holds
         * LAST_ACK with the FIN retry untouched -- a premature close
         * would drop the duplicate-ACK obligation. A duplicate FIN whose
         * ACK covers our FIN additionally closes at once (the re-ACK is
         * still parked: the peer missed our ACK of its FIN). Anything else
         * (stale ACK, stray data-shaped segment, off-window FIN) drops with
         * LAST_ACK held, so the FIN retry keeps running. No reply frame
         * is ever parked on the close: a bare close needs no wire answer. */
        ack = (uint32_t)(((uint32_t)f[off + 8] << 24) | ((uint32_t)f[off + 9] << 16) | ((uint32_t)f[off + 10] << 8) |
                         (uint32_t)f[off + 11]);
        if (flags & (unsigned)TCP_FIN)
        {
            seq = (uint32_t)(((uint32_t)f[off + 4] << 24) | ((uint32_t)f[off + 5] << 16) | ((uint32_t)f[off + 6] << 8) |
                             (uint32_t)f[off + 7]);
            if (seq != c->rcv_nxt - 1u)
                return 0;
            tcp_park_ack(c, f, sip, out, outlen);
            if ((flags & (unsigned)TCP_ACK) && ack == c->snd_nxt)
            {
                c->state = NET_TCP_TIME_WAIT;
                c->retry_deadline = now + NET_TCP_TIME_WAIT_TICKS;
                c->retry_count = 0u;
            }
            return 1;
        }
        if ((flags & (unsigned)TCP_ACK) && ack == c->snd_nxt)
        {
            c->state = NET_TCP_TIME_WAIT;
            c->retry_deadline = now + NET_TCP_TIME_WAIT_TICKS;
            c->retry_count = 0u;
        }
        return 0;
    }
    if (c->state == NET_TCP_TIME_WAIT)
    {
        /* Linger hold (Task 1 slice): never re-close, never re-arm.
         * Duplicate-ACK replies land here in Task 2; until then drop
         * with TIME_WAIT held. */
        return 0;
    }
    if (c->state == NET_TCP_ESTABLISHED && (flags & (unsigned)TCP_FIN))
    {
        /* Passive-close entry (RFC 793 section 3.5): an in-order peer FIN
         * (seq == rcv_nxt, same offsets as the SYN_SENT leg) is consumed
         * (rcv_nxt + 1, never queued as data) and ACKed at once with a
         * pure ACK in out (returns 1). An off-window FIN drops with
         * ESTABLISHED held: no state change, no reply, nothing parked. */
        seq = (uint32_t)(((uint32_t)f[off + 4] << 24) | ((uint32_t)f[off + 5] << 16) | ((uint32_t)f[off + 6] << 8) |
                         (uint32_t)f[off + 7]);
        if (seq != c->rcv_nxt)
            return 0;
        c->rcv_nxt += 1u;
        c->state = NET_TCP_CLOSE_WAIT;
        tcp_park_ack(c, f, sip, out, outlen);
        return 1;
    }
    if (c->state != NET_TCP_SYN_SENT)
        return 0;
    if (!(flags & (unsigned)TCP_SYN) || !(flags & (unsigned)TCP_ACK))
        return 0;
    seq = (uint32_t)(((uint32_t)f[off + 4] << 24) | ((uint32_t)f[off + 5] << 16) | ((uint32_t)f[off + 6] << 8) |
                     (uint32_t)f[off + 7]);
    ack = (uint32_t)(((uint32_t)f[off + 8] << 24) | ((uint32_t)f[off + 9] << 16) | ((uint32_t)f[off + 10] << 8) |
                     (uint32_t)f[off + 11]);
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
    ck = net_tcp_checksum((uint32_t)NET_IP_SELF, sip, out + ETH_HDR_LEN + IP_MIN, (unsigned)TCP_HDR_MIN);
    out[50] = (uint8_t)(ck >> 8);
    out[51] = (uint8_t)(ck & 0xFFu);
    *outlen = total;
    return 1;
}

/* Legacy input (no clock): TIME_WAIT linger stamps relative to 0.
 * Kept so the loop and older vectors compile unchanged until Task 2
 * threads u_rdtime() through net_tcp_input_at. */
static inline int net_tcp_input(struct net_tcp_conn *c, const uint8_t *f, unsigned long len, uint8_t *out,
                                unsigned long *outlen)
{
    return net_tcp_input_at(c, f, len, out, outlen, 0u);
}

#endif /* NET_TCP_H */
