/* userspace/net/sock.c - Socket table with port demux. UDP + TCP. */
#include "sock.h"

#include "tcp.h" /* per-entry TCB bind + MSS/state constants (RFC 793 handshake) */

/* 1-slot fair-share: each open socket owns one slot carved from the
 * 4-slot datagram queue, so the 5th concurrent open fails. */
#define NET_SOCK_FAIR_MAX 4

static net_sock_t net_socks[NET_SOCK_MAX];

/* Per-socket TCB table (design Sec 1, RFC 793 one state machine per
 * connection; lwIP multi-PCB shape): each of the NET_TCP_MAX entries
 * binds to its socket id (-1 when free). At most 4 TCP sockets open
 * concurrently under the fair-share bound above, so the array never
 * overflows -- no LRU, no steal. S_CLOSE frees only its entry; RST
 * aborts only its entry. Port uniqueness stays table-wide across kinds
 * (checked in net_sock_open). The boot SYN proof (v2_main net_boot_tcp)
 * and the S_OPEN/S_SEND RPC legs drive a per-entry bind (same MSS 536
 * via tcp.h, same rdtime ISS source at the caller). */
static struct net_tcp_conn net_tcbs[NET_TCP_MAX];
static int net_tcb_sock[NET_TCP_MAX] = {-1, -1, -1, -1}; /* bound socket id, -1 when free */

/* Per-entry TX slots (Task 2, design Sec 2, RFC 793 one state machine
 * per connection: the shared slot let a second entry's send clobber the
 * first entry's parked frame, so resends emitted the wrong bytes).
 * Each entry parks its last emitted segment (the SYN leg writes the
 * caller's buffer, never a slot) in its own 1514B slot (payload <= 536,
 * same wire bound as before). The wire TX path copies an entry's frame
 * out via net_sock_tcp_tx_for; net_sock_tcp_tx keeps the legacy shape
 * (first bound entry's frame) for single-entry callers. */
static uint8_t net_tcp_tx[NET_TCP_MAX][1514];
static unsigned long net_tcp_tx_len[NET_TCP_MAX];

/* Bounded retransmit cap (design Sec 2, RFC 793 section 3.7): expiries 1-4
 * resend the parked frame verbatim, the 5th RST-aborts. The spacing lives
 * with the caller (v2_main passes NET_IRQ_TIMEOUT_TICKS, ~2s @10MHz); the
 * poll below only counts expiries against this cap. */
#define NET_TCP_RETRY_MAX 5u

/* Slot holding socket id, or -1 when unbound. */
static int tcb_slot_for(int id)
{
    int i;
    for (i = 0; i < NET_TCP_MAX; i++) /* bound: 4 */
    {
        if (net_tcb_sock[i] == id)
            return i;
    }
    return -1;
}

/* Table slot for a bound TCB pointer, or -1 (defensive: net_sock_tcp
 * only returns in-table entries, so this never fires on the seam). */
static int tcb_slot_of(const struct net_tcp_conn *c)
{
    if (!c || c < net_tcbs || c >= net_tcbs + NET_TCP_MAX)
        return -1;
    return (int)(c - net_tcbs);
}

/* Bound TCB for a socket, or 0 when the socket is unused, non-TCP, or
 * has no entry. Callers drive the RFC 793 handshake (net_tcp_syn /
 * net_tcp_input) or the sock wrappers on the returned TCB. */
struct net_tcp_conn *net_sock_tcp(int id)
{
    int slot;
    if (id < 0 || id >= NET_SOCK_MAX || !net_socks[id].used)
        return 0;
    if (net_socks[id].kind != NET_SOCK_TCP)
        return 0;
    slot = tcb_slot_for(id);
    if (slot < 0)
        return 0;
    return &net_tcbs[slot];
}

/* First bound socket id in table order, or -1 when no TCP entry is
 * live (no open TCP socket holds an entry). */
int net_sock_tcp_bound(void)
{
    int i;
    for (i = 0; i < NET_TCP_MAX; i++) /* bound: 4 */
    {
        int sid = net_tcb_sock[i];
        if (sid < 0 || sid >= NET_SOCK_MAX)
            continue;
        if (!net_socks[sid].used)
            continue;
        if (net_socks[sid].kind != NET_SOCK_TCP)
            continue;
        return sid;
    }
    return -1;
}

/* One waiter per socket slot, indexed by sock_id. Absolute deadline
 * (now+timeout); expiry uses wrap-safe unsigned compare. */
static struct net_waiter net_waiters[NET_SOCK_MAX];

void net_waiter_clear(int sock_id)
{
    if (sock_id < 0 || sock_id >= NET_SOCK_MAX)
        return;
    net_waiters[sock_id].armed = 0;
    net_waiters[sock_id].sock_id = 0;
    net_waiters[sock_id].owner = 0;
    net_waiters[sock_id].deadline = 0;
}

int net_sock_open(unsigned kind, uint16_t port, unsigned owner)
{
    unsigned i;
    unsigned used = 0;
    int slot;
    if (kind != NET_SOCK_UDP && kind != NET_SOCK_TCP)
        return -1;
    if (kind == NET_SOCK_TCP)
    {
        /* Table-full guard (additive to fair-share): with 4 concurrent
         * TCP opens every entry is bound, so a 5th fails closed without
         * touching any live entry. Unreachable via fair-share alone
         * (4 sockets max), kept as defense-in-depth. Each entry's
         * TIME_WAIT linger blocks only its own port (the lingering
         * socket keeps the port, so the duplicate-port scan above
         * rejects rebinds of that port until close). */
        for (slot = 0; slot < NET_TCP_MAX; slot++) /* bound: 4 */
        {
            if (net_tcb_sock[slot] < 0)
                break;
        }
        if (slot >= NET_TCP_MAX)
            return -1;
    }
    for (i = 0; i < NET_SOCK_MAX; i++)
    {
        if (!net_socks[i].used)
            continue;
        if (net_socks[i].port == port)
            return -1;
        used++;
    }
    if (used >= NET_SOCK_FAIR_MAX)
        return -1;
    for (i = 0; i < NET_SOCK_MAX; i++)
    {
        if (net_socks[i].used)
            continue;
        net_socks[i].used = 1;
        net_socks[i].kind = (uint8_t)kind;
        net_socks[i].port = port;
        net_socks[i].owner = owner;
        if (kind == NET_SOCK_TCP)
        {
            /* Bind a free entry, CLOSED until the SYN leg arms it. The
             * table-full guard above guarantees a free slot; re-scan
             * and roll back the socket on the unreachable miss. */
            for (slot = 0; slot < NET_TCP_MAX; slot++) /* bound: 4 */
            {
                if (net_tcb_sock[slot] < 0)
                    break;
            }
            if (slot >= NET_TCP_MAX)
            {
                net_socks[i].used = 0;
                net_socks[i].kind = NET_SOCK_NONE;
                net_socks[i].port = 0;
                net_socks[i].owner = 0;
                return -1;
            }
            net_tcb_sock[slot] = (int)i;
            net_tcbs[slot].state = NET_TCP_CLOSED;
            net_tcbs[slot].iss = 0u;
            net_tcbs[slot].irs = 0u;
            net_tcbs[slot].snd_nxt = 0u;
            net_tcbs[slot].rcv_nxt = 0u;
            net_tcbs[slot].lport = port;
            net_tcbs[slot].rport = 0u;
            net_tcbs[slot].rip = 0u;
            net_tcbs[slot].retry_deadline = 0u;
            net_tcbs[slot].retry_count = 0u;
            net_tcp_tx_len[slot] = 0u;
        }
        return (int)i;
    }
    return -1;
}

int net_sock_close(int id)
{
    int slot;
    if (id < 0 || id >= NET_SOCK_MAX)
        return -1;
    if (!net_socks[id].used)
        return -1;
    slot = tcb_slot_for(id);
    if (slot >= 0)
    {
        /* Release only this socket's entry for the next TCP open, and
         * drop its parked frame so a later rebind starts empty. */
        net_tcb_sock[slot] = -1;
        net_tcbs[slot].state = NET_TCP_CLOSED;
        net_tcbs[slot].retry_deadline = 0u;
        net_tcbs[slot].retry_count = 0u;
        net_tcp_tx_len[slot] = 0u;
    }
    net_socks[id].used = 0;
    net_socks[id].kind = NET_SOCK_NONE;
    net_socks[id].port = 0;
    net_socks[id].owner = 0;
    net_waiter_clear(id);
    return 0;
}

int net_sock_demux(uint16_t dport)
{
    unsigned i;
    for (i = 0; i < NET_SOCK_MAX; i++)
    {
        if (net_socks[i].used && net_socks[i].port == dport)
            return (int)i;
    }
    return -1;
}

int net_sock_owned(long id, unsigned long owner)
{
    if (id < 0 || id >= (long)NET_SOCK_MAX)
        return 0;
    if (!net_socks[id].used)
        return 0;
    return net_socks[id].owner == owner;
}

/* Active open through the bind: builds the SYN with the socket's bound
 * port as lport (MSS 536 + ISS flow through tcp.h: the same SYN the boot
 * proof emits, with the caller-supplied ISS source). */
int net_sock_tcp_syn(int id, const uint8_t *dmac, uint32_t rip, uint16_t rport, uint32_t iss, uint8_t *out,
                     unsigned long *outlen)
{
    uint16_t lport;
    struct net_tcp_conn *c = net_sock_tcp(id);
    if (!c)
        return -1;
    lport = net_socks[id].port;
    return net_tcp_syn(c, dmac, rip, rport, lport, iss, out, outlen);
}

/* TIME_WAIT duplicate-ACK (design Sec 2, RFC 793 section 3.5): a valid
 * duplicate data segment (payload present) or FIN arriving while already
 * lingering parks a pure re-ACK (returns 1, byte-identical to the entry
 * ACK via tcp_park_ack) with state, sequence, and retry held -- never a
 * re-close, re-delivery, or re-arm. Bare ACKs (covering-ACK retransmits)
 * and anything failing the peer/port/checksum gates drop (returns 0).
 * RST never reaches here (tcp.h aborts to CLOSED first). */
static int net_sock_tw_ack(const struct net_tcp_conn *c, const uint8_t *f, unsigned long len, uint8_t *out,
                           unsigned long *outlen)
{
    unsigned ihl, off, doff, flags;
    uint32_t sip;
    unsigned long pay;
    if (!c || !f || !out || !outlen)
        return 0;
    if (!tcp_hdr_ok(f, len))
        return 0;
    ihl = ip_ihl_bytes(f, len);
    off = (unsigned)ETH_HDR_LEN + ihl;
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
        return 0;
    doff = (unsigned)(f[off + 12] >> 4) * 4u;
    pay = len - ((unsigned long)off + (unsigned long)doff);
    if (!(flags & (unsigned)TCP_FIN) && pay == 0)
        return 0;
    tcp_park_ack(c, f, sip, out, outlen);
    return 1;
}

/* Handshake/data input through the bind: feeds one RX frame to the bound
 * TCB (SYN-ACK check + RST abort live in tcp.h). An abort back to CLOSED
 * disarms the socket's waiter, so no waiter is left armed on a dead
 * connection. A passive-close entry to CLOSE_WAIT parks the FIN-ACK
 * (rc 1) with the retry budget and waiter untouched, so bytes queued
 * before the FIN still drain. A LAST_ACK covering ACK or FIN_WAIT
 * covering ACK/FIN enters TIME_WAIT (rc 0, no reply frame) with the
 * linger stamped (now + NET_TCP_TIME_WAIT_TICKS) and the waiter held
 * armed across entry (the loop wakes it once, Task 3); a stale ACK
 * holds LAST_ACK/FIN_WAIT with the FIN retry untouched. A duplicate
 * data/FIN arriving while already lingering parks a re-ACK (rc 1) with
 * state, sequence, and retry held; a bare ACK retransmit drops (rc 0).
 * Returns net_tcp_input_at's 1 (ACK emitted) / 0 (drop). The legacy
 * net_sock_tcp_input wrapper passes now = 0 (baseline stamp); the loop
 * threads u_rdtime() through net_sock_tcp_input_at (Task 2). */
int net_sock_tcp_input_at(int id, const uint8_t *f, unsigned long len, uint8_t *out, unsigned long *outlen,
                          uint64_t now)
{
    int rc;
    int was_syn_sent;
    int was_time_wait;
    struct net_tcp_conn *c = net_sock_tcp(id);
    if (!c)
        return -1;
    was_syn_sent = (c->state == NET_TCP_SYN_SENT);
    was_time_wait = (c->state == NET_TCP_TIME_WAIT);
    rc = net_tcp_input_at(c, f, len, out, outlen, now);
    if (rc == 1 && was_syn_sent)
    {
        /* SYN-ACK accepted (SYN_SENT -> ESTABLISHED): the SYN retry budget
         * is spent, so the fresh connection starts disarmed. Gated on the
         * prior state, not just rc: the seam also routes FIN_WAIT inputs
         * (v2_main non-ESTABLISHED leg), and a future 1-return from any
         * other state (Task 3 peer-ACK close) must leave that state's
         * retry budget alone. The CLOSED abort below already disarmed via
         * tcp.h; only handshake success needs this. */
        c->retry_deadline = 0u;
        c->retry_count = 0u;
    }
    if (c->state == NET_TCP_CLOSED)
        net_waiter_clear(id);
    if (rc == 0 && was_time_wait && c->state == NET_TCP_TIME_WAIT)
    {
        /* Already lingering when the frame arrived (the closing frame
         * itself keeps the bare-close rc 0): duplicate data/FIN re-ACKs. */
        rc = net_sock_tw_ack(c, f, len, out, outlen);
    }
    return rc;
}

/* Legacy input (no clock): linger stamps relative to 0. Kept so the
 * loop and older vectors compile unchanged until Task 2 threads
 * u_rdtime() through net_sock_tcp_input_at. */
int net_sock_tcp_input(int id, const uint8_t *f, unsigned long len, uint8_t *out, unsigned long *outlen)
{
    return net_sock_tcp_input_at(id, f, len, out, outlen, 0u);
}

/* In-order TCP data segment (one slice, PSH|ACK): seq = snd_nxt, ack =
 * rcv_nxt, payload capped at TCP_MSS_DEFAULT 536 (total frame
 * 14+20+20+len <= 590 <= 1514, same wire bound as the SYN path). The
 * destination MAC resolves via ARP; a miss fails closed with no frame and
 * no sequence advance. Advances snd_nxt by len on success. */
static int tcp_data_build(struct net_tcp_conn *c, const uint8_t *buf, unsigned long len, uint8_t *out,
                          unsigned long *outlen)
{
    uint8_t dmac[6];
    unsigned long total;
    unsigned long ip_len;
    unsigned i;
    uint16_t ck;
    if (!c || (len > 0 && !buf) || !out || !outlen)
        return -1;
    if (len > (unsigned long)TCP_MSS_DEFAULT)
        return -1;
    total = (unsigned long)14 + 20u + (unsigned long)TCP_HDR_MIN + len;
    if (total > 1514UL)
        return -1;
    if (net_arp_lookup(c->rip, dmac) != 0)
        return -1;
    for (i = 0; i < 6u; i++) /* bound: 6 */
    {
        out[i] = dmac[i];
        out[6 + i] = NET_MAC_SELF[i];
    }
    out[12] = 0x08u;
    out[13] = 0x00u;
    ip_len = 20u + (unsigned long)TCP_HDR_MIN + len;
    out[14] = 0x45u;
    out[15] = 0x00u;
    out[16] = (uint8_t)(ip_len >> 8);
    out[17] = (uint8_t)(ip_len & 0xFFu);
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
    out[30] = (uint8_t)(c->rip >> 24);
    out[31] = (uint8_t)(c->rip >> 16);
    out[32] = (uint8_t)(c->rip >> 8);
    out[33] = (uint8_t)c->rip;
    ck = net_ip_checksum(out + 14, 20);
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
    out[47] = (uint8_t)(TCP_PSH | TCP_ACK);
    out[48] = 0x08u;
    out[49] = 0x00u; /* window 2048, same as the SYN path */
    out[50] = 0u;
    out[51] = 0u;
    for (i = 0; i < (unsigned)len; i++) /* bound: 536 */
        out[54 + i] = buf[i];
    ck = net_tcp_checksum((uint32_t)NET_IP_SELF, c->rip, out + 34, (unsigned)((unsigned long)TCP_HDR_MIN + len));
    out[50] = (uint8_t)(ck >> 8);
    out[51] = (uint8_t)(ck & 0xFFu);
    *outlen = total;
    c->snd_nxt += (uint32_t)len;
    return 0;
}

/* Header-only FIN|ACK (active close, RFC 793 section 3.5: seq = snd_nxt, ack =
 * rcv_nxt, no payload; total 14+20+20 = 54 <= 1514, same wire bound as
 * the data path). The destination MAC resolves via ARP; a miss fails
 * closed with no frame and no sequence advance. Advances snd_nxt by 1:
 * FIN consumes one sequence number, so the covering peer ACK (next
 * slice) is the post-FIN snd_nxt. */
static int tcp_fin_build(struct net_tcp_conn *c, uint8_t *out, unsigned long *outlen)
{
    uint8_t dmac[6];
    unsigned long total;
    unsigned long ip_len;
    unsigned i;
    uint16_t ck;
    if (!c || !out || !outlen)
        return -1;
    total = (unsigned long)14 + 20u + (unsigned long)TCP_HDR_MIN;
    if (total > 1514UL)
        return -1;
    if (net_arp_lookup(c->rip, dmac) != 0)
        return -1;
    for (i = 0; i < 6u; i++) /* bound: 6 */
    {
        out[i] = dmac[i];
        out[6 + i] = NET_MAC_SELF[i];
    }
    out[12] = 0x08u;
    out[13] = 0x00u;
    ip_len = 20u + (unsigned long)TCP_HDR_MIN;
    out[14] = 0x45u;
    out[15] = 0x00u;
    out[16] = (uint8_t)(ip_len >> 8);
    out[17] = (uint8_t)(ip_len & 0xFFu);
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
    out[30] = (uint8_t)(c->rip >> 24);
    out[31] = (uint8_t)(c->rip >> 16);
    out[32] = (uint8_t)(c->rip >> 8);
    out[33] = (uint8_t)c->rip;
    ck = net_ip_checksum(out + 14, 20);
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
    out[47] = (uint8_t)(TCP_FIN | TCP_ACK);
    out[48] = 0x08u;
    out[49] = 0x00u; /* window 2048, same as the SYN/data paths */
    out[50] = 0u;
    out[51] = 0u;
    out[52] = 0u;
    out[53] = 0u;
    ck = net_tcp_checksum((uint32_t)NET_IP_SELF, c->rip, out + 34, (unsigned)TCP_HDR_MIN);
    out[50] = (uint8_t)(ck >> 8);
    out[51] = (uint8_t)(ck & 0xFFu);
    *outlen = total;
    c->snd_nxt += 1u;
    return 0;
}

/* Header-only RST|ACK (retry-exhaustion abort, RFC 793 section 3.5: seq =
 * snd_nxt, ack = rcv_nxt, no payload; total 14+20+20 = 54 <= 1514, same
 * wire bound as the FIN path). The destination MAC resolves via ARP; a
 * miss fails closed with no frame. Unlike FIN, RST consumes no sequence
 * number, so snd_nxt is untouched (a later FIN-ACK match in Task 3 still
 * sees the pre-RST edge). */
static int tcp_rst_build(struct net_tcp_conn *c, uint8_t *out, unsigned long *outlen)
{
    uint8_t dmac[6];
    unsigned long total;
    unsigned long ip_len;
    unsigned i;
    uint16_t ck;
    if (!c || !out || !outlen)
        return -1;
    total = (unsigned long)14 + 20u + (unsigned long)TCP_HDR_MIN;
    if (total > 1514UL)
        return -1;
    if (net_arp_lookup(c->rip, dmac) != 0)
        return -1;
    for (i = 0; i < 6u; i++) /* bound: 6 */
    {
        out[i] = dmac[i];
        out[6 + i] = NET_MAC_SELF[i];
    }
    out[12] = 0x08u;
    out[13] = 0x00u;
    ip_len = 20u + (unsigned long)TCP_HDR_MIN;
    out[14] = 0x45u;
    out[15] = 0x00u;
    out[16] = (uint8_t)(ip_len >> 8);
    out[17] = (uint8_t)(ip_len & 0xFFu);
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
    out[30] = (uint8_t)(c->rip >> 24);
    out[31] = (uint8_t)(c->rip >> 16);
    out[32] = (uint8_t)(c->rip >> 8);
    out[33] = (uint8_t)c->rip;
    ck = net_ip_checksum(out + 14, 20);
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
    out[47] = (uint8_t)(TCP_RST | TCP_ACK);
    out[48] = 0x08u;
    out[49] = 0x00u; /* window 2048, same as the SYN/data paths */
    out[50] = 0u;
    out[51] = 0u;
    out[52] = 0u;
    out[53] = 0u;
    ck = net_tcp_checksum((uint32_t)NET_IP_SELF, c->rip, out + 34, (unsigned)TCP_HDR_MIN);
    out[50] = (uint8_t)(ck >> 8);
    out[51] = (uint8_t)(ck & 0xFFu);
    *outlen = total;
    return 0;
}

/* Unified send seam (design Sec 3): UDP keeps the direct path
 * (net_stack_udp_send with the caller's routing; no per-socket route is
 * stored in the table, so this leg stays fail-closed -1 and the v2_main
 * S_SEND payload phase still calls net_stack_udp_send for UDP). TCP
 * requires the bound TCB in ESTABLISHED (ownership is enforced by the
 * RPC layer via net_sock_owned before this seam runs) and a capped
 * payload, then emits one in-order segment into the parked TX frame
 * (copy out via net_sock_tcp_tx_for). S_SEND in CLOSE_WAIT (passive close:
 * the peer is done sending), LAST_ACK, FIN_WAIT, or TIME_WAIT (2MSL
 * linger: no new data while duplicates may still be in flight) answers
 * -1 (S_ERR at the RPC layer) with snd_nxt untouched -- the state gate
 * below is the whole enforcement. Stop-and-wait: a second S_SEND while
 * the retry is armed (one segment already outstanding, covering ACK not
 * yet seen) is rejected, never interleaving bytes; the covering ACK
 * (ack_cover) disarms for the next send. Any gate failure emits nothing.
 * Returns payload bytes accepted, or -1. */
int net_sock_send(int id, const uint8_t *buf, unsigned long len)
{
    unsigned long flen = 0;
    int slot;
    struct net_tcp_conn *c = net_sock_tcp(id);
    if (!c)
        return -1;
    slot = tcb_slot_of(c);
    if (slot < 0)
        return -1;
    if (c->state == NET_TCP_TIME_WAIT)
        return -1; /* linger: no new data, snd_nxt untouched */
    if (c->state != NET_TCP_ESTABLISHED)
        return -1;
    if (c->retry_deadline != 0u)
        return -1;
    if (len < 1 || len > (unsigned long)TCP_MSS_DEFAULT)
        return -1;
    if (!buf)
        return -1;
    if (tcp_data_build(c, buf, len, net_tcp_tx[slot], &flen) != 0)
        return -1;
    net_tcp_tx_len[slot] = flen;
    /* Fresh frame, fresh budget: clear any stale retry state, still
     * unarmed (the TX pass arms the deadline after transmitting, per the
     * tcp.h convention; a covering ACK disarms via ack_cover below). */
    c->retry_deadline = 0u;
    c->retry_count = 0u;
    return (int)len;
}

/* Graceful-close seam (design Sec 2: the S_CLOSE legs the RPC close
 * handler calls instead of the abort release): ESTABLISHED emits one
 * header-only FIN|ACK into the parked TX frame (copy out via
 * net_sock_tcp_tx_for; the retry slice resends it verbatim and arms the
 * deadline on the TX pass, so the deadline stays unarmed here) and
 * enters FIN_WAIT; CLOSE_WAIT (passive close: the peer FIN is already
 * ACKed, our FIN pending) emits the same header-only FIN|ACK and enters
 * LAST_ACK. Both keep the socket open and its entry bound: unrelated
 * sockets keep their own entries and S_SEND stays gated off per entry.
 * A socket already in LAST_ACK answers success at once (idempotent
 * close: no second FIN is parked, snd_nxt holds -- the RPC layer maps
 * this to S_OK, mirroring its FIN_WAIT branch). A parked unacked frame
 * (retry armed by the TX pass) still owns its entry's TX slot, so
 * building FIN here would silently drop data: that close is rejected
 * with -1 and changes nothing (close after the covering ACK disarms, or
 * after exhaustion aborts). Any other gate failure (bad id, unbound,
 * non-TCP, FIN_WAIT/CLOSED / SYN_SENT state, ARP miss) emits nothing and
 * changes nothing. Returns 0 on FIN entry or idempotent LAST_ACK, -1
 * otherwise. */
int net_sock_fin_close(int id)
{
    unsigned long flen = 0;
    int passive = 0;
    int slot;
    struct net_tcp_conn *c = net_sock_tcp(id);
    if (!c)
        return -1;
    slot = tcb_slot_of(c);
    if (slot < 0)
        return -1;
    if (c->state == NET_TCP_LAST_ACK)
        return 0;
    if (c->state == NET_TCP_CLOSE_WAIT)
        passive = 1;
    else if (c->state != NET_TCP_ESTABLISHED)
        return -1;
    if (c->retry_deadline != 0u)
        return -1;
    if (tcp_fin_build(c, net_tcp_tx[slot], &flen) != 0)
        return -1;
    net_tcp_tx_len[slot] = flen;
    c->state = passive ? NET_TCP_LAST_ACK : NET_TCP_FIN_WAIT;
    c->retry_deadline = 0u;
    c->retry_count = 0u;
    return 0;
}

/* Parked TX frame for one entry (Task 2): sets *len_out and returns
 * that entry's frame bytes, or 0/0 when unbound or nothing was ever
 * emitted there. The wire TX path copies the frame before transmitting. */
const uint8_t *net_sock_tcp_tx_for(int id, unsigned long *len_out)
{
    int slot;
    struct net_tcp_conn *c = net_sock_tcp(id);
    if (!c)
    {
        if (len_out)
            *len_out = 0;
        return 0;
    }
    slot = tcb_slot_of(c);
    if (slot < 0)
    {
        if (len_out)
            *len_out = 0;
        return 0;
    }
    if (len_out)
        *len_out = net_tcp_tx_len[slot];
    return net_tcp_tx_len[slot] ? net_tcp_tx[slot] : 0;
}

/* Legacy parked-frame shape: the first bound entry's frame, or 0/0 when
 * no TCP entry is live. Single-entry callers behave exactly as before. */
const uint8_t *net_sock_tcp_tx(unsigned long *len_out)
{
    return net_sock_tcp_tx_for(net_sock_tcp_bound(), len_out);
}

/* Bound socket id for table slot s, or -1 when the slot is free, out of
 * range, or its socket closed (Task 2: lets the v2_main loop iterate all
 * 4 entries per pass instead of the first bound entry only). */
int net_sock_tcp_slot_sid(int s)
{
    int sid;
    if (s < 0 || s >= NET_TCP_MAX)
        return -1;
    sid = net_tcb_sock[s];
    if (sid < 0 || sid >= NET_SOCK_MAX)
        return -1;
    if (!net_socks[sid].used)
        return -1;
    if (net_socks[sid].kind != NET_SOCK_TCP)
        return -1;
    return sid;
}

/* Arm the retry deadline after the TX pass transmits the parked frame
 * (design Sec 2, RFC 793 section 3.7: the tcp.h convention is that builds
 * leave the deadline unarmed and the TX pass arms it). Applies to any live
 * state (SYN_SENT SYN, ESTABLISHED PSH, FIN_WAIT/LAST_ACK FIN); the count
 * is left alone (builds zero it for a fresh budget, the poll below
 * advances it on resend), so re-arming an already-armed frame only moves
 * the deadline. Returns 0 on arming, -1 when unbound, CLOSED, or nothing
 * is parked. */
int net_sock_tcp_retry_arm(int id, uint64_t now, uint64_t spacing)
{
    int slot;
    struct net_tcp_conn *c = net_sock_tcp(id);
    if (!c)
        return -1;
    if (c->state == NET_TCP_CLOSED)
        return -1;
    slot = tcb_slot_of(c);
    if (slot < 0)
        return -1;
    if (net_tcp_tx_len[slot] == 0)
        return -1;
    c->retry_deadline = now + spacing;
    return 0;
}

/* Covering-ACK disarm (RFC 793 section 3.7: ACKed data stops retransmit).
 * Single-flight stop-and-wait: exactly one segment is ever outstanding,
 * so an ack equal to snd_nxt covers it fully and disarms. ESTABLISHED
 * only: FIN_WAIT/LAST_ACK ACKs close via the tcp.h input leg, never
 * disarmed here. Returns 1 on disarm, 0 when untouched, -1 when unbound. */
int net_sock_tcp_ack_cover(int id, uint32_t ack)
{
    struct net_tcp_conn *c = net_sock_tcp(id);
    if (!c)
        return -1;
    if (c->state != NET_TCP_ESTABLISHED)
        return 0;
    if (c->retry_deadline == 0u)
        return 0;
    if (ack != c->snd_nxt)
        return 0;
    c->retry_deadline = 0u;
    c->retry_count = 0u;
    return 1;
}

/* Per-entry retry due check (Task 2, design Sec 2, RFC 793 section
 * 3.7: the loop runs this for every entry on the same pass that pumps
 * RX, 4 x the old bounded cost). Wrap-safe unsigned compare, as the
 * waiter expiry. On a due expiry with budget left the entry's parked
 * frame is resent verbatim (bytes untouched, snd_nxt holds) and the
 * deadline re-arms; on the 5th due expiry (count already at
 * NET_TCP_RETRY_MAX - 1) the entry RST-aborts to CLOSED with a
 * header-only RST|ACK parked in its own slot for the wire pass, the
 * retry state disarms, and that entry's socket waiter (if armed) is
 * captured for the caller's single S_ERR wake and cleared. A TIME_WAIT
 * linger never resends: past its deadline (wrap-safe compare) the entry
 * falls to CLOSED
 * with the retry disarmed (return 0, outs zeroed), freeing the port for
 * rebind; the socket stays open for an explicit close and no waiter
 * wakes (the entry wake is Task 3). Returns 0 (nothing due),
 * 1 (resend: transmit net_sock_tcp_tx_for verbatim), or 2 (abort:
 * transmit the parked RST, ASEND S_ERR once iff *waiter_out). Both
 * out-params are always written (0 on 0/1) and tolerate NULL. */
int net_sock_tcp_retry_poll_one(int id, uint64_t now, uint64_t spacing, unsigned *owner_out, int *waiter_out)
{
    struct net_tcp_conn *c;
    int slot;
    unsigned long rstlen = 0;
    if (owner_out)
        *owner_out = 0;
    if (waiter_out)
        *waiter_out = 0;
    c = net_sock_tcp(id);
    if (!c || c->state == NET_TCP_CLOSED)
        return 0;
    slot = tcb_slot_of(c);
    if (slot < 0)
        return 0;
    if (c->state == NET_TCP_TIME_WAIT)
    {
        /* Linger expiry (design Sec 3): no retransmits run in TIME_WAIT.
         * One tick before the deadline holds; at the deadline the TCB
         * falls to CLOSED (wrap-safe compare), freeing the port. */
        if ((int64_t)(now - c->retry_deadline) < 0)
            return 0;
        c->state = NET_TCP_CLOSED;
        c->retry_deadline = 0u;
        c->retry_count = 0u;
        return 0;
    }
    if (c->retry_deadline == 0u)
        return 0;
    if (net_tcp_tx_len[slot] == 0)
    {
        /* Defensive: armed with nothing parked (unreachable via the seam
         * above); disarm rather than spin. */
        c->retry_deadline = 0u;
        c->retry_count = 0u;
        return 0;
    }
    if ((int64_t)(now - c->retry_deadline) < 0)
        return 0;
    if (c->retry_count < NET_TCP_RETRY_MAX - 1u)
    {
        c->retry_count++;
        c->retry_deadline = now + spacing;
        return 1;
    }
    if (tcp_rst_build(c, net_tcp_tx[slot], &rstlen) == 0)
        net_tcp_tx_len[slot] = rstlen;
    else
        net_tcp_tx_len[slot] = 0; /* ARP miss: abort the state, send nothing */
    c->state = NET_TCP_CLOSED;
    c->retry_deadline = 0u;
    c->retry_count = 0u;
    if (id >= 0 && id < NET_SOCK_MAX && net_waiters[id].armed)
    {
        if (owner_out)
            *owner_out = net_waiters[id].owner;
        if (waiter_out)
            *waiter_out = 1;
        net_waiter_clear(id);
    }
    return 2;
}

/* Legacy per-pass poll shape: runs the per-entry check over all 4 table
 * entries in table order and reports the first due entry (same 0/1/2
 * contract, outs for that entry). Single-entry callers behave exactly
 * as before; multi-entry callers needing every due entry in one pass
 * (the v2_main loop) iterate net_sock_tcp_slot_sid + poll_one instead. */
int net_sock_tcp_retry_poll(uint64_t now, uint64_t spacing, unsigned *owner_out, int *waiter_out)
{
    int i;
    if (owner_out)
        *owner_out = 0;
    if (waiter_out)
        *waiter_out = 0;
    for (i = 0; i < NET_TCP_MAX; i++) /* bound: 4 */
    {
        int sid = net_sock_tcp_slot_sid(i);
        unsigned o = 0;
        int w = 0;
        int trc;
        if (sid < 0)
            continue;
        trc = net_sock_tcp_retry_poll_one(sid, now, spacing, &o, &w);
        if (trc != 0)
        {
            if (owner_out)
                *owner_out = o;
            if (waiter_out)
                *waiter_out = w;
            return trc;
        }
    }
    return 0;
}

int net_waiter_arm(int sock_id, unsigned owner, uint64_t now, uint64_t timeout)
{
    if (sock_id < 0 || sock_id >= NET_SOCK_MAX)
        return -1;
    if (!net_socks[sock_id].used)
        return -1;
    if (net_socks[sock_id].owner != owner)
        return -1;
    if (timeout == 0)
        return 1;
    net_waiters[sock_id].armed = 1;
    net_waiters[sock_id].sock_id = sock_id;
    net_waiters[sock_id].owner = owner;
    net_waiters[sock_id].deadline = now + timeout;
    return 0;
}

int net_waiter_match(uint16_t dport, unsigned *owner_out)
{
    unsigned i;
    for (i = 0; i < NET_SOCK_MAX; i++)
    {
        int sid;
        if (!net_waiters[i].armed)
            continue;
        sid = net_waiters[i].sock_id;
        if (sid < 0 || sid >= NET_SOCK_MAX)
            continue;
        if (!net_socks[sid].used)
            continue;
        if (net_socks[sid].port != dport)
            continue;
        if (owner_out)
            *owner_out = net_waiters[i].owner;
        return sid;
    }
    return -1;
}

int net_waiter_match_kind(uint16_t dport, unsigned kind, unsigned *owner_out)
{
    unsigned i;
    if (kind != (unsigned)NET_SOCK_UDP && kind != (unsigned)NET_SOCK_TCP)
        return -1;
    for (i = 0; i < NET_SOCK_MAX; i++) /* bound: 8 */
    {
        int sid;
        if (!net_waiters[i].armed)
            continue;
        sid = net_waiters[i].sock_id;
        if (sid < 0 || sid >= NET_SOCK_MAX)
            continue;
        if (!net_socks[sid].used)
            continue;
        if (net_socks[sid].kind != (uint8_t)kind)
            continue;
        if (net_socks[sid].port != dport)
            continue;
        if (owner_out)
            *owner_out = net_waiters[i].owner;
        return sid;
    }
    return -1;
}

int net_waiter_expire(uint64_t now, int *sock_out, unsigned *owner_out)
{
    unsigned i;
    for (i = 0; i < NET_SOCK_MAX; i++)
    {
        int sid;
        if (!net_waiters[i].armed)
            continue;
        /* Wrap-safe absolute-deadline compare: expired iff now is strictly
         * past deadline in modular arithmetic (timeouts << 2^63). */
        if ((int64_t)(now - net_waiters[i].deadline) < 0)
            continue;
        sid = net_waiters[i].sock_id;
        if (sock_out)
            *sock_out = sid;
        if (owner_out)
            *owner_out = net_waiters[i].owner;
        net_waiters[i].armed = 0;
        net_waiters[i].sock_id = 0;
        net_waiters[i].owner = 0;
        net_waiters[i].deadline = 0;
        return sid;
    }
    return -1;
}
