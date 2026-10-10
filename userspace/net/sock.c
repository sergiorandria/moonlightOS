/* userspace/net/sock.c - Socket table with port demux. UDP + TCP. */
#include "sock.h"

#include "tcp.h" /* single-TCB bind + MSS/state constants (RFC 793 handshake) */

/* 1-slot fair-share: each open socket owns one slot carved from the
 * 4-slot datagram queue, so the 5th concurrent open fails. */
#define NET_SOCK_FAIR_MAX 4

static net_sock_t net_socks[NET_SOCK_MAX];

/* Single-TCB bind (seam design Sec 3, lwIP single-TCB shape): one live TCB
 * shared by every TCP socket. It binds to the socket id at TCP open (state
 * CLOSED) and releases at close; while bound to a live socket no second
 * TCP open succeeds (fail closed, additive to the fair-share bound above).
 * The boot SYN proof (v2_main net_boot_tcp) and the S_OPEN/S_SEND RPC legs
 * drive the same bind (same MSS 536 via tcp.h, same rdtime ISS source at
 * the caller). */
static struct net_tcp_conn net_tcb;
static int net_tcb_sock = -1; /* bound socket id, -1 when free */

/* Last TCP segment emitted by net_sock_send (the send seam has no frame
 * out-param, so the frame parks here; total <= 1514, payload <= 536). The
 * wire TX path copies it out via net_sock_tcp_tx before transmitting. */
static uint8_t net_tcp_tx[1514];
static unsigned long net_tcp_tx_len;

/* Bounded retransmit cap (design Sec 2, RFC 793 section 3.7): expiries 1-4
 * resend the parked frame verbatim, the 5th RST-aborts. The spacing lives
 * with the caller (v2_main passes NET_IRQ_TIMEOUT_TICKS, ~2s @10MHz); the
 * poll below only counts expiries against this cap. */
#define NET_TCP_RETRY_MAX 5u

/* Bound TCB for a socket, or 0 when the socket is unused, non-TCP, or not
 * the bind holder. Callers drive the RFC 793 handshake (net_tcp_syn /
 * net_tcp_input) or the sock wrappers on the returned TCB. */
struct net_tcp_conn *net_sock_tcp(int id)
{
    if (id < 0 || id >= NET_SOCK_MAX || !net_socks[id].used)
        return 0;
    if (id != net_tcb_sock)
        return 0;
    return &net_tcb;
}

/* Socket id holding the single TCB, or -1 when free. */
int net_sock_tcp_bound(void)
{
    return net_tcb_sock;
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
    if (kind != NET_SOCK_UDP && kind != NET_SOCK_TCP)
        return -1;
    if (kind == NET_SOCK_TCP)
    {
        /* Single live TCB guard (additive to fair-share): while the TCB
         * is live (bound to an open socket past CLOSED) a second
         * concurrent TCP open fails closed, never aliasing the TCB.
         * CLOSED-bound sockets do not block Task-1 fair-share vectors:
         * the bind moves to the new opener at alloc below. */
        if (net_tcb_sock >= 0 && net_tcb_sock < NET_SOCK_MAX && net_socks[net_tcb_sock].used &&
            net_socks[net_tcb_sock].kind == NET_SOCK_TCP && net_tcb.state != NET_TCP_CLOSED)
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
            /* Bind the single TCB, CLOSED until the SYN leg arms it. */
            net_tcb_sock = (int)i;
            net_tcb.state = NET_TCP_CLOSED;
            net_tcb.iss = 0u;
            net_tcb.irs = 0u;
            net_tcb.snd_nxt = 0u;
            net_tcb.rcv_nxt = 0u;
            net_tcb.lport = port;
            net_tcb.rport = 0u;
            net_tcb.rip = 0u;
            net_tcb.retry_deadline = 0u;
            net_tcb.retry_count = 0u;
        }
        return (int)i;
    }
    return -1;
}

int net_sock_close(int id)
{
    if (id < 0 || id >= NET_SOCK_MAX)
        return -1;
    if (!net_socks[id].used)
        return -1;
    if (id == net_tcb_sock)
    {
        /* Release the single TCB for the next TCP open. */
        net_tcb_sock = -1;
        net_tcb.state = NET_TCP_CLOSED;
        net_tcb.retry_deadline = 0u;
        net_tcb.retry_count = 0u;
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
    if (id < 0 || id >= NET_SOCK_MAX || !net_socks[id].used)
        return -1;
    if (net_socks[id].kind != NET_SOCK_TCP || id != net_tcb_sock)
        return -1;
    lport = net_socks[id].port;
    return net_tcp_syn(&net_tcb, dmac, rip, rport, lport, iss, out, outlen);
}

/* Handshake/data input through the bind: feeds one RX frame to the bound
 * TCB (SYN-ACK check + RST abort live in tcp.h). An abort back to CLOSED
 * disarms the socket's waiter, so no waiter is left armed on a dead
 * connection. Returns net_tcp_input's 1 (ACK emitted) / 0 (drop). */
int net_sock_tcp_input(int id, const uint8_t *f, unsigned long len, uint8_t *out, unsigned long *outlen)
{
    int rc;
    int was_syn_sent;
    if (id < 0 || id >= NET_SOCK_MAX || !net_socks[id].used)
        return -1;
    if (net_socks[id].kind != NET_SOCK_TCP || id != net_tcb_sock)
        return -1;
    was_syn_sent = (net_tcb.state == NET_TCP_SYN_SENT);
    rc = net_tcp_input(&net_tcb, f, len, out, outlen);
    if (rc == 1 && was_syn_sent)
    {
        /* SYN-ACK accepted (SYN_SENT -> ESTABLISHED): the SYN retry budget
         * is spent, so the fresh connection starts disarmed. Gated on the
         * prior state, not just rc: the seam also routes FIN_WAIT inputs
         * (v2_main non-ESTABLISHED leg), and a future 1-return from any
         * other state (Task 3 peer-ACK close) must leave that state's
         * retry budget alone. The CLOSED abort below already disarmed via
         * tcp.h; only handshake success needs this. */
        net_tcb.retry_deadline = 0u;
        net_tcb.retry_count = 0u;
    }
    if (net_tcb.state == NET_TCP_CLOSED)
        net_waiter_clear(id);
    return rc;
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
 * (copy out via net_sock_tcp_tx). Stop-and-wait: a second S_SEND while
 * the retry is armed (one segment already outstanding, covering ACK not
 * yet seen) is rejected, never interleaving bytes; the covering ACK
 * (ack_cover) disarms for the next send. Any gate failure emits nothing.
 * Returns payload bytes accepted, or -1. */
int net_sock_send(int id, const uint8_t *buf, unsigned long len)
{
    unsigned long flen = 0;
    if (id < 0 || id >= NET_SOCK_MAX || !net_socks[id].used)
        return -1;
    if (net_socks[id].kind != NET_SOCK_TCP)
        return -1;
    if (id != net_tcb_sock || net_tcb.state != NET_TCP_ESTABLISHED)
        return -1;
    if (net_tcb.retry_deadline != 0u)
        return -1;
    if (len < 1 || len > (unsigned long)TCP_MSS_DEFAULT)
        return -1;
    if (!buf)
        return -1;
    if (tcp_data_build(&net_tcb, buf, len, net_tcp_tx, &flen) != 0)
        return -1;
    net_tcp_tx_len = flen;
    /* Fresh frame, fresh budget: clear any stale retry state, still
     * unarmed (the TX pass arms the deadline after transmitting, per the
     * tcp.h convention; a covering ACK disarms via ack_cover below). */
    net_tcb.retry_deadline = 0u;
    net_tcb.retry_count = 0u;
    return (int)len;
}

/* Graceful-close seam (design Sec 2: the S_CLOSE-on-ESTABLISHED leg the
 * RPC close handler calls instead of the abort release): ESTABLISHED
 * emits one header-only FIN|ACK into the parked TX frame (copy out via
 * net_sock_tcp_tx; the retry slice resends it verbatim and arms the
 * deadline on the TX pass, so the deadline stays unarmed here) and
 * enters FIN_WAIT with cleared retry state. The socket stays open and
 * bound: a second concurrent TCP open still fails closed and S_SEND
 * stays gated off. A parked unacked frame (retry armed by the TX pass)
 * still owns the single TX slot, so building FIN here would silently
 * drop data: that close is rejected with -1 and changes nothing (close
 * after the covering ACK disarms, or after exhaustion aborts). Any other
 * gate failure (bad id, unbound, non-TCP, non-ESTABLISHED, ARP miss)
 * emits nothing and changes nothing. Returns 0 on FIN_WAIT entry, -1
 * otherwise. */
int net_sock_fin_close(int id)
{
    unsigned long flen = 0;
    if (id < 0 || id >= NET_SOCK_MAX || !net_socks[id].used)
        return -1;
    if (net_socks[id].kind != NET_SOCK_TCP)
        return -1;
    if (id != net_tcb_sock || net_tcb.state != NET_TCP_ESTABLISHED)
        return -1;
    if (net_tcb.retry_deadline != 0u)
        return -1;
    if (tcp_fin_build(&net_tcb, net_tcp_tx, &flen) != 0)
        return -1;
    net_tcp_tx_len = flen;
    net_tcb.state = NET_TCP_FIN_WAIT;
    net_tcb.retry_deadline = 0u;
    net_tcb.retry_count = 0u;
    return 0;
}

/* Parked TX frame from the last successful TCP net_sock_send: sets
 * *len_out and returns the frame bytes, or 0/0 when nothing was ever
 * emitted. The wire TX path copies the frame before transmitting. */
const uint8_t *net_sock_tcp_tx(unsigned long *len_out)
{
    if (len_out)
        *len_out = net_tcp_tx_len;
    return net_tcp_tx_len ? net_tcp_tx : 0;
}

/* Arm the retry deadline after the TX pass transmits the parked frame
 * (design Sec 2, RFC 793 section 3.7: the tcp.h convention is that builds
 * leave the deadline unarmed and the TX pass arms it). Applies to any live
 * state (SYN_SENT SYN, ESTABLISHED PSH, FIN_WAIT FIN); the count is left
 * alone (builds zero it for a fresh budget, the poll below advances it on
 * resend), so re-arming an already-armed frame only moves the deadline.
 * Returns 0 on arming, -1 when unbound, CLOSED, or nothing is parked. */
int net_sock_tcp_retry_arm(int id, uint64_t now, uint64_t spacing)
{
    struct net_tcp_conn *c = net_sock_tcp(id);
    if (!c)
        return -1;
    if (c->state == NET_TCP_CLOSED)
        return -1;
    if (net_tcp_tx_len == 0)
        return -1;
    c->retry_deadline = now + spacing;
    return 0;
}

/* Covering-ACK disarm (RFC 793 section 3.7: ACKed data stops retransmit).
 * Single-flight stop-and-wait: exactly one segment is ever outstanding,
 * so an ack equal to snd_nxt covers it fully and disarms. ESTABLISHED
 * only: FIN_WAIT ACKs belong to the Task 3 peer-ACK close, never disarmed
 * here. Returns 1 on disarm, 0 when untouched, -1 when unbound. */
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

/* Per-pass retry due check (design Sec 2, RFC 793 section 3.7: same pass
 * that pumps RX). Wrap-safe unsigned compare, as the waiter expiry. On a
 * due expiry with budget left the parked frame is resent verbatim (bytes
 * untouched, snd_nxt holds) and the deadline re-arms; on the 5th due
 * expiry (count already at NET_TCP_RETRY_MAX - 1) the TCB RST-aborts to
 * CLOSED with a header-only RST|ACK parked for the wire pass, the retry
 * state disarms, and the bound socket's waiter (if armed) is captured for
 * the caller's single S_ERR wake and cleared. Returns 0 (nothing due),
 * 1 (resend: transmit net_sock_tcp_tx verbatim), or 2 (abort: transmit
 * the parked RST, ASEND S_ERR once iff *waiter_out). Both out-params are
 * always written (0 on 0/1) and tolerate NULL. */
int net_sock_tcp_retry_poll(uint64_t now, uint64_t spacing, unsigned *owner_out, int *waiter_out)
{
    int bound = net_sock_tcp_bound();
    struct net_tcp_conn *c;
    unsigned long rstlen = 0;
    if (owner_out)
        *owner_out = 0;
    if (waiter_out)
        *waiter_out = 0;
    c = net_sock_tcp(bound);
    if (!c || c->state == NET_TCP_CLOSED)
        return 0;
    if (c->retry_deadline == 0u)
        return 0;
    if (net_tcp_tx_len == 0)
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
    if (tcp_rst_build(c, net_tcp_tx, &rstlen) == 0)
        net_tcp_tx_len = rstlen;
    else
        net_tcp_tx_len = 0; /* ARP miss: abort the state, send nothing */
    c->state = NET_TCP_CLOSED;
    c->retry_deadline = 0u;
    c->retry_count = 0u;
    if (bound >= 0 && bound < NET_SOCK_MAX && net_waiters[bound].armed)
    {
        if (owner_out)
            *owner_out = net_waiters[bound].owner;
        if (waiter_out)
            *waiter_out = 1;
        net_waiter_clear(bound);
    }
    return 2;
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
