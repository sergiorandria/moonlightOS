/* tests/test_tcp.c - TCP socket-API seam vectors (real API: table +
 * handshake bind + send seam + RX demux). Single-TU pattern: sock.c and
 * stack.c are included so the bind accessors (declared only in sock.c,
 * not sock.h) and the RX queue live in one translation unit. */
#include "../userspace/net/sock.c"
#include "../userspace/net/stack.c"
#include "../userspace/net/stack.h"
#include <stdio.h>
#include <string.h>

#define CHECK(c)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(c))                                                                                                      \
        {                                                                                                              \
            printf("FAIL line %d: %s\n", __LINE__, #c);                                                                \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

/* Build an RX TCP frame (eth + IP/20 + TCP/20 + payload) with valid
 * checksums. Returns the total frame length. */
static unsigned t_mk_tcp(uint8_t *f, const uint8_t *smac, uint32_t sip, uint16_t sport, uint16_t dport, uint32_t seq,
                         uint32_t ack, uint8_t flags, const uint8_t *pay, unsigned paylen)
{
    unsigned tot, i;
    uint16_t ck;
    tot = 20u + 20u + paylen;
    for (i = 0; i < 6; i++) /* bound: 6 */
    {
        f[i] = NET_MAC_SELF[i];
        f[6 + i] = smac[i];
    }
    f[12] = 0x08u;
    f[13] = 0x00u;
    f[14] = 0x45u;
    f[15] = 0x00u;
    f[16] = (uint8_t)(tot >> 8);
    f[17] = (uint8_t)(tot & 0xFFu);
    f[18] = 0x12u;
    f[19] = 0x34u;
    f[20] = 0x40u;
    f[21] = 0x00u;
    f[22] = 64u;
    f[23] = IP_PROTO_TCP;
    f[24] = 0u;
    f[25] = 0u;
    f[26] = (uint8_t)(sip >> 24);
    f[27] = (uint8_t)(sip >> 16);
    f[28] = (uint8_t)(sip >> 8);
    f[29] = (uint8_t)sip;
    f[30] = (uint8_t)(NET_IP_SELF >> 24);
    f[31] = (uint8_t)(NET_IP_SELF >> 16);
    f[32] = (uint8_t)(NET_IP_SELF >> 8);
    f[33] = (uint8_t)NET_IP_SELF;
    ck = net_ip_checksum(f + 14, 20);
    f[24] = (uint8_t)(ck >> 8);
    f[25] = (uint8_t)(ck & 0xFFu);
    f[34] = (uint8_t)(sport >> 8);
    f[35] = (uint8_t)sport;
    f[36] = (uint8_t)(dport >> 8);
    f[37] = (uint8_t)dport;
    f[38] = (uint8_t)(seq >> 24);
    f[39] = (uint8_t)(seq >> 16);
    f[40] = (uint8_t)(seq >> 8);
    f[41] = (uint8_t)seq;
    f[42] = (uint8_t)(ack >> 24);
    f[43] = (uint8_t)(ack >> 16);
    f[44] = (uint8_t)(ack >> 8);
    f[45] = (uint8_t)ack;
    f[46] = (uint8_t)(5u << 4);
    f[47] = flags;
    f[48] = 0x08u;
    f[49] = 0x00u;
    f[50] = 0u;
    f[51] = 0u;
    for (i = 0; i < paylen; i++) /* bound: 537 */
        f[54 + i] = pay[i];
    ck = net_tcp_checksum(sip, (uint32_t)NET_IP_SELF, f + 34, 20u + paylen);
    f[50] = (uint8_t)(ck >> 8);
    f[51] = (uint8_t)(ck & 0xFFu);
    return 14u + tot;
}

/* Mirror a SYN into its peer SYN-ACK: swap MACs/IPs/ports, set SYN|ACK,
 * peer seq, and ack = iss+1. Re-checksums both headers. */
static void t_mk_synack(const uint8_t *syn, uint8_t *sa, uint32_t peer_seq, uint32_t iss, uint16_t lport_raw_hi,
                        uint16_t lport_raw_lo)
{
    unsigned i;
    for (i = 0; i < 14u + 20u + 24u; i++) /* bound: 58 */
        sa[i] = syn[i];
    for (i = 0; i < 6u; i++) /* bound: 6 */
    {
        sa[i] = syn[6 + i];
        sa[6 + i] = syn[i];
    }
    for (i = 0; i < 4u; i++) /* bound: 4 */
    {
        uint8_t tmp = sa[26 + i];
        sa[26 + i] = sa[30 + i];
        sa[30 + i] = tmp;
    }
    sa[34] = 0u;
    sa[35] = 80u;
    sa[36] = lport_raw_hi;
    sa[37] = lport_raw_lo;
    sa[14 + 20 + 13] = (uint8_t)(TCP_SYN | TCP_ACK);
    sa[38] = (uint8_t)(peer_seq >> 24);
    sa[39] = (uint8_t)(peer_seq >> 16);
    sa[40] = (uint8_t)(peer_seq >> 8);
    sa[41] = (uint8_t)peer_seq;
    sa[42] = (uint8_t)((iss + 1u) >> 24);
    sa[43] = (uint8_t)((iss + 1u) >> 16);
    sa[44] = (uint8_t)((iss + 1u) >> 8);
    sa[45] = (uint8_t)(iss + 1u);
    sa[24] = 0u;
    sa[25] = 0u;
    {
        uint16_t ipck = net_ip_checksum(sa + 14, 20);
        sa[24] = (uint8_t)(ipck >> 8);
        sa[25] = (uint8_t)(ipck & 0xFFu);
    }
    sa[52] = 0u;
    sa[53] = 0u;
    {
        uint32_t rip = (uint32_t)(((uint32_t)sa[26] << 24) | ((uint32_t)sa[27] << 16) | ((uint32_t)sa[28] << 8) |
                                  (uint32_t)sa[29]);
        uint16_t ck = net_tcp_checksum(rip, (uint32_t)NET_IP_SELF, sa + 34, 24);
        sa[52] = (uint8_t)(ck >> 8);
        sa[53] = (uint8_t)(ck & 0xFFu);
    }
}

#include "../userspace/net/arp_cache.c"

int main(void)
{
    static const uint8_t gwmac[6] = {0x52u, 0x54u, 0x00u, 0x12u, 0x34u, 0x56u};
    static const uint8_t hello[5] = {'h', 'e', 'l', 'l', 'o'};
    static uint8_t big[537];
    uint8_t syn[14 + 20 + 24];
    uint8_t sa[14 + 20 + 24];
    uint8_t rep[14 + 20 + 20];
    uint8_t fr[14 + 20 + 20 + 537];
    uint8_t buf[600];
    unsigned long synlen = 0, replen = 0;
    unsigned flen;
    uint8_t dmac[6];
    uint32_t rip, iss = 0x01020304u, peer = 0x0A0B0C0Du;
    uint32_t sip = 0;
    uint16_t sport = 0;
    int trunc = -1, n, a, b2;
    unsigned wowner = 0;
    struct net_tcp_conn *t;
    unsigned i;
    for (i = 0; i < sizeof(big); i++) /* bound: 537 */
        big[i] = 0x41u;

    /* ---- Table: TCP is a first-class entry ---- */
    net_stack_init();
    CHECK(net_arp_lookup((uint32_t)NET_IP_GW, dmac) == 0);
    a = net_sock_open(NET_SOCK_TCP, 8080, 1);
    CHECK(a >= 0);
    CHECK(net_sock_open(NET_SOCK_TCP, 8080, 2) < 0); /* duplicate port */
    CHECK(net_sock_open(99, 8100, 1) < 0);           /* bad kind */
    CHECK(net_sock_demux(8080) == a);
    CHECK(net_sock_demux(9999) < 0);
    CHECK(net_sock_owned(a, 1));
    CHECK(!net_sock_owned(a, 2));
    /* CLOSED bind: exactly one TCB, no TX parked. */
    t = net_sock_tcp(a);
    CHECK(t != 0);
    CHECK(t->state == NET_TCP_CLOSED);
    CHECK(net_sock_tcp_bound() == a);
    {
        unsigned long txlen = 0;
        CHECK(net_sock_tcp_tx(&txlen) == 0 && txlen == 0);
    }
    CHECK(net_sock_tcp(-1) == 0);

    /* ---- Handshake: SYN -> SYN-ACK -> ESTABLISHED + pure ACK ---- */
    rip = (uint32_t)NET_IP_GW;
    CHECK(net_sock_tcp_syn(a, dmac, rip, 80u, iss, syn, &synlen) == 0);
    CHECK(t->state == NET_TCP_SYN_SENT && t->snd_nxt == iss + 1u);
    CHECK(synlen == sizeof(syn));
    CHECK(syn[14 + 20 + 13] == (uint8_t)TCP_SYN);
    CHECK(net_ip_checksum(syn + 14, 20) == 0u);
    CHECK(net_tcp_checksum((uint32_t)NET_IP_SELF, rip, syn + 34, 24) == 0u);
    CHECK(net_sock_tcp_syn(-1, dmac, rip, 80u, iss, syn, &synlen) < 0);
    /* Send gate: SYN_SENT emits nothing, advances nothing. */
    {
        uint32_t snd0 = t->snd_nxt;
        unsigned long l0 = 0;
        CHECK(net_sock_send(a, hello, sizeof(hello)) < 0);
        CHECK(t->snd_nxt == snd0);
        CHECK(net_sock_tcp_tx(&l0) == 0 && l0 == 0);
    }
    t_mk_synack(syn, sa, peer, iss, 0x1Fu, 0x90u);
    CHECK(net_sock_tcp_input(a, sa, sizeof(sa), rep, &replen) == 1);
    CHECK(t->state == NET_TCP_ESTABLISHED && t->irs == peer);
    CHECK(replen == sizeof(rep));
    CHECK(rep[14 + 20 + 13] == (uint8_t)TCP_ACK);
    CHECK(rep[42] == (uint8_t)((peer + 1u) >> 24) && rep[43] == (uint8_t)((peer + 1u) >> 16) &&
          rep[44] == (uint8_t)((peer + 1u) >> 8) && rep[45] == (uint8_t)(peer + 1u)); /* ack = irs+1, full BE */
    CHECK(net_tcp_checksum((uint32_t)NET_IP_SELF, rip, rep + 34, 20) == 0u);

    /* ---- Send seam: one in-order MSS-capped segment ---- */
    {
        uint32_t snd0 = t->snd_nxt;
        unsigned long txlen = 0;
        const uint8_t *tx;
        CHECK(net_sock_send(a, hello, sizeof(hello)) == (int)sizeof(hello));
        CHECK(t->snd_nxt == snd0 + 5u);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(tx != 0 && txlen == 14u + 20u + 20u + sizeof(hello));
        CHECK(tx[12] == 0x08u && tx[13] == 0x00u);
        CHECK(tx[14 + 9] == IP_PROTO_TCP);
        CHECK(tx[14 + 20 + 13] == (uint8_t)(TCP_PSH | TCP_ACK));
        CHECK(memcmp(tx + 54, hello, sizeof(hello)) == 0);
        CHECK(net_ip_checksum(tx + 14, 20) == 0u);
        CHECK(net_tcp_checksum((uint32_t)NET_IP_SELF, rip, tx + 34, 20 + sizeof(hello)) == 0u);
        /* Oversize (> MSS 536) fails closed: no advance. */
        CHECK(net_sock_send(a, big, sizeof(big)) < 0);
        CHECK(t->snd_nxt == snd0 + 5u);
    }
    /* Single live TCB: second concurrent TCP open fails closed. */
    b2 = net_sock_open(NET_SOCK_TCP, 8081, 2);
    CHECK(b2 < 0);
    CHECK(net_sock_demux(8081) < 0);

    /* ---- RX demux: in-order PSH/ACK queues, wakes the waiter once ---- */
    {
        uint32_t rcv0 = t->rcv_nxt, snd0 = t->snd_nxt;
        unsigned long alen = 0;
        const uint8_t *ackf;
        CHECK(net_waiter_arm(a, 1, 1000, 50) == 0);
        flen = t_mk_tcp(fr, gwmac, rip, 80u, 8080u, rcv0, snd0, (uint8_t)(TCP_PSH | TCP_ACK), hello, sizeof(hello));
        CHECK(net_stack_rx(fr, flen) == NET_CLASS_TCP);
        CHECK(t->rcv_nxt == rcv0 + sizeof(hello));
        CHECK(t->snd_nxt == snd0); /* RX never advances snd_nxt */
        CHECK(net_waiter_match(8080, &wowner) == a);
        CHECK(wowner == 1);
        trunc = -1;
        sip = 0;
        sport = 0;
        n = net_tcp_recv_from(8080, buf, sizeof(buf), &sip, &sport, &trunc);
        CHECK(n == (int)sizeof(hello));
        CHECK(trunc == 0);
        CHECK(sip == rip && sport == 80u);
        CHECK(memcmp(buf, hello, sizeof(hello)) == 0);
        net_waiter_clear(a);
        CHECK(net_waiter_match(8080, &wowner) < 0);
        /* Parked ACK covers the new rcv_nxt, clears exactly once. */
        ackf = net_tcp_ack_tx(&alen);
        CHECK(ackf != 0 && alen == 14u + 20u + 20u);
        CHECK(ackf[14 + 20 + 13] == (uint8_t)TCP_ACK);
        CHECK(ackf[42] == (uint8_t)(t->rcv_nxt >> 24) && ackf[43] == (uint8_t)(t->rcv_nxt >> 16) &&
              ackf[44] == (uint8_t)(t->rcv_nxt >> 8) && ackf[45] == (uint8_t)t->rcv_nxt);
        net_tcp_ack_clear();
        ackf = net_tcp_ack_tx(&alen);
        CHECK(ackf == 0 && alen == 0);
        /* Duplicate drops: no double delivery. */
        CHECK(net_stack_rx(fr, flen) == NET_CLASS_TCP);
        CHECK(t->rcv_nxt == rcv0 + sizeof(hello));
        CHECK(net_tcp_recv_from(8080, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        /* Unbound dport: classified TCP, never queued. */
        flen = t_mk_tcp(fr, gwmac, rip, 80u, 9999u, rcv0, snd0, (uint8_t)(TCP_PSH | TCP_ACK), hello, sizeof(hello));
        CHECK(net_stack_rx(fr, flen) == NET_CLASS_TCP);
        CHECK(net_tcp_recv_from(9999, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
    }

    /* ---- RST aborts to CLOSED, disarms the waiter, frees the bind ---- */
    CHECK(net_sock_close(a) == 0);
    CHECK(net_sock_tcp_bound() < 0);
    CHECK(net_sock_close(a) < 0); /* double close fails */
    b2 = net_sock_open(NET_SOCK_TCP, 8081, 2);
    CHECK(b2 >= 0);
    CHECK(net_sock_tcp_bound() == b2);
    t = net_sock_tcp(b2);
    CHECK(t != 0 && t->state == NET_TCP_CLOSED);
    CHECK(net_sock_tcp_syn(b2, dmac, rip, 80u, iss, syn, &synlen) == 0);
    CHECK(t->state == NET_TCP_SYN_SENT);
    t_mk_synack(syn, sa, peer, iss, 0x1Fu, 0x91u);
    sa[14 + 20 + 13] = (uint8_t)(TCP_RST | TCP_ACK);
    sa[52] = 0u;
    sa[53] = 0u;
    {
        uint32_t rsp = (uint32_t)(((uint32_t)sa[26] << 24) | ((uint32_t)sa[27] << 16) | ((uint32_t)sa[28] << 8) |
                                  (uint32_t)sa[29]);
        uint16_t ck = net_tcp_checksum(rsp, (uint32_t)NET_IP_SELF, sa + 34, 24);
        sa[52] = (uint8_t)(ck >> 8);
        sa[53] = (uint8_t)(ck & 0xFFu);
    }
    CHECK(net_waiter_arm(b2, 2, 1000, 50) == 0);
    CHECK(net_sock_tcp_input(b2, sa, sizeof(sa), rep, &replen) == 0);
    CHECK(t->state == NET_TCP_CLOSED);
    CHECK(net_waiter_match(8081, &wowner) < 0);
    CHECK(net_sock_send(b2, hello, sizeof(hello)) < 0); /* CLOSED gate */
    CHECK(net_sock_close(b2) == 0);
    CHECK(net_sock_tcp_bound() < 0);

    /* ---- Active close: S_CLOSE equivalent enters FIN_WAIT (RFC 793 section 3.5) ---- */
    {
        int c2, c3;
        uint32_t sndf;
        unsigned long flen2 = 0;
        const uint8_t *fin;
        CHECK(net_sock_fin_close(-1) < 0);
        c2 = net_sock_open(NET_SOCK_TCP, 8090, 3);
        CHECK(c2 >= 0);
        t = net_sock_tcp(c2);
        CHECK(t != 0 && t->state == NET_TCP_CLOSED);
        CHECK(t->retry_count == 0u && t->retry_deadline == 0u);
        CHECK(net_sock_fin_close(c2) < 0); /* CLOSED gate: nothing emitted */
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(net_sock_tcp_syn(c2, dmac, rip, 80u, iss, syn, &synlen) == 0);
        t_mk_synack(syn, sa, peer, iss, 0x1Fu, 0x9Au);
        CHECK(net_sock_tcp_input(c2, sa, sizeof(sa), rep, &replen) == 1);
        CHECK(t->state == NET_TCP_ESTABLISHED);
        sndf = t->snd_nxt;
        /* S_CLOSE equivalent: FIN parks, FIN_WAIT holds the bind. */
        CHECK(net_sock_fin_close(c2) == 0);
        CHECK(t->state == NET_TCP_FIN_WAIT);
        CHECK(t->retry_count == 0u && t->retry_deadline == 0u);
        CHECK(t->snd_nxt == sndf + 1u); /* FIN consumes one sequence number */
        fin = net_sock_tcp_tx(&flen2);
        CHECK(fin != 0 && flen2 == 14u + 20u + 20u);
        CHECK(fin[14 + 20 + 13] == (uint8_t)(TCP_FIN | TCP_ACK));
        CHECK(fin[38] == (uint8_t)(sndf >> 24) && fin[39] == (uint8_t)(sndf >> 16) && fin[40] == (uint8_t)(sndf >> 8) &&
              fin[41] == (uint8_t)sndf);
        CHECK(fin[42] == (uint8_t)(t->rcv_nxt >> 24) && fin[43] == (uint8_t)(t->rcv_nxt >> 16) &&
              fin[44] == (uint8_t)(t->rcv_nxt >> 8) && fin[45] == (uint8_t)t->rcv_nxt);
        CHECK(net_ip_checksum(fin + 14, 20) == 0u);
        CHECK(net_tcp_checksum((uint32_t)NET_IP_SELF, rip, fin + 34, 20) == 0u);
        CHECK(net_sock_tcp_bound() == c2); /* bind held in FIN_WAIT */
        CHECK(net_sock_open(NET_SOCK_TCP, 8091, 4) < 0);
        CHECK(net_sock_send(c2, hello, sizeof(hello)) < 0); /* FIN_WAIT: no new data */
        /* RST in FIN_WAIT aborts to CLOSED and disarms the waiter. */
        CHECK(net_waiter_arm(c2, 3, 1000, 50) == 0);
        sa[14 + 20 + 13] = (uint8_t)(TCP_RST | TCP_ACK);
        sa[52] = 0u;
        sa[53] = 0u;
        {
            uint32_t rsp = (uint32_t)(((uint32_t)sa[26] << 24) | ((uint32_t)sa[27] << 16) | ((uint32_t)sa[28] << 8) |
                                      (uint32_t)sa[29]);
            uint16_t ck = net_tcp_checksum(rsp, (uint32_t)NET_IP_SELF, sa + 34, 24);
            sa[52] = (uint8_t)(ck >> 8);
            sa[53] = (uint8_t)(ck & 0xFFu);
        }
        CHECK(net_sock_tcp_input(c2, sa, sizeof(sa), rep, &replen) == 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(t->retry_count == 0u && t->retry_deadline == 0u);
        CHECK(net_waiter_match(8090, &wowner) < 0);
        CHECK(net_sock_close(c2) == 0);
        CHECK(net_sock_tcp_bound() < 0);
        /* Reopened socket starts with zeroed retry state (no leaked deadline). */
        c3 = net_sock_open(NET_SOCK_TCP, 8092, 3);
        CHECK(c3 >= 0);
        t = net_sock_tcp(c3);
        CHECK(t != 0 && t->state == NET_TCP_CLOSED);
        CHECK(t->retry_count == 0u && t->retry_deadline == 0u);
        CHECK(net_sock_close(c3) == 0);
    }

    /* ---- Task 3 peer-ACK close (RFC 793 section 3.5 FIN-WAIT-1/2,
     * single-TCB slice): FIN->ACK and FIN->FIN-ACK close exactly once
     * (no reply frame, retry disarmed, waiter disarmed); a duplicate FIN
     * after CLOSED drops with no second close; an early FIN-ACK (peer
     * closing before our FIN is ACKed) still closes once; a stale ACK
     * holds FIN_WAIT with the FIN retry untouched ---- */
    {
        int c4;
        uint32_t sndf;
        unsigned long rl2 = 0;
        /* FIN -> pure covering ACK closes. */
        c4 = net_sock_open(NET_SOCK_TCP, 8093, 3);
        CHECK(c4 >= 0);
        t = net_sock_tcp(c4);
        CHECK(t != 0);
        CHECK(net_sock_tcp_syn(c4, dmac, rip, 80u, iss, syn, &synlen) == 0);
        t_mk_synack(syn, sa, peer, iss, 0x1Fu, 0x9Du);
        CHECK(net_sock_tcp_input(c4, sa, sizeof(sa), rep, &replen) == 1);
        CHECK(t->state == NET_TCP_ESTABLISHED);
        CHECK(net_sock_fin_close(c4) == 0);
        CHECK(t->state == NET_TCP_FIN_WAIT);
        sndf = t->snd_nxt;
        flen = t_mk_tcp(fr, gwmac, rip, 80u, 8093u, t->rcv_nxt, sndf, (uint8_t)TCP_ACK, hello, 0);
        CHECK(net_sock_tcp_input(c4, fr, flen, rep, &rl2) == 0);
        CHECK(rl2 == 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(t->retry_deadline == 0u && t->retry_count == 0u);
        /* Duplicate ACK after CLOSED: drops, no second close. */
        CHECK(net_sock_tcp_input(c4, fr, flen, rep, &rl2) == 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(t->retry_deadline == 0u && t->retry_count == 0u);
        CHECK(net_sock_close(c4) == 0);
        CHECK(net_sock_tcp_bound() < 0);
        /* FIN -> FIN-ACK closes; duplicate FIN drops with no second
         * close; the armed waiter disarms (loop wakes it once). */
        c4 = net_sock_open(NET_SOCK_TCP, 8094, 3);
        CHECK(c4 >= 0);
        t = net_sock_tcp(c4);
        CHECK(t != 0);
        CHECK(net_sock_tcp_syn(c4, dmac, rip, 80u, iss, syn, &synlen) == 0);
        t_mk_synack(syn, sa, peer, iss, 0x1Fu, 0x9Eu);
        CHECK(net_sock_tcp_input(c4, sa, sizeof(sa), rep, &replen) == 1);
        CHECK(net_sock_fin_close(c4) == 0);
        sndf = t->snd_nxt;
        CHECK(net_waiter_arm(c4, 3, 1000, 50) == 0);
        flen = t_mk_tcp(fr, gwmac, rip, 80u, 8094u, t->rcv_nxt, sndf, (uint8_t)(TCP_FIN | TCP_ACK), hello, 0);
        CHECK(net_sock_tcp_input(c4, fr, flen, rep, &rl2) == 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(t->retry_deadline == 0u && t->retry_count == 0u);
        CHECK(net_waiter_match(8094, &wowner) < 0);
        CHECK(net_sock_tcp_input(c4, fr, flen, rep, &rl2) == 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(net_waiter_match(8094, &wowner) < 0);
        CHECK(net_sock_close(c4) == 0);
        /* Early FIN-ACK (ack covers only the pre-FIN edge: the peer had
         * not seen our FIN) still closes exactly once. */
        c4 = net_sock_open(NET_SOCK_TCP, 8095, 3);
        CHECK(c4 >= 0);
        t = net_sock_tcp(c4);
        CHECK(t != 0);
        CHECK(net_sock_tcp_syn(c4, dmac, rip, 80u, iss, syn, &synlen) == 0);
        t_mk_synack(syn, sa, peer, iss, 0x1Fu, 0x9Fu);
        CHECK(net_sock_tcp_input(c4, sa, sizeof(sa), rep, &replen) == 1);
        CHECK(net_sock_fin_close(c4) == 0);
        sndf = t->snd_nxt;
        flen = t_mk_tcp(fr, gwmac, rip, 80u, 8095u, t->rcv_nxt, sndf - 1u, (uint8_t)(TCP_FIN | TCP_ACK), hello, 0);
        CHECK(net_sock_tcp_input(c4, fr, flen, rep, &rl2) == 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(net_sock_tcp_input(c4, fr, flen, rep, &rl2) == 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(net_sock_close(c4) == 0);
        /* Stale pure ACK (pre-FIN edge, no FIN flag) holds FIN_WAIT with
         * the armed FIN retry untouched; the covering ACK then closes. */
        c4 = net_sock_open(NET_SOCK_TCP, 8096, 3);
        CHECK(c4 >= 0);
        t = net_sock_tcp(c4);
        CHECK(t != 0);
        CHECK(net_sock_tcp_syn(c4, dmac, rip, 80u, iss, syn, &synlen) == 0);
        t_mk_synack(syn, sa, peer, iss, 0x1Fu, 0xA0u);
        CHECK(net_sock_tcp_input(c4, sa, sizeof(sa), rep, &replen) == 1);
        CHECK(net_sock_fin_close(c4) == 0);
        sndf = t->snd_nxt;
        CHECK(net_sock_tcp_retry_arm(c4, 1000, 50) == 0);
        flen = t_mk_tcp(fr, gwmac, rip, 80u, 8096u, t->rcv_nxt, sndf - 1u, (uint8_t)TCP_ACK, hello, 0);
        CHECK(net_sock_tcp_input(c4, fr, flen, rep, &rl2) == 0);
        CHECK(t->state == NET_TCP_FIN_WAIT);
        CHECK(t->retry_deadline == 1050u && t->retry_count == 0u);
        flen = t_mk_tcp(fr, gwmac, rip, 80u, 8096u, t->rcv_nxt, sndf, (uint8_t)TCP_ACK, hello, 0);
        CHECK(net_sock_tcp_input(c4, fr, flen, rep, &rl2) == 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(t->retry_deadline == 0u && t->retry_count == 0u);
        CHECK(net_sock_close(c4) == 0);
        CHECK(net_sock_tcp_bound() < 0);
    }

    /* ---- Fair-share: 4 concurrent opens hold all slots ---- */
    {
        int ids[4];
        unsigned j;
        for (j = 0; j < 4; j++) /* bound: 4 */
        {
            ids[j] = net_sock_open(NET_SOCK_UDP, (uint16_t)(4000 + j), 5);
            CHECK(ids[j] >= 0);
        }
        CHECK(net_sock_open(NET_SOCK_UDP, 5000, 5) < 0);
        for (j = 0; j < 4; j++) /* bound: 4 */
            CHECK(net_sock_close(ids[j]) == 0);
    }

    /* ---- Header validators (tcp_hdr_ok ground truth) ---- */
    {
        uint8_t valid[14 + 20 + 20];
        uint8_t shortf[16];
        memset(valid, 0, sizeof(valid));
        valid[12] = 0x08u;
        valid[13] = 0x00u;
        valid[14] = 0x45u;
        valid[16] = 0u;
        valid[17] = 40u;
        valid[23] = IP_PROTO_TCP;
        valid[14 + 20 + 12] = 0x50u;
        {
            uint16_t ipck = net_ip_checksum(valid + 14, 20);
            valid[24] = (uint8_t)(ipck >> 8);
            valid[25] = (uint8_t)(ipck & 0xFFu);
        }
        {
            uint16_t ck = net_tcp_checksum(0u, 0u, valid + 34, 20);
            valid[50] = (uint8_t)(ck >> 8);
            valid[51] = (uint8_t)(ck & 0xFFu);
        }
        CHECK(tcp_hdr_ok(valid, sizeof(valid)) == 1);
        memset(shortf, 0, sizeof(shortf));
        CHECK(tcp_hdr_ok(shortf, sizeof(shortf)) == 0);
        valid[14 + 20 + 12] = 0x40u; /* data offset 4 < min */
        CHECK(tcp_hdr_ok(valid, sizeof(valid)) == 0);
    }

    puts("PASS: test_tcp");
    return 0;
}
