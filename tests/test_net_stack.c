/* tests/test_net_stack.c - classify + socket stub. */
#include "../userspace/net/cksum.h"
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

/* Task 2: ARP table implementation (same single-TU pattern as sock.c/stack.c).
 * Later tasks include arp_cache.h for the canonical MAC/IP constants. */
#include "../userspace/net/arp_cache.c"

static int t_carve_drop7(uint16_t dport)
{
    return dport == 7;
}

static int t_tcp_drop8080(uint16_t dport)
{
    return dport == 8080;
}

/* Seam Task 3: build an RX TCP frame (eth + IP/20 + TCP/20 + payload)
 * with valid checksums. Returns the total frame length. */
static unsigned t3_mk_tcp(uint8_t *f, const uint8_t *smac, uint32_t sip, uint16_t sport, uint16_t dport, uint32_t seq,
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

/* Task 3: DNS codec (same single-TU pattern). */
#include "../userspace/net/dns.c"

/* DHCP client (same single-TU pattern). */
#include "../userspace/net/dhcp.c"

static void t2_mk_arp(uint8_t *f, const uint8_t *dmac, const uint8_t *smac, unsigned op, const uint8_t *sha,
                      uint32_t spa, const uint8_t *tha, uint32_t tpa)
{
    unsigned i;
    for (i = 0; i < 6; i++)
    {
        f[i] = dmac[i];
        f[6 + i] = smac[i];
    }
    f[12] = 0x08;
    f[13] = 0x06;
    f[14] = 0x00;
    f[15] = 0x01;
    f[16] = 0x08;
    f[17] = 0x00;
    f[18] = 0x06;
    f[19] = 0x04;
    f[20] = 0x00;
    f[21] = (uint8_t)op;
    for (i = 0; i < 6; i++)
    {
        f[22 + i] = sha[i];
        f[32 + i] = tha[i];
    }
    f[28] = (uint8_t)(spa >> 24);
    f[29] = (uint8_t)(spa >> 16);
    f[30] = (uint8_t)(spa >> 8);
    f[31] = (uint8_t)spa;
    f[38] = (uint8_t)(tpa >> 24);
    f[39] = (uint8_t)(tpa >> 16);
    f[40] = (uint8_t)(tpa >> 8);
    f[41] = (uint8_t)tpa;
}

/* FIN-retry Task 2: drive a fresh TCP socket to ESTABLISHED through the
 * bind (same canned SYN-ACK shape as the seam vectors: sport 80, peer seq,
 * ack = iss + 1, valid checksums). Returns 0 on ESTABLISHED, -1 otherwise.
 * Buffers: syn/sa 58B, rep 54B. */
static int t2_establish(int id, const uint8_t *dmac, uint32_t rip, uint32_t iss, uint32_t peer, uint16_t lport,
                        uint8_t *syn, uint8_t *sa, uint8_t *rep, unsigned long *replen)
{
    unsigned long synlen = 0, rl = 0;
    uint32_t ack = iss + 1u;
    unsigned i;
    uint16_t ck;
    if (!dmac || !syn || !sa || !rep || !replen)
        return -1;
    if (net_sock_tcp_syn(id, dmac, rip, 80u, iss, syn, &synlen) != 0)
        return -1;
    if (synlen != 58u)
        return -1;
    for (i = 0; i < 58u; i++) /* bound: 58 */
        sa[i] = syn[i];
    for (i = 0; i < 6u; i++) /* bound: 6 */
    {
        sa[i] = syn[6 + i];
        sa[6 + i] = syn[i];
    }
    for (i = 0; i < 4u; i++) /* bound: 4 */
    {
        uint8_t tmpb = sa[26 + i];
        sa[26 + i] = sa[30 + i];
        sa[30 + i] = tmpb;
    }
    sa[34] = 0u;
    sa[35] = 80u;
    sa[36] = (uint8_t)(lport >> 8);
    sa[37] = (uint8_t)lport;
    sa[14 + 20 + 13] = (uint8_t)(TCP_SYN | TCP_ACK);
    sa[38] = (uint8_t)(peer >> 24);
    sa[39] = (uint8_t)(peer >> 16);
    sa[40] = (uint8_t)(peer >> 8);
    sa[41] = (uint8_t)peer;
    sa[42] = (uint8_t)(ack >> 24);
    sa[43] = (uint8_t)(ack >> 16);
    sa[44] = (uint8_t)(ack >> 8);
    sa[45] = (uint8_t)ack;
    sa[24] = 0u;
    sa[25] = 0u;
    ck = net_ip_checksum(sa + 14, 20);
    sa[24] = (uint8_t)(ck >> 8);
    sa[25] = (uint8_t)(ck & 0xFFu);
    sa[52] = 0u;
    sa[53] = 0u;
    ck = net_tcp_checksum(rip, (uint32_t)NET_IP_SELF, sa + 34, 24);
    sa[52] = (uint8_t)(ck >> 8);
    sa[53] = (uint8_t)(ck & 0xFFu);
    /* Simulate the TX pass arming the SYN retry, then prove handshake
     * success (rc == 1 from SYN_SENT) disarms it via the gated seam. */
    {
        struct net_tcp_conn *tc = net_sock_tcp(id);
        if (!tc)
            return -1;
        tc->retry_deadline = 1000u;
        tc->retry_count = 2u;
    }
    if (net_sock_tcp_input(id, sa, 58u, rep, &rl) != 1)
        return -1;
    {
        struct net_tcp_conn *tc = net_sock_tcp(id);
        if (!tc || tc->state != NET_TCP_ESTABLISHED || tc->retry_deadline != 0u || tc->retry_count != 0u)
            return -1;
    }
    *replen = rl;
    return 0;
}

int main(void)
{
    uint8_t arp[42];
    uint8_t ip[34];
    memset(arp, 0, sizeof(arp));
    arp[12] = 0x08;
    arp[13] = 0x06;
    arp[14] = 0x00;
    arp[15] = 0x01;
    arp[16] = 0x08;
    arp[17] = 0x00;
    arp[18] = 6;
    arp[19] = 4;
    arp[20] = 0x00;
    arp[21] = 0x01;
    CHECK(net_classify(arp, sizeof(arp)) == NET_CLASS_ARP);
    memset(ip, 0, sizeof(ip));
    ip[12] = 0x08;
    ip[13] = 0x00;
    ip[14] = 0x45;
    ip[16] = 0x00;
    ip[17] = 20;
    ip[23] = IP_PROTO_TCP;
    /* TCP header min 20 after IHL 20: need 14+20+20 = 54 bytes */
    {
        uint8_t tcp[54];
        memset(tcp, 0, sizeof(tcp));
        memcpy(tcp, ip, 34);
        tcp[17] = 40; /* tot = 40 */
        tcp[23] = IP_PROTO_TCP;
        tcp[14 + 20 + 12] = 0x50; /* data offset 5 */
        /* Task 3: RX validates IP/TCP checksums (UDP precedent), so the
         * classify-level zeroed frame must carry valid checksums. */
        {
            uint16_t ipck = net_ip_checksum(tcp + 14, 20);
            tcp[24] = (uint8_t)(ipck >> 8);
            tcp[25] = (uint8_t)(ipck & 0xFFu);
        }
        {
            uint16_t ck = net_tcp_checksum(0u, 0u, tcp + 34, 20);
            tcp[50] = (uint8_t)(ck >> 8);
            tcp[51] = (uint8_t)(ck & 0xFFu);
        }
        CHECK(net_stack_init() == 0);
        CHECK(net_stack_rx(tcp, sizeof(tcp)) == NET_CLASS_TCP);
    }
    /* ---- Task 1: socket table with port demux (UDP + TCP) ---- */
    {
        int id;
        int ids[4];
        unsigned i;
        id = net_sock_open(NET_SOCK_UDP, 53, 5);
        CHECK(id >= 0);
        CHECK(net_sock_open(NET_SOCK_UDP, 53, 6) < 0);
        CHECK(net_sock_demux(53) == id);
        CHECK(net_sock_demux(9999) < 0);
        CHECK(net_sock_close(id) == 0);
        CHECK(net_sock_close(id) < 0);
        id = net_sock_open(NET_SOCK_UDP, 53, 5);
        CHECK(id >= 0);
        CHECK(net_sock_close(id) == 0);
        /* 1-slot fair-share: 4 concurrent opens hold all slots. */
        for (i = 0; i < 4; i++)
        {
            ids[i] = net_sock_open(NET_SOCK_UDP, (uint16_t)(1000 + i), 5);
            CHECK(ids[i] >= 0);
        }
        CHECK(net_sock_open(NET_SOCK_UDP, 2000, 5) < 0);
        for (i = 0; i < 4; i++)
            CHECK(net_sock_close(ids[i]) == 0);
        id = net_sock_open(NET_SOCK_UDP, 2000, 5);
        CHECK(id >= 0);
        CHECK(net_sock_close(id) == 0);
        /* TCP sockets are first-class table entries (same fair-share). */
        {
            int tid;
            int tids[4];
            unsigned j;
            unsigned owner = 0;
            tid = net_sock_open(NET_SOCK_TCP, 8080, 1);
            CHECK(tid >= 0);
            CHECK(net_sock_open(NET_SOCK_TCP, 8080, 2) < 0);
            CHECK(net_sock_open(99, 8100, 1) < 0);
            CHECK(net_sock_demux(8080) == tid);
            CHECK(net_sock_owned(tid, 1));
            CHECK(net_waiter_arm(tid, 1, 100, 50) == 0);
            CHECK(net_waiter_match(8080, &owner) == tid);
            CHECK(net_sock_close(tid) == 0);
            CHECK(net_waiter_match(8080, &owner) < 0);
            for (j = 0; j < 4; j++) /* bound: 4 */
            {
                tids[j] = net_sock_open(NET_SOCK_TCP, (uint16_t)(9000 + j), 1);
                CHECK(tids[j] >= 0);
            }
            CHECK(net_sock_open(NET_SOCK_TCP, 9004, 1) < 0);
            for (j = 0; j < 4; j++) /* bound: 4 */
                CHECK(net_sock_close(tids[j]) == 0);
        }
    }
    CHECK(net_sock_send(0, ip, 4) < 0);
    /* RFC-style fixed vectors: IPv4 header checksum (field zeroed). */
    {
        static const uint8_t hdr[20] = {0x45, 0x00, 0x00, 0x29, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11,
                                        0x00, 0x00, 0x0A, 0x00, 0x02, 0x0F, 0x0A, 0x00, 0x02, 0x02};
        CHECK(net_ip_checksum(hdr, sizeof(hdr)) == 0x1080u);
    }
    /* UDP pseudo-header checksum: odd 21B segment (13B "Hello, world!"
     * payload, trailing byte padded as high-order octet). */
    {
        static const uint8_t seg[21] = {0x12, 0x34, 0x00, 0x35, 0x00, 0x15, 0x00, 0x00, 0x48, 0x65, 0x6C,
                                        0x6C, 0x6F, 0x2C, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};
        CHECK(net_udp_checksum(0x0A00020Fu, 0x0A000202u, seg, sizeof(seg)) == 0x93FEu);
    }
    /* UDP pseudo-header checksum: even 12B segment (4B "test" payload). */
    {
        static const uint8_t seg[12] = {0x12, 0x34, 0x00, 0x35, 0x00, 0x0C, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74};
        CHECK(net_udp_checksum(0x0A00020Fu, 0x0A000202u, seg, sizeof(seg)) == 0xED82u);
    }
    /* ---- Task 2: ARP table (seed/learn/reply/expiry/evict) ---- */
    {
        static const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        static const uint8_t zeros[6] = {0, 0, 0, 0, 0, 0};
        static const uint8_t pmac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};
        static const uint8_t qmac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x04};
        uint8_t mac[6], rmac[6], frame[42], out[42];
        uint32_t rip;
        unsigned i;
        net_arp_init();
        CHECK(net_arp_need_reply(&rip, rmac) == 0);
        CHECK(net_arp_lookup(NET_IP_GW, mac) == 0);
        CHECK(memcmp(mac, NET_MAC_SELF, 6) == 0);
        CHECK(net_arp_lookup(0x0A000263u, mac) < 0);
        CHECK(net_arp_lookup(NET_IP_GW, NULL) < 0);
        /* Learn from a reply, then lookup hits. */
        t2_mk_arp(frame, NET_MAC_SELF, pmac, 2, pmac, 0x0A000203u, NET_MAC_SELF, NET_IP_SELF);
        net_arp_learn(frame, sizeof(frame));
        CHECK(net_arp_lookup(0x0A000203u, mac) == 0);
        CHECK(memcmp(mac, pmac, 6) == 0);
        CHECK(net_arp_need_reply(&rip, rmac) == 0);
        /* Short frame ignored, entry intact. */
        net_arp_learn(frame, 20u);
        CHECK(net_arp_lookup(0x0A000203u, mac) == 0);
        /* Request for another IP: dropped, no learn, no flag. */
        t2_mk_arp(frame, bcast, qmac, 1, qmac, 0x0A000204u, zeros, 0x0A000263u);
        net_arp_learn(frame, sizeof(frame));
        CHECK(net_arp_need_reply(&rip, rmac) == 0);
        CHECK(net_arp_lookup(0x0A000204u, mac) < 0);
        /* Request for self: learns sender + flags reply. */
        t2_mk_arp(frame, bcast, qmac, 1, qmac, 0x0A000204u, zeros, NET_IP_SELF);
        net_arp_learn(frame, sizeof(frame));
        CHECK(net_arp_lookup(0x0A000204u, mac) == 0);
        CHECK(memcmp(mac, qmac, 6) == 0);
        CHECK(net_arp_need_reply(&rip, rmac) == 1);
        CHECK(rip == 0x0A000204u);
        CHECK(memcmp(rmac, qmac, 6) == 0);
        CHECK(net_arp_need_reply(&rip, rmac) == 0);
        /* Built reply byte-matches the vector. */
        {
            static const uint8_t expect[42] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x52, 0x54, 0x00, 0x12, 0x34,
                                               0x56, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
                                               0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x0A, 0x00, 0x02, 0x0F, 0x02,
                                               0x00, 0x00, 0x00, 0x00, 0x04, 0x0A, 0x00, 0x02, 0x04};
            CHECK(net_arp_build_reply(frame, sizeof(frame), out) == 42);
            CHECK(memcmp(out, expect, sizeof(expect)) == 0);
        }
        CHECK(net_arp_build_reply(frame, 20u, out) < 0);
        CHECK(net_arp_build_reply(frame, sizeof(frame), NULL) < 0);
        /* A reply frame is not a request: no reply built. */
        t2_mk_arp(frame, NET_MAC_SELF, pmac, 2, pmac, 0x0A000203u, NET_MAC_SELF, NET_IP_SELF);
        CHECK(net_arp_build_reply(frame, sizeof(frame), out) < 0);
        /* Request builder vector. */
        CHECK(net_arp_build_request(NET_IP_GW, out) == 42);
        CHECK(memcmp(out, bcast, 6) == 0);
        CHECK(memcmp(out + 6, NET_MAC_SELF, 6) == 0);
        CHECK(out[12] == 0x08 && out[13] == 0x06);
        CHECK(out[20] == 0x00 && out[21] == 0x01);
        CHECK(memcmp(out + 22, NET_MAC_SELF, 6) == 0);
        CHECK(out[28] == 0x0A && out[29] == 0x00 && out[30] == 0x02 && out[31] == 0x0F);
        CHECK(out[32] == 0 && out[33] == 0 && out[34] == 0 && out[35] == 0 && out[36] == 0 && out[37] == 0);
        CHECK(out[38] == 0x0A && out[39] == 0x00 && out[40] == 0x02 && out[41] == 0x02);
        CHECK(net_arp_build_request(NET_IP_GW, NULL) < 0);
        /* Expiry after 60s ticks (boundary still valid). */
        net_arp_init();
        net_arp_tick(NET_ARP_TIMEOUT_TICKS);
        CHECK(net_arp_lookup(NET_IP_GW, mac) == 0);
        net_arp_tick(NET_ARP_TIMEOUT_TICKS + 1u);
        CHECK(net_arp_lookup(NET_IP_GW, mac) < 0);
        /* Learned entries expire relative to learn time. */
        net_arp_init();
        net_arp_tick(1000u);
        t2_mk_arp(frame, NET_MAC_SELF, pmac, 2, pmac, 0x0A000203u, NET_MAC_SELF, NET_IP_SELF);
        net_arp_learn(frame, sizeof(frame));
        net_arp_tick(1000u + NET_ARP_TIMEOUT_TICKS);
        CHECK(net_arp_lookup(0x0A000203u, mac) == 0);
        net_arp_tick(1000u + NET_ARP_TIMEOUT_TICKS + 1u);
        CHECK(net_arp_lookup(0x0A000203u, mac) < 0);
        /* 8 entries: the 9th learn evicts the oldest (gateway at t=0). */
        net_arp_init();
        net_arp_tick(1000u);
        for (i = 0; i < 7; i++)
        {
            uint8_t m[6] = {0x02, 0x00, 0x00, 0x00, 0x00, (uint8_t)(0x10 + i)};
            t2_mk_arp(frame, NET_MAC_SELF, m, 2, m, 0x0A000214u + i, NET_MAC_SELF, NET_IP_SELF);
            net_arp_learn(frame, sizeof(frame));
        }
        {
            static const uint8_t nm[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x77};
            t2_mk_arp(frame, NET_MAC_SELF, nm, 2, nm, 0x0A00025Au, NET_MAC_SELF, NET_IP_SELF);
            net_arp_learn(frame, sizeof(frame));
            CHECK(net_arp_lookup(NET_IP_GW, mac) < 0);
            CHECK(net_arp_lookup(0x0A00025Au, mac) == 0);
            CHECK(memcmp(mac, nm, 6) == 0);
            CHECK(net_arp_lookup(0x0A000214u, mac) == 0);
        }
    }
    /* ---- Task 3: UDP send builder + RX queue + dispatch ---- */
    {
        static const uint8_t hello[13] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};
        static const uint8_t expect[55] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x52, 0x54, 0x00, 0x12, 0x34,
                                           0x56, 0x08, 0x00, 0x45, 0x00, 0x00, 0x29, 0x12, 0x34, 0x40, 0x00,
                                           0x40, 0x11, 0x10, 0x80, 0x0A, 0x00, 0x02, 0x0F, 0x0A, 0x00, 0x02,
                                           0x02, 0xC0, 0x00, 0x00, 0x35, 0x00, 0x15, 0xE6, 0x31, 0x48, 0x65,
                                           0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};
        uint8_t frame[1514];
        uint8_t buf[32];
        unsigned long flen = 0;
        uint32_t sip = 0;
        uint16_t sport = 0;
        int trunc = -1;
        int n;
        unsigned i;
        net_stack_init();
        net_arp_init();
        CHECK(net_stack_udp_send(0x0A000202u, 53, 49152, hello, sizeof(hello), frame, &flen) == 0);
        CHECK(flen == sizeof(expect));
        CHECK(memcmp(frame, expect, sizeof(expect)) == 0);
        CHECK(frame[12] == 0x08 && frame[13] == 0x00);
        CHECK(frame[14] == 0x45 && frame[22] == 64 && frame[23] == IP_PROTO_UDP);
        CHECK(frame[34] == 0xC0 && frame[35] == 0x00);
        CHECK(frame[36] == 0x00 && frame[37] == 0x35);
        CHECK(frame[38] == 0x00 && frame[39] == 0x15);
        CHECK(net_stack_udp_send(0x0A000263u, 53, 49152, hello, sizeof(hello), frame, &flen) == -1);
        {
            static uint8_t bigpay[1473];
            memset(bigpay, 0x41, sizeof(bigpay));
            CHECK(net_stack_udp_send(0x0A000202u, 53, 49152, bigpay, sizeof(bigpay), frame, &flen) == -2);
        }
        net_stack_init();
        net_arp_init();
        CHECK(net_stack_rx(expect, sizeof(expect)) == NET_CLASS_UDP);
        trunc = -1;
        sip = 0;
        sport = 0;
        n = net_udp_recv(buf, sizeof(buf), &sip, &sport, &trunc);
        CHECK(n == 13);
        CHECK(trunc == 0);
        CHECK(sip == 0x0A00020Fu);
        CHECK(sport == 49152);
        CHECK(memcmp(buf, hello, sizeof(hello)) == 0);
        {
            uint8_t bad[55];
            memcpy(bad, expect, sizeof(bad));
            bad[sizeof(bad) - 1] ^= 0xFFu;
            CHECK(net_stack_rx(bad, sizeof(bad)) == NET_CLASS_DROP);
            CHECK(net_udp_recv(buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        }
        CHECK(net_stack_rx(expect, sizeof(expect)) == NET_CLASS_UDP);
        trunc = -1;
        CHECK(net_udp_recv(buf, 4, &sip, &sport, &trunc) == -(NET_ERR_TRUNC));
        CHECK(trunc == 1);
        CHECK(memcmp(buf, hello, 4) == 0);
        CHECK(net_stack_rx(expect, sizeof(expect)) == NET_CLASS_UDP);
        trunc = -1;
        CHECK(net_udp_recv(buf, 0, &sip, &sport, &trunc) == -(NET_ERR_TRUNC));
        CHECK(trunc == 1);
        CHECK(net_udp_recv(buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        net_stack_init();
        net_arp_init();
        for (i = 0; i < 5; i++)
        {
            uint8_t p[1];
            p[0] = (uint8_t)('0' + i);
            CHECK(net_stack_udp_send(0x0A000202u, 53, 49152, p, sizeof(p), frame, &flen) == 0);
            CHECK(net_stack_rx(frame, flen) == NET_CLASS_UDP);
        }
        for (i = 0; i < 4; i++)
        {
            trunc = -1;
            n = net_udp_recv(buf, sizeof(buf), &sip, &sport, &trunc);
            CHECK(n == 1);
            CHECK(trunc == 0);
            CHECK(buf[0] == (uint8_t)('0' + i));
        }
        CHECK(net_udp_recv(buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        net_stack_init();
        net_arp_init();
        {
            static uint8_t big[1600];
            memset(big, 0, sizeof(big));
            CHECK(net_stack_rx(big, sizeof(big)) == NET_CLASS_DROP);
            CHECK(net_udp_recv(buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        }
    }
    /* ---- SDD 2026-10-08 net-blocking-recv Task 1: per-socket queue carve ---- */
    {
        static const uint8_t p53[] = {'D', 'N', 'S', '5', '3'};
        static const uint8_t p7[] = {'E', 'C', 'H', 'O', '7', 'X', '9'};
        uint8_t frame[1514];
        uint8_t buf[32];
        unsigned long flen = 0;
        uint32_t sip = 0;
        uint16_t sport = 0;
        int trunc = -1;
        int n;
        net_stack_init();
        net_arp_init();
        CHECK(net_stack_udp_send(0x0A000202u, 53, 4001, p53, sizeof(p53), frame, &flen) == 0);
        CHECK(net_stack_rx(frame, flen) == NET_CLASS_UDP);
        CHECK(net_stack_udp_send(0x0A000202u, 7, 4002, p7, sizeof(p7), frame, &flen) == 0);
        CHECK(net_stack_rx(frame, flen) == NET_CLASS_UDP);
        /* Cross-socket invisibility: port 9999 sees nothing, queue intact. */
        trunc = -1;
        CHECK(net_udp_recv_from(9999, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        CHECK(trunc == 0);
        /* Selective drain: port 7 first, then port 53. */
        trunc = -1;
        sip = 0;
        sport = 0;
        n = net_udp_recv_from(7, buf, sizeof(buf), &sip, &sport, &trunc);
        CHECK(n == (int)sizeof(p7));
        CHECK(trunc == 0);
        CHECK(sport == 4002);
        CHECK(memcmp(buf, p7, sizeof(p7)) == 0);
        trunc = -1;
        sip = 0;
        sport = 0;
        n = net_udp_recv_from(53, buf, sizeof(buf), &sip, &sport, &trunc);
        CHECK(n == (int)sizeof(p53));
        CHECK(trunc == 0);
        CHECK(sport == 4001);
        CHECK(memcmp(buf, p53, sizeof(p53)) == 0);
        CHECK(net_udp_recv_from(53, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        /* drop_if: re-enqueue both, drop port 7 only. */
        CHECK(net_stack_udp_send(0x0A000202u, 53, 4001, p53, sizeof(p53), frame, &flen) == 0);
        CHECK(net_stack_rx(frame, flen) == NET_CLASS_UDP);
        CHECK(net_stack_udp_send(0x0A000202u, 7, 4002, p7, sizeof(p7), frame, &flen) == 0);
        CHECK(net_stack_rx(frame, flen) == NET_CLASS_UDP);
        net_udp_drop_if(t_carve_drop7);
        trunc = -1;
        CHECK(net_udp_recv_from(7, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        CHECK(trunc == 0);
        trunc = -1;
        n = net_udp_recv_from(53, buf, sizeof(buf), &sip, &sport, &trunc);
        CHECK(n == (int)sizeof(p53));
        CHECK(trunc == 0);
        CHECK(memcmp(buf, p53, sizeof(p53)) == 0);
        CHECK(net_udp_recv(buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        /* trunc/empty contract incl cap==0. */
        CHECK(net_stack_udp_send(0x0A000202u, 7, 4002, p7, sizeof(p7), frame, &flen) == 0);
        CHECK(net_stack_rx(frame, flen) == NET_CLASS_UDP);
        trunc = -1;
        CHECK(net_udp_recv_from(7, buf, 0, &sip, &sport, &trunc) == -(NET_ERR_TRUNC));
        CHECK(trunc == 1);
        CHECK(net_udp_recv_from(7, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        CHECK(trunc == 0);
        CHECK(net_stack_udp_send(0x0A000202u, 7, 4002, p7, sizeof(p7), frame, &flen) == 0);
        CHECK(net_stack_rx(frame, flen) == NET_CLASS_UDP);
        trunc = -1;
        CHECK(net_udp_recv_from(7, buf, 4, &sip, &sport, &trunc) == -(NET_ERR_TRUNC));
        CHECK(trunc == 1);
        CHECK(memcmp(buf, p7, 4) == 0);
        /* Oversize frame drops, queue stays empty. */
        {
            static uint8_t big[1600];
            memset(big, 0, sizeof(big));
            CHECK(net_stack_rx(big, sizeof(big)) == NET_CLASS_DROP);
            CHECK(net_udp_recv_from(53, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        }
    }
    /* ---- SDD 2026-10-08 net-blocking-recv Task 2: waiter table ---- */
    {
        int s0, s1;
        unsigned owner = 0;
        int rsock = -9;
        unsigned rowner = 0;
        s0 = net_sock_open(NET_SOCK_UDP, 5000, 5);
        CHECK(s0 >= 0);
        s1 = net_sock_open(NET_SOCK_UDP, 5001, 7);
        CHECK(s1 >= 0);
        /* register with fake ticks: deadline 150 */
        CHECK(net_waiter_arm(s0, 5, 100, 50) == 0);
        owner = 0;
        CHECK(net_waiter_match(5000, &owner) >= 0);
        CHECK(owner == 5);
        CHECK(net_waiter_match(5001, &owner) < 0);
        CHECK(net_waiter_match(9999, &owner) < 0);
        /* expiry boundary: 149 misses, 151 hits once then misses */
        CHECK(net_waiter_expire(149, &rsock, &rowner) < 0);
        CHECK(net_waiter_expire(151, &rsock, &rowner) >= 0);
        CHECK(rsock == s0);
        CHECK(rowner == 5);
        CHECK(net_waiter_expire(151, &rsock, &rowner) < 0);
        CHECK(net_waiter_match(5000, &owner) < 0);
        /* replace-arm resets deadline: 210+50=260 */
        CHECK(net_waiter_arm(s0, 5, 200, 50) == 0);
        CHECK(net_waiter_arm(s0, 5, 210, 50) == 0);
        CHECK(net_waiter_expire(255, &rsock, &rowner) < 0);
        CHECK(net_waiter_expire(261, &rsock, &rowner) >= 0);
        CHECK(rsock == s0);
        CHECK(net_waiter_expire(261, &rsock, &rowner) < 0);
        /* clear disarms */
        CHECK(net_waiter_arm(s0, 5, 300, 50) == 0);
        net_waiter_clear(s0);
        CHECK(net_waiter_match(5000, &owner) < 0);
        CHECK(net_waiter_expire(400, &rsock, &rowner) < 0);
        /* wrong owner / bad sock fail */
        CHECK(net_waiter_arm(s0, 6, 400, 50) < 0);
        CHECK(net_waiter_arm(-1, 5, 400, 50) < 0);
        CHECK(net_waiter_match(5000, &owner) < 0);
        /* timeout 0 -> no-wait code 1 without arming */
        CHECK(net_waiter_arm(s0, 5, 400, 0) == 1);
        CHECK(net_waiter_match(5000, &owner) < 0);
        CHECK(net_waiter_expire(500, &rsock, &rowner) < 0);
        CHECK(net_sock_close(s0) == 0);
        CHECK(net_sock_close(s1) == 0);
    }
    /* ---- Kind-guarded waiter match: same port never cross-wakes ---- */
    {
        int su, st;
        unsigned owner = 0;
        su = net_sock_open(NET_SOCK_UDP, 5100, 5);
        CHECK(su >= 0);
        st = net_sock_open(NET_SOCK_TCP, 5200, 7);
        CHECK(st >= 0);
        CHECK(net_waiter_arm(su, 5, 100, 50) == 0);
        CHECK(net_waiter_arm(st, 7, 100, 50) == 0);
        CHECK(net_waiter_match_kind(5100, (unsigned)NET_SOCK_UDP, &owner) == su);
        CHECK(owner == 5);
        CHECK(net_waiter_match_kind(5100, (unsigned)NET_SOCK_TCP, &owner) < 0);
        CHECK(net_waiter_match_kind(5200, (unsigned)NET_SOCK_TCP, &owner) == st);
        CHECK(owner == 7);
        CHECK(net_waiter_match_kind(5200, (unsigned)NET_SOCK_UDP, &owner) < 0);
        CHECK(net_waiter_match_kind(5100, 99u, &owner) < 0);
        CHECK(net_sock_close(su) == 0);
        CHECK(net_sock_close(st) == 0);
    }
    /* ---- Task 3: DNS codec (query build + first-A parse) ---- */
    {
        static const uint8_t dns_q_expect[29] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
                                                 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01};
        static const uint8_t dns_resp[45] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                                             0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
                                             0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00,
                                             0x00, 0x0E, 0x10, 0x00, 0x04, 0x5D, 0xB8, 0xD8, 0x22};
        static const uint8_t dns_noans[29] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                                              0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
                                              0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01};
        static const uint8_t dns_garbage[3] = {0x00, 0x01, 0x02};
        uint8_t q[512];
        uint8_t tc[45];
        unsigned long qlen = 0;
        uint32_t ip = 0;
        unsigned k;
        CHECK(net_dns_build_query("example.com", 0x1234u, q, &qlen) == 0);
        CHECK(qlen == sizeof(dns_q_expect));
        CHECK(memcmp(q, dns_q_expect, sizeof(dns_q_expect)) == 0);
        CHECK(net_dns_build_query(NULL, 0x1234u, q, &qlen) < 0);
        CHECK(net_dns_build_query("example.com", 0x1234u, NULL, &qlen) < 0);
        CHECK(net_dns_build_query("example.com", 0x1234u, q, NULL) < 0);
        CHECK(net_dns_build_query("", 0x1234u, q, &qlen) < 0);
        CHECK(net_dns_build_query("example..com", 0x1234u, q, &qlen) < 0);
        {
            char big[70];
            for (k = 0; k < 64; k++)
                big[k] = 'a';
            big[64] = '\0';
            CHECK(net_dns_build_query(big, 0x1234u, q, &qlen) < 0);
        }
        {
            /* 4 x 63-char labels: wire QNAME 257 > 255 -> reject. */
            char big[260];
            unsigned o2 = 0;
            unsigned li;
            for (li = 0; li < 4; li++)
            {
                for (k = 0; k < 63; k++)
                    big[o2++] = (char)('a' + (int)li);
                if (li < 3)
                    big[o2++] = '.';
            }
            big[o2] = '\0';
            CHECK(net_dns_build_query(big, 0x1234u, q, &qlen) < 0);
        }
        CHECK(net_dns_parse_a(dns_resp, sizeof(dns_resp), &ip) == 0);
        CHECK(ip == 0x5DB8D822u);
        CHECK(net_dns_parse_a(NULL, sizeof(dns_resp), &ip) == -(NET_ERR_TRUNC));
        CHECK(net_dns_parse_a(dns_resp, sizeof(dns_resp), NULL) == -(NET_ERR_TRUNC));
        memcpy(tc, dns_resp, sizeof(tc));
        tc[2] |= 0x02u;
        CHECK(net_dns_parse_a(tc, sizeof(tc), &ip) == -(NET_ERR_TRUNC));
        CHECK(net_dns_parse_a(dns_resp, sizeof(dns_resp) - 2u, &ip) == -(NET_ERR_TRUNC));
        CHECK(net_dns_parse_a(dns_noans, sizeof(dns_noans), &ip) == -(NET_ERR_EMPTY));
        CHECK(net_dns_parse_a(dns_garbage, sizeof(dns_garbage), &ip) == -(NET_ERR_TRUNC));
    }
    /* ICMP echo (RFC 792): request build, reply swap, id/seq match. */
    {
        uint8_t req[14 + 20 + 8 + 4];
        uint8_t rep[sizeof(req)];
        unsigned long reqlen = 0, replen = 0;
        uint8_t pay[4] = {0xDEu, 0xADu, 0xBEu, 0xEFu};
        uint8_t gwmac[6] = {0x52u, 0x54u, 0x00u, 0x12u, 0x34u, 0x56u};
        CHECK(net_icmp_build_request(gwmac, 0x0A00020Fu, 0x1234u, 0x0001u, pay, sizeof(pay), req, &reqlen) == 0);
        CHECK(reqlen == sizeof(req));
        CHECK(req[12] == 0x08u && req[13] == 0x00u); /* ethertype IPv4 */
        CHECK(req[14 + 9] == IP_PROTO_ICMP);
        CHECK(req[14 + 20] == ICMP_ECHO_REQUEST && req[14 + 21] == 0u);
        CHECK(req[14 + 24] == 0x12u && req[14 + 25] == 0x34u); /* id */
        CHECK(req[14 + 26] == 0x00u && req[14 + 27] == 0x01u); /* seq */
        CHECK(net_ip_checksum(req + 14, 20) == 0u);
        CHECK(net_icmp_checksum(req + 34, 12) == 0u);
        CHECK(net_stack_icmp_reply(req, reqlen, rep, &replen) == 0);
        CHECK(replen == reqlen);
        CHECK(rep[14 + 20] == ICMP_ECHO_REPLY);
        CHECK(net_ip_checksum(rep + 14, 20) == 0u);
        CHECK(net_icmp_checksum(rep + 34, 12) == 0u);
        CHECK(memcmp(rep + 42, pay, sizeof(pay)) == 0); /* payload preserved */
        CHECK(net_ping_match(rep, replen, 0x1234u, 0x0001u) == 0);
        CHECK(net_ping_match(rep, replen, 0x1235u, 0x0001u) < 0);   /* id mismatch */
        CHECK(net_ping_match(rep, replen, 0x1234u, 0x0002u) < 0);   /* seq mismatch */
        CHECK(net_stack_icmp_reply(rep, replen, req, &reqlen) < 0); /* reply != request */
    }
    /* DHCP client (RFC 2131 + udhcpc option discipline). */
    {
        uint8_t dis[400];
        uint8_t off[400];
        uint8_t req[400];
        unsigned long dislen = 0, offlen = 0, reqlen = 0;
        struct net_dhcp_lease ls;
        uint32_t xid = 0x12345678u;
        /* Craft a minimal OFFER: eth + ip + udp + bootp + options. */
        {
            unsigned o = 0, i;
            for (i = 0; i < 6; i++)
            {
                off[o++] = 0x52u;
                off[o++] = 0x52u;
            }
            for (i = 0; i < 6; i++)
                off[o++] = 0x52u; /* dst = bcast-ish, parse ignores eth */
            off[12] = 0x08u;
            off[13] = 0x00u;
            off[14] = 0x45u;
            off[15] = 0x00u;
            off[16] = 0x01u;
            off[17] = 0x2Eu; /* tot = 302 */
            memset(off + 18, 0, 8);
            off[23] = IP_PROTO_UDP;
            off[26] = 0x0Au;
            off[27] = 0x00u;
            off[28] = 0x02u;
            off[29] = 0x02u; /* src = server */
            off[30] = 0xFFu;
            off[31] = 0xFFu;
            off[32] = 0xFFu;
            off[33] = 0xFFu; /* dst = broadcast */
            off[34] = 0u;
            off[35] = 67u; /* sport 67 */
            off[36] = 0u;
            off[37] = 68u; /* dport 68 */
            off[38] = 0x01u;
            off[39] = 0x1Au; /* ulen = 282 */
            memset(off + 40, 0, 2);
            off[42] = 2u; /* BOOTREPLY */
            off[43] = 1u;
            off[44] = 6u;
            off[45] = 0u; /* hops */
            off[46] = 0x12u;
            off[47] = 0x34u;
            off[48] = 0x56u;
            off[49] = 0x78u; /* xid */
            memset(off + 50, 0, 8);
            off[58] = 0x0Au;
            off[59] = 0x00u;
            off[60] = 0x02u;
            off[61] = 0x64u; /* yiaddr = 10.0.2.100 */
            memset(off + 62, 0, 18 + 64 + 128);
            o = 42 + 236;
            off[o++] = 99u;
            off[o++] = 130u;
            off[o++] = 83u;
            off[o++] = 99u; /* magic cookie */
            off[o++] = 53u;
            off[o++] = 1u;
            off[o++] = 2u; /* OFFER */
            off[o++] = 54u;
            off[o++] = 4u;
            off[o++] = 0x0Au;
            off[o++] = 0x00u;
            off[o++] = 0x02u;
            off[o++] = 0x02u; /* server 10.0.2.2 */
            off[o++] = 51u;
            off[o++] = 4u;
            off[o++] = 0u;
            off[o++] = 0u;
            off[o++] = 0x0Eu;
            off[o++] = 0x10u; /* lease 3600 */
            off[o++] = 1u;
            off[o++] = 4u;
            off[o++] = 0xFFu;
            off[o++] = 0xFFu;
            off[o++] = 0xFFu;
            off[o++] = 0u; /* mask /24 */
            off[o++] = 3u;
            off[o++] = 4u;
            off[o++] = 0x0Au;
            off[o++] = 0x00u;
            off[o++] = 0x02u;
            off[o++] = 0x02u; /* router */
            off[o++] = 6u;
            off[o++] = 4u;
            off[o++] = 0x0Au;
            off[o++] = 0x00u;
            off[o++] = 0x02u;
            off[o++] = 0x03u; /* dns */
            off[o++] = 255u;  /* end */
            offlen = o;
        }
        CHECK(net_dhcp_build_discover(xid, dis, &dislen) == 0);
        CHECK(dislen >= 300u);
        CHECK(dis[0] == 0xFFu && dis[5] == 0xFFu);           /* bcast eth */
        CHECK(dis[30] == 0xFFu && dis[33] == 0xFFu);         /* bcast IP */
        CHECK(dis[34] == 0u && dis[35] == 68u);              /* sport 68 */
        CHECK(dis[36] == 0u && dis[37] == 67u);              /* dport 67 */
        CHECK(dis[42] == 1u && dis[44] == 6u);               /* BOOTP request, eth */
        CHECK(dis[46] == 0x12u && dis[49] == 0x78u);         /* xid echo */
        CHECK(dis[42 + 236] == 99u && dis[42 + 239] == 99u); /* cookie */
        CHECK(dis[42 + 240] == 53u && dis[42 + 242] == 1u);  /* DISCOVER */
        CHECK(net_dhcp_parse_offer(off, offlen, xid, &ls) == 0);
        CHECK(ls.yiaddr == 0x0A000264u);
        CHECK(ls.server == 0x0A000202u);
        CHECK(ls.subnet == 0xFFFFFF00u);
        CHECK(ls.router == 0x0A000202u);
        CHECK(ls.dns == 0x0A000203u);
        CHECK(ls.lease_sec == 3600u);
        CHECK(net_dhcp_parse_offer(off, offlen, xid ^ 1u, &ls) < 0); /* xid */
        off[42 + 242] = 1u;                                          /* DISCOVER, not OFFER */
        CHECK(net_dhcp_parse_offer(off, offlen, xid, &ls) < 0);
        off[42 + 242] = 2u;
        CHECK(net_dhcp_build_request(xid, &ls, req, &reqlen) == 0);
        CHECK(req[42 + 242] == 3u); /* REQUEST */
        off[42 + 242] = 5u;         /* ACK for the ack-path test */
        CHECK(net_dhcp_parse_ack(off, offlen, xid, &ls) == 0);
        off[42 + 240] = 0u; /* bad cookie */
        CHECK(net_dhcp_parse_ack(off, offlen, xid, &ls) < 0);
        net_dhcp_apply(&ls);
        CHECK(NET_IP_SELF == 0x0A000264u);
        CHECK(NET_IP_GW == 0x0A000202u);
        CHECK(NET_IP_DNS == 0x0A000203u);
        CHECK(NET_IP_SUBNET == 0xFFFFFF00u);
    }
    /* TCP handshake (lwIP-grounded: SYN/SYN-ACK/ACK, single TCB). */
    {
        struct net_tcp_conn c;
        uint8_t syn[14 + 20 + 24];
        uint8_t sa[14 + 20 + 24];
        uint8_t rep[14 + 20 + 20];
        unsigned long synlen = 0, replen = 0;
        uint8_t gwmac[6] = {0x52u, 0x54u, 0x00u, 0x12u, 0x34u, 0x56u};
        unsigned i;
        CHECK(net_tcp_syn(&c, gwmac, 0x0A000202u, 80u, 49152u, 0x01020304u, syn, &synlen) == 0);
        CHECK(c.state == NET_TCP_SYN_SENT && c.iss == 0x01020304u);
        CHECK(synlen == sizeof(syn));
        CHECK(syn[14 + 20 + 13] == (TCP_SYN & 0xFFu));
        CHECK(net_ip_checksum(syn + 14, 20) == 0u);
        CHECK(net_tcp_checksum(NET_IP_SELF, 0x0A000202u, syn + 34, 24) == 0u);
        /* Craft matching SYN-ACK (peer seq 0x0A0B0C0D). */
        for (i = 0; i < sizeof(sa); i++)
            sa[i] = syn[i];
        for (i = 0; i < 6u; i++)
        {
            sa[i] = syn[6 + i];
            sa[6 + i] = syn[i];
        }
        for (i = 0; i < 4u; i++) /* swap IP src/dst */
        {
            uint8_t t = sa[26 + i];
            sa[26 + i] = sa[30 + i];
            sa[30 + i] = t;
        }
        sa[34] = 0u;
        sa[35] = 80u; /* sport = server */
        sa[36] = 0xC0u;
        sa[37] = 0x00u; /* dport = 49152 */
        sa[14 + 20 + 13] = (uint8_t)(TCP_SYN | TCP_ACK);
        sa[38] = 0x0Au;
        sa[39] = 0x0Bu;
        sa[40] = 0x0Cu;
        sa[41] = 0x0Du; /* peer seq */
        sa[42] = 0x01u;
        sa[43] = 0x02u;
        sa[44] = 0x03u;
        sa[45] = 0x05u; /* ack = iss+1 */
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
            uint16_t ck = net_tcp_checksum(0x0A000202u, NET_IP_SELF, sa + 34, 24);
            sa[52] = (uint8_t)(ck >> 8);
            sa[53] = (uint8_t)(ck & 0xFFu);
        }
        CHECK(net_tcp_input(&c, sa, sizeof(sa), rep, &replen) == 1);
        CHECK(c.state == NET_TCP_ESTABLISHED && c.irs == 0x0A0B0C0Du);
        CHECK(replen == 14u + 20u + 20u);
        CHECK(rep[14 + 20 + 13] == (uint8_t)TCP_ACK);
        CHECK(rep[42] == 0x0Au && rep[45] == 0x0Eu); /* ack = irs+1 */
        CHECK(net_tcp_checksum(NET_IP_SELF, 0x0A000202u, rep + 34, 20) == 0u);
        /* Wrong ack: dropped, state holds. */
        sa[45] = 0x09u;
        {
            uint16_t ck = net_tcp_checksum(0x0A000202u, NET_IP_SELF, sa + 34, 24);
            sa[52] = (uint8_t)(ck >> 8);
            sa[53] = (uint8_t)(ck & 0xFFu);
        }
        c.state = NET_TCP_SYN_SENT;
        c.snd_nxt = c.iss + 1u;
        CHECK(net_tcp_input(&c, sa, sizeof(sa), rep, &replen) == 0);
        CHECK(c.state == NET_TCP_SYN_SENT);
        /* RST aborts to CLOSED. */
        sa[14 + 20 + 13] = (uint8_t)(TCP_RST | TCP_ACK);
        sa[52] = 0u;
        sa[53] = 0u;
        {
            uint16_t ck = net_tcp_checksum(0x0A000202u, NET_IP_SELF, sa + 34, 24);
            sa[52] = (uint8_t)(ck >> 8);
            sa[53] = (uint8_t)(ck & 0xFFu);
        }
        CHECK(net_tcp_input(&c, sa, sizeof(sa), rep, &replen) == 0);
        CHECK(c.state == NET_TCP_CLOSED);
    }
    /* ---- Seam Task 2: single-TCB bind + send seam ---- */
    {
        static const uint8_t hello[5] = {'h', 'e', 'l', 'l', 'o'};
        static uint8_t big[537];
        int a, b2, u;
        struct net_tcp_conn *t;
        uint8_t syn[14 + 20 + 24];
        uint8_t sa[14 + 20 + 24];
        uint8_t rep[14 + 20 + 20];
        uint8_t dmac[6];
        unsigned long synlen = 0, replen = 0, txlen = 0, l2 = 0;
        const uint8_t *tx = 0;
        uint32_t rip;
        uint32_t iss = 0x01020304u;
        uint32_t peer = 0x0A0B0C0Du;
        uint32_t snd0;
        unsigned i;
        unsigned wowner = 0;
        for (i = 0; i < sizeof(big); i++) /* bound: 537 */
            big[i] = 0x41u;
        net_stack_init();
        rip = (uint32_t)NET_IP_GW;
        CHECK(net_arp_lookup(rip, dmac) == 0);
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        /* Bind: exactly one TCB, CLOSED at open. */
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(net_sock_tcp_bound() == a);
        CHECK(net_sock_tcp(-1) == 0);
        tx = net_sock_tcp_tx(&txlen);
        /* UDP leg unchanged: no route stored, the direct path owns UDP. */
        u = net_sock_open(NET_SOCK_UDP, 5050, 1);
        CHECK(u >= 0);
        CHECK(net_sock_tcp(u) == 0);
        CHECK(net_sock_send(u, hello, sizeof(hello)) < 0);
        CHECK(net_sock_close(u) == 0);
        /* CLOSED gate: no frame, no sequence advance. */
        CHECK(net_sock_send(a, hello, sizeof(hello)) < 0);
        tx = net_sock_tcp_tx(&l2);
        CHECK(l2 == txlen);
        /* Active open through the bind (MSS 536 + ISS via tcp.h, as boot). */
        CHECK(net_sock_tcp_syn(a, dmac, rip, 80u, iss, syn, &synlen) == 0);
        CHECK(t->state == NET_TCP_SYN_SENT && t->snd_nxt == iss + 1u);
        CHECK(synlen == sizeof(syn));
        CHECK(net_sock_tcp_syn(-1, dmac, rip, 80u, iss, syn, &synlen) < 0);
        snd0 = t->snd_nxt;
        CHECK(net_sock_send(a, hello, sizeof(hello)) < 0);
        CHECK(t->snd_nxt == snd0);
        tx = net_sock_tcp_tx(&l2);
        CHECK(l2 == txlen);
        /* Canned SYN-ACK: ESTABLISHED + pure ACK. */
        for (i = 0; i < sizeof(sa); i++) /* bound: 58 */
            sa[i] = syn[i];
        for (i = 0; i < 6u; i++) /* bound: 6 */
        {
            sa[i] = syn[6 + i];
            sa[6 + i] = syn[i];
        }
        for (i = 0; i < 4u; i++) /* bound: 4 */
        {
            uint8_t tmpb = sa[26 + i];
            sa[26 + i] = sa[30 + i];
            sa[30 + i] = tmpb;
        }
        sa[34] = 0u;
        sa[35] = 80u;
        sa[36] = 0x1Fu;
        sa[37] = 0x90u;
        sa[14 + 20 + 13] = (uint8_t)(TCP_SYN | TCP_ACK);
        sa[38] = 0x0Au;
        sa[39] = 0x0Bu;
        sa[40] = 0x0Cu;
        sa[41] = 0x0Du;
        sa[42] = 0x01u;
        sa[43] = 0x02u;
        sa[44] = 0x03u;
        sa[45] = 0x05u;
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
            uint16_t ck = net_tcp_checksum(rip, NET_IP_SELF, sa + 34, 24);
            sa[52] = (uint8_t)(ck >> 8);
            sa[53] = (uint8_t)(ck & 0xFFu);
        }
        CHECK(net_sock_tcp_input(a, sa, sizeof(sa), rep, &replen) == 1);
        CHECK(t->state == NET_TCP_ESTABLISHED && t->irs == peer);
        CHECK(replen == 14u + 20u + 20u);
        CHECK(rep[14 + 20 + 13] == (uint8_t)TCP_ACK);
        CHECK(rep[42] == 0x0Au && rep[45] == 0x0Eu);
        /* Single live TCB: second concurrent TCP open fails closed. */
        b2 = net_sock_open(NET_SOCK_TCP, 8081, 2);
        CHECK(b2 < 0);
        CHECK(net_sock_demux(8081) < 0);
        /* ESTABLISHED send: one in-order segment, MSS-capped. */
        CHECK(net_sock_send(a, hello, sizeof(hello)) == (int)sizeof(hello));
        CHECK(t->snd_nxt == snd0 + 5u);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(tx != 0 && txlen == 14u + 20u + 20u + sizeof(hello));
        CHECK(tx[12] == 0x08u && tx[13] == 0x00u);
        CHECK(tx[14 + 9] == IP_PROTO_TCP);
        CHECK(tx[34] == 0x1Fu && tx[35] == 0x90u);
        CHECK(tx[36] == 0u && tx[37] == 80u);
        CHECK(tx[38] == 0x01u && tx[39] == 0x02u && tx[40] == 0x03u && tx[41] == 0x05u);
        CHECK(tx[42] == 0x0Au && tx[45] == 0x0Eu);
        CHECK(tx[14 + 20 + 13] == (uint8_t)(TCP_PSH | TCP_ACK));
        CHECK(net_ip_checksum(tx + 14, 20) == 0u);
        CHECK(net_tcp_checksum((uint32_t)NET_IP_SELF, rip, tx + 34, 20 + sizeof(hello)) == 0u);
        CHECK(memcmp(tx + 54, hello, sizeof(hello)) == 0);
        CHECK(net_sock_send(a, big, sizeof(big)) < 0);
        CHECK(t->snd_nxt == snd0 + 5u);
        /* Close releases the single TCB for the next socket. */
        CHECK(net_sock_close(a) == 0);
        CHECK(net_sock_tcp_bound() < 0);
        /* RST in SYN_SENT aborts to CLOSED and disarms the waiter. */
        b2 = net_sock_open(NET_SOCK_TCP, 8081, 2);
        CHECK(b2 >= 0);
        CHECK(net_sock_tcp_bound() == b2);
        t = net_sock_tcp(b2);
        CHECK(t != 0 && t->state == NET_TCP_CLOSED);
        CHECK(net_sock_tcp_syn(b2, dmac, rip, 80u, iss, syn, &synlen) == 0);
        CHECK(t->state == NET_TCP_SYN_SENT);
        for (i = 0; i < sizeof(sa); i++) /* bound: 58 */
            sa[i] = syn[i];
        for (i = 0; i < 6u; i++) /* bound: 6 */
        {
            sa[i] = syn[6 + i];
            sa[6 + i] = syn[i];
        }
        for (i = 0; i < 4u; i++) /* bound: 4 */
        {
            uint8_t tmpb = sa[26 + i];
            sa[26 + i] = sa[30 + i];
            sa[30 + i] = tmpb;
        }
        sa[34] = 0u;
        sa[35] = 80u;
        sa[36] = 0x1Fu;
        sa[37] = 0x91u;
        sa[14 + 20 + 13] = (uint8_t)(TCP_RST | TCP_ACK);
        sa[38] = 0x0Au;
        sa[39] = 0x0Bu;
        sa[40] = 0x0Cu;
        sa[41] = 0x0Du;
        sa[42] = 0x01u;
        sa[43] = 0x02u;
        sa[44] = 0x03u;
        sa[45] = 0x05u;
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
            uint16_t ck = net_tcp_checksum(rip, NET_IP_SELF, sa + 34, 24);
            sa[52] = (uint8_t)(ck >> 8);
            sa[53] = (uint8_t)(ck & 0xFFu);
        }
        CHECK(net_waiter_arm(b2, 2, 1000, 50) == 0);
        CHECK(net_sock_tcp_input(b2, sa, sizeof(sa), rep, &replen) == 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(net_waiter_match(8081, &wowner) < 0);
        CHECK(net_sock_send(b2, hello, sizeof(hello)) < 0);
        CHECK(net_sock_close(b2) == 0);
        CHECK(net_sock_tcp_bound() < 0);
    }
    /* ---- Seam Task 3: TCP RX demux + waiter wakeup ---- */
    {
        static const uint8_t hello[5] = {'h', 'e', 'l', 'l', 'o'};
        static const uint8_t gwmac[6] = {0x52u, 0x54u, 0x00u, 0x12u, 0x34u, 0x56u};
        static uint8_t big[537];
        uint8_t fr[14 + 20 + 20 + 537];
        uint8_t buf[600];
        uint8_t syn[14 + 20 + 24];
        uint8_t sa[14 + 20 + 24];
        uint8_t rep[14 + 20 + 20];
        unsigned long synlen = 0, replen = 0;
        unsigned flen;
        int a, b2;
        struct net_tcp_conn *t;
        uint8_t dmac[6];
        uint32_t rip;
        uint32_t iss = 0x01020304u;
        uint32_t peer = 0x0A0B0C0Du;
        uint32_t rcv0, snd0;
        unsigned wowner = 0;
        int rsock = -9;
        unsigned rowner = 0;
        uint32_t sip = 0;
        uint16_t sport = 0;
        int trunc = -1;
        int n;
        unsigned i;
        for (i = 0; i < sizeof(big); i++) /* bound: 537 */
            big[i] = 0x41u;
        net_stack_init();
        net_arp_init();
        rip = (uint32_t)NET_IP_GW;
        CHECK(net_arp_lookup(rip, dmac) == 0);
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        b2 = net_sock_open(NET_SOCK_UDP, 8053, 2);
        CHECK(b2 >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        /* Drive A to ESTABLISHED (canned SYN-ACK, Task 2 shape). */
        CHECK(net_sock_tcp_syn(a, dmac, rip, 80u, iss, syn, &synlen) == 0);
        for (i = 0; i < sizeof(sa); i++) /* bound: 58 */
            sa[i] = syn[i];
        for (i = 0; i < 6u; i++) /* bound: 6 */
        {
            sa[i] = syn[6 + i];
            sa[6 + i] = syn[i];
        }
        for (i = 0; i < 4u; i++) /* bound: 4 */
        {
            uint8_t tmpb = sa[26 + i];
            sa[26 + i] = sa[30 + i];
            sa[30 + i] = tmpb;
        }
        sa[34] = 0u;
        sa[35] = 80u;
        sa[36] = 0x1Fu;
        sa[37] = 0x90u;
        sa[14 + 20 + 13] = (uint8_t)(TCP_SYN | TCP_ACK);
        sa[38] = 0x0Au;
        sa[39] = 0x0Bu;
        sa[40] = 0x0Cu;
        sa[41] = 0x0Du;
        sa[42] = 0x01u;
        sa[43] = 0x02u;
        sa[44] = 0x03u;
        sa[45] = 0x05u;
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
            uint16_t ck = net_tcp_checksum(rip, (uint32_t)NET_IP_SELF, sa + 34, 24);
            sa[52] = (uint8_t)(ck >> 8);
            sa[53] = (uint8_t)(ck & 0xFFu);
        }
        CHECK(net_sock_tcp_input(a, sa, sizeof(sa), rep, &replen) == 1);
        CHECK(t->state == NET_TCP_ESTABLISHED && t->irs == peer);
        rcv0 = t->rcv_nxt;
        snd0 = t->snd_nxt;
        CHECK(rcv0 == peer + 1u);
        /* In-order PSH/ACK with an armed waiter: demuxed to A, queued,
         * rcv_nxt advances (snd_nxt moves on TX only, RFC 793), the UDP
         * socket never sees it, and the waiter match fires (the host
         * image of the v2_main S_DATA wakeup). */
        CHECK(net_waiter_arm(a, 1, 1000, 50) == 0);
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, rcv0, snd0, (uint8_t)(TCP_PSH | TCP_ACK), hello, sizeof(hello));
        CHECK(net_stack_rx(fr, flen) == NET_CLASS_TCP);
        CHECK(t->rcv_nxt == rcv0 + sizeof(hello));
        CHECK(t->snd_nxt == snd0);
        trunc = -1;
        CHECK(net_udp_recv_from(8053, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        CHECK(trunc == 0);
        CHECK(net_udp_recv(buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        CHECK(net_waiter_match(8080, &wowner) == a);
        CHECK(wowner == 1);
        /* Waiter consumes exactly once (v2_main clears after ASEND):
         * payload intact, then no second wake. */
        trunc = -1;
        sip = 0;
        sport = 0;
        n = net_tcp_recv_from(8080, buf, sizeof(buf), &sip, &sport, &trunc);
        CHECK(n == (int)sizeof(hello));
        CHECK(trunc == 0);
        CHECK(sip == rip);
        CHECK(sport == 80u);
        CHECK(memcmp(buf, hello, sizeof(hello)) == 0);
        net_waiter_clear(a);
        CHECK(net_waiter_match(8080, &wowner) < 0);
        CHECK(net_tcp_recv_from(8080, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        /* Parked ACK covers the new rcv_nxt (pure ACK, checksummed);
         * cleared exactly once. */
        {
            unsigned long alen = 0;
            const uint8_t *ackf = net_tcp_ack_tx(&alen);
            CHECK(ackf != 0 && alen == 14u + 20u + 20u);
            CHECK(ackf[14 + 20 + 13] == (uint8_t)TCP_ACK);
            CHECK(ackf[34] == 0x1Fu && ackf[35] == 0x90u);
            CHECK(ackf[36] == 0u && ackf[37] == 80u);
            CHECK(ackf[42] == (uint8_t)(t->rcv_nxt >> 24) && ackf[45] == (uint8_t)t->rcv_nxt);
            CHECK(net_ip_checksum(ackf + 14, 20) == 0u);
            CHECK(net_tcp_checksum((uint32_t)NET_IP_SELF, rip, ackf + 34, 20) == 0u);
            net_tcp_ack_clear();
            ackf = net_tcp_ack_tx(&alen);
            CHECK(ackf == 0 && alen == 0);
        }
        /* Duplicate of the accepted segment: dropped, no double delivery. */
        CHECK(net_stack_rx(fr, flen) == NET_CLASS_TCP);
        CHECK(t->rcv_nxt == rcv0 + sizeof(hello));
        CHECK(net_tcp_recv_from(8080, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        /* OOO gap: dropped with duplicate-ACK parked, rcv_nxt holds. */
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, rcv0 + (uint32_t)sizeof(hello) + 7u, snd0,
                         (uint8_t)(TCP_PSH | TCP_ACK), hello, sizeof(hello));
        CHECK(net_stack_rx(fr, flen) == NET_CLASS_TCP);
        CHECK(t->rcv_nxt == rcv0 + sizeof(hello));
        CHECK(net_tcp_recv_from(8080, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        {
            unsigned long alen = 0;
            const uint8_t *ackf = net_tcp_ack_tx(&alen);
            CHECK(ackf != 0 && alen == 14u + 20u + 20u);
            CHECK(ackf[45] == (uint8_t)t->rcv_nxt);
            net_tcp_ack_clear();
        }
        /* Oversize (> MSS 536) segment: fail-closed, no advance. */
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, t->rcv_nxt, snd0, (uint8_t)(TCP_PSH | TCP_ACK), big, sizeof(big));
        CHECK(net_stack_rx(fr, flen) == NET_CLASS_TCP);
        CHECK(t->rcv_nxt == rcv0 + sizeof(hello));
        CHECK(net_tcp_recv_from(8080, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        /* Unbound dport: classified TCP, never queued. */
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 9999u, rcv0, snd0, (uint8_t)(TCP_PSH | TCP_ACK), hello, sizeof(hello));
        CHECK(net_stack_rx(fr, flen) == NET_CLASS_TCP);
        CHECK(net_tcp_recv_from(9999, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        CHECK(t->rcv_nxt == rcv0 + sizeof(hello));
        /* Expiry fires once (fake ticks); post-expiry RX wakes nothing
         * (data still queues for a later poll, but no waiter fires). */
        CHECK(net_waiter_arm(a, 1, 2000, 50) == 0);
        CHECK(net_waiter_expire(2049, &rsock, &rowner) < 0);
        CHECK(net_waiter_expire(2051, &rsock, &rowner) == a);
        CHECK(rsock == a && rowner == 1);
        CHECK(net_waiter_expire(2051, &rsock, &rowner) < 0);
        CHECK(net_waiter_match(8080, &wowner) < 0);
        flen =
            t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, t->rcv_nxt, snd0, (uint8_t)(TCP_PSH | TCP_ACK), hello, sizeof(hello));
        CHECK(net_stack_rx(fr, flen) == NET_CLASS_TCP);
        CHECK(net_waiter_match(8080, &wowner) < 0);
        trunc = -1;
        n = net_tcp_recv_from(8080, buf, sizeof(buf), &sip, &sport, &trunc);
        CHECK(n == (int)sizeof(hello));
        CHECK(trunc == 0);
        CHECK(memcmp(buf, hello, sizeof(hello)) == 0);
        /* Queue-full drops newest: 4 chained 1B segments queue in order,
         * the 5th drops, rcv_nxt covers only the 4 kept. */
        {
            uint32_t base = t->rcv_nxt;
            uint8_t one[1];
            unsigned k;
            for (k = 0; k < 5; k++) /* bound: 5 */
            {
                one[0] = (uint8_t)('0' + k);
                flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, base + k, snd0, (uint8_t)(TCP_PSH | TCP_ACK), one,
                                 sizeof(one));
                CHECK(net_stack_rx(fr, flen) == NET_CLASS_TCP);
            }
            CHECK(t->rcv_nxt == base + 4u);
            for (k = 0; k < 4; k++) /* bound: 4 */
            {
                trunc = -1;
                n = net_tcp_recv_from(8080, buf, sizeof(buf), &sip, &sport, &trunc);
                CHECK(n == 1);
                CHECK(trunc == 0);
                CHECK(buf[0] == (uint8_t)('0' + k));
            }
            CHECK(net_tcp_recv_from(8080, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        }
        /* S_CLOSE drains only that socket's stream bytes. */
        flen =
            t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, t->rcv_nxt, snd0, (uint8_t)(TCP_PSH | TCP_ACK), hello, sizeof(hello));
        CHECK(net_stack_rx(fr, flen) == NET_CLASS_TCP);
        net_tcp_ack_clear();
        CHECK(net_sock_close(a) == 0);
        net_tcp_drop_if(t_tcp_drop8080);
        CHECK(net_tcp_recv_from(8080, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        CHECK(net_sock_tcp_bound() < 0);
        CHECK(net_sock_close(b2) == 0);
    }
    /* ---- FIN-retry Task 2: bounded retransmit (RFC 793 section 3.7) ----
     * Armed retry past deadline resends the parked frame verbatim (PSH,
     * then FIN); expiries 1-4 resend, the 5th RST-aborts to CLOSED and
     * disarms the waiter once; zero-length S_SEND in FIN_WAIT is rejected
     * without touching snd_nxt; a wrap-around deadline still fires. */
    {
        static const uint8_t hello[5] = {'h', 'e', 'l', 'l', 'o'};
        int a;
        struct net_tcp_conn *t;
        uint8_t syn[58], sa[58], rep[54];
        uint8_t snap[1514];
        unsigned long replen = 0, txlen = 0, snaplen = 0;
        const uint8_t *tx = 0;
        uint8_t dmac[6];
        uint32_t rip;
        uint32_t snd1;
        uint64_t t0 = 1000u, sp = 50u, t1 = 5000u;
        uint64_t w0 = 0xFFFFFFFFFFFFFFF0u; /* 2^64 - 16: arm wraps the deadline */
        unsigned owner = 0;
        unsigned long k;
        int trc, had = 0;
        net_stack_init();
        rip = (uint32_t)NET_IP_GW;
        CHECK(net_arp_lookup(rip, dmac) == 0);
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t2_establish(a, dmac, rip, 0x01020304u, 0x0A0B0C0Du, 8080u, syn, sa, rep, &replen) == 0);
        CHECK(t->state == NET_TCP_ESTABLISHED);
        CHECK(t->retry_deadline == 0u && t->retry_count == 0u);
        /* Nothing armed: poll is a silent no-op. */
        trc = net_sock_tcp_retry_poll(t0, sp, &owner, &had);
        CHECK(trc == 0 && had == 0);
        /* One segment: fresh budget, still unarmed until the TX pass arms. */
        CHECK(net_sock_send(a, hello, sizeof(hello)) == (int)sizeof(hello));
        snd1 = t->snd_nxt;
        CHECK(t->retry_deadline == 0u && t->retry_count == 0u);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(tx != 0 && txlen == 14u + 20u + 20u + sizeof(hello));
        for (k = 0; k < txlen; k++) /* bound: 1514 */
            snap[k] = tx[k];
        snaplen = txlen;
        /* TX pass arms the deadline (fake ticks). */
        CHECK(net_sock_tcp_retry_arm(a, t0, sp) == 0);
        CHECK(t->retry_deadline == t0 + sp && t->retry_count == 0u);
        CHECK(net_sock_tcp_retry_arm(-1, t0, sp) < 0);
        /* Not yet due: no resend, no state change. */
        trc = net_sock_tcp_retry_poll(t0 + sp - 1u, sp, &owner, &had);
        CHECK(trc == 0 && had == 0);
        CHECK(t->retry_count == 0u);
        /* Past deadline: verbatim resend, rearmed, snd_nxt holds. */
        trc = net_sock_tcp_retry_poll(t0 + sp, sp, &owner, &had);
        CHECK(trc == 1 && had == 0);
        CHECK(t->retry_count == 1u && t->retry_deadline == t0 + 2u * sp);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(tx != 0 && txlen == snaplen && memcmp(tx, snap, snaplen) == 0);
        CHECK(t->snd_nxt == snd1);
        /* fin_close while TX parked: rejected, frame/state untouched. */
        CHECK(net_sock_fin_close(a) < 0);
        CHECK(t->state == NET_TCP_ESTABLISHED);
        CHECK(t->snd_nxt == snd1);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(txlen == snaplen && memcmp(tx, snap, snaplen) == 0);
        CHECK(tx[14 + 20 + 13] == (uint8_t)(TCP_PSH | TCP_ACK));
        /* Stale ACK: no-op, still armed. Covering ACK: disarms. */
        CHECK(net_sock_tcp_ack_cover(a, snd1 - 1u) == 0);
        CHECK(t->retry_deadline != 0u);
        CHECK(net_sock_tcp_ack_cover(a, snd1) == 1);
        CHECK(t->retry_deadline == 0u && t->retry_count == 0u);
        CHECK(net_sock_tcp_ack_cover(-1, snd1) < 0);
        /* Re-arm on a fresh base: expiries 1-4 resend, 5th aborts. */
        CHECK(net_sock_tcp_retry_arm(a, t1, sp) == 0);
        CHECK(net_sock_tcp_retry_poll(t1 + sp, sp, &owner, &had) == 1);
        CHECK(t->retry_count == 1u);
        CHECK(net_sock_tcp_retry_poll(t1 + 2u * sp, sp, &owner, &had) == 1);
        CHECK(t->retry_count == 2u);
        CHECK(net_sock_tcp_retry_poll(t1 + 3u * sp, sp, &owner, &had) == 1);
        CHECK(t->retry_count == 3u);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(txlen == snaplen && memcmp(tx, snap, snaplen) == 0);
        CHECK(net_sock_tcp_retry_poll(t1 + 4u * sp, sp, &owner, &had) == 1);
        CHECK(t->retry_count == 4u);
        /* 5th expiry: RST-abort wakes the armed waiter exactly once. */
        CHECK(net_waiter_arm(a, 1, t1, 100000u) == 0);
        trc = net_sock_tcp_retry_poll(t1 + 5u * sp, sp, &owner, &had);
        CHECK(trc == 2 && had == 1 && owner == 1);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(t->retry_deadline == 0u && t->retry_count == 0u);
        CHECK(net_waiter_match(8080, &owner) < 0);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(tx != 0 && txlen == 14u + 20u + 20u);
        CHECK(tx[14 + 20 + 13] == (uint8_t)(TCP_RST | TCP_ACK));
        CHECK(tx[38] == (uint8_t)(snd1 >> 24) && tx[39] == (uint8_t)(snd1 >> 16) && tx[40] == (uint8_t)(snd1 >> 8) &&
              tx[41] == (uint8_t)snd1);
        CHECK(tx[42] == 0x0Au && tx[43] == 0x0Bu && tx[44] == 0x0Cu && tx[45] == 0x0Eu);
        CHECK(net_ip_checksum(tx + 14, 20) == 0u);
        CHECK(net_tcp_checksum((uint32_t)NET_IP_SELF, rip, tx + 34, 20) == 0u);
        CHECK(t->snd_nxt == snd1); /* RST consumes no sequence number */
        /* Post-abort polls stay silent: the waiter fired exactly once. */
        trc = net_sock_tcp_retry_poll(t1 + 6u * sp, sp, &owner, &had);
        CHECK(trc == 0 && had == 0);
        CHECK(net_sock_close(a) == 0);
        CHECK(net_sock_tcp_bound() < 0);
        /* Wrap-around: deadline across 2^64 still fires (unsigned compare). */
        a = net_sock_open(NET_SOCK_TCP, 8082, 1);
        CHECK(a >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t2_establish(a, dmac, rip, 0x01020304u, 0x0A0B0C0Du, 8082u, syn, sa, rep, &replen) == 0);
        CHECK(net_sock_send(a, hello, sizeof(hello)) == (int)sizeof(hello));
        tx = net_sock_tcp_tx(&txlen);
        CHECK(tx != 0);
        for (k = 0; k < txlen; k++) /* bound: 1514 */
            snap[k] = tx[k];
        snaplen = txlen;
        CHECK(net_sock_tcp_retry_arm(a, w0, sp) == 0);
        CHECK(t->retry_deadline == 34u); /* w0 + 50 wraps to 34 */
        CHECK(net_sock_tcp_retry_poll(33u, sp, &owner, &had) == 0);
        CHECK(net_sock_tcp_retry_poll(34u, sp, &owner, &had) == 1);
        CHECK(t->retry_count == 1u);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(txlen == snaplen && memcmp(tx, snap, snaplen) == 0);
        CHECK(net_sock_close(a) == 0);
        /* FIN path on a fresh connection: zero-length S_SEND rejected,
         * FIN resends verbatim, FIN_WAIT ACKs belong to Task 3. */
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t2_establish(a, dmac, rip, 0x01020304u, 0x0A0B0C0Du, 8080u, syn, sa, rep, &replen) == 0);
        snd1 = t->snd_nxt;
        CHECK(net_sock_fin_close(a) == 0);
        CHECK(t->state == NET_TCP_FIN_WAIT);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(tx != 0 && txlen == 14u + 20u + 20u);
        for (k = 0; k < txlen; k++) /* bound: 1514 */
            snap[k] = tx[k];
        snaplen = txlen;
        CHECK(net_sock_send(a, hello, 0) < 0); /* zero-length: S_ERR, no advance */
        CHECK(net_sock_send(a, hello, sizeof(hello)) < 0);
        CHECK(t->snd_nxt == snd1 + 1u);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(txlen == snaplen && memcmp(tx, snap, snaplen) == 0);
        CHECK(net_sock_tcp_ack_cover(a, t->snd_nxt) == 0); /* FIN_WAIT: Task 3 owns ACKs */
        CHECK(t->retry_deadline == 0u);
        CHECK(net_sock_tcp_retry_arm(a, t1, sp) == 0);
        /* FIN_WAIT input through the seam (dropped SYN-ACK shape) never
         * disarms the FIN retry Task 3 relies on. */
        CHECK(net_sock_tcp_input(a, sa, sizeof(sa), rep, &replen) == 0);
        CHECK(t->state == NET_TCP_FIN_WAIT);
        CHECK(t->retry_deadline == t1 + sp && t->retry_count == 0u);
        trc = net_sock_tcp_retry_poll(t1 + sp, sp, &owner, &had);
        CHECK(trc == 1 && had == 0 && t->retry_count == 1u);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(txlen == snaplen && memcmp(tx, snap, snaplen) == 0);
        CHECK(net_sock_close(a) == 0);
        CHECK(net_sock_tcp_bound() < 0);
    }
    /* ---- FIN-retry Task 3: stop-and-wait S_SEND reject + FIN-exhaustion
     * waiter S_ERR-once (RFC 793 sections 3.5/3.7; carried rulings: a
     * second S_SEND while the retry is armed is rejected, never
     * interleaving bytes; the 5th FIN expiry RST-aborts and captures the
     * armed waiter exactly once) ---- */
    {
        static const uint8_t hello[5] = {'h', 'e', 'l', 'l', 'o'};
        int a;
        struct net_tcp_conn *t;
        uint8_t syn[58], sa[58], rep[54];
        unsigned long replen = 0, txlen = 0;
        const uint8_t *tx = 0;
        uint8_t dmac[6];
        uint32_t rip;
        uint32_t snd1;
        uint64_t t0 = 20000u, sp = 50u;
        unsigned owner = 0;
        int had = 0, trc;
        net_stack_init();
        rip = (uint32_t)NET_IP_GW;
        CHECK(net_arp_lookup(rip, dmac) == 0);
        /* Stop-and-wait: S_SEND while a retry is armed is rejected. */
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t2_establish(a, dmac, rip, 0x01020304u, 0x0A0B0C0Du, 8080u, syn, sa, rep, &replen) == 0);
        CHECK(net_sock_send(a, hello, sizeof(hello)) == (int)sizeof(hello));
        snd1 = t->snd_nxt;
        CHECK(net_sock_tcp_retry_arm(a, t0, sp) == 0);
        CHECK(net_sock_send(a, hello, sizeof(hello)) < 0); /* armed: S_ERR */
        CHECK(t->snd_nxt == snd1);                         /* nothing interleaved */
        tx = net_sock_tcp_tx(&txlen);
        CHECK(tx != 0 && txlen == 14u + 20u + 20u + sizeof(hello));
        CHECK(tx[14 + 20 + 13] == (uint8_t)(TCP_PSH | TCP_ACK)); /* first segment intact */
        CHECK(net_sock_tcp_ack_cover(a, snd1) == 1);             /* covering ACK disarms */
        CHECK(net_sock_send(a, hello, sizeof(hello)) == (int)sizeof(hello));
        CHECK(t->snd_nxt == snd1 + (uint32_t)sizeof(hello));
        CHECK(net_sock_close(a) == 0);
        /* FIN exhaustion: expiries 1-4 resend the FIN verbatim, the 5th
         * RST-aborts and captures the armed waiter exactly once. */
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t2_establish(a, dmac, rip, 0x01020304u, 0x0A0B0C0Du, 8080u, syn, sa, rep, &replen) == 0);
        CHECK(net_sock_fin_close(a) == 0);
        CHECK(t->state == NET_TCP_FIN_WAIT);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(tx != 0 && txlen == 14u + 20u + 20u);
        CHECK(tx[14 + 20 + 13] == (uint8_t)(TCP_FIN | TCP_ACK));
        CHECK(net_sock_tcp_retry_arm(a, t0, sp) == 0);
        CHECK(net_sock_tcp_retry_poll(t0 + sp, sp, &owner, &had) == 1);
        CHECK(net_sock_tcp_retry_poll(t0 + 2u * sp, sp, &owner, &had) == 1);
        CHECK(net_sock_tcp_retry_poll(t0 + 3u * sp, sp, &owner, &had) == 1);
        CHECK(net_sock_tcp_retry_poll(t0 + 4u * sp, sp, &owner, &had) == 1);
        CHECK(t->retry_count == 4u);
        CHECK(t->state == NET_TCP_FIN_WAIT);
        CHECK(net_waiter_arm(a, 1, t0, 100000u) == 0);
        trc = net_sock_tcp_retry_poll(t0 + 5u * sp, sp, &owner, &had);
        CHECK(trc == 2 && had == 1 && owner == 1);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(t->retry_deadline == 0u && t->retry_count == 0u);
        CHECK(net_waiter_match(8080, &owner) < 0);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(tx != 0 && txlen == 14u + 20u + 20u);
        CHECK(tx[14 + 20 + 13] == (uint8_t)(TCP_RST | TCP_ACK));
        trc = net_sock_tcp_retry_poll(t0 + 6u * sp, sp, &owner, &had);
        CHECK(trc == 0 && had == 0); /* fired exactly once */
        CHECK(net_sock_close(a) == 0);
        /* Dead owner (no armed waiter): abort captures nothing, so the
         * loop SENDs nothing. */
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t2_establish(a, dmac, rip, 0x01020304u, 0x0A0B0C0Du, 8080u, syn, sa, rep, &replen) == 0);
        CHECK(net_sock_fin_close(a) == 0);
        CHECK(net_sock_tcp_retry_arm(a, t0, sp) == 0);
        CHECK(net_sock_tcp_retry_poll(t0 + sp, sp, &owner, &had) == 1);
        CHECK(net_sock_tcp_retry_poll(t0 + 2u * sp, sp, &owner, &had) == 1);
        CHECK(net_sock_tcp_retry_poll(t0 + 3u * sp, sp, &owner, &had) == 1);
        CHECK(net_sock_tcp_retry_poll(t0 + 4u * sp, sp, &owner, &had) == 1);
        trc = net_sock_tcp_retry_poll(t0 + 5u * sp, sp, &owner, &had);
        CHECK(trc == 2 && had == 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(net_sock_close(a) == 0);
        CHECK(net_sock_tcp_bound() < 0);
    }
    /* ---- Passive close Task 2: LAST_ACK via S_CLOSE + retry reuse ----
     * (RFC 793 section 3.5): S_CLOSE in CLOSE_WAIT emits one header-only
     * FIN|ACK into the parked TX frame and enters LAST_ACK; the peer ACK
     * covering our FIN closes exactly once to CLOSED (a duplicate ACK
     * after CLOSED drops); a repeat close succeeds without a second FIN;
     * retry exhaustion RST-aborts and wakes the waiter once; an RST in
     * LAST_ACK aborts at once. */
    {
        static const uint8_t hello[5] = {'h', 'e', 'l', 'l', 'o'};
        static const uint8_t gwmac[6] = {0x52u, 0x54u, 0x00u, 0x12u, 0x34u, 0x56u};
        int a;
        struct net_tcp_conn *t;
        uint8_t syn[58], sa[58], rep[54], fr[128];
        uint8_t snap[1514];
        unsigned long replen = 0, txlen = 0, snaplen = 0, flen = 0, rl = 0;
        const uint8_t *tx = 0;
        uint8_t dmac[6];
        uint32_t rip;
        uint32_t snd0, rcv1;
        uint64_t t0 = 30000u, sp = 50u;
        unsigned owner = 0;
        unsigned long k;
        int had = 0, trc;
        net_stack_init();
        net_arp_init();
        rip = (uint32_t)NET_IP_GW;
        CHECK(net_arp_lookup(rip, dmac) == 0);
        CHECK(NET_TCP_LAST_ACK == 5);
        /* CLOSE_WAIT close: one header-only FIN|ACK parks, LAST_ACK holds. */
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t2_establish(a, dmac, rip, 0x01020304u, 0x0A0B0C0Du, 8080u, syn, sa, rep, &replen) == 0);
        CHECK(t->state == NET_TCP_ESTABLISHED);
        snd0 = t->snd_nxt;
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, t->rcv_nxt, snd0, (uint8_t)(TCP_FIN | TCP_ACK), hello, 0);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 1);
        CHECK(t->state == NET_TCP_CLOSE_WAIT);
        rcv1 = t->rcv_nxt;
        CHECK(net_sock_send(a, hello, sizeof(hello)) < 0); /* CLOSE_WAIT: S_ERR, no advance */
        CHECK(t->snd_nxt == snd0);
        CHECK(net_sock_fin_close(a) == 0);
        CHECK(t->state == NET_TCP_LAST_ACK);
        CHECK(t->snd_nxt == snd0 + 1u);                         /* FIN consumes one sequence number */
        CHECK(t->retry_deadline == 0u && t->retry_count == 0u); /* TX pass arms */
        tx = net_sock_tcp_tx(&txlen);
        CHECK(tx != 0 && txlen == 14u + 20u + 20u);
        CHECK(tx[14 + 20 + 13] == (uint8_t)(TCP_FIN | TCP_ACK));
        CHECK(tx[38] == (uint8_t)(snd0 >> 24) && tx[39] == (uint8_t)(snd0 >> 16) && tx[40] == (uint8_t)(snd0 >> 8) &&
              tx[41] == (uint8_t)snd0);
        CHECK(tx[42] == (uint8_t)(rcv1 >> 24) && tx[43] == (uint8_t)(rcv1 >> 16) && tx[44] == (uint8_t)(rcv1 >> 8) &&
              tx[45] == (uint8_t)rcv1);
        CHECK(net_ip_checksum(tx + 14, 20) == 0u);
        CHECK(net_tcp_checksum((uint32_t)NET_IP_SELF, rip, tx + 34, 20) == 0u);
        for (k = 0; k < txlen; k++) /* bound: 1514 */
            snap[k] = tx[k];
        snaplen = txlen;
        /* Repeat close: success without a second FIN (RPC maps 0 to S_OK). */
        CHECK(net_sock_fin_close(a) == 0);
        CHECK(t->state == NET_TCP_LAST_ACK);
        CHECK(t->snd_nxt == snd0 + 1u);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(txlen == snaplen && memcmp(tx, snap, snaplen) == 0);
        /* TX pass arms the FIN retry (fake ticks). */
        CHECK(net_sock_tcp_retry_arm(a, t0, sp) == 0);
        /* Stale pure ACK: drops, LAST_ACK held, retry untouched. */
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, rcv1, snd0, (uint8_t)TCP_ACK, hello, 0);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 0);
        CHECK(rl == 0);
        CHECK(t->state == NET_TCP_LAST_ACK);
        CHECK(t->retry_deadline == t0 + sp && t->retry_count == 0u);
        /* Covering ACK of our FIN: enters the linger (legacy now = 0
         * stamp: deadline = NET_TCP_TIME_WAIT_TICKS), never CLOSED. */
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, rcv1, snd0 + 1u, (uint8_t)TCP_ACK, hello, 0);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 0);
        CHECK(rl == 0);
        CHECK(t->state == NET_TCP_TIME_WAIT);
        CHECK(t->retry_deadline == NET_TCP_TIME_WAIT_TICKS && t->retry_count == 0u);
        /* Duplicate covering ACK in TIME_WAIT: drops (bare ACK), holds. */
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 0);
        CHECK(t->state == NET_TCP_TIME_WAIT);
        CHECK(net_sock_close(a) == 0);
        CHECK(net_sock_tcp_bound() < 0);
        /* FIN exhaustion from LAST_ACK: expiries 1-4 resend the FIN
         * verbatim, the 5th RST-aborts and captures the waiter once. */
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t2_establish(a, dmac, rip, 0x01020304u, 0x0A0B0C0Du, 8080u, syn, sa, rep, &replen) == 0);
        snd0 = t->snd_nxt;
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, t->rcv_nxt, snd0, (uint8_t)(TCP_FIN | TCP_ACK), hello, 0);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 1);
        CHECK(t->state == NET_TCP_CLOSE_WAIT);
        rcv1 = t->rcv_nxt;
        CHECK(net_sock_fin_close(a) == 0);
        CHECK(t->state == NET_TCP_LAST_ACK);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(tx != 0 && txlen == 14u + 20u + 20u);
        CHECK(tx[14 + 20 + 13] == (uint8_t)(TCP_FIN | TCP_ACK));
        for (k = 0; k < txlen; k++) /* bound: 1514 */
            snap[k] = tx[k];
        snaplen = txlen;
        CHECK(net_sock_tcp_retry_arm(a, t0, sp) == 0);
        CHECK(net_sock_tcp_retry_poll(t0 + sp, sp, &owner, &had) == 1);
        CHECK(net_sock_tcp_retry_poll(t0 + 2u * sp, sp, &owner, &had) == 1);
        CHECK(net_sock_tcp_retry_poll(t0 + 3u * sp, sp, &owner, &had) == 1);
        CHECK(net_sock_tcp_retry_poll(t0 + 4u * sp, sp, &owner, &had) == 1);
        CHECK(t->retry_count == 4u);
        CHECK(t->state == NET_TCP_LAST_ACK);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(txlen == snaplen && memcmp(tx, snap, snaplen) == 0);
        CHECK(net_waiter_arm(a, 1, t0, 100000u) == 0);
        trc = net_sock_tcp_retry_poll(t0 + 5u * sp, sp, &owner, &had);
        CHECK(trc == 2 && had == 1 && owner == 1);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(t->retry_deadline == 0u && t->retry_count == 0u);
        CHECK(net_waiter_match(8080, &owner) < 0);
        tx = net_sock_tcp_tx(&txlen);
        CHECK(tx != 0 && txlen == 14u + 20u + 20u);
        CHECK(tx[14 + 20 + 13] == (uint8_t)(TCP_RST | TCP_ACK));
        CHECK(tx[38] == (uint8_t)((snd0 + 1u) >> 24) && tx[39] == (uint8_t)((snd0 + 1u) >> 16) &&
              tx[40] == (uint8_t)((snd0 + 1u) >> 8) && tx[41] == (uint8_t)(snd0 + 1u));
        CHECK(tx[42] == (uint8_t)(rcv1 >> 24) && tx[43] == (uint8_t)(rcv1 >> 16) && tx[44] == (uint8_t)(rcv1 >> 8) &&
              tx[45] == (uint8_t)rcv1);
        CHECK(net_ip_checksum(tx + 14, 20) == 0u);
        CHECK(net_tcp_checksum((uint32_t)NET_IP_SELF, rip, tx + 34, 20) == 0u);
        CHECK(t->snd_nxt == snd0 + 1u); /* RST consumes no sequence number */
        trc = net_sock_tcp_retry_poll(t0 + 6u * sp, sp, &owner, &had);
        CHECK(trc == 0 && had == 0); /* fired exactly once */
        CHECK(net_sock_close(a) == 0);
        /* RST in LAST_ACK aborts at once (seam clears the waiter). */
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t2_establish(a, dmac, rip, 0x01020304u, 0x0A0B0C0Du, 8080u, syn, sa, rep, &replen) == 0);
        snd0 = t->snd_nxt;
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, t->rcv_nxt, snd0, (uint8_t)(TCP_FIN | TCP_ACK), hello, 0);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 1);
        CHECK(t->state == NET_TCP_CLOSE_WAIT);
        CHECK(net_sock_fin_close(a) == 0);
        CHECK(t->state == NET_TCP_LAST_ACK);
        CHECK(net_waiter_arm(a, 1, t0, 100000u) == 0);
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, t->rcv_nxt, snd0 + 1u, (uint8_t)(TCP_RST | TCP_ACK), hello, 0);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(t->retry_deadline == 0u && t->retry_count == 0u);
        CHECK(net_waiter_match(8080, &owner) < 0);
        CHECK(net_sock_close(a) == 0);
        CHECK(net_sock_tcp_bound() < 0);
    }
    /* ---- Passive close Task 3: ESTABLISHED FIN routing + duplicate-FIN
     * re-ACK + waiter errors (RFC 793 section 3.5; carried ruling: a
     * duplicate FIN in CLOSE_WAIT/LAST_ACK parks a re-ACK and holds state,
     * never a premature close). The wire FIN classifies TCP without
     * touching either queue (invisible to the UDP carve); the seam feed
     * the v2_main ESTABLISHED leg performs consumes it once; drained recv
     * answers EMPTY (S_EMPTY analog); an RST abort clears the waiter for
     * the loop's single S_ERR. */
    {
        static const uint8_t hello[5] = {'h', 'e', 'l', 'l', 'o'};
        static const uint8_t gwmac[6] = {0x52u, 0x54u, 0x00u, 0x12u, 0x34u, 0x56u};
        int a;
        struct net_tcp_conn *t;
        uint8_t syn[58], sa[58], rep[54], fr[128], buf[600];
        unsigned long replen = 0, flen = 0, rl = 0, alen = 0;
        const uint8_t *ackf;
        uint8_t dmac[6];
        uint32_t rip, snd0, rcv0, rcv1;
        uint32_t sip = 0;
        uint16_t sport = 0;
        int trunc = -1, n;
        unsigned owner = 0;
        net_stack_init();
        net_arp_init();
        rip = (uint32_t)NET_IP_GW;
        CHECK(net_arp_lookup(rip, dmac) == 0);
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t2_establish(a, dmac, rip, 0x01020304u, 0x0A0B0C0Du, 8080u, syn, sa, rep, &replen) == 0);
        /* Queue 5 stream bytes via the wire path; park + clear the ACK. */
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, t->rcv_nxt, t->snd_nxt, (uint8_t)(TCP_PSH | TCP_ACK), hello,
                         sizeof(hello));
        CHECK(net_stack_rx(fr, flen) == NET_CLASS_TCP);
        rcv0 = t->rcv_nxt;
        snd0 = t->snd_nxt;
        ackf = net_tcp_ack_tx(&alen);
        CHECK(ackf != 0 && alen == 14u + 20u + 20u);
        net_tcp_ack_clear();
        /* Wire FIN: TCP class, neither queue touched (UDP carve blind). */
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, rcv0, snd0, (uint8_t)(TCP_FIN | TCP_ACK), hello, 0);
        CHECK(net_stack_rx(fr, flen) == NET_CLASS_TCP);
        CHECK(t->state == NET_TCP_ESTABLISHED);
        CHECK(t->rcv_nxt == rcv0);
        CHECK(net_udp_recv(fr, sizeof(fr), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        /* The v2_main ESTABLISHED feed: seam consumes the FIN once. */
        rl = 0;
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 1);
        CHECK(rl == sizeof(rep));
        CHECK(t->state == NET_TCP_CLOSE_WAIT);
        rcv1 = t->rcv_nxt;
        CHECK(rcv1 == rcv0 + 1u);
        /* Queued bytes drain intact; drained recv answers EMPTY. */
        trunc = -1;
        sip = 0;
        sport = 0;
        n = net_tcp_recv_from(8080, buf, sizeof(buf), &sip, &sport, &trunc);
        CHECK(n == (int)sizeof(hello) && trunc == 0 && sip == rip && sport == 80u);
        CHECK(memcmp(buf, hello, sizeof(hello)) == 0);
        CHECK(net_tcp_recv_from(8080, buf, sizeof(buf), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        /* Duplicate FIN: re-ACK + hold (never a second close). */
        rl = 0;
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 1);
        CHECK(rl == sizeof(rep));
        CHECK(t->state == NET_TCP_CLOSE_WAIT && t->rcv_nxt == rcv1 && t->snd_nxt == snd0);
        CHECK(rep[14 + 20 + 13] == (uint8_t)TCP_ACK);
        CHECK(net_tcp_checksum((uint32_t)NET_IP_SELF, rip, rep + 34, 20) == 0u);
        /* RST in CLOSE_WAIT aborts at once and clears the waiter once. */
        CHECK(net_waiter_arm(a, 1, 30000u, 100000u) == 0);
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, rcv1, snd0, (uint8_t)(TCP_RST | TCP_ACK), hello, 0);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(net_waiter_match(8080, &owner) < 0);
        CHECK(net_sock_close(a) == 0);
        /* LAST_ACK duplicate FIN: re-ACK + hold, then the single close. */
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t2_establish(a, dmac, rip, 0x01020304u, 0x0A0B0C0Du, 8080u, syn, sa, rep, &replen) == 0);
        snd0 = t->snd_nxt;
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, t->rcv_nxt, snd0, (uint8_t)(TCP_FIN | TCP_ACK), hello, 0);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 1);
        CHECK(t->state == NET_TCP_CLOSE_WAIT);
        rcv1 = t->rcv_nxt;
        CHECK(net_sock_fin_close(a) == 0);
        CHECK(t->state == NET_TCP_LAST_ACK);
        CHECK(net_sock_tcp_retry_arm(a, 30000u, 50u) == 0);
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, rcv1 - 1u, snd0, (uint8_t)(TCP_FIN | TCP_ACK), hello, 0);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 1);
        CHECK(rl == sizeof(rep));
        CHECK(t->state == NET_TCP_LAST_ACK);
        CHECK(t->retry_deadline == 30050u && t->retry_count == 0u);
        CHECK(rep[42] == (uint8_t)(rcv1 >> 24) && rep[43] == (uint8_t)(rcv1 >> 16) && rep[44] == (uint8_t)(rcv1 >> 8) &&
              rep[45] == (uint8_t)rcv1);
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, rcv1, snd0 + 1u, (uint8_t)TCP_ACK, hello, 0);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 0);
        CHECK(t->state == NET_TCP_TIME_WAIT);
        CHECK(t->retry_deadline == NET_TCP_TIME_WAIT_TICKS && t->retry_count == 0u);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 0); /* duplicate bare ACK: drops, holds */
        CHECK(t->state == NET_TCP_TIME_WAIT);
        CHECK(net_sock_close(a) == 0);
        CHECK(net_sock_tcp_bound() < 0);
    }
    /* ---- TIME_WAIT linger Task 2: duplicate-ACK + expiry + port reserve
     * (RFC 793 section 3.5, 2MSL = NET_TCP_TIME_WAIT_TICKS): duplicate
     * FIN/data re-ACK without state change; expiry one tick before the
     * deadline holds, at the deadline falls to CLOSED; the lingering
     * port refuses open and every new open fails closed until expiry. ---- */
    {
        static const uint8_t hello[5] = {'h', 'e', 'l', 'l', 'o'};
        static const uint8_t gwmac[6] = {0x52u, 0x54u, 0x00u, 0x12u, 0x34u, 0x56u};
        int a;
        struct net_tcp_conn *t;
        uint8_t syn[58], sa[58], rep[54], fr[128];
        unsigned long replen = 0, rl = 0, flen = 0;
        uint8_t dmac[6];
        uint32_t rip, snd0, rcv1;
        uint64_t tnow = 5000u, dl;
        unsigned owner = 0;
        int had = 0;
        net_stack_init();
        net_arp_init();
        rip = (uint32_t)NET_IP_GW;
        CHECK(net_arp_lookup(rip, dmac) == 0);
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t2_establish(a, dmac, rip, 0x01020304u, 0x0A0B0C0Du, 8080u, syn, sa, rep, &replen) == 0);
        /* Passive close to LAST_ACK, then the covering ACK enters the
         * linger on an explicit clock (deadline = tnow + 2MSL). */
        snd0 = t->snd_nxt;
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, t->rcv_nxt, snd0, (uint8_t)(TCP_FIN | TCP_ACK), hello, 0);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 1);
        CHECK(t->state == NET_TCP_CLOSE_WAIT);
        rcv1 = t->rcv_nxt;
        CHECK(net_sock_fin_close(a) == 0);
        CHECK(t->state == NET_TCP_LAST_ACK);
        snd0 = t->snd_nxt;
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, rcv1, snd0, (uint8_t)TCP_ACK, hello, 0);
        CHECK(net_sock_tcp_input_at(a, fr, flen, rep, &rl, tnow) == 0);
        CHECK(rl == 0);
        CHECK(t->state == NET_TCP_TIME_WAIT);
        dl = tnow + (uint64_t)NET_TCP_TIME_WAIT_TICKS;
        CHECK(t->retry_deadline == dl && t->retry_count == 0u);
        /* Port reserve: the lingering port refuses a new open. */
        CHECK(net_sock_open(NET_SOCK_TCP, 8080, 2) < 0);
        /* Duplicate FIN re-ACKs: rc 1, pure ACK, state/seq/retry held. */
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, rcv1 - 1u, snd0, (uint8_t)(TCP_FIN | TCP_ACK), hello, 0);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 1);
        CHECK(rl == sizeof(rep));
        CHECK(t->state == NET_TCP_TIME_WAIT);
        CHECK(t->rcv_nxt == rcv1 && t->snd_nxt == snd0);
        CHECK(t->retry_deadline == dl && t->retry_count == 0u);
        CHECK(rep[14 + 20 + 13] == (uint8_t)TCP_ACK);
        CHECK(rep[42] == (uint8_t)(rcv1 >> 24) && rep[43] == (uint8_t)(rcv1 >> 16) && rep[44] == (uint8_t)(rcv1 >> 8) &&
              rep[45] == (uint8_t)rcv1);
        CHECK(net_ip_checksum(rep + 14, 20) == 0u);
        CHECK(net_tcp_checksum((uint32_t)NET_IP_SELF, rip, rep + 34, 20) == 0u);
        /* Duplicate data re-ACKs the same way, never queued. */
        rl = 0;
        flen =
            t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, rcv1 - 5u, snd0, (uint8_t)(TCP_PSH | TCP_ACK), hello, sizeof(hello));
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 1);
        CHECK(rl == sizeof(rep));
        CHECK(t->state == NET_TCP_TIME_WAIT);
        CHECK(t->rcv_nxt == rcv1 && t->snd_nxt == snd0);
        CHECK(t->retry_deadline == dl && t->retry_count == 0u);
        {
            uint32_t sip = 0;
            uint16_t sport = 0;
            int trunc = -1;
            CHECK(net_tcp_recv_from(8080, fr, sizeof(fr), &sip, &sport, &trunc) == -(NET_ERR_EMPTY));
        }
        /* Bare covering-ACK retransmit: drops, holds (Task 1 compat). */
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, rcv1, snd0, (uint8_t)TCP_ACK, hello, 0);
        CHECK(net_sock_tcp_input(a, fr, flen, rep, &rl) == 0);
        CHECK(rl == 0);
        CHECK(t->state == NET_TCP_TIME_WAIT);
        /* Expiry: one tick before the deadline holds ... */
        CHECK(net_sock_tcp_retry_poll(dl - 1u, 50u, &owner, &had) == 0 && had == 0);
        CHECK(t->state == NET_TCP_TIME_WAIT);
        CHECK(t->retry_deadline == dl && t->retry_count == 0u);
        /* ... every new open fails closed for the whole linger (spec
         * Sec 2): the linger survives, keeping its duplicate-ACK duty. */
        CHECK(net_sock_open(NET_SOCK_TCP, 8081, 2) < 0);
        CHECK(t->state == NET_TCP_TIME_WAIT);
        CHECK(t->retry_deadline == dl && t->retry_count == 0u);
        CHECK(net_sock_close(a) == 0);
        /* ... and a fresh linger falls to CLOSED exactly at the deadline,
         * freeing the port for rebind. */
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        t = net_sock_tcp(a);
        CHECK(t != 0);
        CHECK(t2_establish(a, dmac, rip, 0x01020304u, 0x0A0B0C0Du, 8080u, syn, sa, rep, &replen) == 0);
        CHECK(net_sock_fin_close(a) == 0);
        CHECK(t->state == NET_TCP_FIN_WAIT);
        snd0 = t->snd_nxt;
        rl = 0;
        flen = t3_mk_tcp(fr, gwmac, rip, 80u, 8080u, t->rcv_nxt, snd0, (uint8_t)TCP_ACK, hello, 0);
        CHECK(net_sock_tcp_input_at(a, fr, flen, rep, &rl, tnow) == 0);
        CHECK(t->state == NET_TCP_TIME_WAIT);
        dl = tnow + (uint64_t)NET_TCP_TIME_WAIT_TICKS;
        CHECK(t->retry_deadline == dl);
        CHECK(net_sock_tcp_retry_poll(dl, 50u, &owner, &had) == 0 && had == 0);
        CHECK(t->state == NET_TCP_CLOSED);
        CHECK(t->retry_deadline == 0u && t->retry_count == 0u);
        CHECK(net_sock_open(NET_SOCK_TCP, 8080, 2) < 0);
        CHECK(net_sock_close(a) == 0);
        a = net_sock_open(NET_SOCK_TCP, 8080, 1);
        CHECK(a >= 0);
        CHECK(net_sock_close(a) == 0);
        CHECK(net_sock_tcp_bound() < 0);
    }
    puts("PASS: test_net_stack");
    return 0;
}
