/* tests/test_net_stack.c - classify + socket stub. */
#include "../userspace/net/cksum.h"
#include "../userspace/net/sock.c"
#include "../userspace/net/stack.c"
#include "../userspace/net/stack.h"
#include <stdio.h>
#include <string.h>

#define CHECK(c)                                                                                   \
    do                                                                                             \
    {                                                                                              \
        if (!(c))                                                                                  \
        {                                                                                          \
            printf("FAIL line %d: %s\n", __LINE__, #c);                                            \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* Task 2: ARP table implementation (same single-TU pattern as sock.c/stack.c).
 * Later tasks include arp_cache.h for the canonical MAC/IP constants. */
#include "../userspace/net/arp_cache.c"

static void t2_mk_arp(uint8_t *f, const uint8_t *dmac, const uint8_t *smac, unsigned op,
                      const uint8_t *sha, uint32_t spa, const uint8_t *tha, uint32_t tpa)
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
        CHECK(net_stack_init() == 0);
        CHECK(net_stack_rx(tcp, sizeof(tcp)) == NET_CLASS_TCP);
    }
    /* ---- Task 1: socket table with port demux ---- */
    {
        int id;
        int ids[4];
        unsigned i;
        CHECK(net_sock_open(NET_SOCK_TCP, 80, 5) < 0);
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
        static const uint8_t seg[21] = {0x12, 0x34, 0x00, 0x35, 0x00, 0x15, 0x00,
                                        0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C,
                                        0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};
        CHECK(net_udp_checksum(0x0A00020Fu, 0x0A000202u, seg, sizeof(seg)) == 0x93FEu);
    }
    /* UDP pseudo-header checksum: even 12B segment (4B "test" payload). */
    {
        static const uint8_t seg[12] = {0x12, 0x34, 0x00, 0x35, 0x00, 0x0C,
                                        0x00, 0x00, 0x74, 0x65, 0x73, 0x74};
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
            static const uint8_t expect[42] = {
                0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x08, 0x06,
                0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
                0x0A, 0x00, 0x02, 0x0F, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x0A, 0x00, 0x02, 0x04};
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
        CHECK(out[32] == 0 && out[33] == 0 && out[34] == 0 && out[35] == 0 && out[36] == 0 &&
              out[37] == 0);
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
        static const uint8_t hello[13] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20,
                                          0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};
        static const uint8_t expect[55] = {
            0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x29, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x10, 0x80, 0x0A, 0x00,
            0x02, 0x0F, 0x0A, 0x00, 0x02, 0x02, 0xC0, 0x00, 0x00, 0x35, 0x00, 0x15, 0xE6, 0x31,
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21};
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
            CHECK(net_stack_udp_send(0x0A000202u, 53, 49152, bigpay, sizeof(bigpay), frame,
                                     &flen) == -2);
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
    puts("PASS: test_net_stack");
    return 0;
}
