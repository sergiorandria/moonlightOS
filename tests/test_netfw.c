/* tests/test_netfw.c - firewall ruleset header (fw.h) host tests. */
#include <stdio.h>
#include <string.h>
#include "../userspace/firewall/fw.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

/* 14B eth + 20B IP-min; proto at pkt[23], dport BE at pkt[36..37]. */
static void mkpkt(uint8_t *pkt, uint8_t proto, unsigned dport,
                  uint8_t eth0, uint8_t eth1)
{
    memset(pkt, 0, 64);
    pkt[12] = eth0;
    pkt[13] = eth1;
    pkt[FW_ETH_HDR + 9] = proto;
    pkt[FW_ETH_HDR + FW_IP_MIN + 2] = (uint8_t)((dport >> 8) & 0xFF);
    pkt[FW_ETH_HDR + FW_IP_MIN + 3] = (uint8_t)(dport & 0xFF);
}

int main(void) {
    uint8_t pkt[64];
    static uint8_t big[2048];
    fw_rule_t rules[2];
    fw_rule_t ord[2];
    fw_rule_t w[1];
    fw_rule_t out[FW_MAX_RULES];
    int rc;

    /* allow row hit (udp/53 from qube 0) + ask row (tcp/443). */
    rules[0].src_qube = 0;
    rules[0].proto = FW_PROTO_UDP;
    rules[0].dport = 53;
    rules[0].verdict = FW_ALLOW;
    rules[1].src_qube = 0;
    rules[1].proto = FW_PROTO_TCP;
    rules[1].dport = 443;
    rules[1].verdict = FW_ASK;
    mkpkt(pkt, FW_PROTO_UDP, 53, 0x08, 0x00);
    CHECK(fw_decide(rules, 2, 0, pkt, 64) == FW_ALLOW);
    mkpkt(pkt, FW_PROTO_TCP, 443, 0x08, 0x00);
    CHECK(fw_decide(rules, 2, 0, pkt, 64) == FW_ASK);

    /* default-deny (tcp/22 has no row). */
    mkpkt(pkt, FW_PROTO_TCP, 22, 0x08, 0x00);
    CHECK(fw_decide(rules, 2, 0, pkt, 64) == FW_DENY);
    CHECK(fw_decide(rules, 0, 0, pkt, 64) == FW_DENY);

    /* wildcard rows: src / proto / port / full. */
    w[0].src_qube = FW_ANY_QUBE;
    w[0].proto = FW_PROTO_TCP;
    w[0].dport = 443;
    w[0].verdict = FW_ALLOW;
    mkpkt(pkt, FW_PROTO_TCP, 443, 0x08, 0x00);
    CHECK(fw_decide(w, 1, 5, pkt, 64) == FW_ALLOW);
    mkpkt(pkt, FW_PROTO_TCP, 443, 0x08, 0x00);
    CHECK(fw_decide(rules, 2, 5, pkt, 64) == FW_DENY); /* no wildcard: other qube denied */
    w[0].src_qube = 0;
    w[0].proto = FW_ANY_PROTO;
    w[0].dport = 53;
    w[0].verdict = FW_ALLOW;
    mkpkt(pkt, FW_PROTO_UDP, 53, 0x08, 0x00);
    CHECK(fw_decide(w, 1, 0, pkt, 64) == FW_ALLOW);
    mkpkt(pkt, FW_PROTO_TCP, 53, 0x08, 0x00);
    CHECK(fw_decide(w, 1, 0, pkt, 64) == FW_ALLOW);
    w[0].src_qube = 0;
    w[0].proto = FW_PROTO_UDP;
    w[0].dport = FW_ANY_PORT;
    w[0].verdict = FW_ALLOW;
    mkpkt(pkt, FW_PROTO_UDP, 1234, 0x08, 0x00);
    CHECK(fw_decide(w, 1, 0, pkt, 64) == FW_ALLOW);
    w[0].src_qube = FW_ANY_QUBE;
    w[0].proto = FW_ANY_PROTO;
    w[0].dport = FW_ANY_PORT;
    w[0].verdict = FW_ALLOW;
    mkpkt(pkt, FW_PROTO_TCP, 22, 0x08, 0x00);
    CHECK(fw_decide(w, 1, 9, pkt, 64) == FW_ALLOW);

    /* first-match-wins order (deny-before-allow for same key). */
    ord[0].src_qube = 0;
    ord[0].proto = FW_PROTO_TCP;
    ord[0].dport = 80;
    ord[0].verdict = FW_DENY;
    ord[1].src_qube = 0;
    ord[1].proto = FW_PROTO_TCP;
    ord[1].dport = 80;
    ord[1].verdict = FW_ALLOW;
    mkpkt(pkt, FW_PROTO_TCP, 80, 0x08, 0x00);
    CHECK(fw_decide(ord, 2, 0, pkt, 64) == FW_DENY);
    ord[0].verdict = FW_ALLOW;
    ord[1].verdict = FW_DENY;
    CHECK(fw_decide(ord, 2, 0, pkt, 64) == FW_ALLOW);

    /* malformed packets ==> FW_DENY. */
    mkpkt(pkt, FW_PROTO_UDP, 53, 0x08, 0x00);
    CHECK(fw_decide(rules, 2, 0, pkt, 0) == FW_DENY); /* zero-len */
    memset(big, 0, sizeof(big));
    big[12] = 0x08;
    big[13] = 0x00;
    big[FW_ETH_HDR + 9] = FW_PROTO_UDP;
    big[FW_ETH_HDR + FW_IP_MIN + 2] = 0;
    big[FW_ETH_HDR + FW_IP_MIN + 3] = 53;
    CHECK(fw_decide(rules, 2, 0, big, 1515) == FW_DENY); /* 1515B oversize */
    CHECK(fw_decide(rules, 2, 0, big, FW_PKT_MAX) != FW_DENY); /* 1514B bound ok */
    mkpkt(pkt, FW_PROTO_UDP, 53, 0x08, 0x00);
    CHECK(fw_decide(rules, 2, 0, pkt, 30) == FW_DENY); /* 30B short */
    mkpkt(pkt, FW_PROTO_UDP, 53, 0x86, 0xDD);
    CHECK(fw_decide(rules, 2, 0, pkt, 64) == FW_DENY); /* non-IPv4 ethertype */
    mkpkt(pkt, 1, 0, 0x08, 0x00);
    CHECK(fw_decide(rules, 2, 0, pkt, 64) == FW_DENY); /* non-TCP/UDP proto (ICMP 1) */
    mkpkt(pkt, FW_PROTO_TCP, 80, 0x08, 0x00);
    CHECK(fw_decide(rules, 2, 0, pkt, 36) == FW_DENY); /* ports-truncated 36B */
    CHECK(fw_decide((const fw_rule_t *)0, 2, 0, pkt, 64) == FW_DENY); /* null rules */
    CHECK(fw_decide(rules, 2, 0, (const uint8_t *)0, 64) == FW_DENY); /* null pkt */

    /* reload good blob (2 rules incl. wildcard FF FF FF FF). */
    {
        static const uint8_t blob[] = {
            2,
            0x00, 0x00, 0x00, 0x00, 17, 53, 0x00, 0,
            0xFF, 0xFF, 0xFF, 0xFF, 6, 0xBB, 0x01, 1,
        };
        rc = fw_reload_validate(blob, sizeof(blob), out, FW_MAX_RULES);
        CHECK(rc == 2);
        CHECK(out[0].src_qube == 0 && out[0].proto == 17 && out[0].dport == 53);
        CHECK(out[0].verdict == FW_ALLOW);
        CHECK(out[1].src_qube == FW_ANY_QUBE && out[1].proto == 6);
        CHECK(out[1].dport == 443 && out[1].verdict == FW_ASK);
        /* reloaded table decides. */
        mkpkt(pkt, FW_PROTO_TCP, 443, 0x08, 0x00);
        CHECK(fw_decide(out, 2, 7, pkt, 64) == FW_ASK);
    }

    /* bad verdict byte. */
    {
        static const uint8_t bad[] = {
            1, 0x00, 0x00, 0x00, 0x00, 17, 53, 0x00, 3,
        };
        CHECK(fw_reload_validate(bad, sizeof(bad), out, FW_MAX_RULES) == -1);
    }

    /* overcount (>16). */
    {
        static const uint8_t over[] = { 17 };
        CHECK(fw_reload_validate(over, sizeof(over), out, FW_MAX_RULES) == -1);
    }

    /* truncated blob. */
    {
        static const uint8_t trunc[] = {
            2, 0x00, 0x00, 0x00, 0x00, 17, 53, 0x00, 0, 0xFF,
        };
        CHECK(fw_reload_validate(trunc, sizeof(trunc), out, FW_MAX_RULES) == -1);
    }

    /* count > cap. */
    {
        static const uint8_t blob[] = {
            2,
            0x00, 0x00, 0x00, 0x00, 17, 53, 0x00, 0,
            0xFF, 0xFF, 0xFF, 0xFF, 6, 0xBB, 0x01, 1,
        };
        CHECK(fw_reload_validate(blob, sizeof(blob), out, 1) == -1);
        CHECK(fw_reload_validate(blob, sizeof(blob), out, 0) == -1);
        CHECK(fw_reload_validate((const uint8_t *)0, sizeof(blob), out, FW_MAX_RULES) == -1);
        CHECK(fw_reload_validate(blob, sizeof(blob), (fw_rule_t *)0, FW_MAX_RULES) == -1);
        CHECK(fw_reload_validate(blob, 0, out, FW_MAX_RULES) == -1);
    }

    printf("PASS: test_netfw\n");
    return 0;
}
