/* userspace/firewall/fw.h - header-only firewall ruleset (S3 Phase 1).
 * Pure C: host-testable (tests/test_netfw.c) and included by firewall/v2_main.c.
 * Header-only parse: ethertype + IPv4 proto/ports. Payload never inspected. */
#ifndef FW_H
#define FW_H

#include <stdint.h>

#define FW_MAX_RULES 16
#define FW_PKT_MAX 1514
#define FW_ETH_HDR 14
#define FW_IP_MIN 20

#define FW_PROTO_TCP 6
#define FW_PROTO_UDP 17

#define FW_ALLOW 0
#define FW_ASK 1
#define FW_DENY 2

#define FW_ANY_QUBE 0xFFFFFFFFUL
#define FW_ANY_PROTO 0xFF
#define FW_ANY_PORT 0xFFFF

typedef struct {
    unsigned long src_qube; /* FW_ANY_QUBE = wildcard */
    unsigned long proto;    /* FW_ANY_PROTO = wildcard */
    unsigned long dport;    /* FW_ANY_PORT = wildcard */
    int verdict;            /* FW_ALLOW / FW_ASK / FW_DENY */
} fw_rule_t;

/* First match wins; no match ==> FW_DENY. Malformed ==> FW_DENY. */
static inline int fw_decide(const fw_rule_t *rules, unsigned long n,
                            unsigned long src, const uint8_t *pkt, unsigned long len)
{
    unsigned long proto, dport;
    if (!rules || !pkt)
        return FW_DENY;
    if (len == 0 || len > (unsigned long)FW_PKT_MAX)
        return FW_DENY;
    if (len < (unsigned long)(FW_ETH_HDR + FW_IP_MIN))
        return FW_DENY;
    if (pkt[12] != 0x08 || pkt[13] != 0x00)
        return FW_DENY; /* IPv4 only; everything else is default-deny */
    proto = pkt[FW_ETH_HDR + 9];
    if (proto != (unsigned long)FW_PROTO_TCP && proto != (unsigned long)FW_PROTO_UDP)
        return FW_DENY;
    if (len < (unsigned long)(FW_ETH_HDR + FW_IP_MIN + 4))
        return FW_DENY; /* no room for ports */
    dport = ((unsigned long)pkt[FW_ETH_HDR + FW_IP_MIN + 2] << 8) |
            (unsigned long)pkt[FW_ETH_HDR + FW_IP_MIN + 3];
    for (unsigned long i = 0; i < n; i++) { /* bound: FW_MAX_RULES */
        const fw_rule_t *r;
        int ms, mp, md;
        if (i >= (unsigned long)FW_MAX_RULES)
            break;
        r = &rules[i];
        ms = (r->src_qube == FW_ANY_QUBE || r->src_qube == src);
        mp = (r->proto == FW_ANY_PROTO || r->proto == proto);
        md = (r->dport == FW_ANY_PORT || r->dport == dport);
        if (ms && md && mp)
            return r->verdict;
    }
    return FW_DENY;
}

/* Reload blob: byte 0 = count, then count * 8B entries
 * (src u32 LE, proto u8, pad, dport u16 LE, verdict u8, pad).
 * Returns parsed count (0..FW_MAX_RULES) or -1 on any malformation.
 * Pure validation: the caller swaps tables only on count >= 0. */
static inline int fw_reload_validate(const uint8_t *blob, unsigned long len,
                                     fw_rule_t *out, unsigned long cap)
{
    unsigned long count, i;
    if (!blob || !out || len < 1)
        return -1;
    count = blob[0];
    if (count > (unsigned long)FW_MAX_RULES || count > cap)
        return -1;
    if (len < 1 + count * 8)
        return -1;
    for (i = 0; i < count; i++) { /* bound: FW_MAX_RULES */
        const uint8_t *e = blob + 1 + i * 8;
        unsigned long v = e[7];
        if (v != (unsigned long)FW_ALLOW && v != (unsigned long)FW_ASK &&
            v != (unsigned long)FW_DENY)
            return -1;
        out[i].src_qube = (unsigned long)e[0] | ((unsigned long)e[1] << 8) |
                          ((unsigned long)e[2] << 16) | ((unsigned long)e[3] << 24);
        out[i].proto = e[4];
        out[i].dport = (unsigned long)e[5] | ((unsigned long)e[6] << 8);
        out[i].verdict = (int)v;
    }
    return (int)count;
}

#endif /* FW_H */
