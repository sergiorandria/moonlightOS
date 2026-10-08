/* userspace/net/dhcp.c - DHCPv4 client codec. See dhcp.h. */
#include "dhcp.h"

#include "arp_cache.h"
#include "cksum.h"
#include "eth.h"
#include "ip.h"

#define DHCP_UDP_LEN (8u + DHCP_MIN_MSG)
#define DHCP_IP_TOT (20u + DHCP_UDP_LEN)

static uint32_t dhcp_ip_at(const uint8_t *f, unsigned o)
{
    return (uint32_t)(((uint32_t)f[o] << 24) | ((uint32_t)f[o + 1] << 16) |
                      ((uint32_t)f[o + 2] << 8) | (uint32_t)f[o + 3]);
}

static void dhcp_ip_put(uint8_t *f, unsigned o, uint32_t ip)
{
    f[o] = (uint8_t)(ip >> 24);
    f[o + 1] = (uint8_t)(ip >> 16);
    f[o + 2] = (uint8_t)(ip >> 8);
    f[o + 3] = (uint8_t)ip;
}

/* Fixed 236B BOOTP header with our MAC, broadcast flags, given xid. */
static void dhcp_hdr_init(uint8_t *b, uint32_t xid)
{
    unsigned i;
    for (i = 0; i < DHCP_HDR_LEN; i++)
        b[i] = 0;
    b[0] = (uint8_t)DHCP_OP_REQUEST;
    b[1] = (uint8_t)DHCP_HTYPE_ETH;
    b[2] = (uint8_t)DHCP_HLEN_ETH;
    b[3] = 0u;
    b[4] = (uint8_t)(xid >> 24);
    b[5] = (uint8_t)(xid >> 16);
    b[6] = (uint8_t)(xid >> 8);
    b[7] = (uint8_t)xid;
    b[10] = (uint8_t)(DHCP_FLAGS_BCAST >> 8);
    b[11] = (uint8_t)DHCP_FLAGS_BCAST;
    for (i = 0; i < 6u; i++)
        b[28 + i] = NET_MAC_SELF[i];
}

/* Full frame: bcast eth/IP, sport 68, dport 67, options appended after
 * the 236B header, zero-padded to the 300B floor. */
static int dhcp_frame(const uint8_t *b, const uint8_t *opts, unsigned olen, uint8_t *out,
                      unsigned long *outlen)
{
    unsigned long total;
    unsigned i;
    uint16_t ck;
    unsigned long mlen;
    if (!b || !opts || !out || !outlen || olen > 64u)
        return -1;
    mlen = (unsigned long)DHCP_HDR_LEN + 4u + (unsigned long)olen;
    if (mlen < (unsigned long)DHCP_MIN_MSG)
        mlen = (unsigned long)DHCP_MIN_MSG;
    total = (unsigned long)ETH_HDR_LEN + 20u + 8u + mlen;
    if (total > 1514UL)
        return -1;
    for (i = 0; i < 6u; i++)
    {
        out[i] = 0xFFu;
        out[6 + i] = NET_MAC_SELF[i];
    }
    out[12] = 0x08u;
    out[13] = 0x00u;
    out[14] = 0x45u;
    out[15] = 0x00u;
    out[16] = (uint8_t)((20u + 8u + mlen) >> 8);
    out[17] = (uint8_t)(20u + 8u + mlen);
    out[18] = 0x12u;
    out[19] = 0x34u;
    out[20] = 0x40u;
    out[21] = 0x00u;
    out[22] = 64u;
    out[23] = IP_PROTO_UDP;
    out[24] = 0u;
    out[25] = 0u;
    dhcp_ip_put(out, 26, 0u); /* ciaddr 0: no address yet */
    dhcp_ip_put(out, 30, 0xFFFFFFFFu);
    ck = net_ip_checksum(out + ETH_HDR_LEN, IP_MIN);
    out[24] = (uint8_t)(ck >> 8);
    out[25] = (uint8_t)(ck & 0xFFu);
    out[34] = 0u;
    out[35] = (uint8_t)DHCP_CLIENT_PORT;
    out[36] = 0u;
    out[37] = (uint8_t)DHCP_SERVER_PORT;
    out[38] = (uint8_t)((8u + mlen) >> 8);
    out[39] = (uint8_t)(8u + mlen);
    out[40] = 0u;
    out[41] = 0u;
    for (i = 0; i < (unsigned)DHCP_HDR_LEN; i++)
        out[42 + i] = b[i];
    out[42 + DHCP_HDR_LEN] = (uint8_t)DHCP_COOKIE_0;
    out[42 + DHCP_HDR_LEN + 1u] = (uint8_t)DHCP_COOKIE_1;
    out[42 + DHCP_HDR_LEN + 2u] = (uint8_t)DHCP_COOKIE_2;
    out[42 + DHCP_HDR_LEN + 3u] = (uint8_t)DHCP_COOKIE_3;
    for (i = 0; i < olen; i++)
        out[42 + DHCP_HDR_LEN + 4u + i] = opts[i];
    for (i = (unsigned)DHCP_HDR_LEN + 4u + olen; i < (unsigned)mlen; i++)
        out[42 + i] = 0u;
    ck = net_udp_checksum(0u, 0xFFFFFFFFu, out + 42, (unsigned)(8u + mlen));
    out[40] = (uint8_t)(ck >> 8);
    out[41] = (uint8_t)(ck & 0xFFu);
    *outlen = total;
    return 0;
}

int net_dhcp_build_discover(uint32_t xid, uint8_t *out, unsigned long *outlen)
{
    uint8_t b[DHCP_HDR_LEN];
    uint8_t o[16];
    unsigned n = 0;
    if (!out || !outlen)
        return -1;
    dhcp_hdr_init(b, xid);
    o[n++] = (uint8_t)DHCP_OPT_MSG_TYPE;
    o[n++] = 1u;
    o[n++] = (uint8_t)DHCP_MSG_DISCOVER;
    o[n++] = (uint8_t)DHCP_OPT_PARAM_REQ;
    o[n++] = 4u;
    o[n++] = (uint8_t)DHCP_OPT_SUBNET;
    o[n++] = (uint8_t)DHCP_OPT_ROUTER;
    o[n++] = (uint8_t)DHCP_OPT_DNS;
    o[n++] = (uint8_t)DHCP_OPT_LEASE;
    o[n++] = (uint8_t)DHCP_OPT_END;
    return dhcp_frame(b, o, n, out, outlen);
}

int net_dhcp_build_request(uint32_t xid, const struct net_dhcp_lease *ls, uint8_t *out,
                           unsigned long *outlen)
{
    uint8_t b[DHCP_HDR_LEN];
    uint8_t o[32];
    unsigned n = 0;
    if (!ls || !out || !outlen || ls->yiaddr == 0u || ls->server == 0u)
        return -1;
    dhcp_hdr_init(b, xid);
    o[n++] = (uint8_t)DHCP_OPT_MSG_TYPE;
    o[n++] = 1u;
    o[n++] = (uint8_t)DHCP_MSG_REQUEST;
    o[n++] = (uint8_t)DHCP_OPT_REQ_IP;
    o[n++] = 4u;
    o[n++] = (uint8_t)(ls->yiaddr >> 24);
    o[n++] = (uint8_t)(ls->yiaddr >> 16);
    o[n++] = (uint8_t)(ls->yiaddr >> 8);
    o[n++] = (uint8_t)ls->yiaddr;
    o[n++] = (uint8_t)DHCP_OPT_SERVER_ID;
    o[n++] = 4u;
    o[n++] = (uint8_t)(ls->server >> 24);
    o[n++] = (uint8_t)(ls->server >> 16);
    o[n++] = (uint8_t)(ls->server >> 8);
    o[n++] = (uint8_t)ls->server;
    o[n++] = (uint8_t)DHCP_OPT_PARAM_REQ;
    o[n++] = 4u;
    o[n++] = (uint8_t)DHCP_OPT_SUBNET;
    o[n++] = (uint8_t)DHCP_OPT_ROUTER;
    o[n++] = (uint8_t)DHCP_OPT_DNS;
    o[n++] = (uint8_t)DHCP_OPT_LEASE;
    o[n++] = (uint8_t)DHCP_OPT_END;
    return dhcp_frame(b, o, n, out, outlen);
}

/* Bounded TLV scan (udhcpc discipline): END/PAD tolerant, zero-length
 * options skipped, overrun rejects. Returns message type or -1. */
static int dhcp_scan(const uint8_t *opts, unsigned olen, uint8_t want, const uint8_t **val,
                     unsigned *vlen)
{
    unsigned p = 0;
    int found_type = -1;
    if (val)
        *val = 0;
    if (vlen)
        *vlen = 0;
    while (p < olen)
    {
        uint8_t code = opts[p];
        unsigned len;
        if (code == DHCP_OPT_END)
            break;
        if (code == DHCP_OPT_PAD)
        {
            p++;
            continue;
        }
        if (p + 1 >= olen)
            return -1;
        len = opts[p + 1];
        if (len == 0u) /* udhcpc: skip zero-length (broken TrendNet peers) */
        {
            p += 2;
            continue;
        }
        if (p + 2 + len > olen)
            return -1;
        if (code == DHCP_OPT_MSG_TYPE && len == 1u)
            found_type = opts[p + 2];
        if (code == want && val && vlen)
        {
            *val = opts + p + 2;
            *vlen = len;
        }
        p += 2 + len;
    }
    return found_type;
}

/* Shared OFFER/ACK validation: cookie, xid, yiaddr, type, server-id. */
static int dhcp_parse(const uint8_t *f, unsigned long len, uint32_t xid, int want_type,
                      struct net_dhcp_lease *out)
{
    unsigned long blen;
    const uint8_t *opts;
    const uint8_t *v = 0;
    unsigned vl = 0;
    int type;
    if (!f || !out || len < (unsigned long)ETH_HDR_LEN + 20u + 8u + DHCP_HDR_LEN + 4u)
        return -1;
    if (f[12] != 0x08u || f[13] != 0x00u)
        return -1;
    if (f[14 + 9] != IP_PROTO_UDP)
        return -1;
    if (f[34] != 0u || f[35] != (uint8_t)DHCP_SERVER_PORT)
        return -1;
    if (f[36] != 0u || f[37] != (uint8_t)DHCP_CLIENT_PORT)
        return -1;
    if (f[42] != 2u) /* BOOTREPLY op */
        return -1;
    if (dhcp_ip_at(f, 46) != xid)
        return -1;
    out->yiaddr = dhcp_ip_at(f, 58);
    if (out->yiaddr == 0u)
        return -1;
    blen = len - ((unsigned long)ETH_HDR_LEN + 20u + 8u + DHCP_HDR_LEN);
    opts = f + ETH_HDR_LEN + 20u + 8u + DHCP_HDR_LEN;
    if (opts[0] != DHCP_COOKIE_0 || opts[1] != DHCP_COOKIE_1 || opts[2] != DHCP_COOKIE_2 ||
        opts[3] != DHCP_COOKIE_3)
        return -1;
    type = dhcp_scan(opts + 4, (unsigned)(blen - 4u), DHCP_OPT_SERVER_ID, &v, &vl);
    if (type != want_type || !v || vl != 4u)
        return -1;
    out->server = dhcp_ip_at(v, 0);
    out->subnet = 0xFFFFFF00u;
    out->router = out->server;
    out->dns = out->server;
    out->lease_sec = 3600u;
    if (dhcp_scan(opts + 4, (unsigned)(blen - 4u), DHCP_OPT_SUBNET, &v, &vl) == want_type && v &&
        vl == 4u)
        out->subnet = dhcp_ip_at(v, 0);
    if (dhcp_scan(opts + 4, (unsigned)(blen - 4u), DHCP_OPT_ROUTER, &v, &vl) == want_type && v &&
        vl == 4u)
        out->router = dhcp_ip_at(v, 0);
    if (dhcp_scan(opts + 4, (unsigned)(blen - 4u), DHCP_OPT_DNS, &v, &vl) == want_type && v &&
        vl == 4u)
        out->dns = dhcp_ip_at(v, 0);
    if (dhcp_scan(opts + 4, (unsigned)(blen - 4u), DHCP_OPT_LEASE, &v, &vl) == want_type && v &&
        vl == 4u)
        out->lease_sec = dhcp_ip_at(v, 0);
    return 0;
}

int net_dhcp_parse_offer(const uint8_t *f, unsigned long len, uint32_t xid,
                         struct net_dhcp_lease *out)
{
    return dhcp_parse(f, len, xid, (int)DHCP_MSG_OFFER, out);
}

int net_dhcp_parse_ack(const uint8_t *f, unsigned long len, uint32_t xid,
                       struct net_dhcp_lease *out)
{
    return dhcp_parse(f, len, xid, (int)DHCP_MSG_ACK, out);
}

void net_dhcp_apply(const struct net_dhcp_lease *ls)
{
    if (!ls || ls->yiaddr == 0u)
        return;
    NET_IP_SELF = ls->yiaddr;
    NET_IP_GW = ls->router ? ls->router : ls->server;
    NET_IP_DNS = ls->dns ? ls->dns : NET_IP_GW;
    NET_IP_SUBNET = ls->subnet ? ls->subnet : 0xFFFFFF00u;
    /* Drop the boot-seeded gateway artifact (it carries our own MAC and
     * would blackhole the first real send); the true entry re-learns
     * from the first reply or ARP exchange. */
    net_arp_invalidate(NET_IP_GW);
}
