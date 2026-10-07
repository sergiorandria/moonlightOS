/* userspace/net/arp_cache.c - 8-entry ARP table with 60s expiry.
 * Pure C, host-testable, libc-free (byte loops only, no string.h) so the
 * freestanding net ELF can share it. Frame offsets follow arp.h/eth.h.
 * Layout (42B): eth dst[0..5] src[6..11] type[12..13], then ARP payload
 * htype[14..15] ptype[16..17] hlen[18] plen[19] op[20..21] sha[22..27]
 * spa[28..31] tha[32..37] tpa[38..41]. */
#include "arp_cache.h"

#include "arp.h"
#include "eth.h"

const uint8_t NET_MAC_SELF[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
const uint32_t NET_IP_SELF = 0x0A00020Fu;
const uint32_t NET_IP_GW = 0x0A000202u;

#define ARP_OFF_OP 20u
#define ARP_OFF_SHA 22u
#define ARP_OFF_SPA 28u
#define ARP_OFF_THA 32u
#define ARP_OFF_TPA 38u

struct arp_entry
{
    uint32_t ip;
    uint8_t mac[6];
    uint64_t last;
    int valid;
};

static struct arp_entry s_tab[NET_ARP_MAX];
static uint64_t s_now;
static int s_need;
static uint32_t s_rip;
static uint8_t s_rmac[6];

static uint32_t arp_ip_at(const uint8_t *f, unsigned o)
{
    return (uint32_t)(((uint32_t)f[o] << 24) | ((uint32_t)f[o + 1] << 16) |
                      ((uint32_t)f[o + 2] << 8) | (uint32_t)f[o + 3]);
}

static void arp_ip_put(uint8_t *f, unsigned o, uint32_t ip)
{
    f[o] = (uint8_t)(ip >> 24);
    f[o + 1] = (uint8_t)(ip >> 16);
    f[o + 2] = (uint8_t)(ip >> 8);
    f[o + 3] = (uint8_t)ip;
}

static void arp_mac_copy(uint8_t *d, const uint8_t *s)
{
    unsigned i;
    for (i = 0; i < ETH_ADDR_LEN; i++)
        d[i] = s[i];
}

/* Insert or refresh; table-full evicts the oldest (ties: lowest index). */
static void arp_insert(uint32_t ip, const uint8_t *mac)
{
    unsigned i, vic;
    for (i = 0; i < NET_ARP_MAX; i++)
    {
        if (s_tab[i].valid && s_tab[i].ip == ip)
        {
            arp_mac_copy(s_tab[i].mac, mac);
            s_tab[i].last = s_now;
            return;
        }
    }
    for (i = 0; i < NET_ARP_MAX; i++)
    {
        if (!s_tab[i].valid)
        {
            s_tab[i].ip = ip;
            arp_mac_copy(s_tab[i].mac, mac);
            s_tab[i].last = s_now;
            s_tab[i].valid = 1;
            return;
        }
    }
    vic = 0;
    for (i = 1; i < NET_ARP_MAX; i++)
    {
        if (s_tab[i].last < s_tab[vic].last)
            vic = i;
    }
    s_tab[vic].ip = ip;
    arp_mac_copy(s_tab[vic].mac, mac);
    s_tab[vic].last = s_now;
    s_tab[vic].valid = 1;
}

void net_arp_init(void)
{
    unsigned i;
    for (i = 0; i < NET_ARP_MAX; i++)
        s_tab[i].valid = 0;
    s_now = 0;
    s_need = 0;
    s_rip = 0;
    for (i = 0; i < ETH_ADDR_LEN; i++)
        s_rmac[i] = 0;
    /* Seed gateway (design Sec 3: QEMU OUI MAC shared with v2_main ARP). */
    s_tab[0].ip = NET_IP_GW;
    arp_mac_copy(s_tab[0].mac, NET_MAC_SELF);
    s_tab[0].last = 0;
    s_tab[0].valid = 1;
}

int net_arp_lookup(uint32_t ip, uint8_t *mac_out)
{
    unsigned i;
    if (!mac_out)
        return -1;
    for (i = 0; i < NET_ARP_MAX; i++)
    {
        if (s_tab[i].valid && s_tab[i].ip == ip)
        {
            arp_mac_copy(mac_out, s_tab[i].mac);
            return 0;
        }
    }
    return -1;
}

void net_arp_learn(const uint8_t *frame, unsigned long len)
{
    uint16_t op;
    uint32_t spa, tpa;
    if (!frame || len < (unsigned long)ETH_HDR_LEN + ARP_HDR_LEN)
        return;
    if (!arp_hdr_ok(frame, len))
        return;
    op = (uint16_t)(((unsigned)frame[ARP_OFF_OP] << 8) | (unsigned)frame[ARP_OFF_OP + 1u]);
    spa = arp_ip_at(frame, ARP_OFF_SPA);
    tpa = arp_ip_at(frame, ARP_OFF_TPA);
    if (op == ARP_OP_REPLY)
    {
        arp_insert(spa, frame + ARP_OFF_SHA);
        return;
    }
    if (op == ARP_OP_REQUEST && tpa == NET_IP_SELF)
    {
        arp_insert(spa, frame + ARP_OFF_SHA);
        s_rip = spa;
        arp_mac_copy(s_rmac, frame + ARP_OFF_SHA);
        s_need = 1;
    }
}

int net_arp_need_reply(uint32_t *sender_ip, uint8_t *sender_mac)
{
    if (!s_need)
        return 0;
    if (sender_ip)
        *sender_ip = s_rip;
    if (sender_mac)
        arp_mac_copy(sender_mac, s_rmac);
    s_need = 0;
    return 1;
}

int net_arp_build_request(uint32_t target_ip, uint8_t *frame_out)
{
    unsigned i;
    if (!frame_out)
        return -1;
    for (i = 0; i < ETH_ADDR_LEN; i++)
    {
        frame_out[i] = 0xFF;
        frame_out[6 + i] = NET_MAC_SELF[i];
    }
    frame_out[12] = 0x08;
    frame_out[13] = 0x06;
    frame_out[14] = 0x00;
    frame_out[15] = 0x01;
    frame_out[16] = 0x08;
    frame_out[17] = 0x00;
    frame_out[18] = ETH_ADDR_LEN;
    frame_out[19] = 4u;
    frame_out[20] = 0x00;
    frame_out[ARP_OFF_OP + 1u] = (uint8_t)ARP_OP_REQUEST;
    arp_mac_copy(frame_out + ARP_OFF_SHA, NET_MAC_SELF);
    arp_ip_put(frame_out, ARP_OFF_SPA, NET_IP_SELF);
    for (i = 0; i < ETH_ADDR_LEN; i++)
        frame_out[ARP_OFF_THA + i] = 0;
    arp_ip_put(frame_out, ARP_OFF_TPA, target_ip);
    return (int)NET_ARP_FRAME_LEN;
}

int net_arp_build_reply(const uint8_t *req, unsigned long reqlen, uint8_t *frame_out)
{
    uint16_t op;
    unsigned i;
    if (!req || !frame_out)
        return -1;
    if (reqlen < (unsigned long)ETH_HDR_LEN + ARP_HDR_LEN)
        return -1;
    if (!arp_hdr_ok(req, reqlen))
        return -1;
    op = (uint16_t)(((unsigned)req[ARP_OFF_OP] << 8) | (unsigned)req[ARP_OFF_OP + 1u]);
    if (op != ARP_OP_REQUEST)
        return -1;
    if (arp_ip_at(req, ARP_OFF_TPA) != NET_IP_SELF)
        return -1;
    for (i = 0; i < ETH_ADDR_LEN; i++)
    {
        frame_out[i] = req[6 + i];
        frame_out[6 + i] = NET_MAC_SELF[i];
    }
    frame_out[12] = 0x08;
    frame_out[13] = 0x06;
    frame_out[14] = 0x00;
    frame_out[15] = 0x01;
    frame_out[16] = 0x08;
    frame_out[17] = 0x00;
    frame_out[18] = ETH_ADDR_LEN;
    frame_out[19] = 4u;
    frame_out[20] = 0x00;
    frame_out[ARP_OFF_OP + 1u] = (uint8_t)ARP_OP_REPLY;
    arp_mac_copy(frame_out + ARP_OFF_SHA, NET_MAC_SELF);
    arp_ip_put(frame_out, ARP_OFF_SPA, NET_IP_SELF);
    arp_mac_copy(frame_out + ARP_OFF_THA, req + ARP_OFF_SHA);
    arp_ip_put(frame_out, ARP_OFF_TPA, arp_ip_at(req, ARP_OFF_SPA));
    return (int)NET_ARP_FRAME_LEN;
}

void net_arp_tick(uint64_t now_ticks)
{
    unsigned i;
    s_now = now_ticks;
    for (i = 0; i < NET_ARP_MAX; i++)
    {
        if (s_tab[i].valid && now_ticks >= s_tab[i].last &&
            now_ticks - s_tab[i].last > NET_ARP_TIMEOUT_TICKS)
            s_tab[i].valid = 0;
    }
}
