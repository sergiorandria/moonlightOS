/* userspace/net/eth.h - Ethernet header parse. Pure C, host-testable.
 * No MMIO. The live net ELF (v2_main.c) owns the NIC; this layer is the
 * next protocol stub above T_FWD frames. */
#ifndef NET_ETH_H
#define NET_ETH_H

#include <stdint.h>

#define ETH_HDR_LEN 14u
#define ETH_ADDR_LEN 6u
#define ETH_TYPE_IPV4 0x0800u
#define ETH_TYPE_ARP 0x0806u
#define ETH_TYPE_IPV6 0x86DDu
#define ETH_FRAME_MAX 1514u

/* Ethernet header offsets */
#define ETH_OFF_DST 0u
#define ETH_OFF_SRC 6u
#define ETH_OFF_TYPE 12u

static inline uint16_t eth_type(const uint8_t *f, unsigned long len)
{
    if (!f || len < (unsigned long)ETH_HDR_LEN)
        return 0;
    return (uint16_t)(((unsigned)f[ETH_OFF_TYPE] << 8) | (unsigned)f[ETH_OFF_TYPE + 1]);
}

static inline int eth_hdr_ok(const uint8_t *f, unsigned long len)
{
    uint16_t t;
    if (!f || len < (unsigned long)ETH_HDR_LEN || len > (unsigned long)ETH_FRAME_MAX)
        return 0;
    t = eth_type(f, len);
    if (t == ETH_TYPE_IPV4 || t == ETH_TYPE_ARP || t == ETH_TYPE_IPV6)
        return 1;
    return 0;
}

#endif /* NET_ETH_H */
