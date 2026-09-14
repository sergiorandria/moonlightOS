/* Moonlight libc - net/ethernet.h (Ethernet header + types). */
#pragma once

#include <stdint.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>

#define ETHER_ADDR_LEN ETH_ALEN
#define ETHER_TYPE_LEN 2
#define ETHER_CRC_LEN 4
#define ETHER_HDR_LEN ETH_HLEN
#define ETHER_MIN_LEN (ETH_ZLEN + ETHER_CRC_LEN)
#define ETHER_MAX_LEN (ETH_FRAME_LEN + ETHER_CRC_LEN)

#define ETHERTYPE_PUP 0x0200
#define ETHERTYPE_SPRITE 0x0500
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_REVARP 0x8035
#define ETHERTYPE_AT 0x809B
#define ETHERTYPE_AARP 0x80F3
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPX 0x8137
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_LOOPBACK 0x9000

struct ether_header {
    uint8_t ether_dhost[ETH_ALEN];
    uint8_t ether_shost[ETH_ALEN];
    uint16_t ether_type;
};

struct ether_arp {
    struct arphdr ea_hdr;
    uint8_t arp_sha[ETH_ALEN];
    uint8_t arp_spa[4];
    uint8_t arp_tha[ETH_ALEN];
    uint8_t arp_tpa[4];
};
