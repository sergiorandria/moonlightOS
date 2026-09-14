/* Moonlight libc - netinet/if_ether.h (ARP header; Ethernet
 * address helpers ether_ntoa/ether_aton live in netinet/ether.h). */
#pragma once

#include <stdint.h>

#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_ZLEN 60
#define ETH_FRAME_LEN 1514
#define ETH_FCS_LEN 4

struct arphdr {
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;
};

#define ARPHRD_ETHER 1
#define ARPHRD_IEEE802 6
#define ARPHRD_LOOPBACK 772

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define ARPOP_RREQUEST 3
#define ARPOP_RREPLY 4
#define ARPOP_InREQUEST 8
#define ARPOP_InREPLY 9
#define ARPOP_NAK 10
