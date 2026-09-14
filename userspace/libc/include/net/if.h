/* Moonlight libc - net/if (interface list over the loopback table).
 * Single interface "lo" (index 1); implemented in src/netif.c. */
#pragma once

#include <stddef.h>
#include <sys/socket.h>

#define IFNAMSIZ 16
#define IF_NAMESIZE 16

#define IFF_UP 0x1
#define IFF_BROADCAST 0x2
#define IFF_DEBUG 0x4
#define IFF_LOOPBACK 0x8
#define IFF_POINTOPOINT 0x10
#define IFF_NOTRAILERS 0x20
#define IFF_RUNNING 0x40
#define IFF_NOARP 0x80
#define IFF_PROMISC 0x100
#define IFF_ALLMULTI 0x200
#define IFF_MASTER 0x400
#define IFF_SLAVE 0x800
#define IFF_MULTICAST 0x1000
#define IFF_PORTSEL 0x2000
#define IFF_AUTOMEDIA 0x4000
#define IFF_DYNAMIC 0x8000

struct ifmap {
    unsigned long mem_start;
    unsigned long mem_end;
    unsigned short base_addr;
    unsigned char irq;
    unsigned char dma;
    unsigned char port;
};

struct ifreq {
    char ifr_name[IFNAMSIZ];
    union {
        struct sockaddr ifr_addr;
        struct sockaddr ifr_dstaddr;
        struct sockaddr ifr_broadaddr;
        struct sockaddr ifr_netmask;
        struct sockaddr ifr_hwaddr;
        short ifr_flags;
        int ifr_ifindex;
        int ifr_mtu;
        struct ifmap ifr_map;
    } ifr_ifru;
};

#define ifr_addr ifr_ifru.ifr_addr
#define ifr_dstaddr ifr_ifru.ifr_dstaddr
#define ifr_broadaddr ifr_ifru.ifr_broadaddr
#define ifr_netmask ifr_ifru.ifr_netmask
#define ifr_hwaddr ifr_ifru.ifr_hwaddr
#define ifr_flags ifr_ifru.ifr_flags
#define ifr_ifindex ifr_ifru.ifr_ifindex
#define ifr_mtu ifr_ifru.ifr_mtu
#define ifr_map ifr_ifru.ifr_map

struct ifconf {
    int ifc_len;
    union {
        char *ifcu_buf;
        struct ifreq *ifcu_req;
    } ifc_ifcu;
};

#define ifc_buf ifc_ifcu.ifcu_buf
#define ifc_req ifc_ifcu.ifcu_req

struct if_nameindex {
    unsigned if_index;
    char *if_name;
};

unsigned if_nametoindex(const char *name);
char *if_indextoname(unsigned idx, char *buf);
struct if_nameindex *if_nameindex(void);
void if_freenameindex(struct if_nameindex *p);
