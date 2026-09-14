/* Moonlight libc - net/if_arp.h (ARP ioctl + map structs). */
#pragma once

#include <stdint.h>
#include <sys/socket.h>

#define ARPHRD_NETROM 0
#define ARPHRD_ETHER 1
#define ARPHRD_EETHER 2
#define ARPHRD_AX25 3
#define ARPHRD_PRONET 4
#define ARPHRD_CHAOS 5
#define ARPHRD_IEEE802 6
#define ARPHRD_ARCNET 7
#define ARPHRD_APPLETLK 8
#define ARPHRD_DLCI 15
#define ARPHRD_ATM 19
#define ARPHRD_METRICOM 23
#define ARPHRD_IEEE1394 24
#define ARPHRD_INFINIBAND 32

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define ARPOP_RREQUEST 3
#define ARPOP_RREPLY 4
#define ARPOP_InREQUEST 8
#define ARPOP_InREPLY 9
#define ARPOP_NAK 10

#define ATF_COM 0x02
#define ATF_PERM 0x04
#define ATF_PUBL 0x08
#define ATF_USETRAILERS 0x10
#define ATF_NETMASK 0x20
#define ATF_DONTPUB 0x40

struct arpreq {
    struct sockaddr arp_pa;
    struct sockaddr arp_ha;
    int arp_flags;
};

struct arpreq_old {
    struct sockaddr arp_pa;
    struct sockaddr arp_ha;
    int arp_flags;
    struct sockaddr arp_netmask;
};
