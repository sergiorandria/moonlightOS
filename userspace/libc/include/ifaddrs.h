/* Moonlight libc - ifaddrs (loopback + AF_UNIX enumeration).
 * Implemented in src/netif.c over the static interface table. */
#pragma once

#include <sys/socket.h>

struct ifaddrs {
    struct ifaddrs *ifa_next;
    char *ifa_name;
    unsigned ifa_flags;
    struct sockaddr *ifa_addr;
    struct sockaddr *ifa_netmask;
    struct sockaddr *ifa_dstaddr;
    void *ifa_data;
};

int getifaddrs(struct ifaddrs **list);
void freeifaddrs(struct ifaddrs *list);
