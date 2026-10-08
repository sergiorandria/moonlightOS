/* Moonlight libc - netinet/ether.h (Ethernet address text
 * conversion; implemented in src/ether.c). */
#pragma once

#include <stdint.h>
#include <stddef.h>

struct ether_addr {
    uint8_t ether_addr_octet[6];
};

char *ether_ntoa(const struct ether_addr *addr);
struct ether_addr *ether_aton(const char *asc);
char *ether_ntoa_r(const struct ether_addr *addr, char *buf);
struct ether_addr *ether_aton_r(const char *asc, struct ether_addr *addr);
int ether_hostton(const char *hostname, struct ether_addr *addr);
int ether_ntohost(char *hostname, const struct ether_addr *addr);
int ether_line(const char *line, struct ether_addr *addr, char *hostname);
