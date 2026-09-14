/* Moonlight libc - netinet/in + arpa/inet + netdb. */
#pragma once

#include <stdint.h>
#include <sys/socket.h>

#define INADDR_ANY ((uint32_t)0)
#define INADDR_LOOPBACK ((uint32_t)0x0100007f)
#define INADDR_NONE ((uint32_t)0xffffffff)
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_IP 0

struct in_addr {
    uint32_t s_addr;
};

uint16_t htons(uint16_t x);
uint16_t ntohs(uint16_t x);
uint32_t htonl(uint32_t x);
uint32_t ntohl(uint32_t x);
