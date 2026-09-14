/* Moonlight libc - arpa/inet. */
#pragma once

#include <stdint.h>
#include <netinet/in.h>

int inet_pton(int af, const char *src, void *dst);
const char *inet_ntop(int af, const void *src, char *dst, unsigned n);
uint32_t inet_addr(const char *s);
char *inet_ntoa(struct in_addr a);
