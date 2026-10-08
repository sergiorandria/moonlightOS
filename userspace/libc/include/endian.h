/* Moonlight libc - endian.h (byte order, rv64 + host LE).
 * Real conversions: the supported targets are little-endian, so
 * htobe* swaps and htole* are identity; detection is compile-time. */
#pragma once

#include <stdint.h>

#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#define __BYTE_ORDER __LITTLE_ENDIAN
#define LITTLE_ENDIAN __LITTLE_ENDIAN
#define BIG_ENDIAN __BIG_ENDIAN
#define BYTE_ORDER __BYTE_ORDER

static inline uint16_t __ml_bswap16(uint16_t x) {
    return (uint16_t)((x << 8) | (x >> 8));
}

static inline uint32_t __ml_bswap32(uint32_t x) {
    return ((x & 0xFFu) << 24) | ((x & 0xFF00u) << 8) |
           ((x & 0xFF0000u) >> 8) | ((x & 0xFF000000u) >> 24);
}

static inline uint64_t __ml_bswap64(uint64_t x) {
    return ((x & 0xFFull) << 56) | ((x & 0xFF00ull) << 40) |
           ((x & 0xFF0000ull) << 24) | ((x & 0xFF000000ull) << 8) |
           ((x & 0xFF00000000ull) >> 8) | ((x & 0xFF0000000000ull) >> 24) |
           ((x & 0xFF000000000000ull) >> 40) |
           ((x & 0xFF00000000000000ull) >> 56);
}

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define htobe16(x) __ml_bswap16(x)
#define htobe32(x) __ml_bswap32(x)
#define htobe64(x) __ml_bswap64(x)
#define be16toh(x) __ml_bswap16(x)
#define be32toh(x) __ml_bswap32(x)
#define be64toh(x) __ml_bswap64(x)
#define htole16(x) (x)
#define htole32(x) (x)
#define htole64(x) (x)
#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)
#else
#define htobe16(x) (x)
#define htobe32(x) (x)
#define htobe64(x) (x)
#define be16toh(x) (x)
#define be32toh(x) (x)
#define be64toh(x) (x)
#define htole16(x) __ml_bswap16(x)
#define htole32(x) __ml_bswap32(x)
#define htole64(x) __ml_bswap64(x)
#define le16toh(x) __ml_bswap16(x)
#define le32toh(x) __ml_bswap32(x)
#define le64toh(x) __ml_bswap64(x)
#endif

#define htons(x) htobe16(x)
#define htonl(x) htobe32(x)
#define ntohs(x) be16toh(x)
#define ntohl(x) be32toh(x)
