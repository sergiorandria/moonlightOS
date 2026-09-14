/* Moonlight libc - byteswap.h (glibc-compatible byte swaps). */
#pragma once

#include <stdint.h>
#include <endian.h>

#define bswap_16(x) __ml_bswap16(x)
#define bswap_32(x) __ml_bswap32(x)
#define bswap_64(x) __ml_bswap64(x)
