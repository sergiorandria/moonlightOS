/* Moonlight libc - stdbit.h (C23 bit utilities, real builtins). */
#pragma once

#include <stdint.h>
#include <limits.h>

/* Bit width of each unsigned type. */
#define BIT_WIDTH_UINT8 8
#define BIT_WIDTH_UINT16 16
#define BIT_WIDTH_UINT32 32
#define BIT_WIDTH_UINT64 64

static inline unsigned stdc_leading_zeros_uc(unsigned char x) {
    return x ? (unsigned)__builtin_clz((unsigned)x) - (sizeof(unsigned) * CHAR_BIT - 8) : 8;
}

static inline unsigned stdc_leading_zeros_us(unsigned short x) {
    return x ? (unsigned)__builtin_clz((unsigned)x) - (sizeof(unsigned) * CHAR_BIT - 16) : 16;
}

static inline unsigned stdc_leading_zeros_ui(unsigned x) {
    return x ? (unsigned)__builtin_clz(x) : sizeof(unsigned) * CHAR_BIT;
}

static inline unsigned stdc_leading_zeros_ul(unsigned long x) {
    return x ? (unsigned)__builtin_clzl(x) : sizeof(unsigned long) * CHAR_BIT;
}

static inline unsigned stdc_leading_zeros_ull(unsigned long long x) {
    return x ? (unsigned)__builtin_clzll(x) : sizeof(unsigned long long) * CHAR_BIT;
}

static inline unsigned stdc_trailing_zeros_uc(unsigned char x) {
    return x ? (unsigned)__builtin_ctz((unsigned)x) : 8;
}

static inline unsigned stdc_trailing_zeros_us(unsigned short x) {
    return x ? (unsigned)__builtin_ctz((unsigned)x) : 16;
}

static inline unsigned stdc_trailing_zeros_ui(unsigned x) {
    return x ? (unsigned)__builtin_ctz(x) : sizeof(unsigned) * CHAR_BIT;
}

static inline unsigned stdc_trailing_zeros_ul(unsigned long x) {
    return x ? (unsigned)__builtin_ctzl(x) : sizeof(unsigned long) * CHAR_BIT;
}

static inline unsigned stdc_trailing_zeros_ull(unsigned long long x) {
    return x ? (unsigned)__builtin_ctzll(x) : sizeof(unsigned long long) * CHAR_BIT;
}

static inline unsigned stdc_leading_ones_uc(unsigned char x) {
    return stdc_leading_zeros_uc((unsigned char)~x);
}

static inline unsigned stdc_leading_ones_us(unsigned short x) {
    return stdc_leading_zeros_us((unsigned short)~x);
}

static inline unsigned stdc_leading_ones_ui(unsigned x) {
    return stdc_leading_zeros_ui(~x);
}

static inline unsigned stdc_leading_ones_ul(unsigned long x) {
    return stdc_leading_zeros_ul(~x);
}

static inline unsigned stdc_leading_ones_ull(unsigned long long x) {
    return stdc_leading_zeros_ull(~x);
}

static inline unsigned stdc_trailing_ones_uc(unsigned char x) {
    return stdc_trailing_zeros_uc((unsigned char)~x);
}

static inline unsigned stdc_trailing_ones_us(unsigned short x) {
    return stdc_trailing_zeros_us((unsigned short)~x);
}

static inline unsigned stdc_trailing_ones_ui(unsigned x) {
    return stdc_trailing_zeros_ui(~x);
}

static inline unsigned stdc_trailing_ones_ul(unsigned long x) {
    return stdc_trailing_zeros_ul(~x);
}

static inline unsigned stdc_trailing_ones_ull(unsigned long long x) {
    return stdc_trailing_zeros_ull(~x);
}

static inline unsigned stdc_count_zeros_uc(unsigned char x) {
    return 8 - (unsigned)__builtin_popcount((unsigned)x);
}

static inline unsigned stdc_count_zeros_us(unsigned short x) {
    return 16 - (unsigned)__builtin_popcount((unsigned)x);
}

static inline unsigned stdc_count_zeros_ui(unsigned x) {
    return (unsigned)(sizeof(unsigned) * CHAR_BIT - __builtin_popcount(x));
}

static inline unsigned stdc_count_zeros_ul(unsigned long x) {
    return (unsigned)(sizeof(unsigned long) * CHAR_BIT - __builtin_popcountl(x));
}

static inline unsigned stdc_count_zeros_ull(unsigned long long x) {
    return (unsigned)(sizeof(unsigned long long) * CHAR_BIT - __builtin_popcountll(x));
}

static inline unsigned stdc_count_ones_uc(unsigned char x) {
    return (unsigned)__builtin_popcount((unsigned)x);
}

static inline unsigned stdc_count_ones_us(unsigned short x) {
    return (unsigned)__builtin_popcount((unsigned)x);
}

static inline unsigned stdc_count_ones_ui(unsigned x) {
    return (unsigned)__builtin_popcount(x);
}

static inline unsigned stdc_count_ones_ul(unsigned long x) {
    return (unsigned)__builtin_popcountl(x);
}

static inline unsigned stdc_count_ones_ull(unsigned long long x) {
    return (unsigned)__builtin_popcountll(x);
}

static inline unsigned stdc_has_single_bit_uc(unsigned char x) {
    return x && !(x & (unsigned char)(x - 1));
}

static inline unsigned stdc_has_single_bit_us(unsigned short x) {
    return x && !(x & (unsigned short)(x - 1));
}

static inline unsigned stdc_has_single_bit_ui(unsigned x) {
    return x && !(x & (x - 1));
}

static inline unsigned stdc_has_single_bit_ul(unsigned long x) {
    return x && !(x & (x - 1));
}

static inline unsigned stdc_has_single_bit_ull(unsigned long long x) {
    return x && !(x & (x - 1));
}

static inline unsigned char stdc_bit_floor_uc(unsigned char x) {
    if (!x) return 0;
    x |= (unsigned char)(x >> 1);
    x |= (unsigned char)(x >> 2);
    x |= (unsigned char)(x >> 4);
    return (unsigned char)(x - (x >> 1));
}

static inline unsigned long long stdc_bit_floor_ull(unsigned long long x) {
    if (!x) return 0;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    return x - (x >> 1);
}

static inline unsigned stdc_bit_width_uc(unsigned char x) {
    return x ? 8 - stdc_leading_zeros_uc(x) : 0;
}

static inline unsigned stdc_bit_width_ui(unsigned x) {
    return x ? (unsigned)sizeof(unsigned) * CHAR_BIT - stdc_leading_zeros_ui(x) : 0;
}

static inline unsigned stdc_bit_width_ul(unsigned long x) {
    return x ? (unsigned)sizeof(unsigned long) * CHAR_BIT - stdc_leading_zeros_ul(x) : 0;
}

static inline unsigned stdc_bit_width_ull(unsigned long long x) {
    return x ? (unsigned)sizeof(unsigned long long) * CHAR_BIT - stdc_leading_zeros_ull(x) : 0;
}

/* Generic selection over the operand type. */
#define stdc_leading_zeros(x) \
    (sizeof(x) == 1 ? stdc_leading_zeros_uc(x) \
     : sizeof(x) == 2 ? stdc_leading_zeros_us(x) \
     : sizeof(x) <= sizeof(unsigned) ? stdc_leading_zeros_ui(x) \
     : sizeof(x) <= sizeof(unsigned long) ? stdc_leading_zeros_ul(x) \
     : stdc_leading_zeros_ull(x))
#define stdc_trailing_zeros(x) \
    (sizeof(x) == 1 ? stdc_trailing_zeros_uc(x) \
     : sizeof(x) == 2 ? stdc_trailing_zeros_us(x) \
     : sizeof(x) <= sizeof(unsigned) ? stdc_trailing_zeros_ui(x) \
     : sizeof(x) <= sizeof(unsigned long) ? stdc_trailing_zeros_ul(x) \
     : stdc_trailing_zeros_ull(x))
#define stdc_count_ones(x) \
    (sizeof(x) == 1 ? stdc_count_ones_uc(x) \
     : sizeof(x) == 2 ? stdc_count_ones_us(x) \
     : sizeof(x) <= sizeof(unsigned) ? stdc_count_ones_ui(x) \
     : sizeof(x) <= sizeof(unsigned long) ? stdc_count_ones_ul(x) \
     : stdc_count_ones_ull(x))
#define stdc_has_single_bit(x) \
    (sizeof(x) == 1 ? stdc_has_single_bit_uc(x) \
     : sizeof(x) == 2 ? stdc_has_single_bit_us(x) \
     : sizeof(x) <= sizeof(unsigned) ? stdc_has_single_bit_ui(x) \
     : sizeof(x) <= sizeof(unsigned long) ? stdc_has_single_bit_ul(x) \
     : stdc_has_single_bit_ull(x))
#define stdc_bit_width(x) \
    (sizeof(x) == 1 ? stdc_bit_width_uc(x) \
     : sizeof(x) <= sizeof(unsigned) ? stdc_bit_width_ui(x) \
     : sizeof(x) <= sizeof(unsigned long) ? stdc_bit_width_ul(x) \
     : stdc_bit_width_ull(x))
