/* userspace/crypt/sha256.h - portable SHA-256 (FIPS 180-4).
 * Pure C99, stdint.h/stddef.h only: host-testable (tests/test_aead.c)
 * and freestanding-safe for the later vault/cryptblk ELFs. No malloc,
 * no host calls. Timing is input-independent (fixed 64 rounds/block). */
#ifndef MOONLIGHT_CRYPT_SHA256_H
#define MOONLIGHT_CRYPT_SHA256_H

#include <stddef.h>
#include <stdint.h>

static const uint32_t SHA256_K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL,
};

typedef struct {
    uint32_t h[8];
    uint8_t buf[64];
    unsigned long nbuf;  /* buffered bytes, always < 64 */
    unsigned long total; /* all bytes fed, for the length suffix */
} sha256_ctx;

static inline uint32_t sha256_rotr(uint32_t x, unsigned n)
{
    return (uint32_t)((x >> n) | (x << (32 - n)));
}

static inline uint32_t sha256_ld32be(const uint8_t *p)
{
    return (uint32_t)(((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                      ((uint32_t)p[2] << 8) | (uint32_t)p[3]);
}

static inline void sha256_st32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* One compression: straight-line, no secret branches. */
static inline void sha256_block(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, hh, t1, t2;
    unsigned t;
    for (t = 0; t < 16; t++) /* bound: 16 */
        w[t] = sha256_ld32be(p + 4 * t);
    for (t = 16; t < 64; t++) { /* bound: 48 */
        uint32_t s0 = sha256_rotr(w[t - 15], 7) ^ sha256_rotr(w[t - 15], 18) ^
                      (w[t - 15] >> 3);
        uint32_t s1 = sha256_rotr(w[t - 2], 17) ^ sha256_rotr(w[t - 2], 19) ^
                      (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (t = 0; t < 64; t++) { /* bound: 64 */
        uint32_t S1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = hh + S1 + ch + SHA256_K[t] + w[t];
        {
            uint32_t S0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            t2 = S0 + mj;
        }
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static inline void sha256_init(sha256_ctx *c)
{
    c->h[0] = 0x6a09e667UL; c->h[1] = 0xbb67ae85UL;
    c->h[2] = 0x3c6ef372UL; c->h[3] = 0xa54ff53aUL;
    c->h[4] = 0x510e527fUL; c->h[5] = 0x9b05688cUL;
    c->h[6] = 0x1f83d9abUL; c->h[7] = 0x5be0cd19UL;
    c->nbuf = 0;
    c->total = 0;
}

/* d may be NULL iff n == 0 (never dereferenced then). */
static inline void sha256_update(sha256_ctx *c, const uint8_t *d, unsigned long n)
{
    c->total += n;
    while (n > 0) { /* bound: caller len, drained in <=64B takes */
        unsigned long take = 64 - c->nbuf;
        unsigned long i;
        if (take > n)
            take = n;
        for (i = 0; i < take; i++) /* bound: 64 */
            c->buf[c->nbuf + i] = d[i];
        c->nbuf += take;
        d += take;
        n -= take;
        if (c->nbuf == 64) {
            sha256_block(c->h, c->buf);
            c->nbuf = 0;
        }
    }
}

static inline void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = (uint64_t)c->total << 3;
    unsigned long i;
    c->buf[c->nbuf] = 0x80;
    c->nbuf++;
    if (c->nbuf > 56) { /* no room for the length: pad out this block */
        for (i = c->nbuf; i < 64; i++) /* bound: 64 */
            c->buf[i] = 0;
        sha256_block(c->h, c->buf);
        c->nbuf = 0;
    }
    for (i = c->nbuf; i < 56; i++) /* bound: 56 */
        c->buf[i] = 0;
    for (i = 0; i < 8; i++) /* bound: 8 */
        c->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_block(c->h, c->buf);
    for (i = 0; i < 8; i++) /* bound: 8 */
        sha256_st32be(out + 4 * i, c->h[i]);
}

/* One-shot. msg may be NULL iff len == 0. */
static inline void sha256(const uint8_t *msg, unsigned long len, uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, msg, len);
    sha256_final(&c, out);
}

#endif /* MOONLIGHT_CRYPT_SHA256_H */
