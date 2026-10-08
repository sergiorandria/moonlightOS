/* userspace/crypt/aead.h - ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8).
 * Pure C99, stdint.h/stddef.h plus crypt_util.h only: host-testable
 * (tests/test_aead.c) and freestanding-safe for the later vault/cryptblk
 * ELFs. No malloc, no host calls. Constant-time discipline: quarter-round
 * straight-line, Poly1305 reduction branch-free, tag compare via
 * accumulated diff with a single return, no secret-dependent indices or
 * early-outs. Key-material stack residue (ks0, want) is wiped before
 * every return. */
#ifndef MOONLIGHT_CRYPT_AEAD_H
#define MOONLIGHT_CRYPT_AEAD_H

#include <stddef.h>
#include <stdint.h>

#include "crypt_util.h"

/* RFC 8439 P_MAX: the 32-bit block counter addresses 2^32-1 blocks. */
#define AEAD_MAX_MSG ((unsigned long)0xffffffffUL << 6)

static inline uint32_t crypt_ld32le(const uint8_t *p)
{
    return (uint32_t)(((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
                      ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static inline void crypt_st32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void crypt_st64le(uint8_t *p, uint64_t v)
{
    unsigned i;
    for (i = 0; i < 8; i++) /* bound: 8 */
        p[i] = (uint8_t)(v >> (8 * i));
}

/* Accumulated-diff compare: single return, no early-out. */
static inline unsigned crypt_ct_eq(const uint8_t *a, const uint8_t *b, unsigned long n)
{
    unsigned diff = 0;
    unsigned long i;
    for (i = 0; i < n; i++) /* bound: caller len */
        diff |= (unsigned)(a[i] ^ b[i]);
    return diff;
}

static inline uint32_t chacha_rotl(uint32_t x, unsigned n)
{
    return (uint32_t)((x << n) | (x >> (32 - n)));
}

#define CHACHA_QR(x, a, b, c, d) do { \
    x[a] += x[b]; x[d] ^= x[a]; x[d] = chacha_rotl(x[d], 16); \
    x[c] += x[d]; x[b] ^= x[c]; x[b] = chacha_rotl(x[b], 12); \
    x[a] += x[b]; x[d] ^= x[a]; x[d] = chacha_rotl(x[d], 8); \
    x[c] += x[d]; x[b] ^= x[c]; x[b] = chacha_rotl(x[b], 7); \
} while (0)

/* RFC 8439 section 2.3: 20 rounds, then add the input state. */
static inline void chacha20_block(const uint8_t key[32], uint32_t ctr,
                                  const uint8_t nonce[12], uint8_t out[64])
{
    uint32_t x[16] = {
        0x61707865UL, 0x3320646eUL, 0x79622d32UL, 0x6b206574UL,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    uint32_t w[16];
    unsigned i, r;
    for (i = 0; i < 8; i++) /* bound: 8 */
        x[4 + i] = crypt_ld32le(key + 4 * i);
    x[12] = ctr;
    for (i = 0; i < 3; i++) /* bound: 3 */
        x[13 + i] = crypt_ld32le(nonce + 4 * i);
    for (i = 0; i < 16; i++) /* bound: 16 */
        w[i] = x[i];
    for (r = 0; r < 10; r++) { /* bound: 10 double-rounds */
        CHACHA_QR(w, 0, 4, 8, 12);
        CHACHA_QR(w, 1, 5, 9, 13);
        CHACHA_QR(w, 2, 6, 10, 14);
        CHACHA_QR(w, 3, 7, 11, 15);
        CHACHA_QR(w, 0, 5, 10, 15);
        CHACHA_QR(w, 1, 6, 11, 12);
        CHACHA_QR(w, 2, 7, 8, 13);
        CHACHA_QR(w, 3, 4, 9, 14);
    }
    for (i = 0; i < 16; i++) /* bound: 16 */
        crypt_st32le(out + 4 * i, w[i] + x[i]);
}

/* Stream xor, counter running from ctr0. In-place safe (in == out). */
static inline void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                                uint32_t ctr0, const uint8_t *in,
                                unsigned long len, uint8_t *out)
{
    uint8_t ks[64];
    unsigned long i = 0;
    while (i < len) { /* bound: len/64 + 1 keystream blocks */
        unsigned long n = len - i;
        unsigned long j;
        if (n > 64)
            n = 64;
        chacha20_block(key, (uint32_t)(ctr0 + (uint32_t)(i / 64)), nonce, ks);
        for (j = 0; j < n; j++) /* bound: 64 */
            out[i + j] = (uint8_t)(in[i + j] ^ ks[j]);
        i += n;
    }
}

/* ---- Poly1305, radix 2^26, five limbs in uint64_t (products < 2^58,
 * carries keep limbs < 2^26; no 128-bit type needed). ---- */

static inline void poly_add(uint64_t h[5], const uint8_t *m, unsigned long mlen)
{
    /* mlen <= 16: padded block buf = m || zeros || 0x01 at [mlen]. */
    uint8_t buf[17];
    unsigned long i, j;
    for (i = 0; i < 17; i++) /* bound: 17 */
        buf[i] = (i < mlen) ? m[i] : ((i == mlen) ? 1 : 0);
    for (i = 0; i < 17; i++) { /* bound: 17 */
        unsigned long limb = (8 * i) / 26;
        unsigned bits = (unsigned)((8 * i) % 26);
        h[limb] += (uint64_t)buf[i] << bits;
    }
    for (j = 0; j < 4; j++) { /* bound: 4 */
        h[j + 1] += h[j] >> 26;
        h[j] &= 0x3ffffffUL;
    }
    h[0] += (h[4] >> 26) * 5;
    h[4] &= 0x3ffffffUL;
}

static inline void poly_mul(uint64_t h[5], const uint64_t r[5])
{
    uint64_t s1 = r[1] * 5, s2 = r[2] * 5, s3 = r[3] * 5, s4 = r[4] * 5;
    uint64_t h0 = h[0] * r[0] + h[1] * s4 + h[2] * s3 + h[3] * s2 + h[4] * s1;
    uint64_t h1 = h[0] * r[1] + h[1] * r[0] + h[2] * s4 + h[3] * s3 + h[4] * s2;
    uint64_t h2 = h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * s4 + h[4] * s3;
    uint64_t h3 = h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * s4;
    uint64_t h4 = h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0];
    uint64_t c;
    c = h0 >> 26; h1 += c; h0 &= 0x3ffffffUL;
    c = h1 >> 26; h2 += c; h1 &= 0x3ffffffUL;
    c = h2 >> 26; h3 += c; h2 &= 0x3ffffffUL;
    c = h3 >> 26; h4 += c; h3 &= 0x3ffffffUL;
    c = h4 >> 26; h0 += c * 5; h4 &= 0x3ffffffUL;
    c = h0 >> 26; h1 += c; h0 &= 0x3ffffffUL;
    h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3; h[4] = h4;
}

typedef struct {
    uint64_t h[5];
    uint64_t r[5];
    uint8_t buf[16];
    unsigned long nbuf; /* staged bytes, always < 16 */
} poly_ctx;

static inline void poly_rsetup(const uint8_t key[32], uint64_t r[5]);
static inline void poly1305_finish(const uint64_t h5[5], const uint8_t key[32],
                                   uint8_t out[16]);

static inline void poly_init(poly_ctx *c, const uint8_t key[32])
{
    c->h[0] = 0; c->h[1] = 0; c->h[2] = 0; c->h[3] = 0; c->h[4] = 0;
    poly_rsetup(key, c->r);
    c->nbuf = 0;
}

/* Stage bytes; full 16B blocks are absorbed with the 2^128 terminator.
 * m may be NULL iff len == 0 (never dereferenced then). */
static inline void poly_feed(poly_ctx *c, const uint8_t *m, unsigned long len)
{
    while (len > 0) { /* bound: caller len, drained in <=16B takes */
        unsigned long take = 16 - c->nbuf;
        unsigned long i;
        if (take > len)
            take = len;
        for (i = 0; i < take; i++) /* bound: 16 */
            c->buf[c->nbuf + i] = m[i];
        c->nbuf += take;
        m += take;
        len -= take;
        if (c->nbuf == 16) {
            poly_add(c->h, c->buf, 16);
            poly_mul(c->h, c->r);
            c->nbuf = 0;
        }
    }
}

/* AEAD phase pad: zero-fill to the block end and absorb; empty when the
 * phase is already a multiple of 16 (RFC 8439 pad16). */
static inline void poly_pad16(poly_ctx *c)
{
    unsigned long i;
    if (c->nbuf == 0)
        return;
    for (i = c->nbuf; i < 16; i++) /* bound: 16 */
        c->buf[i] = 0;
    poly_add(c->h, c->buf, 16);
    poly_mul(c->h, c->r);
    c->nbuf = 0;
}

/* Raw-message end: absorb the final partial block with its 2^(8*n)
 * terminator (no extra block for the empty message). */
static inline void poly_mac_end(poly_ctx *c, const uint8_t key[32], uint8_t out[16])
{
    if (c->nbuf > 0) {
        poly_add(c->h, c->buf, c->nbuf);
        poly_mul(c->h, c->r);
        c->nbuf = 0;
    }
    poly1305_finish(c->h, key, out);
}

/* Raw Poly1305 MAC over one message (RFC 8439 section 2.5).
 * msg may be NULL iff msglen == 0. */
static inline void poly1305_mac(const uint8_t *msg, unsigned long msglen,
                                const uint8_t key[32], uint8_t out[16])
{
    poly_ctx c;
    poly_init(&c, key);
    poly_feed(&c, msg, msglen);
    poly_mac_end(&c, key, out);
}

/* Poly1305 over (ad || pad16 || ct || pad16 || le64(adlen) || le64(ctlen)). */
static inline void poly1305_auth2(const uint8_t *ad, unsigned long adlen,
                                  const uint8_t *ct, unsigned long ctlen,
                                  const uint8_t key[32], uint8_t out[16])
{
    poly_ctx c;
    uint8_t lens[16];
    poly_init(&c, key);
    poly_feed(&c, ad, adlen);
    poly_pad16(&c);
    poly_feed(&c, ct, ctlen);
    poly_pad16(&c);
    crypt_st64le(lens, (uint64_t)adlen);
    crypt_st64le(lens + 8, (uint64_t)ctlen);
    poly_feed(&c, lens, sizeof(lens));
    poly1305_finish(c.h, key, out);
}

/* Clamp r per RFC 8439 section 2.5, then split into 26-bit limbs. */
static inline void poly_rsetup(const uint8_t key[32], uint64_t r[5])
{
    uint8_t rk[16];
    unsigned i;
    for (i = 0; i < 16; i++) /* bound: 16 */
        rk[i] = key[i];
    rk[3] &= 15; rk[7] &= 15; rk[11] &= 15; rk[15] &= 15;
    rk[4] &= 252; rk[8] &= 252; rk[12] &= 252;
    r[0] = (uint64_t)(crypt_ld32le(rk) & 0x3ffffffUL);
    r[1] = (uint64_t)((crypt_ld32le(rk + 3) >> 2) & 0x3ffffffUL);
    r[2] = (uint64_t)((crypt_ld32le(rk + 6) >> 4) & 0x3ffffffUL);
    r[3] = (uint64_t)((crypt_ld32le(rk + 9) >> 6) & 0x3ffffffUL);
    r[4] = (uint64_t)(crypt_ld32le(rk + 12) >> 8);
}

/* Freeze h (full carry + branch-free conditional subtract of p =
 * 2^130-5), add s = key[16..32], store little-endian. */
static inline void poly1305_finish(const uint64_t h5[5], const uint8_t key[32],
                                   uint8_t out[16])
{
    uint64_t h0 = h5[0], h1 = h5[1], h2 = h5[2], h3 = h5[3], h4 = h5[4];
    uint32_t g0, g1, g2, g3, g4, mask;
    uint64_t t, carry;
    t = h1 >> 26; h2 += t; h1 &= 0x3ffffffUL;
    t = h2 >> 26; h3 += t; h2 &= 0x3ffffffUL;
    t = h3 >> 26; h4 += t; h3 &= 0x3ffffffUL;
    t = h4 >> 26; h0 += t * 5; h4 &= 0x3ffffffUL;
    t = h0 >> 26; h1 += t; h0 &= 0x3ffffffUL;
    g0 = (uint32_t)h0 + 5; t = g0 >> 26; g0 &= 0x3ffffffUL;
    g1 = (uint32_t)h1 + (uint32_t)t; t = g1 >> 26; g1 &= 0x3ffffffUL;
    g2 = (uint32_t)h2 + (uint32_t)t; t = g2 >> 26; g2 &= 0x3ffffffUL;
    g3 = (uint32_t)h3 + (uint32_t)t; t = g3 >> 26; g3 &= 0x3ffffffUL;
    g4 = (uint32_t)h4 + (uint32_t)t - (1UL << 26);
    mask = (g4 >> 31) - 1; /* h<p (borrow) ==> 0, else all-ones */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    g0 |= (uint32_t)h0 & mask; g1 |= (uint32_t)h1 & mask;
    g2 |= (uint32_t)h2 & mask; g3 |= (uint32_t)h3 & mask;
    g4 |= (uint32_t)h4 & mask;
    /* Serialize h + s (key[16..32]) with a 64-bit carry chain. Each
     * word is masked to 32 bits first: the shifted-out high bits belong
     * to the next word and must not leak in through the carry. */
    t = (((uint64_t)g0 | ((uint64_t)g1 << 26)) & 0xffffffffUL) +
        crypt_ld32le(key + 16);
    crypt_st32le(out, (uint32_t)t); carry = t >> 32;
    t = (((uint64_t)(g1 >> 6) | ((uint64_t)g2 << 20)) & 0xffffffffUL) +
        crypt_ld32le(key + 20) + carry;
    crypt_st32le(out + 4, (uint32_t)t); carry = t >> 32;
    t = (((uint64_t)(g2 >> 12) | ((uint64_t)g3 << 14)) & 0xffffffffUL) +
        crypt_ld32le(key + 24) + carry;
    crypt_st32le(out + 8, (uint32_t)t); carry = t >> 32;
    t = (((uint64_t)(g3 >> 18) | ((uint64_t)g4 << 8)) & 0xffffffffUL) +
        crypt_ld32le(key + 28) + carry;
    crypt_st32le(out + 12, (uint32_t)t);
}

/* Seal: ct = ChaCha20(ctr=1, pt); tag = Poly1305(otk from ctr=0).
 * ad/pt may be NULL iff the matching length is 0. Returns 0 ok, -1 arg. */
static inline int aead_seal(const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *ad, unsigned long adlen,
                            const uint8_t *pt, unsigned long ptlen,
                            uint8_t *ct, uint8_t tag[16])
{
    uint8_t ks0[64];
    if (!key || !nonce || !ct || !tag)
        return -1;
    if ((adlen && !ad) || (ptlen && !pt))
        return -1;
    if (ptlen > AEAD_MAX_MSG)
        return -1;
    chacha20_block(key, 0, nonce, ks0);
    chacha20_xor(key, nonce, 1, pt, ptlen, ct);
    poly1305_auth2(ad, adlen, ct, ptlen, ks0, tag);
    crypt_wipe(ks0, sizeof(ks0));
    return 0;
}

/* Open: recompute tag over (ad, ct); decrypt only into pt; on mismatch
 * wipe pt and return -1. pt must be non-NULL (ct buffer may alias pt). */
static inline int aead_open(const uint8_t key[32], const uint8_t nonce[12],
                            const uint8_t *ad, unsigned long adlen,
                            const uint8_t *ct, unsigned long ctlen,
                            const uint8_t tag[16], uint8_t *pt)
{
    uint8_t ks0[64];
    uint8_t want[16];
    unsigned bad;
    if (!key || !nonce || !ct || !tag || !pt)
        return -1;
    if ((adlen && !ad))
        return -1;
    if (ctlen > AEAD_MAX_MSG)
        return -1;
    chacha20_block(key, 0, nonce, ks0);
    poly1305_auth2(ad, adlen, ct, ctlen, ks0, want);
    crypt_wipe(ks0, sizeof(ks0));
    chacha20_xor(key, nonce, 1, ct, ctlen, pt);
    bad = crypt_ct_eq(tag, want, 16);
    if (bad != 0) {
        crypt_wipe(pt, ctlen);
        crypt_wipe(want, sizeof(want)); /* recomputed tag is key material */
        return -1;
    }
    crypt_wipe(want, sizeof(want));
    return 0;
}

#endif /* MOONLIGHT_CRYPT_AEAD_H */
