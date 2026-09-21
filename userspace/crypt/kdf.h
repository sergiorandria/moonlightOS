/* userspace/crypt/kdf.h - HMAC-SHA256, PBKDF2-HMAC-SHA256, test DRBG.
 * Pure C99 over sha256.h + crypt_util.h: host-testable (tests/test_aead.c)
 * and freestanding-safe for the later vault/cryptblk ELFs. No malloc, no
 * host calls. PBKDF2 iteration count is caller-chosen (work factor).
 * Key-material stack residue (kx, inner, U, T) is wiped before every
 * return. The DRBG is a deterministic SHA-256 counter generator for
 * TEST_KEYS vectors and slot-wrap nonces (Task 2/4 seed it explicitly) —
 * NOT a production entropy source. DRBG state has exactly one owner per
 * program: see CRYPT_DRBG_DEFINE below. */
#ifndef MOONLIGHT_CRYPT_KDF_H
#define MOONLIGHT_CRYPT_KDF_H

#include <stddef.h>
#include <stdint.h>

#include "crypt_util.h"
#include "sha256.h"

/* Derived-key cap: Task 2/4 need 16..64B; 4K leaves ample headroom. */
#define KDF_PBKDF2_MAX_DK 4096

/* HMAC over m1 || m2; either part may be NULL iff its length is 0. */
static inline int hmac_sha256_2(const uint8_t *key, unsigned long keylen,
                                const uint8_t *m1, unsigned long m1len,
                                const uint8_t *m2, unsigned long m2len,
                                uint8_t out[32])
{
    uint8_t kx[64];
    uint8_t inner[32];
    sha256_ctx c;
    unsigned long i;
    int rc = 0;
    if (!key && keylen)
        rc = -1;
    else if ((!m1 && m1len) || (!m2 && m2len) || !out)
        rc = -1;
    else if (keylen > 64) {
        sha256(key, keylen, kx);
        for (i = 32; i < 64; i++) /* bound: 32 */
            kx[i] = 0;
    } else {
        for (i = 0; i < 64; i++) /* bound: 64 */
            kx[i] = (i < keylen) ? key[i] : 0;
    }
    if (rc != 0) {
        crypt_wipe(kx, sizeof(kx)); /* arg-guard path: nothing secret yet */
        crypt_wipe(inner, sizeof(inner));
        return rc;
    }
    for (i = 0; i < 64; i++) /* bound: 64 */
        kx[i] ^= 0x36;
    sha256_init(&c);
    sha256_update(&c, kx, 64);
    sha256_update(&c, m1, m1len);
    sha256_update(&c, m2, m2len);
    sha256_final(&c, inner);
    for (i = 0; i < 64; i++) /* bound: 64 */
        kx[i] ^= (uint8_t)(0x36 ^ 0x5c); /* ipad -> opad */
    sha256_init(&c);
    sha256_update(&c, kx, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
    crypt_wipe(kx, sizeof(kx)); /* key-derived pads must not linger */
    crypt_wipe(inner, sizeof(inner));
    return 0;
}

static inline int hmac_sha256(const uint8_t *key, unsigned long keylen,
                              const uint8_t *msg, unsigned long msglen,
                              uint8_t out[32])
{
    return hmac_sha256_2(key, keylen, msg, msglen, (const uint8_t *)0, 0, out);
}

/* PBKDF2-HMAC-SHA256 (RFC 2898 section 5.2, HMAC-SHA-256 as PRF).
 * Returns 0 ok, -1 on bad args (iter == 0, dklen == 0 or over the cap,
 * NULL buffers with nonzero lengths). */
static inline int pbkdf2_hmac_sha256(const uint8_t *pw, unsigned long pwlen,
                                     const uint8_t *salt, unsigned long saltlen,
                                     unsigned long iter,
                                     uint8_t *dk, unsigned long dklen)
{
    unsigned long nblocks, blk, it, i, off;
    uint8_t U[32], T[32]; /* function scope so every return path can wipe */
    if (!dk || dklen == 0 || dklen > KDF_PBKDF2_MAX_DK)
        return -1;
    if (iter == 0)
        return -1;
    if ((pwlen && !pw) || (saltlen && !salt))
        return -1;
    nblocks = (dklen + 31) / 32;
    off = 0;
    for (blk = 1; blk <= nblocks; blk++) { /* bound: dklen/32 + 1 */
        uint8_t be[4];
        unsigned long want;
        be[0] = (uint8_t)(blk >> 24); be[1] = (uint8_t)(blk >> 16);
        be[2] = (uint8_t)(blk >> 8); be[3] = (uint8_t)blk;
        if (hmac_sha256_2(pw, pwlen, salt, saltlen, be, 4, U) != 0) {
            crypt_wipe(U, sizeof(U));
            crypt_wipe(T, sizeof(T));
            return -1;
        }
        for (i = 0; i < 32; i++) /* bound: 32 */
            T[i] = U[i];
        for (it = 1; it < iter; it++) { /* bound: iter (KDF work factor) */
            if (hmac_sha256_2(pw, pwlen, U, 32,
                              (const uint8_t *)0, 0, U) != 0) {
                crypt_wipe(U, sizeof(U));
                crypt_wipe(T, sizeof(T));
                return -1;
            }
            for (i = 0; i < 32; i++) /* bound: 32 */
                T[i] ^= U[i];
        }
        want = dklen - off;
        if (want > 32)
            want = 32;
        for (i = 0; i < want; i++) /* bound: 32 */
            dk[off + i] = T[i];
        off += want;
    }
    crypt_wipe(U, sizeof(U)); /* chaining state must not linger */
    crypt_wipe(T, sizeof(T));
    return 0;
}

/* ---- Deterministic SHA-256 counter DRBG (test/dev use). ----
 *
 * Single-ownership rule: DRBG state exists exactly once per program.
 * Exactly one TU in each program (each ELF, and the host test) must
 * define CRYPT_DRBG_DEFINE before including this header; that TU owns
 * and zero-initializes the state, all other TUs see it as extern.
 * Defining it in zero TUs fails to link (undefined reference);
 * defining it in two or more TUs fails to link (multiple definition).
 * Either failure is loud and safe — never a silent forked stream. */

#ifdef CRYPT_DRBG_DEFINE
uint8_t drbg_s[32] = { 0 };
uint64_t drbg_c;
#else
extern uint8_t drbg_s[32];
extern uint64_t drbg_c;
#endif

static inline void drbg_seed(const uint8_t *seed, unsigned long seedlen)
{
    if (seedlen && !seed)
        return; /* fail-soft: keep previous state */
    sha256(seed, seedlen, drbg_s);
    drbg_c = 0;
}

static inline void drbg_st64le(uint8_t *p, uint64_t v)
{
    unsigned i;
    for (i = 0; i < 8; i++) /* bound: 8 */
        p[i] = (uint8_t)(v >> (8 * i));
}

/* out must be non-NULL. Reseeding with the same seed replays the stream. */
static inline void drbg_next(uint8_t *out, unsigned long len)
{
    uint8_t blk[40];
    unsigned long i;
    if (!out)
        return;
    for (i = 0; i < 32; i++) /* bound: 32 */
        blk[i] = drbg_s[i];
    while (len > 0) { /* bound: caller len / 32 + 1 */
        uint8_t tmp[32];
        unsigned long n = (len > 32) ? 32 : len;
        drbg_st64le(blk + 32, drbg_c);
        sha256(blk, sizeof(blk), tmp);
        for (i = 0; i < n; i++) /* bound: 32 */
            out[i] = tmp[i];
        out += n;
        len -= n;
        drbg_c++;
    }
}

#endif /* MOONLIGHT_CRYPT_KDF_H */
