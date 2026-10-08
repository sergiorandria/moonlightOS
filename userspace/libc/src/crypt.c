/* libc crypt: SHA-256/SHA-512 password hashing ($5$/$6$,
 * Ulrich Drepper⣿SHA-crypt) plus traditional DES setkey/encrypt.
 * Self-contained (local SHA-256/512 cores); every declared entry
 * point is fully implemented. */
#include <crypt.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>

/* ================= SHA-256 ================= */

typedef struct {
    uint32_t h[8];
    uint64_t total;
    unsigned char buf[64];
    size_t buflen;
} ml_sha256_t;

static const uint32_t ml_sha256_k[64] = {
    0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u, 0x3956C25Bu,
    0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u, 0xD807AA98u, 0x12835B01u,
    0x243185BEu, 0x550C7DC3u, 0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u,
    0xC19BF174u, 0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu,
    0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu, 0x983E5152u,
    0xA831C66Du, 0xB00327C8u, 0xBF597FC7u, 0xC6E00BF3u, 0xD5A79147u,
    0x06CA6351u, 0x14292967u, 0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu,
    0x53380D13u, 0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
    0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u, 0xD192E819u,
    0xD6990624u, 0xF40E3585u, 0x106AA070u, 0x19A4C116u, 0x1E376C08u,
    0x2748774Cu, 0x34B0BCB5u, 0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu,
    0x682E6FF3u, 0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u,
    0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u,
};

static void ml_sha256_block(ml_sha256_t *c, const unsigned char *p) {
    uint32_t w[64], a, b, cc, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 =
            (w[i - 15] >> 7 | w[i - 15] << 25) ^
            (w[i - 15] >> 18 | w[i - 15] << 14) ^ (w[i - 15] >> 3);
        uint32_t s1 =
            (w[i - 2] >> 17 | w[i - 2] << 15) ^
            (w[i - 2] >> 19 | w[i - 2] << 13) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0];
    b = c->h[1];
    cc = c->h[2];
    d = c->h[3];
    e = c->h[4];
    f = c->h[5];
    g = c->h[6];
    h = c->h[7];
    {
        for (i = 0; i < 64; i++) {
            uint32_t S1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^
                          (e >> 25 | e << 7);
            uint32_t ch = (e & f) ^ (~e & g);
            t1 = h + S1 + ch + ml_sha256_k[i] + w[i];
            {
                uint32_t S0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^
                              (a >> 22 | a << 10);
                uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
                t2 = S0 + maj;
            }
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = cc;
            cc = b;
            b = a;
            a = t1 + t2;
        }
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += h;
}

static void ml_sha256_init(ml_sha256_t *c) {
    c->h[0] = 0x6A09E667u;
    c->h[1] = 0xBB67AE85u;
    c->h[2] = 0x3C6EF372u;
    c->h[3] = 0xA54FF53Au;
    c->h[4] = 0x510E527Fu;
    c->h[5] = 0x9B05688Cu;
    c->h[6] = 0x1F83D9ABu;
    c->h[7] = 0x5BE0CD19u;
    c->total = 0;
    c->buflen = 0;
}

static void ml_sha256_input(ml_sha256_t *c, const void *data, size_t n) {
    const unsigned char *p = data;
    c->total += n;
    while (n) {
        size_t take = 64 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 64) {
            ml_sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void ml_sha256_final(ml_sha256_t *c, unsigned char out[32]) {
    uint64_t bits = c->total * 8;
    unsigned char pad = 0x80, zero = 0;
    int i;
    ml_sha256_input(c, &pad, 1);
    while (c->buflen != 56) ml_sha256_input(c, &zero, 1);
    for (i = 7; i >= 0; i--) {
        unsigned char b = (unsigned char)(bits >> (i * 8));
        ml_sha256_input(c, &b, 1);
    }
    for (i = 0; i < 8; i++) {
        out[i * 4] = (unsigned char)(c->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)c->h[i];
    }
}

/* ================= SHA-512 ================= */

typedef struct {
    uint64_t h[8];
    uint64_t total_lo, total_hi;
    unsigned char buf[128];
    size_t buflen;
} ml_sha512_t;

static const uint64_t ml_sha512_k[80] = {
    0x428A2F98D728AE22ull, 0x7137449123EF65CDull, 0xB5C0FBCFEC4D3B2Full,
    0xE9B5DBA58189DBBCull, 0x3956C25BF348B538ull, 0x59F111F1B605D019ull,
    0x923F82A4AF194F9Bull, 0xAB1C5ED5DA6D8118ull, 0xD807AA98A3030242ull,
    0x12835B0145706FBEull, 0x243185BE4EE4B28Cull, 0x550C7DC3D5FFB4E2ull,
    0x72BE5D74F27B896Full, 0x80DEB1FE3B1696B1ull, 0x9BDC06A725C71235ull,
    0xC19BF174CF692694ull, 0xE49B69C19EF14AD2ull, 0xEFBE4786384F25E3ull,
    0x0FC19DC68B8CD5B5ull, 0x240CA1CC77AC9C65ull, 0x2DE92C6F592B0275ull,
    0x4A7484AA6EA6E483ull, 0x5CB0A9DCBD41FBD4ull, 0x76F988DA831153B5ull,
    0x983E5152EE66DFABull, 0xA831C66D2DB43210ull, 0xB00327C898FB213Full,
    0xBF597FC7BEEF0EE4ull,     0xC6E00BF33DA88FC2ull, 0xD5A79147930AA725ull,
    0x06CA6351E003826Full, 0x142929670A0E6E70ull, 0x27B70A8546D22FFCull,
    0x2E1B21385C26C926ull, 0x4D2C6DFC5AC42AEDull, 0x53380D139D95B3DFull,
    0x650A73548BAF63DEull, 0x766A0ABB3C77B2A8ull, 0x81C2C92E47EDAEE6ull,
    0x92722C851482353Bull, 0xA2BFE8A14CF10364ull, 0xA81A664BBC423001ull,
    0xC24B8B70D0F89791ull, 0xC76C51A30654BE30ull, 0xD192E819D6EF5218ull,
    0xD69906245565A910ull, 0xF40E35855771202Aull, 0x106AA07032BBD1B8ull,
    0x19A4C116B8D2D0C8ull, 0x1E376C085141AB53ull, 0x2748774CDF8EEB99ull,
    0x34B0BCB5E19B48A8ull, 0x391C0CB3C5C95A63ull, 0x4ED8AA4AE3418ACBull,
    0x5B9CCA4F7763E373ull, 0x682E6FF3D6B2B8A3ull, 0x748F82EE5DEFB2FCull,
    0x78A5636F43172F60ull, 0x84C87814A1F0AB72ull, 0x8CC702081A6439ECull,
    0x90BEFFFA23631E28ull, 0xA4506CEBDE82BDE9ull, 0xBEF9A3F7B2C67915ull,
    0xC67178F2E372532Bull, 0xCA273ECEEA26619Cull, 0xD186B8C721C0C207ull,
    0xEADA7DD6CDE0EB1Eull, 0xF57D4F7FEE6ED178ull, 0x06F067AA72176FBAull,
    0x0A637DC5A2C898A6ull, 0x113F9804BEF90DAEull, 0x1B710B35131C471Bull,
    0x28DB77F523047D84ull, 0x32CAAB7B40C72493ull, 0x3C9EBE0A15C9BEBCull,
    0x431D67C49C100D4Cull, 0x4CC5D4BECB3E42B6ull, 0x597F299CFC657E2Aull,
    0x5FCB6FAB3AD6FAECull, 0x6C44198C4A475817ull,
};

static void ml_sha512_block(ml_sha512_t *c, const unsigned char *p) {
    uint64_t w[80], a, b, cc, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint64_t)p[i * 8] << 56) | ((uint64_t)p[i * 8 + 1] << 48) |
               ((uint64_t)p[i * 8 + 2] << 40) | ((uint64_t)p[i * 8 + 3] << 32) |
               ((uint64_t)p[i * 8 + 4] << 24) | ((uint64_t)p[i * 8 + 5] << 16) |
               ((uint64_t)p[i * 8 + 6] << 8) | (uint64_t)p[i * 8 + 7];
    for (i = 16; i < 80; i++) {
        uint64_t s0 = (w[i - 15] >> 1 | w[i - 15] << 63) ^
                      (w[i - 15] >> 8 | w[i - 15] << 56) ^ (w[i - 15] >> 7);
        uint64_t s1 = (w[i - 2] >> 19 | w[i - 2] << 45) ^
                      (w[i - 2] >> 61 | w[i - 2] << 3) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0];
    b = c->h[1];
    cc = c->h[2];
    d = c->h[3];
    e = c->h[4];
    f = c->h[5];
    g = c->h[6];
    h = c->h[7];
    for (i = 0; i < 80; i++) {
        uint64_t S1 = (e >> 14 | e << 50) ^ (e >> 18 | e << 46) ^
                      (e >> 41 | e << 23);
        uint64_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + ml_sha512_k[i] + w[i];
        {
            uint64_t S0 = (a >> 28 | a << 36) ^ (a >> 34 | a << 30) ^
                          (a >> 39 | a << 25);
            uint64_t maj = (a & b) ^ (a & cc) ^ (b & cc);
            t2 = S0 + maj;
        }
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += h;
}

static void ml_sha512_init(ml_sha512_t *c) {
    c->h[0] = 0x6A09E667F3BCC908ull;
    c->h[1] = 0xBB67AE8584CAA73Bull;
    c->h[2] = 0x3C6EF372FE94F82Bull;
    c->h[3] = 0xA54FF53A5F1D36F1ull;
    c->h[4] = 0x510E527FADE682D1ull;
    c->h[5] = 0x9B05688C2B3E6C1Full;
    c->h[6] = 0x1F83D9ABFB41BD6Bull;
    c->h[7] = 0x5BE0CD19137E2179ull;
    c->total_lo = 0;
    c->total_hi = 0;
    c->buflen = 0;
}

static void ml_sha512_input(ml_sha512_t *c, const void *data, size_t n) {
    const unsigned char *p = data;
    uint64_t nl = c->total_lo + (uint64_t)n;
    if (nl < c->total_lo) c->total_hi++;
    c->total_lo = nl;
    while (n) {
        size_t take = 128 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 128) {
            ml_sha512_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void ml_sha512_final(ml_sha512_t *c, unsigned char out[64]) {
    /* Length in bits, 128-bit big-endian (high word first). */
    uint64_t hi = (c->total_hi << 3) | (c->total_lo >> 61);
    uint64_t lo = c->total_lo << 3;
    unsigned char pad = 0x80, zero = 0;
    int i;
    ml_sha512_input(c, &pad, 1);
    while (c->buflen != 112) ml_sha512_input(c, &zero, 1);
    for (i = 7; i >= 0; i--) {
        unsigned char b = (unsigned char)(hi >> (i * 8));
        ml_sha512_input(c, &b, 1);
    }
    for (i = 7; i >= 0; i--) {
        unsigned char b = (unsigned char)(lo >> (i * 8));
        ml_sha512_input(c, &b, 1);
    }
    for (i = 0; i < 8; i++) {
        int k;
        for (k = 0; k < 8; k++)
            out[i * 8 + k] = (unsigned char)(c->h[i] >> ((7 - k) * 8));
    }
}

/* ================= SHA-crypt ($5$/$6$) ================= */

static const char ml_itoa64[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void ml_b64_3(const unsigned char *src, int b2, int b1, int b0,
                     int n, char *dst) {
    unsigned w = ((unsigned)src[b2] << 16) | ((unsigned)src[b1] << 8) |
                 (unsigned)src[b0];
    int i;
    for (i = 0; i < n; i++) {
        dst[i] = ml_itoa64[w & 0x3F];
        w >>= 6;
    }
}

/* Final triple: the top byte is an explicit zero (Drepper passes a
 * literal 0, not alt[0]: 3 chars consume 18 bits, so alt[0] would
 * leak into the last character). */
static void ml_b64_3z(int b1, int b0, const unsigned char *src, char *dst) {
    unsigned w = ((unsigned)src[b1] << 8) | (unsigned)src[b0];
    int i;
    for (i = 0; i < 3; i++) {
        dst[i] = ml_itoa64[w & 0x3F];
        w >>= 6;
    }
}

/* Parse "$5$rounds=N$salt$" / "$5$salt$" / "$6$...". Returns 0 on
 * success, filling sha512 flag, rounds, salt and salt length. */
static int ml_parse_setting(const char *setting, int *is512,
                            unsigned long *rounds, char *salt,
                            size_t *saltlen) {
    const char *p;
    size_t n;
    if (!setting || setting[0] != '$') return -1;
    if (setting[1] == '5') *is512 = 0;
    else if (setting[1] == '6') *is512 = 1;
    else return -1;
    if (setting[2] != '$') return -1;
    p = setting + 3;
    *rounds = 5000;
    if (strncmp(p, "rounds=", 7) == 0) {
        char *end = 0;
        unsigned long r;
        p += 7;
        r = strtoul(p, &end, 10);
        if (!end || end == p || *end != '$') return -1;
        if (r < 1000) r = 1000;
        if (r > 999999999ul) r = 999999999ul;
        *rounds = r;
        p = end + 1;
    }
    /* Salt: up to 16 chars of [./0-9A-Za-z], ends at '$' or NUL. */
    n = 0;
    while (*p && *p != '$' && n < 16) {
        char c = *p;
        int ok = (c == '.' || c == '/') || (c >= '0' && c <= '9') ||
                 (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        if (!ok) return -1;
        salt[n++] = c;
        p++;
    }
    if (*p && *p != '$') {
        /* Overlong salt: must still be valid chars; skip to end. */
        while (*p && *p != '$') {
            char c = *p;
            int ok = (c == '.' || c == '/') || (c >= '0' && c <= '9') ||
                     (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
            if (!ok) return -1;
            p++;
        }
    }
    salt[n] = '\0';
    *saltlen = n;
    return 0;
}

static char *ml_sha_crypt(const char *key, const char *setting, char *out,
                          size_t outcap) {
    int is512 = 0;
    unsigned long rounds = 5000;
    char salt[17];
    size_t saltlen = 0, keylen;
    unsigned char alt[64], tmp[64], pbuf[256], sbuf[64];
    unsigned ds = 32; /* digest size */
    char *o;
    size_t need;
    unsigned long i;
    /* Select engine sizes. */
    if (ml_parse_setting(setting, &is512, &rounds, salt, &saltlen) != 0) {
        errno = EINVAL;
        return 0;
    }
    if (is512) ds = 64;
    keylen = strlen(key);
    if (keylen > 256) keylen = 256; /* bound working buffers */
    /* A: key + salt. */
    if (!is512) {
        ml_sha256_t ctx, altc;
        size_t cnt;
        ml_sha256_init(&ctx);
        ml_sha256_input(&ctx, key, keylen);
        ml_sha256_input(&ctx, salt, saltlen);
        /* B: key + salt + key. */
        ml_sha256_init(&altc);
        ml_sha256_input(&altc, key, keylen);
        ml_sha256_input(&altc, salt, saltlen);
        ml_sha256_input(&altc, key, keylen);
        ml_sha256_final(&altc, alt);
        for (cnt = keylen; cnt > 0; cnt--)
            ml_sha256_input(&ctx, alt + (keylen - cnt) % 32, 1);
        for (cnt = keylen; cnt > 0; cnt >>= 1) {
            if (cnt & 1) ml_sha256_input(&ctx, alt, 32);
            else ml_sha256_input(&ctx, key, keylen);
        }
        ml_sha256_final(&ctx, tmp);
        memcpy(alt, tmp, 32);
        /* P sequence. */
        ml_sha256_init(&ctx);
        for (cnt = keylen; cnt > 0; cnt--)
            ml_sha256_input(&ctx, key, keylen);
        ml_sha256_final(&ctx, tmp);
        for (cnt = 0; cnt < keylen; cnt++)
            pbuf[cnt] = tmp[cnt % 32];
        /* S sequence: salt repeated (16 + A[0]) times (Drepper). */
        ml_sha256_init(&ctx);
        for (cnt = 0; cnt < 16 + (size_t)alt[0]; cnt++)
            ml_sha256_input(&ctx, salt, saltlen);
        ml_sha256_final(&ctx, tmp);
        for (cnt = 0; cnt < saltlen; cnt++)
            sbuf[cnt] = tmp[cnt % 32];
        /* Rounds. */
        for (i = 0; i < rounds; i++) {
            ml_sha256_init(&ctx);
            if (i & 1) ml_sha256_input(&ctx, pbuf, keylen);
            else ml_sha256_input(&ctx, alt, 32);
            if (i % 3) ml_sha256_input(&ctx, sbuf, saltlen);
            if (i % 7) ml_sha256_input(&ctx, pbuf, keylen);
            if (i & 1) ml_sha256_input(&ctx, alt, 32);
            else ml_sha256_input(&ctx, pbuf, keylen);
            ml_sha256_final(&ctx, alt);
        }
    } else {
        ml_sha512_t ctx, altc;
        size_t cnt;
        ml_sha512_init(&ctx);
        ml_sha512_input(&ctx, key, keylen);
        ml_sha512_input(&ctx, salt, saltlen);
        ml_sha512_init(&altc);
        ml_sha512_input(&altc, key, keylen);
        ml_sha512_input(&altc, salt, saltlen);
        ml_sha512_input(&altc, key, keylen);
        ml_sha512_final(&altc, alt);
        for (cnt = keylen; cnt > 0; cnt--)
            ml_sha512_input(&ctx, alt + (keylen - cnt) % 64, 1);
        for (cnt = keylen; cnt > 0; cnt >>= 1) {
            if (cnt & 1) ml_sha512_input(&ctx, alt, 64);
            else ml_sha512_input(&ctx, key, keylen);
        }
        ml_sha512_final(&ctx, tmp);
        memcpy(alt, tmp, 64);
        ml_sha512_init(&ctx);
        for (cnt = keylen; cnt > 0; cnt--)
            ml_sha512_input(&ctx, key, keylen);
        ml_sha512_final(&ctx, tmp);
        for (cnt = 0; cnt < keylen; cnt++)
            pbuf[cnt] = tmp[cnt % 64];
        ml_sha512_init(&ctx);
        for (cnt = 0; cnt < 16 + (size_t)alt[0]; cnt++)
            ml_sha512_input(&ctx, salt, saltlen);
        ml_sha512_final(&ctx, tmp);
        for (cnt = 0; cnt < saltlen; cnt++)
            sbuf[cnt] = tmp[cnt % 64];
        for (i = 0; i < rounds; i++) {
            ml_sha512_init(&ctx);
            if (i & 1) ml_sha512_input(&ctx, pbuf, keylen);
            else ml_sha512_input(&ctx, alt, 64);
            if (i % 3) ml_sha512_input(&ctx, sbuf, saltlen);
            if (i % 7) ml_sha512_input(&ctx, pbuf, keylen);
            if (i & 1) ml_sha512_input(&ctx, alt, 64);
            else ml_sha512_input(&ctx, pbuf, keylen);
            ml_sha512_final(&ctx, alt);
        }
    }
    /* Render "$5$salt$hash" (rounds= prefix when non-default). */
    o = out;
    need = 3 + saltlen + 1 + (is512 ? 86 : 43) + 1;
    if (rounds != 5000) need += 16;
    if (need > outcap) {
        errno = ERANGE;
        return 0;
    }
    *o++ = '$';
    *o++ = is512 ? '6' : '5';
    *o++ = '$';
    if (rounds != 5000) {
        o += snprintf(o, outcap - (size_t)(o - out), "rounds=%lu$",
                      rounds);
    }
    memcpy(o, salt, saltlen);
    o += saltlen;
    *o++ = '$';
    if (!is512) {
        ml_b64_3(alt, 0, 10, 20, 4, o); o += 4;
        ml_b64_3(alt, 21, 1, 11, 4, o); o += 4;
        ml_b64_3(alt, 12, 22, 2, 4, o); o += 4;
        ml_b64_3(alt, 3, 13, 23, 4, o); o += 4;
        ml_b64_3(alt, 24, 4, 14, 4, o); o += 4;
        ml_b64_3(alt, 15, 25, 5, 4, o); o += 4;
        ml_b64_3(alt, 6, 16, 26, 4, o); o += 4;
        ml_b64_3(alt, 27, 7, 17, 4, o); o += 4;
        ml_b64_3(alt, 18, 28, 8, 4, o); o += 4;
        ml_b64_3(alt, 9, 19, 29, 4, o); o += 4;
        ml_b64_3z(31, 30, alt, o); o += 3;
    } else {
        ml_b64_3(alt, 0, 21, 42, 4, o); o += 4;
        ml_b64_3(alt, 22, 43, 1, 4, o); o += 4;
        ml_b64_3(alt, 44, 2, 23, 4, o); o += 4;
        ml_b64_3(alt, 3, 24, 45, 4, o); o += 4;
        ml_b64_3(alt, 25, 46, 4, 4, o); o += 4;
        ml_b64_3(alt, 47, 5, 26, 4, o); o += 4;
        ml_b64_3(alt, 6, 27, 48, 4, o); o += 4;
        ml_b64_3(alt, 28, 49, 7, 4, o); o += 4;
        ml_b64_3(alt, 50, 8, 29, 4, o); o += 4;
        ml_b64_3(alt, 9, 30, 51, 4, o); o += 4;
        ml_b64_3(alt, 31, 52, 10, 4, o); o += 4;
        ml_b64_3(alt, 53, 11, 32, 4, o); o += 4;
        ml_b64_3(alt, 12, 33, 54, 4, o); o += 4;
        ml_b64_3(alt, 34, 55, 13, 4, o); o += 4;
        ml_b64_3(alt, 56, 14, 35, 4, o); o += 4;
        ml_b64_3(alt, 15, 36, 57, 4, o); o += 4;
        ml_b64_3(alt, 37, 58, 16, 4, o); o += 4;
        ml_b64_3(alt, 59, 17, 38, 4, o); o += 4;
        ml_b64_3(alt, 18, 39, 60, 4, o); o += 4;
        ml_b64_3(alt, 40, 61, 19, 4, o); o += 4;
        ml_b64_3(alt, 62, 20, 41, 4, o); o += 4;
        {
            /* Tail pair over alt[63] only (top bytes explicit zero). */
            unsigned w = (unsigned)alt[63];
            int i;
            for (i = 0; i < 2; i++) {
                o[i] = ml_itoa64[w & 0x3F];
                w >>= 6;
            }
            o += 2;
        }
    }
    *o = '\0';
    (void)ds;
    return out;
}

char *crypt_r(const char *key, const char *setting,
              struct crypt_data *data) {
    if (!key || !setting || !data) {
        errno = EINVAL;
        return 0;
    }
    data->initialized = 1;
    if (!ml_sha_crypt(key, setting, data->output, sizeof(data->output))) {
        strcpy(data->output, "*0");
        return data->output;
    }
    return data->output;
}

char *crypt(const char *key, const char *setting) {
    static char ml_crypt_out[256];
    struct crypt_data cd;
    if (!key || !setting) {
        errno = EINVAL;
        return 0;
    }
    if (!ml_sha_crypt(key, setting, ml_crypt_out, sizeof(ml_crypt_out))) {
        strcpy(ml_crypt_out, "*0");
        return ml_crypt_out;
    }
    (void)cd;
    return ml_crypt_out;
}

/* ================= Traditional DES (setkey/encrypt) ================= */

static const unsigned char ml_des_ip[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
};

static const unsigned char ml_des_fp[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
};

static const unsigned char ml_des_e[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
};

static const unsigned char ml_des_p[32] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
};

static const unsigned char ml_des_s[8][64] = {
    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
};

static const unsigned char ml_des_pc1[56] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
};

static const unsigned char ml_des_pc2[48] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
};

static const unsigned char ml_des_rot[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
};

static uint64_t ml_des_keybits; /* 64 bits from setkey ('0'/'1' chars) */
static int ml_des_havekey = 0;

void setkey(const char *key) {
    int i;
    uint64_t k = 0;
    if (!key) {
        ml_des_havekey = 0;
        return;
    }
    for (i = 0; i < 64 && key[i]; i++) {
        k <<= 1;
        if (key[i] == '1') k |= 1;
    }
    k <<= (64 - i);
    ml_des_keybits = k;
    ml_des_havekey = 1;
}

static uint64_t ml_des_perm(uint64_t in, const unsigned char *tab, int n) {
    uint64_t out = 0;
    int i;
    for (i = 0; i < n; i++) {
        out <<= 1;
        out |= (in >> (64 - tab[i])) & 1;
    }
    return out << (64 - n);
}

static void ml_des_keys(uint64_t sub[16]) {
    uint32_t c = 0, d = 0;
    int i, r;
    for (i = 0; i < 28; i++) {
        c <<= 1;
        c |= (uint32_t)((ml_des_keybits >> (64 - ml_des_pc1[i])) & 1);
    }
    for (i = 28; i < 56; i++) {
        d <<= 1;
        d |= (uint32_t)((ml_des_keybits >> (64 - ml_des_pc1[i])) & 1);
    }
    for (r = 0; r < 16; r++) {
        uint64_t cd;
        uint64_t k = 0;
        c = ((c << ml_des_rot[r]) | (c >> (28 - ml_des_rot[r]))) & 0xFFFFFFF;
        d = ((d << ml_des_rot[r]) | (d >> (28 - ml_des_rot[r]))) & 0xFFFFFFF;
        /* CD is 56 bits wide: C in [63..36], D in [35..8], so PC2
         * (1-relative, MSB-first) indexes it directly. */
        cd = ((uint64_t)c << 36) | ((uint64_t)d << 8);
        for (i = 0; i < 48; i++) {
            k <<= 1;
            k |= (cd >> (64 - ml_des_pc2[i])) & 1;
        }
        sub[r] = k << 16;
    }
}

static uint32_t ml_des_f(uint32_t r, uint64_t sub) {
    uint64_t e = 0;
    uint32_t out = 0;
    int i;
    for (i = 0; i < 48; i++) {
        e <<= 1;
        e |= (r >> (32 - ml_des_e[i])) & 1;
    }
    e ^= sub >> 16;
    for (i = 0; i < 8; i++) {
        unsigned row, col;
        unsigned v = (unsigned)((e >> (42 - i * 6)) & 0x3F);
        row = ((v >> 4) & 2) | (v & 1);
        col = (v >> 1) & 15;
        out = (out << 4) | ml_des_s[i][row * 16 + col];
    }
    {
        uint32_t p = 0;
        for (i = 0; i < 32; i++) {
            p <<= 1;
            p |= (out >> (32 - ml_des_p[i])) & 1;
        }
        return p;
    }
}

void encrypt(char *block, int edflag) {
    uint64_t sub[16], data = 0, ip;
    uint32_t l, r, t;
    int i, round;
    if (!block || !ml_des_havekey) return;
    for (i = 0; i < 64 && block[i]; i++) {
        data <<= 1;
        if (block[i] == '1') data |= 1;
    }
    data <<= (64 - i);
    ml_des_keys(sub);
    ip = ml_des_perm(data, ml_des_ip, 64);
    l = (uint32_t)(ip >> 32);
    r = (uint32_t)ip;
    for (round = 0; round < 16; round++) {
        int k = edflag ? 15 - round : round;
        t = r;
        r = l ^ ml_des_f(r, sub[k]);
        l = t;
    }
    {
        uint64_t pre = ((uint64_t)r << 32) | l;
        uint64_t fp = ml_des_perm(pre, ml_des_fp, 64);
        for (i = 63; i >= 0; i--) {
            block[i] = (fp & 1) ? '1' : '0';
            fp >>= 1;
        }
    }
}
