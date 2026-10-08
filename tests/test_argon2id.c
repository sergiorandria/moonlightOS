/* tests/test_argon2id.c - KAT + property + guard tests for the production
 * Argon2id in userspace/crypt/kdf_production.h (RFC 9106, v=0x13, id=2).
 *
 * Reference vectors: P-H-C/phc-winner-argon2 kats/argon2id (version 19):
 *   pw = 32 x 0x01, salt = 16 x 0x02, secret = 8 x 0x03, ad = 12 x 0x04,
 *   m = 32 KiB, t = 3, p = 4, out = 32.
 * BLAKE2b vectors: cross-checked against host python3 hashlib.blake2b
 * (same oracle discipline as test_aead.c's sha256sum checks).
 *
 * CHECK idiom + bound comments follow tests/test_aead.c. */
#include <stdio.h>
#include <string.h>

/* Single DRBG owner for the host test: exactly one TU per program defines
 * CRYPT_DRBG_DEFINE (see kdf_production.h); this TU is it. */
#define CRYPT_DRBG_DEFINE
#include "../userspace/crypt/kdf_production.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

static int hexis(const uint8_t *b, const char *h, unsigned long n)
{
    unsigned long i;
    for (i = 0; i < n; i++) { /* bound: digest len <= 64 */
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1)
            return 0;
        if (b[i] != (uint8_t)v)
            return 0;
    }
    return 1;
}

/* Accumulated-diff zero check (same idiom as crypt_ct_eq). */
static int is_zero(const uint8_t *b, unsigned long n)
{
    unsigned diff = 0;
    unsigned long i;
    for (i = 0; i < n; i++) /* bound: caller len */
        diff |= b[i];
    return diff == 0;
}

int main(void)
{
    /* BLAKE2b-512 (host-oracle vectors): "abc" + empty. */
    {
        uint8_t d[64];
        CHECK(a2_blake2b((const uint8_t *)"abc", 3, d, 64) == 0);
        CHECK(hexis(d, "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923", 64));
        CHECK(a2_blake2b((const uint8_t *)"", 0, d, 64) == 0);
        CHECK(hexis(d, "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce", 64));
        /* Guards: NULL out, zero outlen, over-64 outlen, NULL msg w/ len. */
        CHECK(a2_blake2b((const uint8_t *)"abc", 3, (uint8_t *)0, 64) == -1);
        CHECK(a2_blake2b((const uint8_t *)"abc", 3, d, 0) == -1);
        CHECK(a2_blake2b((const uint8_t *)"abc", 3, d, 65) == -1);
        CHECK(a2_blake2b((const uint8_t *)0, 3, d, 64) == -1);
        CHECK(a2_blake2b((const uint8_t *)0, 0, d, 32) == 0);
    }

    /* Production PBKDF2-HMAC-SHA256 (what vault/cryptblk get post-migration):
     * explicit iters behave like kdf.h (RFC 6070 shape); iter==0 takes the
     * 600K default (kdf.h rejects 0). 600K known-answer from host
     * hashlib.pbkdf2_hmac. */
    {
        uint8_t dk[32], dk0[32];
        CHECK(pbkdf2_hmac_sha256_production((const uint8_t *)"password", 8,
                                            (const uint8_t *)"salt", 4,
                                            1, dk, sizeof(dk)) == 0);
        CHECK(hexis(dk, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", 32));
        CHECK(pbkdf2_hmac_sha256_production((const uint8_t *)"password", 8,
                                            (const uint8_t *)"salt", 4,
                                            0, dk0, sizeof(dk0)) == 0);
        CHECK(hexis(dk0, "669cfe52482116fda1aa2cbe409b2f56c8e4563752b7a28f6eaab614ee005178", 32));
        CHECK(pbkdf2_hmac_sha256_production((const uint8_t *)"password", 8,
                                            (const uint8_t *)"salt", 4,
                                            KDF_PBKDF2_ITERS_RECOMMENDED,
                                            dk, sizeof(dk)) == 0);
        CHECK(memcmp(dk, dk0, sizeof(dk)) == 0);
        /* Guards: empty dk, NULL buffers with nonzero lengths. */
        CHECK(pbkdf2_hmac_sha256_production((const uint8_t *)"pw", 2,
                                            (const uint8_t *)"s", 1, 1, dk, 0) == -1);
        CHECK(pbkdf2_hmac_sha256_production((const uint8_t *)0, 2,
                                            (const uint8_t *)"s", 1, 1, dk, sizeof(dk)) == -1);
        CHECK(pbkdf2_hmac_sha256_production((const uint8_t *)"pw", 2,
                                            (const uint8_t *)"s", 1, 1, (uint8_t *)0, sizeof(dk)) == -1);
    }

    /* Sizing helper: reference alignment (down to lanes*4) + guards. */
    {
        unsigned long nb = 0;
        CHECK(argon2id_blocks(32, 4, &nb) == 0 && nb == 32);
        CHECK(argon2id_blocks(8, 1, &nb) == 0 && nb == 8);
        CHECK(argon2id_blocks(100, 1, &nb) == 0 && nb == 100);
        CHECK(argon2id_blocks(7, 1, &nb) == -1); /* < 8 blocks/lane */
        CHECK(argon2id_blocks(31, 4, &nb) == -1); /* < 8*lanes */
        CHECK(argon2id_blocks(32, 0, &nb) == -1);
        CHECK(argon2id_blocks(32, 4, (unsigned long *)0) == -1);
    }

    /* Argon2id KAT (reference kats/argon2id vector 1, with secret + ad). */
    {
        /* 32 KiB = 32 blocks of 1 KiB. */
        static uint8_t mem[32 * 1024];
        uint8_t pw[32], salt[16], secret[8], ad[12], tag[32];
        unsigned long i;
        for (i = 0; i < sizeof(pw); i++) /* bound: 32 */
            pw[i] = 0x01;
        for (i = 0; i < sizeof(salt); i++) /* bound: 16 */
            salt[i] = 0x02;
        for (i = 0; i < sizeof(secret); i++) /* bound: 8 */
            secret[i] = 0x03;
        for (i = 0; i < sizeof(ad); i++) /* bound: 12 */
            ad[i] = 0x04;
        for (i = 0; i < sizeof(mem); i++) /* bound: 32 KiB */
            mem[i] = 0xA5;
        for (i = 0; i < sizeof(tag); i++) /* bound: 32 */
            tag[i] = 0;
        CHECK(argon2id_kdf_ext(pw, sizeof(pw), salt, sizeof(salt),
                               secret, sizeof(secret), ad, sizeof(ad),
                               32, 3, 4, tag, sizeof(tag),
                               mem, sizeof(mem)) == 0);
        CHECK(hexis(tag, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", 32));
        /* Memory buffer is wiped by the implementation (no residue). */
        CHECK(is_zero(mem, sizeof(mem)));
    }

    /* Small-memory path: with_mem == ext(empty) == plain wrapper;
     * deterministic across runs. */
    {
        uint8_t mem[8 * 1024];
        uint8_t pw[16], salt[16], t1[32], t2[32], t3[32];
        unsigned long i;
        for (i = 0; i < sizeof(pw); i++) /* bound: 16 */
            pw[i] = (uint8_t)(i * 3 + 1);
        for (i = 0; i < sizeof(salt); i++) /* bound: 16 */
            salt[i] = (uint8_t)(i * 7 + 2);
        CHECK(argon2id_kdf_with_mem(pw, sizeof(pw), salt, sizeof(salt),
                                    8, 1, 1, t1, sizeof(t1),
                                    mem, sizeof(mem)) == 0);
        CHECK(argon2id_kdf_ext(pw, sizeof(pw), salt, sizeof(salt),
                               (const uint8_t *)0, 0, (const uint8_t *)0, 0,
                               8, 1, 1, t2, sizeof(t2),
                               mem, sizeof(mem)) == 0);
        CHECK(memcmp(t1, t2, sizeof(t1)) == 0);
        CHECK(argon2id_kdf(pw, sizeof(pw), salt, sizeof(salt),
                           8, 1, 1, t3, sizeof(t3)) == 0);
        CHECK(memcmp(t1, t3, sizeof(t1)) == 0);
        /* Deterministic: same inputs re-derive the same tag. */
        CHECK(argon2id_kdf_with_mem(pw, sizeof(pw), salt, sizeof(salt),
                                    8, 1, 1, t2, sizeof(t2),
                                    mem, sizeof(mem)) == 0);
        CHECK(memcmp(t1, t2, sizeof(t1)) == 0);
        /* Sensitivity: one password byte / one salt byte changes the tag. */
        pw[0] ^= 0x01;
        CHECK(argon2id_kdf_with_mem(pw, sizeof(pw), salt, sizeof(salt),
                                    8, 1, 1, t2, sizeof(t2),
                                    mem, sizeof(mem)) == 0);
        CHECK(memcmp(t1, t2, sizeof(t1)) != 0);
        pw[0] ^= 0x01;
        salt[0] ^= 0x01;
        CHECK(argon2id_kdf_with_mem(pw, sizeof(pw), salt, sizeof(salt),
                                    8, 1, 1, t2, sizeof(t2),
                                    mem, sizeof(mem)) == 0);
        CHECK(memcmp(t1, t2, sizeof(t1)) != 0);
    }

    /* Guards: every bad-arg shape fails closed with -1. */
    {
        uint8_t mem[8 * 1024];
        uint8_t pw[16], salt[16], tag[32];
        unsigned long i;
        for (i = 0; i < sizeof(pw); i++) /* bound: 16 */
            pw[i] = (uint8_t)i;
        for (i = 0; i < sizeof(salt); i++) /* bound: 16 */
            salt[i] = (uint8_t)(i + 1);
        CHECK(argon2id_kdf_with_mem((const uint8_t *)0, sizeof(pw), salt, sizeof(salt), 8, 1, 1, tag, sizeof(tag), mem, sizeof(mem)) == -1);
        CHECK(argon2id_kdf_with_mem(pw, sizeof(pw), (const uint8_t *)0, sizeof(salt), 8, 1, 1, tag, sizeof(tag), mem, sizeof(mem)) == -1);
        CHECK(argon2id_kdf_with_mem(pw, sizeof(pw), salt, 7, 8, 1, 1, tag, sizeof(tag), mem, sizeof(mem)) == -1); /* salt < 8 */
        CHECK(argon2id_kdf_with_mem(pw, sizeof(pw), salt, sizeof(salt), 7, 1, 1, tag, sizeof(tag), mem, sizeof(mem)) == -1); /* m < 8p */
        CHECK(argon2id_kdf_with_mem(pw, sizeof(pw), salt, sizeof(salt), 8, 0, 1, tag, sizeof(tag), mem, sizeof(mem)) == -1); /* t = 0 */
        CHECK(argon2id_kdf_with_mem(pw, sizeof(pw), salt, sizeof(salt), 8, 1, 0, tag, sizeof(tag), mem, sizeof(mem)) == -1); /* p = 0 */
        CHECK(argon2id_kdf_with_mem(pw, sizeof(pw), salt, sizeof(salt), 8, 1, 1, (uint8_t *)0, sizeof(tag), mem, sizeof(mem)) == -1);
        CHECK(argon2id_kdf_with_mem(pw, sizeof(pw), salt, sizeof(salt), 8, 1, 1, tag, 3, mem, sizeof(mem)) == -1); /* out < 4 */
        CHECK(argon2id_kdf_with_mem(pw, sizeof(pw), salt, sizeof(salt), 8, 1, 1, tag, sizeof(tag), (uint8_t *)0, sizeof(mem)) == -1);
        CHECK(argon2id_kdf_with_mem(pw, sizeof(pw), salt, sizeof(salt), 8, 1, 1, tag, sizeof(tag), mem, sizeof(mem) - 1) == -1); /* short mem */
        /* Plain wrapper fails closed past its stack budget (32 KiB). */
        CHECK(argon2id_kdf(pw, sizeof(pw), salt, sizeof(salt), 64, 1, 1, tag, sizeof(tag)) == -1);
    }

    /* Production DRBG: reseed/generate round-trip + catastrophic gate. */
    {
        uint8_t seed[32], a[32], b[32], c[32];
        unsigned long i;
        for (i = 0; i < sizeof(seed); i++) /* bound: 32 */
            seed[i] = (uint8_t)i;
        CHECK(drbg_reseed_production(seed, sizeof(seed), 256) == 0);
        CHECK(drbg_generate_production(a, sizeof(a)) == 0);
        CHECK(drbg_reseed_production(seed, sizeof(seed), 256) == 0);
        CHECK(drbg_generate_production(b, sizeof(b)) == 0);
        CHECK(memcmp(a, b, sizeof(a)) == 0); /* reseed ==> same stream */
        seed[0] ^= 0x01;
        CHECK(drbg_reseed_production(seed, sizeof(seed), 256) == 0);
        CHECK(drbg_generate_production(c, sizeof(c)) == 0);
        CHECK(memcmp(a, c, sizeof(a)) != 0); /* new seed ==> new stream */
        CHECK(drbg_reseed_production((const uint8_t *)0, 32, 256) == -1);
        CHECK(drbg_reseed_production(seed, 31, 256) == -1); /* < 256-bit seed */
        CHECK(drbg_generate_production((uint8_t *)0, 32) == -1);
        /* Low-entropy seed trips the catastrophic gate after 2^16 pulls. */
        CHECK(drbg_reseed_production(seed, sizeof(seed), 64) == 0);
        for (i = 0; i < ((unsigned long)1 << 16); i++) { /* bound: 2^16 */
            if (drbg_generate_production(a, sizeof(a)) != 0) {
                printf("FAIL line %d: catastrophic early at %lu\n", __LINE__, i);
                return 1;
            }
        }
        CHECK(drbg_generate_production(a, sizeof(a)) == -1);
        /* Fresh reseed clears the gate. */
        CHECK(drbg_reseed_production(seed, sizeof(seed), 256) == 0);
        CHECK(drbg_generate_production(a, sizeof(a)) == 0);
    }

    /* Entropy audit record: 80-byte LE serialization + guards. */
    {
        entropy_audit_record_t r;
        uint8_t enc[80], enc2[80];
        unsigned long i;
        for (i = 0; i < sizeof(r.hw_sample); i++) /* bound: 32 */
            r.hw_sample[i] = (uint8_t)(i + 1);
        r.timestamp = 0x1122334455667788ULL;
        r.request_count = 0x0102030405060708ULL;
        r.entropy_bits = 256;
        r.source_tid = 8;
        CHECK(entropy_audit_encode(&r, enc, sizeof(enc)) == 0);
        CHECK(enc[0] == 0x88 && enc[7] == 0x11); /* timestamp LE */
        CHECK(enc[8] == 0x08 && enc[15] == 0x01); /* request_count LE */
        CHECK(enc[16] == 0x00 && enc[17] == 0x01); /* 256 LE */
        CHECK(enc[20] == 0x08 && enc[21] == 0x00); /* tid LE */
        CHECK(enc[24] == 0x01 && enc[55] == 0x20); /* hw_sample verbatim */
        CHECK(is_zero(enc + 56, 24)); /* reserved pad is zero */
        /* Deterministic encoding. */
        CHECK(entropy_audit_encode(&r, enc2, sizeof(enc2)) == 0);
        CHECK(memcmp(enc, enc2, sizeof(enc)) == 0);
        CHECK(entropy_audit_encode((const entropy_audit_record_t *)0, enc, sizeof(enc)) == -1);
        CHECK(entropy_audit_encode(&r, (uint8_t *)0, sizeof(enc)) == -1);
        CHECK(entropy_audit_encode(&r, enc, sizeof(enc) - 1) == -1);
    }

    printf("PASS: test_argon2id\n");
    return 0;
}
