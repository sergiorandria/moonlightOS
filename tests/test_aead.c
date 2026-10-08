/* tests/test_aead.c - KAT + property + tamper tests for the crypt headers. */
#include <stdio.h>
#include <string.h>
/* Single DRBG owner for the host test: exactly one TU per program defines
 * CRYPT_DRBG_DEFINE (see kdf.h); this TU is it. */
#define CRYPT_DRBG_DEFINE
#include "../userspace/crypt/sha256.h"
#include "../userspace/crypt/aead.h"
#include "../userspace/crypt/kdf.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

static int hextob(const char *h, uint8_t *b, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) { /* bound: test vector len */
        unsigned hi, lo;
        if (sscanf(h + 2*i, "%2x", &hi) != 1) return -1;
        lo = hi & 0xF; hi >>= 4; /* keep -Werror -Wconversion-clean shapes simple */
        b[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* Compare a byte buffer against a lowercase hex string. */
static int hexis(const uint8_t *b, const char *h, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) { /* bound: digest len <= 64 */
        unsigned v;
        if (sscanf(h + 2*i, "%2x", &v) != 1) return 0;
        if (b[i] != (uint8_t)v) return 0;
    }
    return 1;
}

int main(void) {
    /* KAT: RFC 8439 section 2.8.2 AEAD_CHACHA20_POLY1305, fetched verbatim
     * from https://www.rfc-editor.org/rfc/rfc8439.txt (NEVER from memory).
     * Nonce = 32-bit fixed-common part (07 00 00 00) | 64-bit IV. */
    static const char *KAT_KEY = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    static const char *KAT_NONCE = "070000004041424344454647";
    static const char *KAT_AAD = "50515253c0c1c2c3c4c5c6c7";
    static const char *KAT_PT =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    static const char *KAT_CT =
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116";
    static const char *KAT_TAG = "1ae10b594f09e26a7e902ecbd0600691";
    {
        uint8_t key[32], nonce[12], aad[12], pt[114], ct[114], back[114], tag[16];
        CHECK(strlen(KAT_PT) == sizeof(pt)); /* 114B sunscreen text */
        CHECK(hextob(KAT_KEY, key, sizeof(key)) == 0);
        CHECK(hextob(KAT_NONCE, nonce, sizeof(nonce)) == 0);
        CHECK(hextob(KAT_AAD, aad, sizeof(aad)) == 0);
        memcpy(pt, KAT_PT, sizeof(pt));
        CHECK(aead_seal(key, nonce, aad, sizeof(aad), pt, sizeof(pt), ct, tag) == 0);
        CHECK(hexis(ct, KAT_CT, sizeof(ct)));
        CHECK(hexis(tag, KAT_TAG, sizeof(tag)));
        CHECK(aead_open(key, nonce, aad, sizeof(aad), ct, sizeof(ct), tag, back) == 0);
        CHECK(memcmp(back, pt, sizeof(pt)) == 0);
        /* Wrong AAD must not open. */
        aad[0] ^= 0x01;
        CHECK(aead_open(key, nonce, aad, sizeof(aad), ct, sizeof(ct), tag, back) == -1);
        aad[0] ^= 0x01;
    }

    /* Poly1305 raw: RFC 8439 section 2.5.2 standalone vector, fetched
     * verbatim (isolates Poly1305 from ChaCha20). */
    {
        uint8_t pkey[32], ptag[16];
        CHECK(hextob("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
                     pkey, sizeof(pkey)) == 0);
        poly1305_mac((const uint8_t *)"Cryptographic Forum Research Group", 34,
                     pkey, ptag);
        CHECK(hexis(ptag, "a8061dc1305136c6c22b8baf0c0127a9", sizeof(ptag)));
    }

    /* SHA-256: "abc" sanity vector (brief-authorized) + empty digest,
     * both cross-checked against host sha256sum. */
    {
        uint8_t d[32];
        sha256((const uint8_t *)"abc", 3, d);
        CHECK(hexis(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32));
        sha256((const uint8_t *)"", 0, d);
        CHECK(hexis(d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32));
    }

    /* HMAC-SHA-256 core: RFC 4231 test cases 1/2/3/6, fetched verbatim
     * from https://www.rfc-editor.org/rfc/rfc4231.txt. TC6 data is built
     * from string literals (54B) to avoid hex transcription risk. */
    {
        uint8_t k20[20], data[50], out[32];
        unsigned long i;
        for (i = 0; i < sizeof(k20); i++) k20[i] = 0x0b; /* bound: 20 */
        CHECK(hmac_sha256(k20, sizeof(k20),
                          (const uint8_t *)"Hi There", 8, out) == 0);
        CHECK(hexis(out, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", 32));
        CHECK(hmac_sha256((const uint8_t *)"Jefe", 4,
                          (const uint8_t *)"what do ya want for nothing?", 28, out) == 0);
        CHECK(hexis(out, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 32));
        for (i = 0; i < sizeof(k20); i++) k20[i] = 0xaa; /* bound: 20 */
        for (i = 0; i < sizeof(data); i++) data[i] = 0xdd; /* bound: 50 */
        CHECK(hmac_sha256(k20, sizeof(k20), data, sizeof(data), out) == 0);
        CHECK(hexis(out, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", 32));
        {
            static uint8_t k131[131];
            static uint8_t d54[54];
            static const char *d1 = "Test Using Larger Than Block-Size Key - ";
            static const char *d2 = "Hash Key First";
            for (i = 0; i < sizeof(k131); i++) k131[i] = 0xaa; /* bound: 131 */
            memcpy(d54, d1, 40);
            memcpy(d54 + 40, d2, 14);
            CHECK(hmac_sha256(k131, sizeof(k131), d54, sizeof(d54), out) == 0);
            CHECK(hexis(out, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", 32));
        }
    }

    /* PBKDF2-HMAC-SHA256: RFC 7914 section 11 vectors (fetched verbatim
     * from https://www.rfc-editor.org/rfc/rfc7914.txt) + RFC-6070-input-
     * shaped vectors (password/salt c=1/2/4096 dkLen=32) corroborated
     * across three independent sources and the host hashlib oracle. */
    {
        uint8_t dk[64];
        CHECK(pbkdf2_hmac_sha256((const uint8_t *)"passwd", 6,
                                 (const uint8_t *)"salt", 4, 1, dk, 64) == 0);
        CHECK(hexis(dk, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                        "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783", 64));
        CHECK(pbkdf2_hmac_sha256((const uint8_t *)"password", 8,
                                 (const uint8_t *)"salt", 4, 1, dk, 32) == 0);
        CHECK(hexis(dk, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", 32));
        CHECK(pbkdf2_hmac_sha256((const uint8_t *)"password", 8,
                                 (const uint8_t *)"salt", 4, 2, dk, 32) == 0);
        CHECK(hexis(dk, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43", 32));
        CHECK(pbkdf2_hmac_sha256((const uint8_t *)"password", 8,
                                 (const uint8_t *)"salt", 4, 4096, dk, 32) == 0);
        CHECK(hexis(dk, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a", 32));
        CHECK(pbkdf2_hmac_sha256((const uint8_t *)"Password", 8,
                                 (const uint8_t *)"NaCl", 4, 80000, dk, 64) == 0);
        CHECK(hexis(dk, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
                        "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d", 64));
        /* dklen edges (1, 32, 64): prefixes of the c=1 dkLen=32 vector. */
        CHECK(pbkdf2_hmac_sha256((const uint8_t *)"password", 8,
                                 (const uint8_t *)"salt", 4, 1, dk, 1) == 0);
        CHECK(dk[0] == 0x12);
        CHECK(pbkdf2_hmac_sha256((const uint8_t *)"password", 8,
                                 (const uint8_t *)"salt", 4, 1, dk, 64) == 0);
        CHECK(hexis(dk, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", 32));
        /* Guards: iter>=1, dklen>=1, non-NULL buffers. */
        CHECK(pbkdf2_hmac_sha256((const uint8_t *)"pw", 2,
                                 (const uint8_t *)"s", 1, 0, dk, 32) == -1);
        CHECK(pbkdf2_hmac_sha256((const uint8_t *)"pw", 2,
                                 (const uint8_t *)"s", 1, 1, dk, 0) == -1);
        CHECK(pbkdf2_hmac_sha256((const uint8_t *)0, 2,
                                 (const uint8_t *)"s", 1, 1, dk, 32) == -1);
        CHECK(pbkdf2_hmac_sha256((const uint8_t *)"pw", 2,
                                 (const uint8_t *)"s", 1, 1, (uint8_t *)0, 32) == -1);
    }

    /* Property: round-trip over adversarial lengths incl. padding edges. */
    {
        static const unsigned lens[] = {0,1,15,16,17,31,32,33,55,56,63,64,65,119,120,135,136,200,256};
        uint8_t key[32], nonce[12], pt[256], ct[256], back[256], tag[16], ad[16];
        for (unsigned li = 0; li < sizeof(lens)/sizeof(lens[0]); li++) { /* bound: 19 */
            unsigned long n = lens[li];
            for (unsigned long i = 0; i < n; i++) pt[i] = (uint8_t)(i * 31 + 7);
            CHECK(aead_seal(key, nonce, ad, sizeof(ad), pt, n, ct, tag) == 0);
            if (n > 0) CHECK(memcmp(ct, pt, n) != 0); /* actually encrypted */
            CHECK(aead_open(key, nonce, ad, sizeof(ad), ct, n, tag, back) == 0);
            CHECK(memcmp(back, pt, n) == 0);
        }
    }

    /* Property: nonce separation (same pt, different nonce ==> different ct). */
    {
        uint8_t key[32], n1[12], n2[12], pt[64], c1[64], c2[64], t1[16], t2[16];
        unsigned long i;
        for (i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)i; /* bound: 64 */
        for (i = 0; i < sizeof(n1); i++) { n1[i] = 0; n2[i] = 0; } /* bound: 12 */
        n2[11] = 1;
        CHECK(aead_seal(key, n1, (const uint8_t *)0, 0, pt, sizeof(pt), c1, t1) == 0);
        CHECK(aead_seal(key, n2, (const uint8_t *)0, 0, pt, sizeof(pt), c2, t2) == 0);
        CHECK(memcmp(c1, c2, sizeof(pt)) != 0);
        CHECK(memcmp(t1, t2, sizeof(t1)) != 0);
        /* Cross-nonce open must fail AND zero the output. */
        memset(c1, 0xA5, sizeof(c1));
        CHECK(aead_open(key, n2, (const uint8_t *)0, 0, c2, sizeof(c2), t1, c1) == -1);
        for (i = 0; i < sizeof(c1); i++) CHECK(c1[i] == 0); /* bound: 64 */
    }

    /* Tamper: flip every byte of one tag + one ct byte ==> open fails AND out zeroed. */
    {
        uint8_t key[32], nonce[12], pt[48], ct[48], back[48], tag[16], bad[16];
        unsigned long i, j;
        for (i = 0; i < sizeof(pt); i++) pt[i] = (uint8_t)(i * 3 + 1); /* bound: 48 */
        CHECK(aead_seal(key, nonce, (const uint8_t *)0, 0, pt, sizeof(pt), ct, tag) == 0);
        for (j = 0; j < sizeof(tag); j++) { /* bound: 16 tag bytes */
            memcpy(bad, tag, sizeof(tag));
            bad[j] ^= 0x01;
            memset(back, 0xA5, sizeof(back));
            CHECK(aead_open(key, nonce, (const uint8_t *)0, 0, ct, sizeof(ct), bad, back) == -1);
            for (i = 0; i < sizeof(back); i++) CHECK(back[i] == 0); /* bound: 48 */
        }
        ct[0] ^= 0x01; /* one ct byte */
        memset(back, 0xA5, sizeof(back));
        CHECK(aead_open(key, nonce, (const uint8_t *)0, 0, ct, sizeof(ct), tag, back) == -1);
        for (i = 0; i < sizeof(back); i++) CHECK(back[i] == 0); /* bound: 48 */
    }

    /* DRBG: deterministic under reseed, separates across seeds. */
    {
        uint8_t a[64], b[64], c[64];
        uint8_t seed[32];
        unsigned long i;
        int diff = 0;
        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)i; /* bound: 32 */
        drbg_seed(seed, sizeof(seed));
        drbg_next(a, sizeof(a));
        drbg_seed(seed, sizeof(seed));
        drbg_next(b, sizeof(b));
        CHECK(memcmp(a, b, sizeof(a)) == 0); /* reseed ==> same stream */
        seed[0] ^= 0x01;
        drbg_seed(seed, sizeof(seed));
        drbg_next(c, sizeof(c));
        for (i = 0; i < sizeof(a); i++) diff |= (a[i] ^ c[i]); /* bound: 64 */
        CHECK(diff != 0); /* different seed ==> different stream */
    }

    printf("PASS: test_aead\n");
    return 0;
}
