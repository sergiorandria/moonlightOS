#include "../kernel/include/sha256.h"
#include "../kernel/include/dice.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Host test for freestanding sha256 + DICE attest core.
 * dice_attest_ranges is the exact function the kernel calls (linker
 * symbols only enter via boot_measure_and_attest, tested on target). */

/* Target-link symbols needed to link kernel/src/dice.c on host.
 * boot_measure_and_attest is never called here (QEMU smoke covers it). */
const uint8_t expected_kernel_hash[32] = {0};
const uint8_t _text_start = 0, _dice_expected_start = 0;
const uint8_t _dice_expected_end = 0, _bss = 0;

static void hexprint(const uint8_t *p, char *out) {
    for (int i = 0; i < 32; i++)
        sprintf(out + 2 * i, "%02x", p[i]);
}

static int hexeq(const uint8_t *p, const char *hex) {
    char buf[65];
    hexprint(p, buf);
    return strcmp(buf, hex) == 0;
}

int main(void) {
    printf("=== sha256 + dice tests ===\n");
    uint8_t out[32];

    /* FIPS 180-4 KATs */
    sha256((const uint8_t *)"", 0, out);
    assert(hexeq(out, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    printf("PASS: empty\n");
    sha256((const uint8_t *)"abc", 3, out);
    assert(hexeq(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    printf("PASS: abc\n");
    /* 56-byte message: exactly one block before padding spills to a
     * second block. Digest cross-checked against Python hashlib. */
    sha256((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, out);
    assert(hexeq(out, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    printf("PASS: 56-byte (one block + padding edge)\n");

    /* Incremental API: byte-at-a-time must equal one-shot.
     * (Implementation also differentially verified against Python hashlib
     * for every length 0..200, covering all padding/block edges.) */
    {
        const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        sha256_ctx c;
        uint8_t a[32], b[32];
        sha256((const uint8_t *)msg, 56, a);
        sha256_init(&c);
        for (int i = 0; i < 56; i++)
            sha256_update(&c, msg + i, 1);
        sha256_final(&c, b);
        assert(memcmp(a, b, 32) == 0);
        /* Split update at every boundary 0..56 for good measure. */
        for (int k = 0; k <= 56; k++) {
            sha256_init(&c);
            sha256_update(&c, msg, (size_t)k);
            sha256_update(&c, msg + k, (size_t)(56 - k));
            sha256_final(&c, b);
            assert(memcmp(a, b, 32) == 0);
        }
    }
    printf("PASS: incremental == one-shot (all split points)\n");

    /* Million-'a' (multi-block streaming). Digest cross-checked
     * against Python hashlib; chunked updates differentially verified. */
    {
        sha256_ctx c;
        uint8_t blk[1000];
        memset(blk, 'a', sizeof(blk));
        sha256_init(&c);
        for (int i = 0; i < 1000; i++)
            sha256_update(&c, blk, sizeof(blk));
        sha256_final(&c, out);
        assert(hexeq(out, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    }
    printf("PASS: 1M x 'a'\n");

    /* dice_attest_ranges over a synthetic image with a fake slot region. */
    uint8_t img[256];
    for (int i = 0; i < 256; i++)
        img[i] = (uint8_t)(i * 7 + 1);
    const uint8_t *lo1 = img, *lo2 = img + 160;
    size_t len1 = 64, len2 = 96; /* img[64..160) is the "slot", excluded */
    uint8_t zero_exp[32] = {0};
    dice_state_t st;

    /* Unprovisioned: rc 1, hash recorded, CDI derived. */
    memset(&st, 0, sizeof(st));
    assert(dice_attest_ranges(lo1, len1, lo2, len2, zero_exp, &st) == 1);
    uint8_t ref_hash[32], ref_cdi[32];
    memcpy(ref_hash, st.kernel_hash, 32);
    memcpy(ref_cdi, st.cdi, 32);
    /* Slot invariance: flipping excluded bytes must not change anything. */
    {
        uint8_t img2[256];
        memcpy(img2, img, sizeof(img2));
        memset(img2 + 64, 0xAA, 96);
        dice_state_t st2;
        memset(&st2, 0, sizeof(st2));
        assert(dice_attest_ranges(img2, len1, img2 + 160, len2, zero_exp, &st2) == 1);
        assert(memcmp(st2.kernel_hash, ref_hash, 32) == 0);
        assert(memcmp(st2.cdi, ref_cdi, 32) == 0);
    }
    printf("PASS: unprovisioned measure-only + slot invariance\n");

    /* Provisioned match: rc 0. */
    memset(&st, 0, sizeof(st));
    assert(dice_attest_ranges(lo1, len1, lo2, len2, ref_hash, &st) == 0);
    assert(memcmp(st.kernel_hash, ref_hash, 32) == 0);
    assert(memcmp(st.cdi, ref_cdi, 32) == 0);
    printf("PASS: provisioned match verifies\n");

    /* Provisioned mismatch: rc -1, fail closed. */
    {
        uint8_t bad[32];
        memcpy(bad, ref_hash, 32);
        bad[0] ^= 0x01;
        memset(&st, 0xAA, sizeof(st));
        assert(dice_attest_ranges(lo1, len1, lo2, len2, bad, &st) == -1);
    }
    printf("PASS: provisioned mismatch fails closed\n");

    /* CDI: deterministic, sensitive to input, UDS-mixed (differs from raw). */
    {
        dice_state_t a, b;
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        assert(dice_attest_ranges(lo1, len1, lo2, len2, zero_exp, &a) == 1);
        assert(dice_attest_ranges(lo1, len1, lo2, len2, zero_exp, &b) == 1);
        assert(memcmp(a.cdi, b.cdi, 32) == 0); /* deterministic */
        uint8_t img3[256];
        memcpy(img3, img, sizeof(img3));
        img3[0] ^= 0x01; /* inside measured range */
        dice_state_t c;
        memset(&c, 0, sizeof(c));
        assert(dice_attest_ranges(img3, len1, img3 + 160, len2, zero_exp, &c) == 1);
        assert(memcmp(c.cdi, a.cdi, 32) != 0);     /* sensitive */
        assert(memcmp(c.kernel_hash, a.cdi, 32) != 0); /* mixed, not raw */
    }
    printf("PASS: CDI deterministic + sensitive\n");

    /* Bad args rejected without touching out. */
    {
        dice_state_t z;
        memset(&z, 0xAA, sizeof(z));
        assert(dice_attest_ranges(NULL, 0, NULL, 0, zero_exp, NULL) == -1);
        assert(dice_attest_ranges(lo1, len1, lo2, len2, zero_exp, NULL) == -1);
        assert(dice_attest_ranges(NULL, 8, lo2, len2, zero_exp, &z) == -1);
        for (size_t i = 0; i < sizeof(z); i++)
            assert(((uint8_t *)&z)[i] == 0xAA);
    }
    printf("PASS: bad args rejected, out untouched\n");

    printf("ALL DICE TESTS PASS\n");
    return 0;
}
