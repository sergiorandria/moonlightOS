#include "../include/dice.h"
#include "../include/sha256.h"
#include <string.h> /* freestanding kernel string.h: memcpy/memset from minilib */

/* DICE measured boot - kernel measurement -> CDI derivation.
 * Moved from boot/dice.c and wired in (PLAN 1.1): real sha256, real call
 * from kernel_boot, expected hash supplied by the linked .dice_expected
 * slot (tools/measure_dice.py + `make provision-dice`). */

dice_state_t g_dice;

/* Linked by kernel/linker.ld (.dice_expected section, kept, file-backed). */
extern const uint8_t expected_kernel_hash[DICE_HASH_SIZE];
extern const uint8_t _text_start;
extern const uint8_t _dice_expected_start;
extern const uint8_t _dice_expected_end;
extern const uint8_t _bss;

void dice_derive_cdi(const uint8_t *uds, const uint8_t *hash,
                     uint8_t cdi[DICE_CDI_SIZE]) {
    uint8_t tmp[64];
    memcpy(tmp, uds, 32);
    memcpy(tmp + 32, hash, 32);
    sha256(tmp, 64, cdi);
    /* Clear UDS-derived scratch - forward secrecy */
    memset(tmp, 0, 64);
}

static int expected_is_zero(const uint8_t expected[DICE_HASH_SIZE]) {
    uint8_t acc = 0;
    for (unsigned i = 0; i < DICE_HASH_SIZE; i++)
        acc |= expected[i];
    return acc == 0;
}

int dice_attest_ranges(const uint8_t *lo1, size_t len1,
                       const uint8_t *lo2, size_t len2,
                       const uint8_t expected[DICE_HASH_SIZE],
                       dice_state_t *out) {
    uint8_t k_hash[DICE_HASH_SIZE];
    sha256_ctx ctx;

    if (!out || !expected)
        return -1;
    if ((len1 && !lo1) || (len2 && !lo2))
        return -1;

    sha256_init(&ctx);
    if (len1)
        sha256_update(&ctx, lo1, len1);
    if (len2)
        sha256_update(&ctx, lo2, len2);
    sha256_final(&ctx, k_hash);

    int provisioned = !expected_is_zero(expected);
    if (provisioned) {
        /* Constant-shape compare (memcmp would do; loop keeps it branchless
         * on the mismatch path too). */
        uint8_t diff = 0;
        for (unsigned i = 0; i < DICE_HASH_SIZE; i++)
            diff |= (uint8_t)(k_hash[i] ^ expected[i]);
        if (diff != 0) {
            memset(k_hash, 0, DICE_HASH_SIZE);
            return -1;
        }
    }

    /* Derive CDI. UDS is zeros on QEMU (no fused OTP); silicon reads OTP
     * read-once into this buffer instead. */
    uint8_t uds[DICE_CDI_SIZE] = {0};
    dice_derive_cdi(uds, k_hash, out->cdi);
    memcpy(out->kernel_hash, k_hash, DICE_HASH_SIZE);
    memset(out->attestation_cert, 0, sizeof(out->attestation_cert));
    memset(uds, 0, DICE_CDI_SIZE);
    memset(k_hash, 0, DICE_HASH_SIZE);
    return provisioned ? 0 : 1;
}

int boot_measure_and_attest(dice_state_t *dice) {
    const uint8_t *t0 = &_text_start;
    const uint8_t *d0 = &_dice_expected_start;
    const uint8_t *d1 = &_dice_expected_end;
    const uint8_t *b0 = &_bss;

    /* Defensive ordering: a broken link that overlaps the slot fails
     * closed instead of measuring garbage. */
    if (!(t0 <= d0 && d0 <= d1 && d1 <= b0))
        return -1;
    return dice_attest_ranges(t0, (size_t)(d0 - t0),
                              d1, (size_t)(b0 - d1),
                              expected_kernel_hash, dice);
}
