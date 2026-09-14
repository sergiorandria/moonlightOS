#pragma once
/* DICE measured boot: measure kernel -> compare against provisioned hash ->
 * derive CDI = SHA256(UDS || kernel_hash). See kernel/src/dice.c.
 *
 * Return codes for boot_measure_and_attest / dice_attest_ranges:
 *   0 = measured and verified against the provisioned hash
 *   1 = measured, unprovisioned (expected slot all-zeros): CDI derived,
 *       boot continues; provision with `make -C kernel provision-dice`
 *  -1 = measured but MISMATCHED a provisioned hash: fail closed (halt)
 *
 * The measured range excludes the expected-hash slot itself (two updates),
 * so provisioning is a fixed point reached in a single rebuild.
 */
#include <stdint.h>
#include <stddef.h>

#include "sha256.h"

#define DICE_CDI_SIZE 32
#define DICE_HASH_SIZE SHA256_DIGEST_SIZE

typedef struct {
    uint8_t cdi[DICE_CDI_SIZE];
    uint8_t kernel_hash[DICE_HASH_SIZE];
    uint8_t attestation_cert[512]; /* reserved: signed CDI goes here */
} dice_state_t;

/* Global attestation state (BSS). kernel_boot() fills it; future
 * attestation responses are served from it. Never log cdi. */
extern dice_state_t g_dice;

/* CDI = SHA256(uds[32] || hash[32]); wipes its scratch. uds is zeros on
 * QEMU (no OTP); real silicon reads fused OTP read-once here. */
void dice_derive_cdi(const uint8_t *uds, const uint8_t *hash,
                     uint8_t cdi[DICE_CDI_SIZE]);

/* Testable core: hash two ranges, enforce, derive. All-or-nothing on args:
 * NULL out is rejected (-1) without touching memory. */
int dice_attest_ranges(const uint8_t *lo1, size_t len1,
                       const uint8_t *lo2, size_t len2,
                       const uint8_t expected[DICE_HASH_SIZE],
                       dice_state_t *out);

/* Boot wrapper: measures [_text_start,_dice_expected_start) +
 * [_dice_expected_end,_bss) against the linked expected_kernel_hash. */
int boot_measure_and_attest(dice_state_t *dice);
