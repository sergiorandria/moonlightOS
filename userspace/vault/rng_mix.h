/* userspace/vault/rng_mix.h - pure RNG mixer validation/packing. */
#ifndef VAULT_RNG_MIX_H
#define VAULT_RNG_MIX_H
#include <stdint.h>
#include <stddef.h>
#define RNG_HW_LEN 32u
#define RNG_MIX_LEN 32u
static inline int rng_mix_ok(const uint8_t *hw, unsigned long hw_len,
    uint64_t rdtime, uint64_t service_delta, uint8_t *out) {
    unsigned long i;
    if (!hw || !out) return 0;
    if (hw_len != (unsigned long)RNG_HW_LEN) return 0;
    for (i = 0u; i < (unsigned long)RNG_HW_LEN; i++) /* bound: RNG_HW_LEN */
        out[i] = (uint8_t)(hw[i] ^ (uint8_t)(rdtime >> ((i % 8u) * 8u)) ^ (uint8_t)(service_delta >> ((i % 8u) * 8u)));
    return 1;
}
#endif
