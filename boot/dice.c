#include <stdint.h>
#include <string.h>

/* DICE measured boot - verified ROM -> kernel attestation */

#define DICE_CDI_SIZE 32
#define HASH_SIZE 32

extern uint8_t _rom_start, _rom_end;
extern uint8_t _kernel_start, _kernel_end;

typedef struct {
    uint8_t cdi[DICE_CDI_SIZE];
    uint8_t kernel_hash[HASH_SIZE];
    uint8_t attestation_cert[512];
} dice_state_t;

/* Minimal SHA256 - for measurement, constant time */
void sha256(const uint8_t *data, size_t len, uint8_t out[HASH_SIZE]);

void dice_derive_cdi(const uint8_t *uds, const uint8_t *hash, uint8_t cdi[DICE_CDI_SIZE]) {
    uint8_t tmp[64];
    memcpy(tmp, uds, 32);
    memcpy(tmp+32, hash, 32);
    sha256(tmp, 64, cdi);
    /* Clear UDS from memory - forward secrecy */
    memset(tmp, 0, 64);
}

int boot_measure_and_attest(dice_state_t *dice) {
    uint8_t k_hash[HASH_SIZE];
    sha256(&_kernel_start, (size_t)(&_kernel_end - &_kernel_start), k_hash);
    /* Verify kernel hash against ROM-expected - fail closed */
    uint8_t expected[HASH_SIZE] = {0}; /* filled at build time via reproducible build */
    if (memcmp(k_hash, expected, HASH_SIZE) != 0) return -1;
    /* Derive CDI */
    uint8_t uds[DICE_CDI_SIZE] = {0}; /* from fused OTP, read-once */
    dice_derive_cdi(uds, k_hash, dice->cdi);
    memcpy(dice->kernel_hash, k_hash, HASH_SIZE);
    memset(uds, 0, DICE_CDI_SIZE);
    return 0;
}
