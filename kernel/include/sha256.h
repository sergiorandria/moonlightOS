#pragma once
/* Freestanding SHA-256 (FIPS 180-4): no libc, no malloc, no static state.
 * Used for DICE measurement; also host-testable (tests/test_dice.c KATs).
 * Incremental API exists so the measured range can exclude the expected-hash
 * slot in two updates (see kernel/src/dice.c). */
#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

typedef struct {
    uint32_t h[8];
    uint64_t total;          /* bytes absorbed so far */
    uint8_t buf[SHA256_BLOCK_SIZE];
    size_t buflen;           /* bytes currently buffered */
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST_SIZE]);

/* One-shot convenience wrapper. */
void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);
