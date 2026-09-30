/* tests/test_rng.c - KATs for vault/rng_mix.h + vault/rng_scan.h. */
#include <stdio.h>
#include <stdint.h>
#include "../userspace/vault/rng_mix.h"
#include "../userspace/vault/rng_scan.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void) {
    uint8_t hw[32] = {0};
    uint8_t out[32];
    hw[0] = 0x01u;
    /* mix_ok: full-length inputs accept, short/zero reject. */
    CHECK(rng_mix_ok(hw, 32u, 12345u, 678u, out));
    CHECK(!rng_mix_ok(hw, 0u, 0u, 0u, out));       /* zero HW len */
    CHECK(!rng_mix_ok((void*)0, 32u, 0u, 0u, out)); /* null HW */
    CHECK(!rng_mix_ok(hw, 32u, 0u, 0u, (void*)0));  /* null out */
    /* scan: transport 0 offset 0, transport 7 last, dev-4 match. */
    CHECK(rng_trans_off(0u) == 0x10000000UL);
    CHECK(rng_trans_off(7u) == (0x10000000UL + 7u * 0x2000UL));
    CHECK(rng_trans_off(8u) == 0xFFFFFFFFUL);        /* sentinel OOB */
    CHECK(rng_dev_match(4u));
    CHECK(!rng_dev_match(1u));                       /* net, not rng */
    CHECK(!rng_dev_match(2u));                       /* blk, not rng */
    printf("PASS: test_rng\n");
    return 0;
}
