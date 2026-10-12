/* tests/test_irq.c - host test of kernel/irq.c (no PLIC). */
#include "../kernel/irq.c"
#include <stdio.h>

#define CHECK(c)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(c))                                                                                                      \
        {                                                                                                              \
            printf("FAIL line %d: %s\n", __LINE__, #c);                                                                \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

int main(void)
{
    uint8_t tid = 99, kind = 99;
    uint64_t bits = 0;
    irq_init();
    CHECK(!irq_lookup(1, &tid, &kind, &bits));
    CHECK(irq_bind(VIRTIO_IRQ_NOT_FOUND, 6, IRQ_KIND_NET, NET_IRQ_BIT) < 0);
    CHECK(irq_bind(1, 6, 99, NET_IRQ_BIT) < 0);
    CHECK(irq_bind(1, 99, IRQ_KIND_NET, NET_IRQ_BIT) < 0);
    CHECK(irq_bind(1, T_NET, IRQ_KIND_NET, NET_IRQ_BIT) == 0);
    CHECK(irq_lookup(1, &tid, &kind, &bits));
    CHECK(tid == T_NET && kind == IRQ_KIND_NET && bits == NET_IRQ_BIT);
    CHECK(irq_kind_wakes(kind));
    CHECK(irq_bind(2, 0, IRQ_KIND_STUB, GPU_IRQ_BIT_RESERVED) == 0);
    CHECK(irq_lookup(2, &tid, &kind, &bits));
    CHECK(kind == IRQ_KIND_STUB);
    CHECK(!irq_kind_wakes(kind));
    CHECK(irq_bind(1, T_NET, IRQ_KIND_NET, NET_IRQ_BIT) == 0); /* update */
    irq_plic_enable(1);

    /* RISC-V correctness (host vectors for target bit math):
     * - PLIC source 0 is reserved (SiFive PLIC spec, QEMU virt).
     * - SIE mask is STIE(bit5)+SEIE(bit9) (RISC-V Priv Spec Ch.4). */
    CHECK(irq_bind(0, T_NET, IRQ_KIND_NET, NET_IRQ_BIT) < 0); /* PLIC 0 reserved */
    CHECK(!irq_lookup(0, &tid, &kind, &bits));
    CHECK(!irq_is_valid_source(0));
    CHECK(!irq_is_valid_source(VIRTIO_IRQ_NOT_FOUND));
    CHECK(irq_is_valid_source(1));
    CHECK(!irq_is_valid_source(PLIC_MAX_IRQ));
    CHECK(irq_bind(PLIC_MAX_IRQ, T_NET, IRQ_KIND_NET, NET_IRQ_BIT) < 0);
    CHECK(irq_bind(PLIC_MAX_IRQ + 100u, T_NET, IRQ_KIND_NET, NET_IRQ_BIT) < 0);

    /* PLIC enable word/bit math (SiFive PLIC: enable array of 32-bit words). */
    CHECK(irq_enable_word(1) == 0u);
    CHECK(irq_enable_bit(1) == (1u << 1));
    CHECK(irq_enable_word(31) == 0u);
    CHECK(irq_enable_bit(31) == (1u << 31));
    CHECK(irq_enable_word(32) == 1u);
    CHECK(irq_enable_bit(32) == (1u << 0));
    CHECK(irq_enable_word(33) == 1u);
    CHECK(irq_enable_bit(33) == (1u << 1));

    /* Spurious-claim guard: PLIC claim 0 means "no IRQ" and must never
     * match a device, even if a device global were ever 0. */
    CHECK(!irq_claim_matches(0, 1));
    CHECK(!irq_claim_matches(1, 0));
    CHECK(!irq_claim_matches(0, 0));
    CHECK(!irq_claim_matches(1, VIRTIO_IRQ_NOT_FOUND));
    CHECK(irq_claim_matches(5, 5));
    CHECK(!irq_claim_matches(5, 6));

    /* SIE fence mask: STIE (bit 5) + SEIE (bit 9), not bits 4+5. */
    CHECK(SIE_MASK_STIE == (1UL << 5));
    CHECK(SIE_MASK_SEIE == (1UL << 9));
    CHECK(SIE_MASK_STIE_SEIE == ((1UL << 5) | (1UL << 9)));

    puts("PASS: test_irq");
    return 0;
}
