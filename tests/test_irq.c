/* tests/test_irq.c - host test of kernel/irq.c (no PLIC). */
#include <stdio.h>
#include "../kernel/irq.c"

#define CHECK(c)                                                               \
    do                                                                         \
    {                                                                          \
        if (!(c))                                                              \
        {                                                                      \
            printf("FAIL line %d: %s\n", __LINE__, #c);                        \
            return 1;                                                          \
        }                                                                      \
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
    puts("PASS: test_irq");
    return 0;
}
