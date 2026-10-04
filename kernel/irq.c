/* kernel/irq.c - PLIC enable + IRQ route table. No device logic. */
#include "irq.h"
#include "services.h"

static irq_route_t irq_routes[IRQ_ROUTES_MAX];

void irq_init(void)
{
    int i;
    for (i = 0; i < IRQ_ROUTES_MAX; i++)
    { /* bound: IRQ_ROUTES_MAX */
        irq_routes[i].irq = VIRTIO_IRQ_NOT_FOUND;
        irq_routes[i].tid = 0;
        irq_routes[i].kind = IRQ_KIND_NONE;
        irq_routes[i].bits = 0;
    }
}

int irq_bind(uint32_t irq, uint8_t tid, uint8_t kind, uint64_t bits)
{
    int i;
    int empty = -1;
    if (irq == VIRTIO_IRQ_NOT_FOUND)
        return -1;
    if (kind != IRQ_KIND_NET && kind != IRQ_KIND_BLK && kind != IRQ_KIND_INPUT &&
        kind != IRQ_KIND_STUB)
        return -1;
    if (kind != IRQ_KIND_STUB && tid > (uint8_t)T_GUI)
        return -1;
    for (i = 0; i < IRQ_ROUTES_MAX; i++)
    { /* bound: IRQ_ROUTES_MAX */
        if (irq_routes[i].irq == irq)
        {
            irq_routes[i].tid = tid;
            irq_routes[i].kind = kind;
            irq_routes[i].bits = bits;
            return 0;
        }
        if (empty < 0 && irq_routes[i].irq == VIRTIO_IRQ_NOT_FOUND)
            empty = i;
    }
    if (empty < 0)
        return -1;
    irq_routes[empty].irq = irq;
    irq_routes[empty].tid = tid;
    irq_routes[empty].kind = kind;
    irq_routes[empty].bits = bits;
    return 0;
}

int irq_lookup(uint32_t irq, uint8_t *tid, uint8_t *kind, uint64_t *bits)
{
    int i;
    if (irq == 0 || irq == VIRTIO_IRQ_NOT_FOUND)
        return 0;
    for (i = 0; i < IRQ_ROUTES_MAX; i++)
    { /* bound: IRQ_ROUTES_MAX */
        if (irq_routes[i].irq == irq)
        {
            if (tid)
                *tid = irq_routes[i].tid;
            if (kind)
                *kind = irq_routes[i].kind;
            if (bits)
                *bits = irq_routes[i].bits;
            return 1;
        }
    }
    return 0;
}

void irq_plic_enable(uint32_t irq)
{
#if defined(__riscv)
    if (irq == 0 || irq == VIRTIO_IRQ_NOT_FOUND)
        return;
    *(volatile uint32_t *)(PLIC_BASE + 4u * irq) = 1;
    *(volatile uint32_t *)PLIC_ENABLE_M |= (1U << irq);
    *(volatile uint32_t *)PLIC_ENABLE_S |= (1U << irq);
    *(volatile uint32_t *)PLIC_THRESH_M = 0;
    *(volatile uint32_t *)PLIC_THRESH_S = 0;
#else
    (void)irq;
#endif
}
