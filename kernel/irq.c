/* kernel/irq.c - PLIC enable + IRQ route table. No device logic. */
#include <stdint.h>

#include "irq.h"
#include "services.h"
#include "platform.h"
#include "kinternal.h"

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


/* irq_trap: S-mode external IRQ via PLIC claim (S-mode external: virtio
 * IRQ via PLIC claim). Either context may carry the delivery (measured:
 * S does); net and blk are served independently so one trap can serve
 * both devices. No device logic here (kernel.h irq.c contract). */
void irq_trap(void)
{
    uint32_t s = *(volatile uint32_t *)PLIC_CLAIM_S;
    uint32_t m = *(volatile uint32_t *)PLIC_CLAIM_M;
    uint32_t src = 0;
    int blk = 0;
    /* Either context may carry the delivery (measured: S does);
     * one marker per trap even if both fired. Net and blk are
     * handled independently so one trap can serve both devices. */
    if (s == net_virtio_irq)
        src = s;
    else if (m == net_virtio_irq)
        src = m;
    if (s == blk_virtio_irq || m == blk_virtio_irq)
        blk = 1;
    if (src != 0)
    {
        threads[6].notify |= NET_IRQ_BIT;
        /* Wake only genuine WAIT waiters (NOTIFY discipline);
         * unknown sources never wake anyone. 
         * Disable interrupts during state transition to prevent race. */
        if (threads[6].state == T_BLOCKED && threads[6].wait_kind == V2_WK_WAIT)
        {
            asm volatile("csrc sie, %0" ::"r"(3UL << 4) : "memory");  /* Disable STIE+SEIE */
            threads[6].state = T_RUNNABLE;
            threads[6].wait_kind = V2_WK_NONE;
            asm volatile("csrs sie, %0" ::"r"(3UL << 4) : "memory");  /* Re-enable STIE+SEIE */
        }
        kputs("NET: irq ok\n");
    }
    if (blk)
    {
        /* No per-IRQ print: a 4K sector op raises up to 8 blk
         * IRQs, so a print here would flood the transcript; the
         * ELF's badge check after WAIT is the delivery proof. */
        threads[9].notify |= BLK_IRQ_BIT;
        /* Disable interrupts during state transition to prevent race. */
        if (threads[9].state == T_BLOCKED && threads[9].wait_kind == V2_WK_WAIT)
        {
            asm volatile("csrc sie, %0" ::"r"(3UL << 4) : "memory");  /* Disable STIE+SEIE */
            threads[9].state = T_RUNNABLE;
            threads[9].wait_kind = V2_WK_NONE;
            asm volatile("csrs sie, %0" ::"r"(3UL << 4) : "memory");  /* Re-enable STIE+SEIE */
        }
    }
    /* S4c VirtIO input IRQs: keyboard and mouse for GUI qube (tid 10).
     * Delivered independently; one trap can serve both if they fire
     * together (QEMU can queue IRQs). Notify bits are or'd so the
     * WAIT badge check detects either source. No per-IRQ print: typing
     * generates high-frequency IRQs that would flood the transcript;
     * the ELF's event poll after WAIT is the delivery proof. */
    int input_irq = 0;
    int input_woke = 0;
    if (s == kbd_virtio_irq || m == kbd_virtio_irq)
    {
        threads[10].notify |= KBD_IRQ_BIT;
        input_irq = 1;
    }
    if (s == mouse_virtio_irq || m == mouse_virtio_irq)
    {
        threads[10].notify |= MOUSE_IRQ_BIT;
        input_irq = 1;
    }
    if (input_irq)
    {
        /* Disable interrupts during state transition to prevent race. */
        if (threads[10].state == T_BLOCKED && threads[10].wait_kind == V2_WK_WAIT)
        {
            asm volatile("csrc sie, %0" ::"r"(3UL << 4) : "memory");  /* Disable STIE+SEIE */
            threads[10].state = T_RUNNABLE;
            threads[10].wait_kind = V2_WK_NONE;
            /* Wake-delivery (NOTIFY precedent): a thread woken
             * from WAIT resumes past the ecall with stale a0, so
             * pre-deliver the pending bits as its WAIT return;
             * pending stays set, so a re-WAIT still collects. */
            threads[10].regs[10] = threads[10].notify;
            asm volatile("csrs sie, %0" ::"r"(3UL << 4) : "memory");  /* Re-enable STIE+SEIE */
            input_woke = 1;
        }
    }
    if (src == 0 && !blk && !input_irq)
    {
        uint8_t kind = IRQ_KIND_NONE;
        int stub = 0;
        if (irq_lookup(s, 0, &kind, 0) && kind == IRQ_KIND_STUB)
            stub = 1;
        else if (irq_lookup(m, 0, &kind, 0) && kind == IRQ_KIND_STUB)
            stub = 1;
        if (!stub)
            kputs("IRQ: unexpected\n");
    }
    if (s != 0)
        *(volatile uint32_t *)PLIC_CLAIM_S = s;
    if (m != 0)
        *(volatile uint32_t *)PLIC_CLAIM_M = m;
    /* S4c live input (Task 4): a post-halt wake leaves nobody
     * scheduled (halt is not a thread) — run the woken server
     * now (SEND-handoff precedent: enter_thread from handler).
     * Pre-park this only fires for a WAIT-blocked input server
     * and is a no-op for everyone else. */
    if (input_woke)
    {
        int n = pick_next();
        if (n >= 0)
            enter_thread(n);
    }
    /* Halt-context return guard: if this trap was taken from
     * halt (cur_ctx == &halt_ctx: idle wfi, S-origin), the
     * trap.S epilogue would restore the zeroed halt save area
     * (sepc=0, sp=0) and sret into a fault — then re-trap from
     * S-mode and corrupt the entry swap (burst-race signature).
     * Never return from a halt entry: schedule a woken thread,
     * or re-park (halt_no_runnable re-arms the halt protocol:
     * cur_ctx, sscratch, SIE, timer-max). */
    if (cur_ctx == &halt_ctx)
    {
        int n = pick_next();
        if (n >= 0)
            enter_thread(n);
        halt_no_runnable();
    }
    return;
}
