/* kernel/irq.c - PLIC enable + IRQ route table. No device logic.
 *
 * Upstream refs:
 * - RISC-V Privileged Spec Ch.4 (sie: SSIE=bit1, STIE=bit5, SEIE=bit9).
 * - SiFive FU540-C000 PLIC + QEMU `virt` PLIC: priority array at
 *   PLIC_BASE+4*irq, enable array of 32-bit words (word=irq/32,
 *   bit=irq%32), threshold/claim-complete per hart context; source 0
 *   is reserved (claim 0 = "no IRQ").
 * - CHERI RISC-V ISA (purecap): MMIO must go through tagged capabilities
 *   with bounds/perms. Stock builds use integer-derived pointers via the
 *   helpers below; purecap must plumb platform-provided MMIO caps through
 *   those same helpers (single swap point, see irq_plic_reg).
 */
#include <stdint.h>

#include "irq.h"
#include "kinternal.h"
#include "platform.h"
#include "services.h"

/* Critical-section fence around route-table wake transitions. Interrupt
 * gating is RISC-V-only (blk_hal.h precedent): host unit tests compile
 * this TU for x86 (test_irq.c) and take the no-op fallback.
 * Trap entry already clears sstatus.SIE, so inside irq_trap() these only
 * mask STIE/SEIE bits (no M-mode effect); thread-context callers
 * (NOTIFY/WAIT analogues) rely on them for the state transition. */
#ifdef __riscv
static inline void irq_fence_off(void)
{
    asm volatile("csrc sie, %0" ::"r"(SIE_MASK_STIE_SEIE) : "memory"); /* STIE+SEIE */
}

static inline void irq_fence_on(void)
{
    asm volatile("csrs sie, %0" ::"r"(SIE_MASK_STIE_SEIE) : "memory"); /* STIE+SEIE */
}
#else
static inline void irq_fence_off(void)
{
}

static inline void irq_fence_on(void)
{
}
#endif

/* CHERI note: irq_routes[].bits is a plain badge mask (never a pointer).
 * uctx_t.regs[] is uint64_t, so capability tags would not survive a
 * context switch; purecap needs a tag-preserving save area (future work).
 * The handler only touches the route owner tid (no global TCB scan). */

static irq_route_t irq_routes[IRQ_ROUTES_MAX];

/* Host-testable PLIC helpers (also used by the target MMIO path). */
int irq_is_valid_source(uint32_t irq)
{
    if (irq == 0 || irq == VIRTIO_IRQ_NOT_FOUND)
        return 0;
    if (irq >= PLIC_MAX_IRQ)
        return 0;
    return 1;
}

uint32_t irq_enable_word(uint32_t irq)
{
    return irq / 32u;
}

uint32_t irq_enable_bit(uint32_t irq)
{
    return 1u << (irq % 32u);
}

int irq_claim_matches(uint32_t claim, uint32_t dev_irq)
{
    if (claim == 0 || claim == VIRTIO_IRQ_NOT_FOUND)
        return 0;
    if (dev_irq == 0 || dev_irq == VIRTIO_IRQ_NOT_FOUND)
        return 0;
    return claim == dev_irq;
}

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
    if (!irq_is_valid_source(irq))
        return -1;
    if (kind != IRQ_KIND_NET && kind != IRQ_KIND_BLK && kind != IRQ_KIND_INPUT && kind != IRQ_KIND_STUB)
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

#ifdef __riscv
/* MMIO single swap point. Stock: integer-derived pointer (QEMU virt PLIC
 * is identity-mapped for S-mode). Purecap TODO: replace the casts below
 * with platform-provided __capability MMIO caps (tagged, bounded to the
 * PLIC window, RW, no X/CAP-store); integer-derived caps fault. */
static inline volatile uint32_t *irq_plic_reg(uintptr_t addr)
{
#ifdef __CHERI_PURE_CAPABILITY__
    /* Placeholder shape (mirrors userspace/drivers/plic.c purecap path):
     * derive from the platform MMIO cap once it exists. */
    __capability volatile uint32_t *cap = (__capability volatile uint32_t *)(void *)addr;
    return (volatile uint32_t *)cap;
#else
    return (volatile uint32_t *)addr;
#endif
}
#endif

void irq_plic_enable(uint32_t irq)
{
#if defined(__riscv)
    volatile uint32_t *prio;
    volatile uint32_t *en_m;
    volatile uint32_t *en_s;
    volatile uint32_t *th_m;
    volatile uint32_t *th_s;
    uint32_t w;
    uint32_t b;
    uint32_t v;
    if (!irq_is_valid_source(irq))
        return;
    w = irq_enable_word(irq);
    b = irq_enable_bit(irq);
    /* Boot-only: called from device_init before SIE is enabled (single
     * hart). The |= RMW is safe there; SMP configuration needs a lock. */
    prio = irq_plic_reg((uintptr_t)PLIC_BASE + (uintptr_t)4u * (uintptr_t)irq);
    en_m = irq_plic_reg((uintptr_t)PLIC_ENABLE_M + (uintptr_t)w * 4u);
    en_s = irq_plic_reg((uintptr_t)PLIC_ENABLE_S + (uintptr_t)w * 4u);
    th_m = irq_plic_reg((uintptr_t)PLIC_THRESH_M);
    th_s = irq_plic_reg((uintptr_t)PLIC_THRESH_S);
    *prio = 1;
    v = *en_m;
    *en_m = v | b;
    v = *en_s;
    *en_s = v | b;
    *th_m = 0;
    *th_s = 0;
    asm volatile("fence iorw,iorw" ::: "memory"); /* order MMIO before SIE on */
#else
    (void)irq;
#endif
}

#ifdef __riscv /* target-only: PLIC MMIO + thread table (host test covers the route table above) */
/* irq_trap: S-mode external IRQ via PLIC claim (S-mode external: virtio
 * IRQ via PLIC claim). Either context may carry the delivery (measured:
 * S does); net/blk/input are served independently so one trap can serve
 * several devices. Route-table driven: the owner tid + badge come from
 * irq_lookup, never from hardcoded thread indices. No device logic here
 * (kernel.h irq.c contract).
 *
 * Single-hart assumption: route writes happen at boot (device_init, SIE
 * off); trap reads are race-free while sstatus.SIE is clear on entry.
 * SMP needs atomics/locks around threads[].notify/state. */
void irq_trap(void)
{
    uint32_t s = *irq_plic_reg((uintptr_t)PLIC_CLAIM_S);
    uint32_t m = *irq_plic_reg((uintptr_t)PLIC_CLAIM_M);
    uint32_t claims[2];
    int served_any = 0;
    int woken[NTHREADS];
    int i;
    claims[0] = s;
    claims[1] = m;
    for (i = 0; i < NTHREADS; i++)
        woken[i] = 0;
    for (i = 0; i < 2; i++)
    { /* bound: 2 PLIC contexts */
        uint32_t c = claims[i];
        uint8_t tid = 0;
        uint8_t kind = IRQ_KIND_NONE;
        uint64_t bits = 0;
        if (c == 0)
            continue; /* spurious/empty claim: never matches, never wakes */
        if (!irq_lookup(c, &tid, &kind, &bits))
            continue; /* unknown source: fail-closed, counted below */
        served_any = 1;
        if (kind == IRQ_KIND_STUB)
            continue; /* known, no owner yet: complete silently */
        if (!irq_kind_wakes(kind))
            continue;
        if (tid >= (uint8_t)NTHREADS)
            continue;
        threads[tid].notify |= bits;
        /* NOTIFY discipline: wake only genuine WAIT waiters. Uniform
         * wake-delivery for all kinds (sys_notify precedent): a thread
         * woken from WAIT resumes past the ecall with stale a0, so
         * pre-deliver pending bits as its WAIT return; pending stays
         * set, so a re-WAIT still collects. */
        if (threads[tid].state == T_BLOCKED && threads[tid].wait_kind == V2_WK_WAIT)
        {
            irq_fence_off();
            threads[tid].state = T_RUNNABLE;
            threads[tid].wait_kind = V2_WK_NONE;
            threads[tid].regs[10] = threads[tid].notify;
            irq_fence_on();
            woken[tid] = 1;
        }
        else if (woken[tid])
        {
            /* Coalesce: second source for the same owner in one trap
             * (e.g. kbd+mouse -> tid 10) refreshes the pre-delivered
             * return so the first wake does not drop the second bit. */
            threads[tid].regs[10] = threads[tid].notify;
        }
    }
    if ((s != 0 || m != 0) && !served_any)
        kputs("IRQ: unexpected\n");
    if (s != 0)
        *irq_plic_reg((uintptr_t)PLIC_CLAIM_S) = s;
    if (m != 0)
        *irq_plic_reg((uintptr_t)PLIC_CLAIM_M) = m;
    /* Halt-context return guard: if this trap was taken from
     * halt (cur_ctx == &halt_ctx: idle wfi, S-origin), the
     * trap.S epilogue would restore the zeroed halt save area
     * (sepc=0, sp=0) and sret into a fault — then re-trap from
     * S-mode and corrupt the entry swap (burst-race signature).
     * Never return from a halt entry: schedule a woken thread,
     * or re-park (halt_no_runnable re-arms the halt protocol:
     * cur_ctx, sscratch, SIE, timer-max). This is the only
     * schedule-from-handler path (net/blk/input all ride it). */
    if (cur_ctx == &halt_ctx)
    {
        int n = pick_next();
        if (n >= 0)
            enter_thread(n);
        halt_no_runnable();
    }
    return;
}

#endif /* __riscv: irq_trap */
