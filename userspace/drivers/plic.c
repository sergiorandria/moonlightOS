/* PLIC driver - RISC-V Platform-Level Interrupt Controller (0x0c000000).
 * Only gets: MMIO Frame cap (PLIC regs), per-IRQ bindings to Notification
 * badges (mirrors kernel irq.c bookkeeping, but programs real HW).
 * No kernel access, crash -> micro-reboot (bindings cleared, threshold kept).
 *
 * Hart0 M-mode context 0 layout (riscv-virt, 240+ sources wired):
 *   priority[i]  0x000000 + 4*i | pending 0x001000 | enable[hart0] 0x002000
 *   threshold    0x200000       | claim/complete  0x200004
 * Core is plain C (host-testable); MMIO is __riscv-only. Claim/complete
 * and dispatch are bounded (32 IRQs per handle call).
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "../abi/cheri.h"
#include "../abi/cap.h"

#define PLIC_BASE_EXPECT 0x0c000000u
#define PLIC_PRIO_OFF   0x000000u
#define PLIC_PEND_OFF   0x001000u
#define PLIC_ENABLE_OFF 0x002000u
#define PLIC_THRESH_OFF 0x200000u
#define PLIC_CLAIM_OFF  0x200004u
#define PLIC_MIN_LEN    0x200008u
#define PLIC_MAX_IRQ    64u
#define PLIC_MAX_DISPATCH 32u

typedef struct {
    uintptr_t mmio_base;
    size_t mmio_len;
} plic_caps_t;

typedef struct {
    bool bound;
    uint32_t badge;
    uint32_t ntfn_id;
} plic_binding_t;

typedef struct {
    uint64_t claims;
    uint64_t completes;
    uint64_t spurious;
    uint64_t disabled_drops;
    uint64_t irqs;
} plic_stats_t;

static plic_caps_t p_caps;
static volatile uint32_t *p_regs;
#if !defined(__riscv)
static uint32_t host_plic[PLIC_MIN_LEN / 4u] __attribute__((aligned(4096)));
#endif
static plic_binding_t p_bind[PLIC_MAX_IRQ];
static plic_stats_t p_st;
static uint32_t p_threshold;

static inline uint32_t p_rd(uint32_t off) {
    return *(volatile uint32_t *)((uintptr_t)p_regs + off);
}

static inline void p_wr(uint32_t off, uint32_t v) {
    *(volatile uint32_t *)((uintptr_t)p_regs + off) = v;
}

bool plic_driver_init(plic_caps_t c) {
    p_caps = c;
    if (c.mmio_base == 0 || c.mmio_len < PLIC_MIN_LEN) return false;
#ifdef __CHERI_PURE_CAPABILITY__
    __capability void *cap = (void *)c.mmio_base;
    if (!__builtin_cheri_tag_get(cap)) return false;
    if (__builtin_cheri_length_get(cap) < c.mmio_len) return false;
    p_regs = (__capability volatile uint32_t *)cap;
#else
    if (c.mmio_base != PLIC_BASE_EXPECT) return false;
#if defined(__riscv)
    p_regs = (volatile uint32_t *)c.mmio_base;
#else
    memset(host_plic, 0, sizeof(host_plic));
    p_regs = (volatile uint32_t *)host_plic;
#endif
#endif
    memset(p_bind, 0, sizeof(p_bind));
    memset(&p_st, 0, sizeof(p_st));
    p_threshold = 0;
    p_wr(PLIC_THRESH_OFF, 0u);
    return true;
}

/* Priority 1..7 (0 = never interrupt). IRQ 0 is reserved (spurious). */
bool plic_set_priority(uint32_t irq, uint32_t prio) {
    if (!p_regs || irq == 0 || irq >= PLIC_MAX_IRQ || prio > 7u) return false;
    p_wr(PLIC_PRIO_OFF + irq * 4u, prio);
    return true;
}

bool plic_enable(uint32_t irq) {
    if (!p_regs || irq == 0 || irq >= PLIC_MAX_IRQ) return false;
    uint32_t w = p_rd(PLIC_ENABLE_OFF + (irq / 32u) * 4u);
    w |= 1u << (irq % 32u);
    p_wr(PLIC_ENABLE_OFF + (irq / 32u) * 4u, w);
    return true;
}

bool plic_disable(uint32_t irq) {
    if (!p_regs || irq == 0 || irq >= PLIC_MAX_IRQ) return false;
    uint32_t w = p_rd(PLIC_ENABLE_OFF + (irq / 32u) * 4u);
    w &= ~(1u << (irq % 32u));
    p_wr(PLIC_ENABLE_OFF + (irq / 32u) * 4u, w);
    return true;
}

bool plic_set_threshold(uint32_t t) {
    if (!p_regs || t > 7u) return false;
    p_threshold = t;
    p_wr(PLIC_THRESH_OFF, t);
    return true;
}

/* Bind an IRQ to a notification badge (mirrors kernel irq_bind). */
bool plic_bind(uint32_t irq, uint32_t ntfn_id, uint32_t badge) {
    if (!p_regs || irq == 0 || irq >= PLIC_MAX_IRQ) return false;
    if (p_bind[irq].bound) return false;
    p_bind[irq].bound = true;
    p_bind[irq].ntfn_id = ntfn_id;
    p_bind[irq].badge = badge;
    return true;
}

bool plic_unbind(uint32_t irq) {
    if (!p_regs || irq == 0 || irq >= PLIC_MAX_IRQ) return false;
    if (!p_bind[irq].bound) return false;
    memset(&p_bind[irq], 0, sizeof(plic_binding_t));
    return true;
}

/* Claim the highest-priority pending IRQ (0 = none/spurious). */
uint32_t plic_claim(void); /* forward (arbitration helper below) */
void plic_complete(uint32_t irq); /* forward */

#if !defined(__riscv)
/* Host model of PLIC arbitration: the claim register always presents the
 * lowest pending IRQ (real HW re-arbitrates on claim/complete the same
 * way). Bounded O(64) scan per call. */
static void plic_arbitrate(void) {
    for (uint32_t irq = 1; irq < PLIC_MAX_IRQ; irq++) {
        uint32_t w = p_rd(PLIC_PEND_OFF + (irq / 32u) * 4u);
        if (w & (1u << (irq % 32u))) {
            p_wr(PLIC_CLAIM_OFF, irq);
            return;
        }
    }
    p_wr(PLIC_CLAIM_OFF, 0u);
}
#endif

/* Claim the highest-priority pending IRQ (0 = none/spurious). */
uint32_t plic_claim(void) {
    if (!p_regs) return 0;
#if !defined(__riscv)
    plic_arbitrate();
#endif
    uint32_t id = p_rd(PLIC_CLAIM_OFF);
    if (id != 0 && id < PLIC_MAX_IRQ) p_st.claims++;
    else p_st.spurious++;
    return id;
}

void plic_complete(uint32_t irq) {
    if (!p_regs || irq == 0 || irq >= PLIC_MAX_IRQ) return;
    p_wr(PLIC_CLAIM_OFF, irq);
    p_st.completes++;
#if !defined(__riscv)
    /* The consumer clears the serviced pending bit before completing
     * (see plic_handle); re-arbitrate so the claim register presents
     * the next pending IRQ, or 0 when idle. */
    plic_arbitrate();
#endif
}

/* Test hook: force a pending bit as if the device raised its line. */
void plic_sim_raise(uint32_t irq) {
    if (irq == 0 || irq >= PLIC_MAX_IRQ) return;
    uint32_t w = p_rd(PLIC_PEND_OFF + (irq / 32u) * 4u);
    w |= 1u << (irq % 32u);
    p_wr(PLIC_PEND_OFF + (irq / 32u) * 4u, w);
}

/* Dispatch pending IRQs to their notification badges (bounded).
 * Returns dispatched count; out_badges gets (ntfn_id, badge) pairs. */
uint16_t plic_handle(uint32_t *out_ntfn, uint32_t *out_badge, uint16_t cap) {
    uint16_t n = 0;
    if (!p_regs) return 0;
    p_st.irqs++;
    while (n < PLIC_MAX_DISPATCH && (uint32_t)n < cap) {
        uint32_t id = plic_claim();
        if (id == 0 || id >= PLIC_MAX_IRQ) break; /* none left / spurious */
        /* Clear the sim pending bit (real HW clears on claim). */
#if !defined(__riscv)
        {
            uint32_t w = p_rd(PLIC_PEND_OFF + (id / 32u) * 4u);
            w &= ~(1u << (id % 32u));
            p_wr(PLIC_PEND_OFF + (id / 32u) * 4u, w);
            p_wr(PLIC_CLAIM_OFF, 0u);
        }
#endif
        if (p_bind[id].bound) {
            if (out_ntfn) out_ntfn[n] = p_bind[id].ntfn_id;
            if (out_badge) out_badge[n] = p_bind[id].badge;
            n++;
        } else {
            p_st.disabled_drops++;
        }
        plic_complete(id);
    }
    return n;
}

void plic_driver_stats(plic_stats_t *out) {
    if (!out) return;
    *out = p_st;
}

void plic_driver_reboot(void) {
    /* Micro-reboot: bindings cleared (re-acquired via mem_server caps),
     * threshold restored, priorities left to re-init by the owner. */
    uint32_t t = p_threshold;
    plic_driver_init(p_caps);
    if (t) plic_set_threshold(t);
}
