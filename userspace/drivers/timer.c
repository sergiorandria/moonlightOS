/* Timer driver - RISC-V CLINT (0x02000000, hart 0), M-mode machine timer.
 * Only gets: MMIO Frame cap (CLINT regs). No DMA, no kernel access,
 * crash -> micro-reboot (compare re-armed, tick count preserved or reset
 * by policy below: preserved, so the scheduler never sees time go back).
 *
 * Layout: MSIP 0x0000 | MTIMECMP(hart0) 0x4000 | MTIME 0xBFF8.
 * Core is plain C (host-testable via a software tick model); MMIO is
 * __riscv-only. All calls O(1). Slice default matches the kernel's
 * TIMER_SLICE_TICKS (100k) so scheduler behavior is unchanged.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "../abi/cheri.h"
#include "../abi/cap.h"

#define CLINT_BASE_EXPECT 0x02000000u
#define CLINT_MSIP_OFF    0x0000u
#define CLINT_MTIMECMP0   0x4000u
#define CLINT_MTIME_OFF   0xBFF8u
#define CLINT_MIN_LEN     0xC000u
#define TIMER_SLICE_TICKS 100000u
#define TIMER_MTIME_HZ    10000000u /* QEMU virt timebase */

typedef struct {
    uintptr_t mmio_base;
    size_t mmio_len;
} timer_caps_t;

typedef struct {
    uint64_t ticks;      /* timer interrupts since init (monotonic) */
    uint64_t rearms;     /* compare re-programs */
    uint64_t overruns;   /* polls that found MTIP already pending */
    uint64_t slices;     /* slices armed */
    uint64_t last_now;   /* last mtime observed */
} timer_stats_t;

static timer_caps_t t_caps;
static volatile uint8_t *t_regs;
#if !defined(__riscv)
static uint8_t host_clint[CLINT_MIN_LEN] __attribute__((aligned(4096)));
static uint64_t host_mtime;
#endif
static timer_stats_t t_st;
static uint64_t t_slice = TIMER_SLICE_TICKS;

static inline uint64_t t_rd64(uint32_t off) {
#if defined(__riscv)
    return *(volatile uint64_t *)(t_regs + off);
#else
    uint64_t v;
    memcpy(&v, (const void *)(t_regs + off), sizeof(v));
    (void)off;
    return v;
#endif
}

static inline void t_wr64(uint32_t off, uint64_t v) {
#if defined(__riscv)
    *(volatile uint64_t *)(t_regs + off) = v;
#else
    memcpy((void *)(t_regs + off), &v, sizeof(v));
#endif
}

bool timer_driver_init(timer_caps_t c) {
    t_regs = NULL;
    memset(&t_caps, 0, sizeof(t_caps));
    if (c.mmio_base == 0 || c.mmio_len < CLINT_MIN_LEN) return false;
#ifdef __CHERI_PURE_CAPABILITY__
    __capability void *cap = (void *)c.mmio_base;
    if (!__builtin_cheri_tag_get(cap)) return false;
    if (__builtin_cheri_length_get(cap) < c.mmio_len) return false;
    t_regs = (__capability volatile uint8_t *)cap;
#else
    if (c.mmio_base != CLINT_BASE_EXPECT) return false;
#if defined(__riscv)
    t_regs = (volatile uint8_t *)c.mmio_base;
#else
    memset(host_clint, 0, sizeof(host_clint));
    t_regs = (volatile uint8_t *)host_clint;
    host_mtime = 0;
#endif
#endif
    t_caps = c;
    /* ticks preserved across micro-reboot by design (see reboot below);
     * fresh init starts at zero. */
    t_slice = TIMER_SLICE_TICKS;
    return true;
}

/* Current time (mtime ticks). */
uint64_t timer_now(void) {
    if (!t_regs) return 0;
#if !defined(__riscv)
    /* Host model: mtime advances only via timer_sim_advance. */
    uint64_t v = host_mtime;
    t_wr64(CLINT_MTIME_OFF, v);
#else
    uint64_t v = t_rd64(CLINT_MTIME_OFF);
#endif
    t_st.last_now = v;
    return v;
}

/* Test hook: advance the software mtime by dt ticks. */
void timer_sim_advance(uint64_t dt) {
#if !defined(__riscv)
    host_mtime += dt;
    t_wr64(CLINT_MTIME_OFF, host_mtime);
#else
    (void)dt;
#endif
}

/* Arm the next slice `slice` ticks ahead of now. */
void timer_arm(uint64_t slice) {
    if (!t_regs || slice == 0) return;
    t_slice = slice;
    uint64_t now = timer_now();
    uint64_t deadline = slice > UINT64_MAX - now ? UINT64_MAX : now + slice;
    t_wr64(CLINT_MTIMECMP0, deadline);
    t_st.slices++;
    t_st.rearms++;
}

/* True when the compare has fired (mtime >= mtimecmp). */
bool timer_pending(void) {
    if (!t_regs) return false;
    return timer_now() >= t_rd64(CLINT_MTIMECMP0);
}

/* Handle one timer tick: if fired, count it and re-arm one slice ahead.
 * Returns 1 when a tick fired, 0 otherwise. MTIP clears when the compare
 * moves ahead of mtime (no separate clear register on CLINT). */
int timer_driver_handle_irq(void) {
    if (!t_regs) return 0;
    if (!timer_pending()) return 0;
    uint64_t now = timer_now();
    uint64_t cmp = t_rd64(CLINT_MTIMECMP0);
    if (now < cmp) {
        t_st.overruns++; /* raced: fired bit set but compare still ahead */
        return 0;
    }
    t_st.ticks++;
    /* Catch up whole slices so a long-blackout tick doesn't burst: the
     * next compare is strictly ahead of now (bounded single re-arm). */
    uint64_t next = t_slice > UINT64_MAX - now ? UINT64_MAX : now + t_slice;
    if (next <= now && now != UINT64_MAX)
        next = UINT64_MAX;
    t_wr64(CLINT_MTIMECMP0, next);
    t_st.rearms++;
    return 1;
}

uint64_t timer_ticks(void) { return t_st.ticks; }

void timer_driver_stats(timer_stats_t *out) {
    if (!out) return;
    *out = t_st;
}

void timer_driver_reboot(void) {
    /* Micro-reboot: compare re-armed from the preserved tick base so time
     * never goes backwards for scheduler consumers. FIFOs: none. */
    uint64_t ticks = t_st.ticks;
    uint64_t slices = t_st.slices;
    timer_caps_t c = t_caps;
    uint64_t slice = t_slice;
    timer_driver_init(c);
    t_st.ticks = ticks;
    t_st.slices = slices;
    timer_arm(slice);
}
