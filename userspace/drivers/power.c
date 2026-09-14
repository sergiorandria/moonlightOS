/* Power driver - SiFive test-finisher (QEMU riscv-virt 0x100000).
 * Only gets: MMIO Frame cap (finisher reg). No IRQ, no DMA, no kernel
 * access. Replaces the raw poke in kernel/src/boot.c's moonsh hook with a
 * capability-gated compartment: only the cap holder can halt the machine.
 *
 * Protocol: write POWEROFF_CODE (0x5555) to halt, RESET_CODE (0x7777) to
 * reboot. Calls never return on target; on host-sim the request is recorded
 * (and returns) so unit tests can assert without halting the build machine.
 * A two-step arm-then-act sequence guards against stray writes: act without
 * a matching arm is rejected and counted.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "../../kernel/include/cheri.h"
#include "../../kernel/include/cap.h"

#define POWER_BASE_EXPECT 0x100000u
#define POWER_REG_OFF     0x0u
#define POWER_MIN_LEN     0x1000u
#define POWER_POWEROFF    0x5555u
#define POWER_RESET       0x7777u

typedef enum {
    POWER_ACT_NONE = 0,
    POWER_ACT_SHUTDOWN = 1,
    POWER_ACT_REBOOT = 2,
} power_action_t;

typedef struct {
    uintptr_t mmio_base;
    size_t mmio_len;
} power_caps_t;

typedef struct {
    uint64_t shutdowns;
    uint64_t reboots;
    uint64_t rejected; /* act-without-arm + bad-action attempts */
    uint64_t last_action; /* last recorded action (host) or requested */
} power_stats_t;

static power_caps_t pw_caps;
static volatile uint32_t *pw_regs;
#if !defined(__riscv)
static uint32_t host_finisher[4] __attribute__((aligned(4096)));
#endif
static power_stats_t pw_st;
static power_action_t pw_armed;

bool power_driver_init(power_caps_t c) {
    pw_caps = c;
    if (c.mmio_base == 0 || c.mmio_len < POWER_MIN_LEN) return false;
#ifdef __CHERI_PURE_CAPABILITY__
    __capability void *cap = (void *)c.mmio_base;
    if (!__builtin_cheri_tag_get(cap)) return false;
    if (__builtin_cheri_length_get(cap) < c.mmio_len) return false;
    pw_regs = (__capability volatile uint32_t *)cap;
#else
    if (c.mmio_base != POWER_BASE_EXPECT) return false;
#if defined(__riscv)
    pw_regs = (volatile uint32_t *)c.mmio_base;
#else
    memset(host_finisher, 0, sizeof(host_finisher));
    pw_regs = (volatile uint32_t *)host_finisher;
#endif
#endif
    memset(&pw_st, 0, sizeof(pw_st));
    pw_armed = POWER_ACT_NONE;
    return true;
}

/* Arm a power action. Returns false for unknown actions. */
bool power_arm(power_action_t act) {
    if (!pw_regs) return false;
    if (act != POWER_ACT_SHUTDOWN && act != POWER_ACT_REBOOT) return false;
    pw_armed = act;
    return true;
}

/* Act on the armed action: must equal the arm, else rejected + counted.
 * Never returns on target (machine halts); records + returns on host. */
void power_act(power_action_t act) {
    if (!pw_regs) return;
    if (act == POWER_ACT_NONE || act != pw_armed) {
        pw_st.rejected++;
        return;
    }
    pw_armed = POWER_ACT_NONE; /* single-use arm */
    pw_st.last_action = (uint64_t)act;
    if (act == POWER_ACT_SHUTDOWN) {
        pw_st.shutdowns++;
        *pw_regs = POWER_POWEROFF;
    } else {
        pw_st.reboots++;
        *pw_regs = POWER_RESET;
    }
#ifdef __riscv
    __asm__ volatile("fence iorw,iorw" ::: "memory");
    while (1) { __asm__ volatile("wfi"); } /* in case the write didn't take */
#else
    return; /* host-sim: recorded above, machine keeps running */
#endif
}

void power_shutdown(void) { power_act(POWER_ACT_SHUTDOWN); }
void power_reboot(void) { power_act(POWER_ACT_REBOOT); }

void power_driver_stats(power_stats_t *out) {
    if (!out) return;
    *out = pw_st;
}

void power_driver_reboot(void) {
    /* Micro-reboot of the driver itself (not the machine): pending arm
     * cleared, counters reset, same caps. */
    power_caps_t c = pw_caps;
    power_driver_init(c);
}
