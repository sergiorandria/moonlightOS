/* RTC driver - Goldfish RTC (QEMU riscv-virt 0x101000), IOMMU-free MMIO+IRQ.
 * Only gets: MMIO Frame cap (RTC regs), IRQ cap (alarm). No kernel access,
 * crash -> micro-reboot (alarm re-armed from preserved deadline, the
 * device-owned wall clock itself never stops).
 *
 * Registers: TIME_LOW 0x00, TIME_HIGH 0x04, ALARM_LOW 0x08, ALARM_HIGH 0x0C,
 * IRQ_ENABLED 0x10, CLEAR_ALARM 0x14, ALARM_STATUS 0x18, CLEAR_INT 0x1C.
 * Time base: nanoseconds since the Unix epoch. 64-bit reads use hi-lo-hi
 * sampling so a rollover mid-read retries instead of tearing.
 * Core is plain C (host-testable); MMIO is __riscv-only. All calls O(1).
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "../../kernel/include/cheri.h"
#include "../../kernel/include/cap.h"

#define RTC_BASE_EXPECT 0x101000u
#define RTC_TIME_LOW    0x00u
#define RTC_TIME_HIGH   0x04u
#define RTC_ALARM_LOW   0x08u
#define RTC_ALARM_HIGH  0x0cu
#define RTC_IRQ_EN      0x10u
#define RTC_CLEAR_ALARM 0x14u
#define RTC_ALARM_STAT  0x18u
#define RTC_CLEAR_INT   0x1cu
#define RTC_MIN_LEN     0x20u
#define RTC_VIRT_IRQ    11u
#define RTC_NS_PER_S    1000000000ull

typedef struct {
    uintptr_t mmio_base;
    size_t mmio_len;
    uint32_t irq; /* expect RTC_VIRT_IRQ on riscv-virt */
} rtc_caps_t;

typedef struct {
    uint64_t reads;
    uint64_t alarms_set;
    uint64_t alarms_fired;
    uint64_t irqs;
    uint64_t torn_retries;
    uint64_t last_alarm_ns;
} rtc_stats_t;

static rtc_caps_t r_caps;
static volatile uint32_t *r_regs;
#if !defined(__riscv)
static uint32_t host_rtc[8] __attribute__((aligned(4096)));
static uint64_t host_ns;
#endif
static rtc_stats_t r_st;
static bool r_alarm_armed;
static uint64_t r_alarm_ns;

static inline uint32_t r_rd(uint32_t off) {
    return *(volatile uint32_t *)((uintptr_t)r_regs + off);
}

static inline void r_wr(uint32_t off, uint32_t v) {
    *(volatile uint32_t *)((uintptr_t)r_regs + off) = v;
}

bool rtc_driver_init(rtc_caps_t c) {
    r_caps = c;
    if (c.mmio_base == 0 || c.mmio_len < RTC_MIN_LEN) return false;
#ifdef __CHERI_PURE_CAPABILITY__
    __capability void *cap = (void *)c.mmio_base;
    if (!__builtin_cheri_tag_get(cap)) return false;
    if (__builtin_cheri_length_get(cap) < c.mmio_len) return false;
    r_regs = (__capability volatile uint32_t *)cap;
#else
    if (c.mmio_base != RTC_BASE_EXPECT) return false;
#if defined(__riscv)
    r_regs = (volatile uint32_t *)c.mmio_base;
#else
    /* Host model: the device-owned wall clock persists across init and
     * reboot (real HW time never resets); only the alarm state is fresh. */
    memset(host_rtc, 0, sizeof(host_rtc));
    r_regs = (volatile uint32_t *)host_rtc;
    host_rtc[RTC_TIME_LOW / 4u] = (uint32_t)(host_ns & 0xffffffffu);
    host_rtc[RTC_TIME_HIGH / 4u] = (uint32_t)(host_ns >> 32);
#endif
#endif
    memset(&r_st, 0, sizeof(r_st));
    r_alarm_armed = false;
    r_alarm_ns = 0;
    r_wr(RTC_IRQ_EN, 0u);
    r_wr(RTC_CLEAR_ALARM, 1u);
    return true;
}

/* Current wall-clock time in nanoseconds (torn-read safe). */
uint64_t rtc_now_ns(void) {
    if (!r_regs) return 0;
    for (int i = 0; i < 3; i++) {
        uint32_t hi1 = r_rd(RTC_TIME_HIGH);
        uint32_t lo = r_rd(RTC_TIME_LOW);
        uint32_t hi2 = r_rd(RTC_TIME_HIGH);
        if (hi1 == hi2) {
            r_st.reads++;
            return ((uint64_t)hi1 << 32) | lo;
        }
        r_st.torn_retries++;
    }
    /* Persistent rollover storm (pathological): return the latest sample. */
    r_st.reads++;
    return ((uint64_t)r_rd(RTC_TIME_HIGH) << 32) | r_rd(RTC_TIME_LOW);
}

uint64_t rtc_now_s(void) {
    return rtc_now_ns() / RTC_NS_PER_S;
}

/* Test hook: advance the software clock (host) / no-op on target. */
void rtc_sim_advance(uint64_t dns) {
#if !defined(__riscv)
    host_ns += dns;
    host_rtc[RTC_TIME_LOW / 4u] = (uint32_t)(host_ns & 0xffffffffu);
    host_rtc[RTC_TIME_HIGH / 4u] = (uint32_t)(host_ns >> 32);
    /* Model alarm firing: device sets status when now >= alarm. */
    if (r_alarm_armed && host_ns >= r_alarm_ns)
        host_rtc[RTC_ALARM_STAT / 4u] = 1u;
#else
    (void)dns;
#endif
}

/* Arm a one-shot alarm ns nanoseconds from now (0 disarms). */
bool rtc_set_alarm_ns(uint64_t dns) {
    if (!r_regs) return false;
    if (dns == 0) {
        r_wr(RTC_CLEAR_ALARM, 1u);
        r_wr(RTC_IRQ_EN, 0u);
        r_alarm_armed = false;
        return true;
    }
    uint64_t at = rtc_now_ns() + dns;
    if (at < rtc_now_ns()) return false; /* wrap: unreachable deadline */
    r_wr(RTC_ALARM_LOW, (uint32_t)(at & 0xffffffffu));
    r_wr(RTC_ALARM_HIGH, (uint32_t)(at >> 32));
    r_wr(RTC_IRQ_EN, 1u);
    r_alarm_armed = true;
    r_alarm_ns = at;
    r_st.alarms_set++;
    r_st.last_alarm_ns = at;
    return true;
}

bool rtc_alarm_pending(void) {
    if (!r_regs) return false;
    return r_rd(RTC_ALARM_STAT) != 0;
}

/* Handle the alarm IRQ: clear device state, count, disarm (one-shot). */
int rtc_driver_handle_irq(void) {
    if (!r_regs) return 0;
    r_st.irqs++;
    if (!rtc_alarm_pending()) return 0;
    r_wr(RTC_CLEAR_INT, 1u);
    r_wr(RTC_CLEAR_ALARM, 1u);
    r_wr(RTC_IRQ_EN, 0u);
#if !defined(__riscv)
    host_rtc[RTC_ALARM_STAT / 4u] = 0u;
#endif
    r_alarm_armed = false;
    r_st.alarms_fired++;
    return 1;
}

bool rtc_alarm_armed(void) { return r_alarm_armed; }

void rtc_driver_stats(rtc_stats_t *out) {
    if (!out) return;
    *out = r_st;
}

void rtc_driver_reboot(void) {
    /* Micro-reboot: device clock keeps running; re-arm the preserved
     * deadline, clamped to now so a deadline that passed while down
     * rings immediately instead of hanging. */
    bool was_armed = r_alarm_armed;
    uint64_t saved = r_alarm_ns;
    uint64_t reads = r_st.reads;
    uint64_t fired = r_st.alarms_fired;
    rtc_caps_t c = r_caps;
    rtc_driver_init(c);
    r_st.reads = reads;
    r_st.alarms_fired = fired;
    if (was_armed) {
        uint64_t now = rtc_now_ns();
        bool overdue = saved <= now;
        uint64_t at = overdue ? now : saved;
        r_wr(RTC_ALARM_LOW, (uint32_t)(at & 0xffffffffu));
        r_wr(RTC_ALARM_HIGH, (uint32_t)(at >> 32));
        r_wr(RTC_IRQ_EN, 1u);
        r_alarm_armed = true;
        r_alarm_ns = at;
        r_st.alarms_set++;
        r_st.last_alarm_ns = at;
#if !defined(__riscv)
        /* Overdue deadline: the device would already be asserting. */
        if (overdue) host_rtc[RTC_ALARM_STAT / 4u] = 1u;
#endif
    }
}
