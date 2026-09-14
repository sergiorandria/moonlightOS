#include "../userspace/abi/cap.h"
#include "../userspace/abi/cheri.h"
#include <assert.h>
#include <stdio.h>

#include "../userspace/drivers/rtc.c"

int main(void) {
    printf("=== rtc driver tests ===\n");

    /* init validation */
    rtc_caps_t bad = {0};
    assert(rtc_driver_init(bad) == false);
    bad.mmio_base = 0x101000u; bad.mmio_len = 0x10;
    assert(rtc_driver_init(bad) == false);
    bad.mmio_base = 0x10000000u; bad.mmio_len = RTC_MIN_LEN;
    assert(rtc_driver_init(bad) == false);
    printf("PASS: rejects bad caps\n");

    rtc_caps_t good = {0};
    good.mmio_base = 0x101000u; good.mmio_len = RTC_MIN_LEN; good.irq = 11;
    assert(rtc_driver_init(good) == true);
    printf("PASS: init OK\n");

    /* clock runs, seconds derive */
    assert(rtc_now_ns() == 0);
    rtc_sim_advance(2500000000ull); /* 2.5 s */
    assert(rtc_now_ns() == 2500000000ull);
    assert(rtc_now_s() == 2);
    printf("PASS: now_ns/now_s\n");

    /* alarm: set, pending only after deadline, one-shot IRQ */
    assert(rtc_set_alarm_ns(1000000000ull) == true);
    assert(rtc_alarm_armed() == true);
    assert(rtc_alarm_pending() == false);
    assert(rtc_driver_handle_irq() == 0);
    rtc_sim_advance(999999999ull);
    assert(rtc_alarm_pending() == false);
    rtc_sim_advance(1ull);
    assert(rtc_alarm_pending() == true);
    assert(rtc_driver_handle_irq() == 1);
    assert(rtc_alarm_armed() == false);
    assert(rtc_alarm_pending() == false);
    assert(rtc_driver_handle_irq() == 0); /* idle quiet */
    rtc_stats_t st = {0};
    rtc_driver_stats(&st);
    assert(st.alarms_set == 1 && st.alarms_fired == 1 && st.irqs == 3);
    printf("PASS: alarm set/fire/one-shot\n");

    /* disarm via zero */
    assert(rtc_set_alarm_ns(5000ull) == true);
    assert(rtc_set_alarm_ns(0ull) == true);
    assert(rtc_alarm_armed() == false);
    printf("PASS: disarm\n");

    /* wrap-safe deadline rejected */
    rtc_sim_advance(0ull); /* no-op sanity */
    assert(rtc_set_alarm_ns(UINT64_MAX) == false); /* now+delta wraps */
    printf("PASS: wrapping deadline rejected\n");

    /* reboot re-arms a future deadline, clamps a past one.
     * (Device time persists across reboot; expectations are relative.) */
    uint64_t now0 = rtc_now_ns();
    assert(rtc_set_alarm_ns(100000ull) == true); /* deadline now0+100000 */
    rtc_driver_reboot();
    assert(rtc_alarm_armed() == true);
    rtc_driver_stats(&st);
    assert(st.last_alarm_ns == now0 + 100000ull);
    /* past-deadline clamp: advance beyond, reboot, alarm rings now */
    rtc_sim_advance(200000ull); /* now0+200000 > deadline */
    rtc_driver_reboot();
    assert(rtc_alarm_armed() == true);
    rtc_driver_stats(&st);
    assert(st.last_alarm_ns == now0 + 200000ull); /* clamped to now */
    assert(rtc_driver_handle_irq() == 1);  /* fires immediately */
    printf("PASS: reboot re-arms / clamps past deadlines\n");

    printf("ALL RTC TESTS PASS\n");
    return 0;
}
