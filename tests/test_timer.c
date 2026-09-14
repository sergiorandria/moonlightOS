#include "../kernel/include/cap.h"
#include "../kernel/include/cheri.h"
#include <assert.h>
#include <stdio.h>

#include "../userspace/drivers/timer.c"

int main(void) {
    printf("=== timer driver tests ===\n");

    /* init validation */
    timer_caps_t bad = {0};
    assert(timer_driver_init(bad) == false);
    bad.mmio_base = 0x02000000u; bad.mmio_len = 0x1000;
    assert(timer_driver_init(bad) == false);
    bad.mmio_base = 0x10000000u; bad.mmio_len = CLINT_MIN_LEN;
    assert(timer_driver_init(bad) == false);
    printf("PASS: rejects bad caps\n");

    timer_caps_t good = {0};
    good.mmio_base = 0x02000000u; good.mmio_len = CLINT_MIN_LEN;
    assert(timer_driver_init(good) == true);
    printf("PASS: init OK\n");

    /* time starts at 0, advances only via sim hook */
    assert(timer_now() == 0);
    timer_sim_advance(500);
    assert(timer_now() == 500);
    printf("PASS: now/advance\n");

    /* arm + pending + handle: one tick per slice, monotonic re-arm */
    assert(timer_driver_init(good) == true); /* now = 0 */
    timer_arm(1000);
    assert(timer_pending() == false); /* 0 < 1000 */
    timer_sim_advance(999);
    assert(timer_pending() == false); /* 999 < 1000 */
    assert(timer_driver_handle_irq() == 0);
    timer_sim_advance(1);             /* now 1000 == cmp */
    assert(timer_pending() == true);
    assert(timer_driver_handle_irq() == 1);
    assert(timer_ticks() == 1);
    assert(timer_pending() == false); /* re-armed to 2000 */
    timer_sim_advance(1000);
    assert(timer_driver_handle_irq() == 1);
    assert(timer_ticks() == 2);
    printf("PASS: arm/fire/re-arm (no burst)\n");

    /* long blackout: single catch-up re-arm, exactly one tick counted */
    timer_sim_advance(10000); /* now far past compare */
    assert(timer_driver_handle_irq() == 1);
    assert(timer_ticks() == 3);
    assert(timer_pending() == false); /* strictly ahead now */
    timer_stats_t st = {0};
    timer_driver_stats(&st);
    assert(st.rearms >= 3 && st.slices >= 1);
    printf("PASS: blackout catch-up, no tick burst\n");

    /* zero/empty paths */
    timer_arm(0); /* ignored */
    assert(timer_driver_handle_irq() == 0); /* nothing pending */
    printf("PASS: arm(0) ignored, idle handle quiet\n");

    /* reboot preserves monotonic ticks, re-arms */
    uint64_t t = timer_ticks();
    timer_driver_reboot();
    assert(timer_ticks() == t);
    assert(timer_pending() == false);
    timer_driver_stats(&st);
    assert(st.rearms >= 1);
    printf("PASS: reboot preserves tick count, re-arms\n");

    printf("ALL TIMER TESTS PASS\n");
    return 0;
}
