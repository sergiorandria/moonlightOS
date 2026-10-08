#include "../userspace/abi/cap.h"
#include "../userspace/abi/cheri.h"
#include <assert.h>
#include <stdio.h>

#include "../userspace/drivers/power.c"

int main(void) {
    printf("=== power driver tests ===\n");

    /* init validation */
    power_caps_t bad = {0};
    assert(power_driver_init(bad) == false);
    bad.mmio_base = 0x100000u; bad.mmio_len = 0x100;
    assert(power_driver_init(bad) == false);
    bad.mmio_base = 0x10000000u; bad.mmio_len = POWER_MIN_LEN;
    assert(power_driver_init(bad) == false);
    printf("PASS: rejects bad caps\n");

    power_caps_t good = {0};
    good.mmio_base = 0x100000u; good.mmio_len = POWER_MIN_LEN;
    assert(power_driver_init(good) == true);
    printf("PASS: init OK\n");

    /* act without arm rejected (single stray write can't halt us) */
    power_shutdown();
    power_reboot();
    power_stats_t st = {0};
    power_driver_stats(&st);
    assert(st.rejected == 2 && st.shutdowns == 0 && st.reboots == 0);
    assert(host_finisher[0] == 0u);
    printf("PASS: unarmed acts rejected, device untouched\n");

    /* bad arm rejected */
    assert(power_arm(POWER_ACT_NONE) == false);
    assert(power_arm((power_action_t)99) == false);
    printf("PASS: bad arm rejected\n");

    /* arm mismatch rejected */
    assert(power_arm(POWER_ACT_SHUTDOWN) == true);
    power_reboot(); /* armed shutdown, asked reboot */
    power_driver_stats(&st);
    assert(st.rejected == 3 && st.reboots == 0);
    printf("PASS: arm mismatch rejected\n");

    /* shutdown path: code lands in the finisher register */
    assert(power_arm(POWER_ACT_SHUTDOWN) == true);
    power_shutdown();
    power_driver_stats(&st);
    assert(st.shutdowns == 1 && st.last_action == POWER_ACT_SHUTDOWN);
    assert(host_finisher[0] == POWER_POWEROFF);
    printf("PASS: shutdown writes 0x5555\n");

    /* arm is single-use: second act without re-arm rejected */
    power_shutdown();
    power_driver_stats(&st);
    assert(st.shutdowns == 1 && st.rejected == 4);
    printf("PASS: arm is single-use\n");

    /* reboot path */
    assert(power_arm(POWER_ACT_REBOOT) == true);
    power_reboot();
    power_driver_stats(&st);
    assert(st.reboots == 1 && st.last_action == POWER_ACT_REBOOT);
    assert(host_finisher[0] == POWER_RESET);
    printf("PASS: reboot writes 0x7777\n");

    /* driver micro-reboot clears arm + counters */
    power_arm(POWER_ACT_SHUTDOWN);
    power_driver_reboot();
    power_shutdown(); /* arm was cleared */
    power_driver_stats(&st);
    assert(st.shutdowns == 0 && st.rejected == 1);
    printf("PASS: driver reboot clears arm + stats\n");

    printf("ALL POWER TESTS PASS\n");
    return 0;
}
