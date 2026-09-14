#include "../userspace/abi/cap.h"
#include "../userspace/abi/cheri.h"
#include <assert.h>
#include <stdio.h>

#include "../userspace/drivers/plic.c"

int main(void) {
    printf("=== plic driver tests ===\n");

    /* init validation */
    plic_caps_t bad = {0};
    assert(plic_driver_init(bad) == false);
    bad.mmio_base = 0x0c000000u; bad.mmio_len = 0x1000;
    assert(plic_driver_init(bad) == false);
    bad.mmio_base = 0x10000000u; bad.mmio_len = PLIC_MIN_LEN;
    assert(plic_driver_init(bad) == false);
    printf("PASS: rejects bad caps\n");

    plic_caps_t good = {0};
    good.mmio_base = 0x0c000000u; good.mmio_len = PLIC_MIN_LEN;
    assert(plic_driver_init(good) == true);
    printf("PASS: init OK\n");

    /* priority + enable + threshold */
    assert(plic_set_priority(0, 1) == false);   /* IRQ 0 reserved */
    assert(plic_set_priority(64, 1) == false);
    assert(plic_set_priority(10, 8) == false);  /* prio 0..7 */
    assert(plic_set_priority(10, 3) == true);
    assert(plic_enable(0) == false);
    assert(plic_enable(10) == true);
    assert(plic_disable(10) == true);
    assert(plic_enable(10) == true);
    assert(plic_set_threshold(8) == false);
    assert(plic_set_threshold(2) == true);
    printf("PASS: prio/enable/threshold validation\n");

    /* bind rules mirror kernel irq_bind */
    assert(plic_bind(0, 1, 0x4000) == false);
    assert(plic_bind(10, 1, 0x4000) == true);
    assert(plic_bind(10, 2, 0x5000) == false); /* already bound */
    assert(plic_unbind(11) == false);          /* not bound */
    assert(plic_unbind(10) == true);
    assert(plic_bind(10, 2, 0x5000) == true);
    printf("PASS: bind/unbind rules\n");

    /* claim -> dispatch -> complete, badge delivered */
    plic_sim_raise(10);
    uint32_t ntfn[4] = {0}, badge[4] = {0};
    uint16_t n = plic_handle(ntfn, badge, 4);
    assert(n == 1 && ntfn[0] == 2 && badge[0] == 0x5000);
    plic_stats_t st = {0};
    plic_driver_stats(&st);
    assert(st.claims >= 1 && st.completes >= 1 && st.irqs == 1);
    /* no more pending: second handle dispatches nothing */
    assert(plic_handle(ntfn, badge, 4) == 0);
    printf("PASS: claim/dispatch/complete with badge\n");

    /* unbound IRQ completes but delivers nothing (drop counted) */
    plic_sim_raise(11);
    assert(plic_handle(ntfn, badge, 4) == 0);
    plic_driver_stats(&st);
    assert(st.disabled_drops == 1);
    printf("PASS: unbound IRQ dropped + counted\n");

    /* dispatch is bounded: raise many, caller cap enforced, 32 max */
    for (uint32_t i = 1; i < 64; i++) {
        plic_bind(i, 9, 0x1000 + i);
        plic_sim_raise(i);
    }
    n = plic_handle(ntfn, badge, 4);
    assert(n == 4);
    uint32_t ntfn2[64] = {0}, badge2[64] = {0};
    n = plic_handle(ntfn2, badge2, 64);
    assert(n == 32); /* hard max per call */
    n = plic_handle(ntfn2, badge2, 64);
    assert(n == 63 - 4 - 32); /* remainder drained on the next call */
    printf("PASS: dispatch bounded by caller cap + 32 max\n");

    /* reboot clears bindings, keeps threshold */
    plic_driver_reboot();
    assert(plic_bind(10, 1, 0x4000) == true); /* bindable again */
    plic_driver_stats(&st);
    assert(st.claims == 0 && st.completes == 0);
    printf("PASS: reboot clears bindings + stats\n");

    printf("ALL PLIC TESTS PASS\n");
    return 0;
}
