#include "../kernel/include/iommu.h"
#include "../kernel/include/cap.h"
#include "../kernel/include/cheri.h"
#include <assert.h>
#include <stdio.h>

/* Queue-layer tests for the extended virtio_net driver (TX/RX virtqueues).
 * Basic MMIO/IOMMU wiring is covered by test_virtio_net.c; here we cover
 * enqueue validation, per-packet DMA confinement, IRQ drain, and reboot. */
#include "../userspace/drivers/virtio_net.c"

static cap_t mk_iocap(uintptr_t base, size_t len, uint32_t perms) {
    cap_t c = {0};
    c.type = CAP_IOMMU;
    c.is_valid = 1;
    c.is_sealed = 1;
    c.rights = perms;
    c.hw_cap.base = base;
    c.hw_cap.top = base + len;
    c.hw_cap.addr = base;
    c.hw_cap.tag = 1;
    c.hw_cap.sealed = 1;
    return c;
}

int main(void) {
    printf("=== virtio_net queue tests ===\n");
    drv_caps_t good = {0};
    good.mmio_base = 0x10002000; good.mmio_len = 0x1000; good.irq = 3;
    assert(net_driver_init(good) == true);

    /* TX without IOMMU rejected */
    assert(net_driver_tx(0x50000000, 100) == false);
    assert(net_driver_rx_provide(0x50000000, 100) == false);
    printf("PASS: queue without IOMMU rejected\n");

    iommu_state_t iommu = {0};
    cap_t ioc = mk_iocap(0x50000000, 0x100000,
                         CHERI_PERM_LOAD | CHERI_PERM_STORE);
    assert(net_driver_set_iommu(ioc, &iommu, 0, 0x50000000, 0x100000) == true);

    /* validation */
    assert(net_driver_tx(0x50000000, 0) == false);          /* empty */
    assert(net_driver_tx(0x50000000, NET_MTU + 1) == false);/* oversize */
    assert(net_driver_tx(0x50200000, 100) == false);        /* OOB pool */
    assert(net_driver_tx(0x50000000 + 0x100000 - 50, 100) == false); /* overrun */
    assert(net_driver_rx_provide(0x50000000, 0) == false);
    assert(net_driver_rx_provide(0x60000000, 100) == false);
    printf("PASS: enqueue validation\n");

    /* TX ok -> complete -> IRQ counts */
    assert(net_driver_tx(0x50000000, 100) == true);
    assert(net_driver_tx(0x50001000, 1514) == true);
    net_stats_t st = {0};
    net_driver_stats(&st);
    assert(st.tx_pending == 2);
    assert(net_driver_sim_complete_tx(2) == 2);
    net_driver_handle_irq();
    net_driver_stats(&st);
    assert(st.tx_ok == 2 && st.tx_pending == 0 && st.irqs == 1);
    printf("PASS: TX enqueue + IRQ drain\n");

    /* RX ok */
    assert(net_driver_rx_provide(0x50002000, 512) == true);
    assert(net_driver_sim_recv(1, 100) == 1);
    net_driver_handle_irq();
    net_driver_stats(&st);
    assert(st.rx_ok == 1 && st.rx_pending == 0);
    printf("PASS: RX provide + receive\n");

    /* RX with oversize payload rejected by sim hook (buffer kept) */
    assert(net_driver_rx_provide(0x50003000, 100) == true);
    assert(net_driver_sim_recv(1, 500) == 0);
    net_driver_handle_irq(); /* nothing completed */
    net_driver_stats(&st);
    assert(st.rx_pending == 1);
    assert(net_driver_sim_recv(1, 100) == 1);
    net_driver_handle_irq();
    net_driver_stats(&st);
    assert(st.rx_ok == 2 && st.rx_pending == 0);
    printf("PASS: RX payload larger than buffer not completed\n");

    /* queue full */
    int n = 0;
    for (int i = 0; i < 64; i++)
        if (net_driver_tx(0x50000000 + (uintptr_t)(i * 0x1000), 100)) n++;
    assert(n == 64);
    assert(net_driver_tx(0x50000000, 100) == false);
    printf("PASS: TX queue-full rejected\n");

    /* bounded drain: 64 done -> 32 per IRQ */
    assert(net_driver_sim_complete_tx(64) == 64);
    net_driver_handle_irq();
    net_driver_stats(&st);
    assert(st.tx_pending == 32);
    net_driver_handle_irq();
    net_driver_stats(&st);
    assert(st.tx_pending == 0);
    printf("PASS: bounded drain 32/IRQ\n");

    /* read-only window: RX provide (needs STORE) rejected, TX ok.
     * Downgrade the pool window to LOAD-only behind the driver's back
     * (same cap rights, narrower window perms). Done BEFORE the revoke
     * subtest below, which unmaps the pool window. */
    assert(iommu_unmap(&iommu, 0, 0x50000000) == ERR_OK);
    assert(iommu_map(&iommu, &ioc, 0, 0x50000000, 0x100000, CHERI_PERM_LOAD) == ERR_OK);
    assert(net_driver_rx_provide(0x50000000, 100) == false);
    assert(net_driver_tx(0x50000000, 100) == true);
    assert(net_driver_sim_complete_tx(1) == 1);
    net_driver_handle_irq(); /* drain the TX above under the RO window */
    /* Restore the RW pool window for the revoke subtest. */
    assert(iommu_map(&iommu, &ioc, 0, 0x50000000, 0x100000,
                     CHERI_PERM_LOAD | CHERI_PERM_STORE) == ERR_OK);
    printf("PASS: perm direction enforced (RO rejects RX)\n");

    /* revoked window: completions become drops (unmap ALL windows at base;
     * the RO dance above can leave two overlapping entries). */
    assert(net_driver_tx(0x50000000, 100) == true);
    assert(net_driver_sim_complete_tx(1) == 1);
    assert(net_driver_dma_unmap(0x50000000) == true);
    while (iommu_unmap(&iommu, 0, 0x50000000) == ERR_OK) {}
    uint64_t ok_before = st.tx_ok;
    net_driver_stats(&st); ok_before = st.tx_ok;
    net_driver_handle_irq();
    net_driver_stats(&st);
    assert(st.tx_ok == ok_before && st.tx_drop >= 1);
    printf("PASS: revoked window -> drop on drain\n");

    /* reboot clears queues + stats */
    net_driver_reboot();
    net_driver_stats(&st);
    assert(st.tx_pending == 0 && st.rx_pending == 0);
    assert(st.tx_ok == 0 && st.rx_ok == 0 && st.irqs == 0);
    printf("PASS: reboot clears queues\n");

    printf("ALL NET QUEUE TESTS PASS\n");
    return 0;
}
