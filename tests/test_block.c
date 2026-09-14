#include "../kernel/include/cap.h"
#include "../kernel/include/cheri.h"
#include "../kernel/include/iommu.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Pull driver implementation directly for host test */
#include "../userspace/drivers/block.c"

static cap_t mk_iocap(uintptr_t base, size_t len)
{
    cap_t c = {0};
    c.type = CAP_IOMMU;
    c.is_valid = 1;
    c.is_sealed = 1;
    c.rights = CHERI_PERM_LOAD | CHERI_PERM_STORE;
    c.hw_cap.base = base;
    c.hw_cap.top = base + len;
    c.hw_cap.addr = base;
    c.hw_cap.tag = 1;
    c.hw_cap.sealed = 1;
    return c;
}

int main(void)
{
    printf("=== block driver tests ===\n");
    static uint8_t pool[0x20000] __attribute__((aligned(4096)));

    /* init rejects bad MMIO */
    blk_caps_t bad = {0};
    assert(block_driver_init(bad, pool, sizeof(pool)) == false);
    bad.mmio_base = 0x10003000;
    bad.mmio_len = 0x800;
    assert(block_driver_init(bad, pool, sizeof(pool)) == false);
    printf("PASS: rejects bad MMIO\n");

    blk_caps_t good = {0};
    good.mmio_base = 0x10003000;
    good.mmio_len = 0x1000;
    good.irq = 4;
    assert(block_driver_init(good, pool, sizeof(pool)) == true);
    printf("PASS: init OK\n");

    /* 256M disk image default (tools/run_qemu.sh), before any probing. */
    assert(block_capacity() == 524288u);
    assert(block_capacity() / 2048u == 256u);
    printf("PASS: default capacity 256M (524288 sectors)\n");

    /* Slot discovery: no ambient MMIO scan in the compartment (microkernel:
     * the driver only validates mem_server-minted caps). block_probe
     * reports the already-bound window; block_probe_slot validates one
     * granted cap; block_probe_table scans a minted table. */
    {
        blk_caps_t found = {0};
        blk_caps_t cand = {0};
        assert(block_probe(NULL) == false);
        assert(block_probe(&found) == true);
        assert(found.mmio_base == good.mmio_base && found.irq == good.irq);
        /* probe_slot: NULL-safe, rejects short windows, no MMIO on host. */
        assert(block_probe_slot(NULL, &found) == false);
        assert(block_probe_slot(&cand, NULL) == false);
        assert(block_probe_slot(NULL, NULL) == false);
        cand.mmio_base = 0x10003000;
        cand.mmio_len = 0x800;
        cand.irq = 4;
        assert(block_probe_slot(&cand, &found) == false);
        cand.mmio_len = 0x1000;
        assert(block_probe_slot(&cand, &found) == false);
        /* probe_table: NULL/empty-safe, no MMIO on host. */
        assert(block_probe_table(NULL, 0, &found) == false);
        assert(block_probe_table(NULL, 1, &found) == false);
        assert(block_probe_table(&cand, 0, &found) == false);
        assert(block_probe_table(&cand, 1, NULL) == false);
        assert(block_probe_table(&cand, 1, &found) == false);
        printf("PASS: probe reports bound window, no ambient scan\n");
    }

    /* I/O without IOMMU must fail (no ambient DMA) */
    uint8_t *b0 = pool + 0x1000;
    assert(block_read(0, b0, 512) == -1);
    assert(block_write(0, b0, 512) == -1);
    printf("PASS: I/O without IOMMU rejected\n");

    iommu_state_t iommu = {0};
    cap_t ioc = mk_iocap((uintptr_t)pool, sizeof(pool));
    assert(block_set_iommu(ioc, &iommu, 1, (uintptr_t)pool, sizeof(pool)) == true);
    printf("PASS: IOMMU bind OK\n");

    /* bad iocap rejected */
    cap_t wrong = ioc;
    wrong.type = CAP_FRAME;
    assert(block_set_iommu(wrong, &iommu, 1, (uintptr_t)pool, sizeof(pool)) == false);
    wrong = ioc;
    wrong.hw_cap.tag = 0;
    assert(block_set_iommu(wrong, &iommu, 1, (uintptr_t)pool, sizeof(pool)) == false);
    printf("PASS: rejects bad IOMMU caps\n");

    /* validation: length, alignment, capacity, pool bounds */
    assert(block_read(0, b0, 100) == -1);                        /* not sector multiple */
    assert(block_read(0, b0, 0) == -1);                          /* empty */
    assert(block_read(0, b0, BLK_MAX_BYTES + 512) == -1);        /* too big */
    assert(block_read(block_capacity(), b0, 512) == -1);         /* past end */
    assert(block_read(block_capacity() - 1, b0, 1024) == -1);    /* wrap past end */
    assert(block_read(0, pool + sizeof(pool) - 256, 512) == -1); /* OOB pool */
    assert(block_read(0, NULL, 512) == -1);
    printf("PASS: validation rejects bad requests\n");

    /* enqueue read + write, drain via IRQ */
    assert(block_read(0, b0, 512) == 512);
    assert(block_write(8, pool + 0x2000, 1024) == 1024);
    blk_stats_t st = {0};
    block_stats(&st);
    assert(st.pending == 2);
    assert(block_sim_complete(2) == 2);
    block_driver_handle_irq();
    block_stats(&st);
    assert(st.reads == 1 && st.writes == 1);
    assert(st.read_bytes == 512 && st.write_bytes == 1024);
    assert(st.pending == 0 && st.errors == 0);
    assert(host_blk_regs[VMM_ISTATUS / 4u] == 0); /* IRQ ACKed via IACK */
    printf("PASS: read/write enqueue + IRQ drain\n");

    /* device error counts */
    assert(block_read(16, b0, 512) == 512);
    assert(block_sim_fail(1) == 1);
    block_driver_handle_irq();
    block_stats(&st);
    assert(st.errors == 1 && st.reads == 1);
    printf("PASS: device error counted\n");

    /* queue full */
    int n = 0;
    for (int i = 0; i < 64; i++)
    {
        if (block_read((uint32_t)i, pool + ((size_t)i * 512 % (sizeof(pool) - 512)), 512) == 512)
            n++;
    }
    assert(n == 64);
    assert(block_read(0, b0, 512) == -1); /* full */
    printf("PASS: queue-full rejected (%d enqueued)\n", n);

    /* IRQ drain is bounded: 64 pending -> 32 per call */
    assert(block_sim_complete(64) == 64);
    block_driver_handle_irq();
    block_stats(&st);
    assert(st.pending == 32);
    block_driver_handle_irq();
    block_stats(&st);
    assert(st.pending == 0);
    printf("PASS: bounded IRQ drain (32/call)\n");

    /* revoke path: unmap pool -> completions count as errors, touch nothing */
    uint64_t reads_before = st.reads;
    assert(block_read(0, b0, 512) == 512);
    assert(block_sim_complete(1) == 1);
    assert(block_dma_unmap((uintptr_t)pool) == true);
    block_driver_handle_irq();
    block_stats(&st);
    assert(st.reads == reads_before && st.errors >= 1);
    printf("PASS: revoked window -> error, no touch\n");

    /* micro-reboot clears everything */
    assert(block_driver_reboot() == true);
    block_stats(&st);
    assert(st.pending == 0 && st.reads == 0 && st.writes == 0 && st.errors == 0);
    assert(block_dma_check((uintptr_t)pool, 512, false) == false);
    printf("PASS: reboot clears queues + IOMMU\n");

    printf("ALL BLOCK TESTS PASS\n");
    return 0;
}
