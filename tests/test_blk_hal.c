/* test_blk_hal.c - Unit test for block device HAL (header-only, host-testable).
 *
 * Tests blk_hal.h inline functions on x86 (uses #ifdef __riscv fallbacks).
 * Verifies discovery logic and constant definitions. IRQ bind functions
 * require irq.c implementation, so we skip those on host builds. */
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

/* Include the kernel headers */
#include "../kernel/blk_hal.h"
#include "../kernel/irq.h"
#include "../kernel/services.h"

int main(void)
{
    blk_hal_transport_t transport;
    int result;

    printf("[test_blk_hal] Testing blk_hal.h header-only functions\n");

    /* Test 1: NULL pointer handling (fail-closed) */
    result = blk_hal_discover(NULL);
    assert(result == 0);
    printf("[test_blk_hal] NULL pointer handling: PASS\n");

    /* Test 2: Discover on x86 (should return 0, not found) */
    result = blk_hal_discover(&transport);
    assert(result == 0);
    assert(transport.found == 0);
    assert(transport.irq == VIRTIO_IRQ_NOT_FOUND);
    assert(transport.dev_id == 0);
    printf("[test_blk_hal] x86 discovery fallback: PASS\n");

    /* Test 3: Verify constant definitions */
    assert(BLK_HAL_MMIO_UVA == 0x80C00000UL);
    assert(BLK_HAL_MMIO_LEN == (8u * 0x1000u));
    assert(BLK_HAL_IRQ_BIT == BLK_IRQ_BIT);
    assert(BLK_HAL_TID == (unsigned)T_CRYPTBLK);
    assert(BLK_HAL_DISK_MB == 256u);
    assert(BLK_HAL_SECTOR_BYTES == 512u);
    assert(BLK_HAL_DISK_SECTORS == 524288);
    printf("[test_blk_hal] constant definitions: PASS\n");

    /* Note: blk_hal_bind_irq requires irq.c implementation (irq_plic_enable, irq_bind).
     * On target (RISC-V), this is tested via kernel build and QEMU smoke.
     * On host (x86), we skip this test as it would require linking irq.c. */

    printf("[test_blk_hal] All tests PASSED\n");
    return 0;
}
