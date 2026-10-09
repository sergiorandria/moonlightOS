/* kernel/blk_hal.h - Block device Hardware Abstraction Layer (HAL).
 *
 * Microkernel contract (mirrors Linux's blkdev + genhd interface role):
 *   The kernel's responsibility for block devices is EXACTLY:
 *     1. Scan virtio-mmio transports to find a virtio-blk device.
 *     2. Record the transport's PLIC IRQ number.
 *     3. Enable + bind that IRQ → T_CRYPTBLK (tid 9) with BLK_IRQ_BIT.
 *     4. Map the transport's 8 MMIO pages into tid 9's U-leaf.
 *     5. Dispatch IRQ notifications to the owner thread.
 *
 * The kernel does NOT:
 *   - Program virtqueues, descriptor rings, or notify registers.
 *   - Negotiate device features.
 *   - Issue any I/O (read/write sectors).
 *   - Allocate or manage DMA buffers.
 *   - Touch any device-specific configuration registers beyond
 *     magic/version/device-id (the identity read in blk_hal_discover).
 *
 * All protocol work lives in userspace/cryptblk/v2_main.c (tid 9 only).
 *
 * This header is host-testable: no MMIO except inside __riscv guards.
 */
#ifndef V2_BLK_HAL_H
#define V2_BLK_HAL_H

#include <stdint.h>
#include "platform.h"
#include "irq.h"
#include "services.h"

/* Transport descriptor: filled by blk_hal_discover, consumed by kboot. */
typedef struct {
    uint32_t irq;        /* PLIC IRQ number (1+transport-index on virt) */
    uint32_t dev_id;     /* Virtio device ID (must equal VIRTIO_DEV_BLK) */
    uint8_t  transport;  /* Transport index (0..VIRTIO_NTRANSPORTS-1) */
    uint8_t  found;      /* 1 if a virtio-blk transport was found */
} blk_hal_transport_t;

/* blk_hal_discover - Scan the VIRTIO0 transport array for a virtio-blk
 * device.  Reads only magic/version/device-id (VIRTIO identity registers).
 * The kernel MUST NOT write to any device register here.
 *
 * On success: fills *out, sets out->found=1, returns 1.
 * On failure (no blk device found): sets out->found=0, returns 0.
 * NULL out: returns 0 (fail-closed).
 *
 * Host-testable: MMIO scan is __riscv-only (host build returns 0,
 * which causes the caller to skip PLIC enable and IRQ bind gracefully).
 */
static inline int blk_hal_discover(blk_hal_transport_t *out)
{
    int ti;
    if (!out)
        return 0;
    out->found = 0;
    out->irq = VIRTIO_IRQ_NOT_FOUND;
    out->dev_id = 0;
    out->transport = 0;
#ifdef __riscv
    for (ti = 0; ti < VIRTIO_NTRANSPORTS; ti++) /* bound: 8 */
    {
        volatile uint32_t *tr =
            (volatile uint32_t *)(VIRTIO0_BASE + (unsigned long)ti * 0x1000UL);
        /* Identity read only: magic, version, device-id */
        uint32_t magic   = tr[0]; /* offset 0x000: magic "virt" */
        uint32_t version = tr[1]; /* offset 0x004: version 2 = modern */
        uint32_t dev_id  = tr[2]; /* offset 0x008: virtio device ID */
        if (magic   != VIRTIO_MAGIC)         continue;
        if (version != VIRTIO_VERSION_MODERN) continue;
        if (dev_id  != VIRTIO_DEV_BLK)       continue;
        out->transport = (uint8_t)ti;
        out->irq       = (uint32_t)(1u + (unsigned)ti);
        out->dev_id    = dev_id;
        out->found     = 1;
        return 1;
    }
#else
    (void)ti;
#endif
    return 0;
}

/* blk_hal_bind_irq - Enable the block IRQ in the PLIC and register it in
 * the kernel IRQ route table.  Fail-closed on bad irq or bind failure.
 *
 * Microkernel rule: the kernel binds the IRQ to T_CRYPTBLK (tid 9) with
 * notify-bit BLK_IRQ_BIT.  The driver thread receives a V2_WAIT wakeup
 * and reads the used-ring completion itself — the kernel never ACKs the
 * device's InterruptAck register.
 *
 * Returns 1 on success, 0 on failure.
 */
static inline int blk_hal_bind_irq(uint32_t irq)
{
    if (irq == VIRTIO_IRQ_NOT_FOUND || irq == 0)
        return 0;
    irq_plic_enable(irq);
    return (irq_bind(irq, (uint8_t)T_CRYPTBLK,
                     IRQ_KIND_BLK, BLK_IRQ_BIT) == 0) ? 1 : 0;
}

/* blk_hal_mmio_uva - User-mode VA at which the block driver (tid 9) can
 * access the virtio-mmio transport pages.  This is the base of the MMIO
 * leaf wired in pagetable_init (l0_blkmmio at l1_t[9][6]).
 *
 * The kernel maps 8 transport pages (all 8 candidates) at consecutive VAs
 * starting here; the userspace driver scans them via virtio magic reads to
 * find the live blk transport.  No transport index is assumed.
 */
#define BLK_HAL_MMIO_UVA 0x80C00000UL /* VPN[1]=6, tid 9 U-leaf */
#define BLK_HAL_MMIO_LEN (8u * 0x1000u) /* 8 transport pages */

/* blk_hal_irq_bit - The notify badge OR'd into tid 9's notify word on
 * every blk IRQ.  Userspace reads this from V2_WAIT return value. */
#define BLK_HAL_IRQ_BIT BLK_IRQ_BIT

/* blk_hal_tid - Owning driver thread.  Matches T_CRYPTBLK in services.h. */
#define BLK_HAL_TID ((unsigned)T_CRYPTBLK) /* == 9 */

/* blk_hal_disk_sectors - Default virtual-disk sector count (512B sectors).
 * Matches the 256M raw image created by tools/run_qemu.sh.
 * The userspace driver reads the actual count from virtio-blk config
 * registers; this constant is for documentation / smoke-gate checks. */
#define BLK_HAL_DISK_MB      256u
#define BLK_HAL_SECTOR_BYTES 512u
#define BLK_HAL_DISK_SECTORS \
    ((BLK_HAL_DISK_MB * 1024u * 1024u) / BLK_HAL_SECTOR_BYTES) /* 524288 */

#endif /* V2_BLK_HAL_H */
