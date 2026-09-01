/* virtio_net driver - unprivileged CHERI compartment
 * Only gets: MMIO cap (virtio regs), IRQ cap, DMA Frame caps via IOMMU. No kernel access.
 * Crash -> micro-reboot: mem_server revokes old Frame caps, re-mints new ones.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct { uintptr_t mmio_base; size_t mmio_len; uint32_t irq; } drv_caps_t;
static drv_caps_t caps;
static volatile uint32_t *virtio_regs;

bool net_driver_init(drv_caps_t c) {
    caps = c;
    virtio_regs = (volatile uint32_t*)c.mmio_base;
    /* Bounds are HW CHERI caps - any OOB access traps, not corrupts kernel */
    return true;
}

void net_driver_handle_irq(void) {
    uint32_t status = virtio_regs[4];
    (void)status;
    /* Only touches DMA buffers granted via IOMMU window - IOMMU check in kernel */
}

void net_driver_reboot(void) {
    /* Micro-reboot: clear state, re-init with same caps - kernel never restarts */
    net_driver_init(caps);
}
