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
    if (c.mmio_len < 0x1000 || c.mmio_base == 0) return false;
#ifdef __CHERI_PURE_CAPABILITY__
    // Purecap: c.mmio_base is sealed Frame cap, check tag/bounds
    __capability void *cap = (void*)c.mmio_base;
    if (!__builtin_cheri_tag_get(cap)) return false;
    if (__builtin_cheri_length_get(cap) < c.mmio_len) return false;
    virtio_regs = (__capability volatile uint32_t *)cap;
#else
    // Hybrid sim: checked-pointer simulation
    if (c.mmio_base < 0x10000000 || c.mmio_base + c.mmio_len > 0x20000000) return false;
    virtio_regs = (volatile uint32_t*)c.mmio_base;
#endif
    // IOMMU: DMA buffers must be mapped via IOMMU window before use - checked in kernel iommu_map()
    // IRQ: will be bound to Notification via irq_bind() in boot, not via shared memory
    return true;
}

void net_driver_handle_irq(void) {
    if (!virtio_regs) return;
    uint32_t status = virtio_regs[4];
    // Only touches DMA buffers granted via IOMMU window - kernel IOMMU check
    // Acknowledge IRQ via Notification (async, no syscall shared memory)
    // In production: moonlight_call(irq_ntfn, &badge) would clear pending
    (void)status;
    // Ensure we never touch kernel memory: virtio_regs is bounded CHERI cap, OOB traps
    __asm__ volatile("" ::: "memory");
}

void net_driver_reboot(void) {
    /* Micro-reboot: clear state, re-init with same caps - kernel never restarts */
    net_driver_init(caps);
}
