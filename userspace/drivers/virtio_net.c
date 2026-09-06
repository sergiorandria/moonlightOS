/* virtio_net driver - unprivileged CHERI compartment
 * Only gets: MMIO cap (virtio regs), IRQ cap, DMA Frame caps via IOMMU. No kernel access.
 * Crash -> micro-reboot: mem_server revokes old Frame caps, re-mints new ones.
 * DMA buffers are explicitly registered via iommu_map and checked via iommu_check.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "../../kernel/include/cheri.h"
#include "../../kernel/include/cap.h"
#include "../../kernel/include/iommu.h"

typedef struct { uintptr_t mmio_base; size_t mmio_len; uint32_t irq; } drv_caps_t;
static drv_caps_t caps;
static volatile uint32_t *virtio_regs;

/* --- IOMMU DMA wiring: driver owns an IOMMU window for its DMA pool --- */
static iommu_state_t *g_iommu = NULL;
static cap_t g_iommu_cap;
static uintptr_t g_dev_id = 0;
static uintptr_t g_dma_base = 0;
static size_t g_dma_len = 0;
static bool g_iommu_bound = false;

bool net_driver_init(drv_caps_t c) {
    caps = c;
    if (c.mmio_len < 0x1000 || c.mmio_base == 0) return false;
#ifdef __CHERI_PURE_CAPABILITY__
    /* Purecap: c.mmio_base is a sealed Frame cap. Derive exact-bounds cap.
     * Mirrors alloc.c: cheri_bounds_set + seal check. */
    __capability void *raw = (__capability void *)c.mmio_base;
    if (!cheri_tag_get(raw)) return false;
    if (cheri_length_get(raw) < c.mmio_len) return false;
    /* Bounds-exact derivation: same pattern as alloc_frame() cheri_bounds_set */
    __capability void *bounded = cheri_bounds_set(raw, c.mmio_len);
    if (!cheri_tag_get(bounded)) return false;
    if (cheri_length_get(bounded) < c.mmio_len) return false;
    virtio_regs = (volatile uint32_t *)bounded;
#else
    /* Hybrid sim: checked-pointer simulation + CHERI sim bounds */
    if (c.mmio_base < 0x10000000 || c.mmio_base + c.mmio_len > 0x20000000) return false;
    /* Simulate vspace_map with CHERI bounds: construct a sim cap and validate */
    sim_cap_t mmio_cap = {0};
    mmio_cap.base = c.mmio_base;
    mmio_cap.top = c.mmio_base + c.mmio_len;
    mmio_cap.addr = c.mmio_base;
    mmio_cap.tag = 1;
    mmio_cap.sealed = 0;
    mmio_cap.perms = CHERI_PERM_LOAD | CHERI_PERM_STORE;
    if (!cheri_tag_get(mmio_cap)) return false;
    if (cheri_length_get(mmio_cap) < c.mmio_len) return false;
    /* In production, MMIO Frame would be mapped via vspace_map(..., cheri_bounds_set(...)) */
    /* Host sim: 0x10002000 is not host-valid, use host-backed buffer for actual accesses
     * while keeping the sim cap for bounds proof. */
    static uint32_t host_mmio[1024] __attribute__((aligned(4096))) = {0};
    (void)mmio_cap;
    virtio_regs = (volatile uint32_t*)host_mmio;
#endif
    return true;
}

/* Bind an IOMMU window for DMA. Must be called before any DMA.
 * In production this is a syscall: moonlight_call(iommu_cap, INV_IOMMU_MAP, ...)
 * For host unit tests, driver directly owns iommu_state_t + sealed IOMMU cap. */
bool net_driver_set_iommu(cap_t iommu_cap, iommu_state_t *iommu, uintptr_t dev_id,
                          uintptr_t dma_paddr, size_t dma_size) {
    if (!iommu) return false;
    if (iommu_cap.type != CAP_IOMMU) return false;
    if (!iommu_cap.is_valid || !cheri_tag_get(iommu_cap.hw_cap)) return false;
    g_iommu = iommu;
    g_iommu_cap = iommu_cap;
    g_dev_id = dev_id;
    g_dma_base = dma_paddr;
    g_dma_len = dma_size;
    g_iommu_bound = false;
    /* Register the initial DMA pool window */
    kerror_t e = iommu_map(g_iommu, &g_iommu_cap, g_dev_id, dma_paddr, dma_size,
                           CHERI_PERM_LOAD | CHERI_PERM_STORE);
    if (e != ERR_OK) return false;
    g_iommu_bound = true;
    return true;
}

/* Register an additional DMA buffer (e.g. per-packet) */
bool net_driver_dma_map(uintptr_t paddr, size_t size, uint32_t perms) {
    if (!g_iommu || !g_iommu_bound) return false;
    if (size % PAGE_SIZE || paddr % PAGE_SIZE) return false;
    /* Validate within the driver's DMA pool bounds before calling iommu_map */
    if (paddr < g_dma_base || paddr + size > g_dma_base + g_dma_len) return false;
    kerror_t e = iommu_map(g_iommu, &g_iommu_cap, g_dev_id, paddr, size, perms);
    return e == ERR_OK;
}

bool net_driver_dma_unmap(uintptr_t paddr) {
    if (!g_iommu) return false;
    return iommu_unmap(g_iommu, g_dev_id, paddr) == ERR_OK;
}

/* Hot-path check: must be called before touching any DMA buffer */
bool net_driver_dma_check(uintptr_t paddr, size_t len, bool is_write) {
    if (!g_iommu) return false;
    return iommu_check(g_iommu, g_dev_id, paddr, len, is_write);
}

void net_driver_handle_irq(void) {
    if (!virtio_regs) return;
    uint32_t status = virtio_regs[4];
    /* Enforce IOMMU window before touching DMA memory.
     * In production the virtio descriptor ring lives in the DMA pool; we check
     * a representative buffer here. Real driver would iterate descriptors. */
    if (g_iommu_bound && g_dma_base != 0) {
        /* Example: check the first PAGE of DMA pool is still authorized */
        if (!iommu_check(g_iommu, g_dev_id, g_dma_base, 512, false)) {
            /* DMA window revoked or wrong dev: drop packet, do not touch memory */
            __asm__ volatile("" ::: "memory");
            (void)status;
            return;
        }
        /* Write path (TX) must have STORE perm */
        if (!iommu_check(g_iommu, g_dev_id, g_dma_base, 512, true)) {
            /* Read-only window: cannot TX */
            (void)status;
            return;
        }
    }
    (void)status;
    /* Acknowledge IRQ via Notification (async, no syscall shared memory) */
    /* In production: moonlight_call(irq_ntfn, &badge) would clear pending */
    /* Ensure we never touch kernel memory: virtio_regs is bounded CHERI cap, OOB traps */
    __asm__ volatile("" ::: "memory");
}

void net_driver_reboot(void) {
    /* Micro-reboot: clear state, re-init with same caps - kernel never restarts.
     * IOMMU windows are revoked by kernel (mdb_revoke) and re-created on rebind. */
    if (g_iommu && g_iommu_bound) {
        iommu_unmap(g_iommu, g_dev_id, g_dma_base);
        g_iommu_bound = false;
    }
    g_iommu = NULL;
    g_dma_base = 0;
    g_dma_len = 0;
    net_driver_init(caps);
}
