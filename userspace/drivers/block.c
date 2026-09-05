/* block driver - IOMMU-isolated, CHERI bounded, purecap
 * Only gets: MMIO cap for virtio-blk regs, IRQ cap, IOMMU windows for DMA buffers
 * No kernel access, crash -> micro-reboot via mem_server
 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define PAGE_SIZE 4096
#define VIRTIO_BLK_T_Q 0
#define VIRTIO_BLK_T_IN 0
#define VIRTIO_BLK_T_OUT 1

typedef struct { uintptr_t mmio_base; size_t mmio_len; uint32_t irq; uint32_t iommu_cap; } blk_caps_t;
static blk_caps_t caps;
static volatile uint32_t *blk_regs;
static uint8_t *dma_pool;
static size_t dma_pool_size;

bool block_driver_init(blk_caps_t c, void *dma_mem, size_t dma_len){
    caps = c;
    if(c.mmio_len < 0x1000) return false;
#ifdef __CHERI_PURE_CAPABILITY__
    __capability void *cap = (void*)c.mmio_base;
    if(!__builtin_cheri_tag_get(cap)) return false;
    blk_regs = (__capability volatile uint32_t*)cap;
#else
    if(c.mmio_base < 0x10000000 || c.mmio_base + c.mmio_len > 0x20000000) return false;
    blk_regs = (volatile uint32_t*)c.mmio_base;
#endif
    dma_pool = dma_mem;
    dma_pool_size = dma_len;
    // IOMMU windows must be programmed before DMA - checked in kernel iommu_map()
    return true;
}

// IOMMU window setup for DMA buffer at paddr
bool block_map_dma(uintptr_t paddr, size_t len){
    // In production: syscall to map IOMMU window for dev 1 (block)
    // iommu_map(iommu_cap, dev_id=1, paddr, len, R|W)
    // For now, just check bounds
    if(paddr < (uintptr_t)dma_pool || paddr + len > (uintptr_t)dma_pool + dma_pool_size) return false;
    return true;
}

int block_read(uint32_t sector, void *buf, size_t len){
    if(!blk_regs || !buf) return -1;
    if(len % 512) return -1;
    // Find DMA buffer in pool with correct color
    uintptr_t paddr = (uintptr_t)buf; // In purecap, buf is a bounded cap, paddr derived via cheri_address_get
    if(!block_map_dma(paddr, len)) return -1;
    // Program virtio descriptor: [blk_regs[0] = sector, blk_regs[1] = len, ...]
    // Only MMIO regs and DMA buffers are accessible - CHERI bounds trap on OOB
    blk_regs[16] = sector;
    blk_regs[17] = len;
    // Wait for IRQ via Notification (async, no polling shared memory)
    // In production: notification_wait(irq_ntfn, &badge)
    return len;
}

int block_write(uint32_t sector, const void *buf, size_t len){
    if(!blk_regs || !buf) return -1;
    uintptr_t paddr = (uintptr_t)buf;
    if(!block_map_dma(paddr, len)) return -1;
    blk_regs[16] = sector;
    blk_regs[17] = len | 0x80000000; // WRITE flag
    return len;
}

void block_driver_handle_irq(void){
    uint32_t status = blk_regs[4];
    (void)status;
    // Clear interrupt via MMIO, not via kernel memory
    blk_regs[4] = status;
    __asm__ volatile("" ::: "memory");
}

void block_driver_reboot(void){
    // Micro-reboot: clear queues, re-init with same caps, no kernel restart
    // Old DMA caps revoked via mdb_revoke, new ones minted via mem_server
    block_driver_init(caps, dma_pool, dma_pool_size);
}
