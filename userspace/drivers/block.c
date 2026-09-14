/* block driver - IOMMU-isolated, CHERI bounded, purecap
 * Only gets: MMIO cap for virtio-blk regs, IRQ cap, IOMMU windows for DMA buffers
 * No kernel access, crash -> micro-reboot via mem_server
 *
 * Queue model: single virtqueue (64 descriptors). Each request is one
 * sector-aligned transfer validated against the IOMMU window on enqueue
 * AND on IRQ completion. Reads need STORE (device writes the buffer),
 * writes need LOAD (device reads the buffer). Bounded work: enqueue O(1),
 * IRQ drain completes at most 32 requests per call.
 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "../../kernel/include/cheri.h"
#include "../../kernel/include/cap.h"
#include "../../kernel/include/iommu.h"
#include "virtio_mmio.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define VIRTIO_BLK_T_IN 0
#define VIRTIO_BLK_T_OUT 1
#define BLK_SECTOR 512u
#define BLK_QSIZE 64u
#define BLK_MAX_BYTES (128u * BLK_SECTOR) /* 64K per request */
#define BLK_MAX_DRAIN 32u
#define BLK_DEFAULT_SECTORS 32768u /* 16 MiB demo disk */

typedef struct { uintptr_t mmio_base; size_t mmio_len; uint32_t irq; uint32_t iommu_cap; } blk_caps_t;

typedef struct {
    uintptr_t paddr;   /* DMA buffer (pool-relative paddr) */
    size_t len;        /* bytes, multiple of 512 */
    uint32_t sector;   /* first LBA */
    uint8_t is_write;  /* 0 = read (device writes), 1 = write (device reads) */
    uint8_t in_use;    /* owned by device */
    uint8_t done;      /* device completed, awaiting drain */
    uint8_t status;    /* 0 = ok, nonzero = device error */
} blk_req_t;

typedef struct {
    uint64_t reads;
    uint64_t writes;
    uint64_t read_bytes;
    uint64_t write_bytes;
    uint64_t errors;
    uint64_t irqs;
    uint16_t pending;
} blk_stats_t;

static blk_caps_t caps;
static volatile uint32_t *blk_regs;
#if !defined(__riscv)
static uint32_t host_blk_regs[64] __attribute__((aligned(4096)));
#endif
static uint8_t *dma_pool;
static size_t dma_pool_size;

/* IOMMU DMA wiring: mirrors virtio_net.c net_driver_set_iommu */
static iommu_state_t *g_iommu = NULL;
static cap_t g_iommu_cap;
static uintptr_t g_dev_id = 1; /* virtio-blk platform device id */
static uintptr_t g_dma_base = 0;
static size_t g_dma_len = 0;
static bool g_iommu_bound = false;

static blk_req_t blk_q[BLK_QSIZE];
static uint16_t blk_head;
static uint16_t blk_pending;
static blk_stats_t blk_st;
static uint32_t g_nsectors = BLK_DEFAULT_SECTORS;

/* --- Target virtio-mmio transport (__riscv only) ---
 * Real split virtqueue 0: 3 descriptors per request (header/data/status).
 * Control structures live in driver-owned static memory (DMA-visible on the
 * identity-mapped bring-up kernel; a future driver compartment maps the same
 * pages for the device via its IOMMU cap). Host-sim keeps the sim hooks. */
#ifdef __riscv
#define BLK_WANT_DESC 192u /* 64 slots x 3 */
static struct vring_desc *b_desc;
static struct vring_avail_q *b_avail;
static volatile struct vring_used_q *b_used;
static uint16_t b_ndesc;
static uint16_t b_seen;
static uint16_t b_ring_cap;
static uint8_t b_leg_mem[8192] __attribute__((aligned(4096)));
static struct vring_desc b_mod_desc[BLK_WANT_DESC] __attribute__((aligned(16)));
static struct vring_avail_q b_mod_avail __attribute__((aligned(2)));
static volatile struct vring_used_q b_mod_used __attribute__((aligned(4096)));
static uint8_t blk_req_hdr[BLK_QSIZE][16];
static uint8_t blk_req_status[BLK_QSIZE];
/* Triple-index freelist + owner table (triple -> shadow slot, -1 = free). */
static uint8_t b_desc_free[BLK_QSIZE];
static uint16_t b_desc_n;
static int b_owner[BLK_QSIZE];

static bool block_transport_probe(void) {
    volatile uint32_t *regs = blk_regs;
    int legacy = 0;
    if (vmm_probe(regs, VIRTIO_DEV_BLK, &legacy) != ERR_OK) return false;
    vmm_begin(regs);
    if (vmm_feat_ok(regs, legacy) != ERR_OK) { vmm_fail(regs); return false; }
    uint16_t n = 0;
    if (legacy)
        n = vmm_setup_leg(regs, 0, BLK_WANT_DESC, b_leg_mem,
                          &b_desc, &b_avail, &b_used);
    else
        n = vmm_setup_mod(regs, 0, BLK_WANT_DESC, b_mod_desc,
                          &b_mod_avail, &b_mod_used);
    if (n < 3u) { vmm_fail(regs); return false; }
    vmm_ready(regs);
    b_ndesc = n;
    b_ring_cap = n / 3u;
    if (b_ring_cap > BLK_QSIZE) b_ring_cap = BLK_QSIZE;
    b_seen = 0;
    b_desc_n = 0;
    for (uint16_t i = 0; i < b_ring_cap; i++) {
        b_desc_free[b_desc_n++] = (uint8_t)i;
        b_owner[i] = -1;
    }
    return true;
}

/* Program one request chain for shadow slot s (triple t already popped). */
static void block_chain_program(uint16_t s, uint8_t t, uintptr_t paddr,
                                size_t len, uint8_t is_write) {
    uint32_t type = is_write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    uint64_t sector = blk_q[s].sector;
    blk_req_hdr[s][0] = (uint8_t)(type & 0xffu);
    blk_req_hdr[s][1] = (uint8_t)((type >> 8) & 0xffu);
    blk_req_hdr[s][2] = (uint8_t)((type >> 16) & 0xffu);
    blk_req_hdr[s][3] = (uint8_t)((type >> 24) & 0xffu);
    blk_req_hdr[s][4] = blk_req_hdr[s][5] = blk_req_hdr[s][6] = blk_req_hdr[s][7] = 0;
    for (int i = 0; i < 8; i++)
        blk_req_hdr[s][8 + i] = (uint8_t)((sector >> (8 * i)) & 0xffu);
    blk_req_status[s] = 0xff;
    uint16_t d = (uint16_t)t * 3u;
    b_desc[d].addr = (uint64_t)(uintptr_t)&blk_req_hdr[s][0];
    b_desc[d].len = 16;
    b_desc[d].flags = VRING_DESC_F_NEXT;
    b_desc[d].next = (uint16_t)(d + 1u);
    b_desc[d + 1].addr = (uint64_t)paddr;
    b_desc[d + 1].len = (uint32_t)len;
    b_desc[d + 1].flags = VRING_DESC_F_NEXT | (is_write ? 0u : VRING_DESC_F_WRITE);
    b_desc[d + 1].next = (uint16_t)(d + 2u);
    b_desc[d + 2].addr = (uint64_t)(uintptr_t)&blk_req_status[s];
    b_desc[d + 2].len = 1;
    b_desc[d + 2].flags = VRING_DESC_F_WRITE;
    b_desc[d + 2].next = 0;
    b_owner[t] = (int)s;
    vmm_fence();
    b_avail->ring[b_avail->idx % b_ndesc] = d;
    vmm_fence();
    b_avail->idx++;
    vmm_fence();
    vmm_notify(blk_regs, 0u);
}

/* Drain the used ring into shadow completions (bounded). */
static void block_drain_used(void) {
    uint32_t n = 0;
    while (b_seen != b_used->idx && n < BLK_MAX_DRAIN) {
        struct vring_used_elem e = b_used->ring[b_seen % b_ndesc];
        vmm_fence();
        uint32_t id = e.id;
        if (id < b_ndesc && (id % 3u) == 0u) {
            uint8_t t = (uint8_t)(id / 3u);
            if (t < b_ring_cap) {
                int s = b_owner[t];
                if (s >= 0 && blk_q[s].in_use && !blk_q[s].done) {
                    blk_q[s].done = 1;
                    blk_q[s].status = blk_req_status[s];
                    b_owner[t] = -1;
                    if (b_desc_n < BLK_QSIZE) b_desc_free[b_desc_n++] = t;
                }
            }
        }
        b_seen++;
        n++;
    }
}
#endif /* __riscv */

bool block_driver_init(blk_caps_t c, void *dma_mem, size_t dma_len){
    caps = c;
    if(c.mmio_len < 0x1000) return false;
#ifdef __CHERI_PURE_CAPABILITY__
    __capability void *cap = (void*)c.mmio_base;
    if(!__builtin_cheri_tag_get(cap)) return false;
    if(__builtin_cheri_length_get(cap) < c.mmio_len) return false;
    blk_regs = (__capability volatile uint32_t*)cap;
#else
    if(c.mmio_base < 0x10000000 || c.mmio_base + c.mmio_len > 0x20000000) return false;
#if defined(__riscv)
    blk_regs = (volatile uint32_t*)c.mmio_base;
#else
    /* Host sim: fake MMIO is not host-valid; use host-backed regs. */
    memset(host_blk_regs, 0, sizeof(host_blk_regs));
    blk_regs = (volatile uint32_t*)host_blk_regs;
#endif
#endif
    dma_pool = (uint8_t*)dma_mem;
    dma_pool_size = dma_len;
    // IOMMU windows must be programmed before DMA - checked in kernel iommu_map()
#ifdef __riscv
    /* Production: refuse to run against an unvalidated MMIO device. */
    if (!block_transport_probe()) {
        blk_regs = NULL;
        return false;
    }
#endif
    return true;
}

/* Bind an IOMMU window for the DMA pool. Must precede any I/O. */
bool block_set_iommu(cap_t iommu_cap, iommu_state_t *iommu, uintptr_t dev_id,
                      uintptr_t dma_paddr, size_t dma_size) {
    if (!iommu) return false;
    if (iommu_cap.type != CAP_IOMMU) return false;
    if (!iommu_cap.is_valid || !cheri_tag_get(iommu_cap.hw_cap)) return false;
    if (dma_size % PAGE_SIZE || dma_paddr % PAGE_SIZE) return false;
    g_iommu = iommu;
    g_iommu_cap = iommu_cap;
    g_dev_id = dev_id;
    g_dma_base = dma_paddr;
    g_dma_len = dma_size;
    g_iommu_bound = false;
    kerror_t e = iommu_map(g_iommu, &g_iommu_cap, g_dev_id, dma_paddr, dma_size,
                           CHERI_PERM_LOAD | CHERI_PERM_STORE);
    if (e != ERR_OK) return false;
    g_iommu_bound = true;
    return true;
}

bool block_dma_map(uintptr_t paddr, size_t size, uint32_t perms) {
    if (!g_iommu || !g_iommu_bound) return false;
    if (size % PAGE_SIZE || paddr % PAGE_SIZE) return false;
    if (paddr < g_dma_base || size > g_dma_len ||
        paddr + size > g_dma_base + g_dma_len) return false;
    if (paddr + size < paddr) return false;
    return iommu_map(g_iommu, &g_iommu_cap, g_dev_id, paddr, size, perms) == ERR_OK;
}

bool block_dma_unmap(uintptr_t paddr) {
    if (!g_iommu) return false;
    return iommu_unmap(g_iommu, g_dev_id, paddr) == ERR_OK;
}

bool block_dma_check(uintptr_t paddr, size_t len, bool is_write) {
    if (!g_iommu) return false;
    return iommu_check(g_iommu, g_dev_id, paddr, len, is_write);
}

void block_set_capacity(uint32_t nsectors) { g_nsectors = nsectors; }
uint32_t block_capacity(void) { return g_nsectors; }

void block_stats(blk_stats_t *out) {
    if (!out) return;
    *out = blk_st;
    out->pending = blk_pending;
}

// IOMMU window setup for DMA buffer at paddr (legacy host-pool check).
// Kept for API compatibility: validates the host dma_pool range.
bool block_map_dma(uintptr_t paddr, size_t len){
    if(!dma_pool) return false;
    if(paddr < (uintptr_t)dma_pool || len > dma_pool_size ||
       paddr + len > (uintptr_t)dma_pool + dma_pool_size) return false;
    if(paddr + len < paddr) return false;
    return true;
}

static int blk_enqueue(uint32_t sector, uintptr_t paddr, size_t len, uint8_t is_write) {
    if (!blk_regs || !dma_pool) return -1;
    if (len == 0 || len % BLK_SECTOR || len > BLK_MAX_BYTES) return -1;
    uint32_t nsec = (uint32_t)(len / BLK_SECTOR);
    /* Wrap-safe range check against capacity */
    if (sector >= g_nsectors || nsec > g_nsectors - sector) return -1;
    if (!block_map_dma(paddr, len)) return -1;
    if (!g_iommu || !g_iommu_bound) return -1;
    /* Direction-appropriate IOMMU perm: read fills buf (STORE), write drains it (LOAD) */
    if (!iommu_check(g_iommu, g_dev_id, paddr, len, is_write ? false : true)) return -1;
    if (blk_pending >= BLK_QSIZE) return -1;
    uint16_t slot = (uint16_t)(blk_head % BLK_QSIZE);
    for (uint16_t i = 0; i < BLK_QSIZE; i++) {
        uint16_t s = (uint16_t)((slot + i) % BLK_QSIZE);
        if (!blk_q[s].in_use) {
            blk_q[s].paddr = paddr;
            blk_q[s].len = len;
            blk_q[s].sector = sector;
            blk_q[s].is_write = is_write;
            blk_q[s].in_use = 1;
            blk_q[s].done = 0;
            blk_q[s].status = 0;
            blk_pending++;
            blk_head = (uint16_t)((s + 1u) % BLK_QSIZE);
            blk_st.pending = blk_pending;
#ifdef __riscv
            /* Real device: program the descriptor chain + notify. The ring
             * may hold fewer triples than shadow slots (device queue size);
             * roll back the shadow alloc when the ring is full. */
            if (b_desc_n == 0) {
                blk_q[s].in_use = 0;
                if (blk_pending > 0) blk_pending--;
                blk_st.pending = blk_pending;
                return -1;
            }
            block_chain_program(s, b_desc_free[--b_desc_n], paddr, len, is_write);
#else
            /* Kick the device (queue notify). Host-sim records the kick. */
            blk_regs[17] = (uint32_t)(is_write ? (len | 0x80000000u) : len);
            __asm__ volatile("" ::: "memory");
#endif
            return (int)len;
        }
    }
    return -1;
}

int block_read(uint32_t sector, void *buf, size_t len){
    if(!blk_regs || !buf) return -1;
    if(len % 512) return -1;
    // Find DMA buffer in pool with correct color
    uintptr_t paddr = (uintptr_t)buf; // In purecap, buf is a bounded cap, paddr derived via cheri_address_get
    return blk_enqueue(sector, paddr, len, VIRTIO_BLK_T_IN);
}

int block_write(uint32_t sector, const void *buf, size_t len){
    if(!blk_regs || !buf) return -1;
    uintptr_t paddr = (uintptr_t)buf;
    return blk_enqueue(sector, paddr, len, VIRTIO_BLK_T_OUT);
}

/* Test/target hooks: mark owned requests complete (status 0 = ok). */
uint16_t block_sim_complete(uint16_t n) {
    uint16_t marked = 0;
    for (uint16_t i = 0; i < BLK_QSIZE && marked < n; i++) {
        if (blk_q[i].in_use && !blk_q[i].done) {
            blk_q[i].done = 1;
            blk_q[i].status = 0;
            marked++;
        }
    }
    return marked;
}

uint16_t block_sim_fail(uint16_t n) {
    uint16_t marked = 0;
    for (uint16_t i = 0; i < BLK_QSIZE && marked < n; i++) {
        if (blk_q[i].in_use && !blk_q[i].done) {
            blk_q[i].done = 1;
            blk_q[i].status = 1;
            marked++;
        }
    }
    return marked;
}

void block_driver_handle_irq(void){
    if (!blk_regs) return;
    uint32_t status = blk_regs[4];
    blk_st.irqs++;
#ifdef __riscv
    /* Real completion path: used ring -> shadow done flags. */
    (void)vmm_irq_ack(blk_regs);
    block_drain_used();
#endif
    uint32_t drained = 0;
    for (uint16_t i = 0; i < BLK_QSIZE && drained < BLK_MAX_DRAIN; i++) {
        if (!blk_q[i].in_use || !blk_q[i].done) continue;
        bool confined = false;
        if (g_iommu && g_iommu_bound)
            confined = iommu_check(g_iommu, g_dev_id, blk_q[i].paddr, blk_q[i].len,
                                   blk_q[i].is_write ? false : true);
        uint8_t was_write = blk_q[i].is_write;
        size_t blen = blk_q[i].len;
        uint8_t dev_ok = blk_q[i].status;
        blk_q[i].in_use = 0;
        blk_q[i].done = 0;
        if (blk_pending > 0) blk_pending--;
        if (confined && dev_ok == 0) {
            if (was_write) { blk_st.writes++; blk_st.write_bytes += blen; }
            else { blk_st.reads++; blk_st.read_bytes += blen; }
        } else {
            blk_st.errors++;
        }
        drained++;
    }
    blk_st.pending = blk_pending;
    // Clear interrupt via MMIO, not via kernel memory
    blk_regs[4] = status;
    __asm__ volatile("" ::: "memory");
}

void block_driver_reboot(void){
    // Micro-reboot: clear queues, re-init with same caps, no kernel restart
    // Old DMA caps revoked via mdb_revoke, new ones minted via mem_server
    if (g_iommu && g_iommu_bound) {
        iommu_unmap(g_iommu, g_dev_id, g_dma_base);
        g_iommu_bound = false;
    }
    g_iommu = NULL;
    g_dma_base = 0;
    g_dma_len = 0;
    memset(blk_q, 0, sizeof(blk_q));
    blk_head = 0;
    blk_pending = 0;
    memset(&blk_st, 0, sizeof(blk_st));
    block_driver_init(caps, dma_pool, dma_pool_size);
}
