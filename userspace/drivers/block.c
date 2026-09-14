/* block driver - userspace compartment, IOMMU-isolated, CHERI bounded, purecap
 * Only gets: MMIO cap for virtio-blk regs, IRQ cap, IOMMU windows for DMA buffers
 * No kernel access (the kernel never touches the disk), crash -> micro-reboot
 * via mem_server.
 *
 * Queue model: single virtqueue (64 descriptors). Each request is one
 * sector-aligned transfer validated against the IOMMU window on enqueue
 * AND on IRQ completion. Reads need STORE (device writes the buffer),
 * writes need LOAD (device reads the buffer). Bounded work: enqueue O(1),
 * IRQ drain completes at most 32 requests per call.
 *
 * Discovery: the compartment never scans physical MMIO itself (no ambient
 * authority). Boot / mem_server mints one bounded MMIO Frame cap per
 * virtio-mmio transport candidate and hands them to the driver; the driver
 * picks the virtio-blk one with block_probe_slot() (or scans a minted
 * table with block_probe_table()), which validates magic/version/device-ID
 * through the granted cap only (read-only vmm_probe, no STATUS writes).
 * block_probe() reports the already-bound window. The kernel maps nothing.
 *
 * Host-sim runs a real in-compartment virtual device (avail/used rings,
 * triple/owner discipline identical to the target) so host tests exercise
 * the same enqueue -> emulate -> IRQ-drain path as hardware.
 */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../abi/cap.h"
#include "../abi/cheri.h"
#include "../abi/iommu.h"
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
/* 256M virtual disk image (tools/run_qemu.sh): 256*1024*1024/512 sectors. */
#define BLK_DISK_MB 256u
#define BLK_DISK_SECTORS 524288u
#define BLK_DEFAULT_SECTORS BLK_DISK_SECTORS

typedef struct
{
    uintptr_t mmio_base;
    size_t mmio_len;
    uint32_t irq;
    uint32_t iommu_cap;
} blk_caps_t;

/* virtio-blk device ID (QEMU riscv-virt); slot layout (8 transports at
 * 0x10001000+i*0x1000, PLIC IRQ slot+1) is knowledge for mem_server when it
 * mints per-slot Frame caps, never an address the driver dereferences
 * itself. A driver that scans physical MMIO would self-authorize access
 * outside its granted caps and break the microkernel least-privilege
 * boundary (cf. V2_DESIGN lesson 6: no ambient authority). */
#define BLK_PROBE_DEV_BLK VIRTIO_DEV_BLK

/* Validate one mem_server-minted MMIO candidate as the virtio-blk
 * transport. Read-only (magic/version/device-ID via vmm_probe, no STATUS
 * writes, no feature negotiation, no queue setup), bounded to the
 * candidate's own Frame cap. On success fills *out (one 4K page window,
 * PLIC line already set by the minter, iommu_cap left 0 for separate
 * minting via mem_server) and returns true; false on host-sim (no MMIO),
 * on NULL args, on short windows, or when the device is not virtio-blk.
 * NOTE: out->irq is taken from the candidate as minted (slot+1 on
 * riscv-virt); this function never derives IRQ lines from raw addresses. */
bool block_probe_slot(const blk_caps_t *cand, blk_caps_t *out)
{
    if (!cand || !out)
        return false;
    if (cand->mmio_len < 0x1000)
        return false;
#ifdef __riscv
    {
        volatile uint32_t *regs = NULL;
#ifdef __CHERI_PURE_CAPABILITY__
        __capability void *cap = (__capability void *)cand->mmio_base;
        if (!__builtin_cheri_tag_get(cap))
            return false;
        if (__builtin_cheri_length_get(cap) < 0x1000)
            return false;
        regs = (__capability volatile uint32_t *)cap;
#else
        if (cand->mmio_base < 0x10000000 || cand->mmio_base + (uintptr_t)0x1000 > (uintptr_t)0x20000000)
            return false;
        regs = (volatile uint32_t *)cand->mmio_base;
#endif
        {
            int legacy = 0;
            if (vmm_probe(regs, BLK_PROBE_DEV_BLK, &legacy) != ERR_OK)
                return false;
        }
        *out = *cand;
        out->mmio_len = 0x1000;
        out->iommu_cap = 0;
        return true;
    }
#else
    (void)cand;
    (void)out;
    return false;
#endif
}

typedef struct
{
    uintptr_t paddr;  /* DMA buffer (pool-relative paddr) */
    size_t len;       /* bytes, multiple of 512 */
    uint32_t sector;  /* first LBA */
    uint8_t is_write; /* 0 = read (device writes), 1 = write (device reads) */
    uint8_t in_use;   /* owned by device */
    uint8_t done;     /* device completed, awaiting drain */
    uint8_t status;   /* 0 = ok, nonzero = device error */
} blk_req_t;

typedef struct
{
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
/* Host-sim virtual device: the driver's own MMIO window (identity regs at
 * proper virtio-mmio offsets) plus a real split-virtqueue model (avail ring
 * fed by enqueue, used ring fed by block_device_emulate, drained by the IRQ
 * path). Same triple/owner discipline as the __riscv target so host tests
 * exercise the real completion path instead of poking shadow state. */
static uint32_t host_blk_regs[256] __attribute__((aligned(4096)));
#define BLK_HOST_TRIPLES BLK_QSIZE /* one triple per shadow slot */
static struct vring_desc h_desc[BLK_HOST_TRIPLES * 3u];
static struct vring_avail_q h_avail;
static volatile struct vring_used_q h_used;
static uint16_t h_seen; /* driver drain cursor into h_used */
static uint8_t h_free[BLK_QSIZE];
static uint16_t h_free_n;
static int h_owner[BLK_QSIZE]; /* triple -> shadow slot, -1 = free */
static uint8_t h_hdr[BLK_QSIZE][16];
static uint8_t h_status[BLK_QSIZE];

static void block_host_reset(void)
{
    memset(host_blk_regs, 0, sizeof(host_blk_regs));
    /* Bound-device identity: virtio-mmio magic, modern version, blk ID. */
    host_blk_regs[VMM_MAGIC / 4u] = VIRTIO_MAGIC_VAL;
    host_blk_regs[VMM_VERSION / 4u] = 2u;
    host_blk_regs[VMM_DEVICE_ID / 4u] = VIRTIO_DEV_BLK;
    memset(h_desc, 0, sizeof(h_desc));
    memset(&h_avail, 0, sizeof(h_avail));
    memset((void *)&h_used, 0, sizeof(h_used));
    h_seen = 0;
    h_free_n = 0;
    for (uint16_t i = 0; i < BLK_QSIZE; i++)
    {
        h_free[h_free_n++] = (uint8_t)i;
        h_owner[i] = -1;
    }
    memset(h_hdr, 0, sizeof(h_hdr));
    memset(h_status, 0, sizeof(h_status));
}
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

#if !defined(__riscv)
/* Program one host request chain for shadow slot s (triple t popped). */
static bool block_host_chain(uint16_t s, uint8_t t, uintptr_t paddr, size_t len, uint8_t is_write)
{
    uint32_t type = is_write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    uint64_t sector = blk_q[s].sector;
    uint16_t d;

    if (t >= BLK_QSIZE || s >= BLK_QSIZE)
        return false;
    h_hdr[s][0] = (uint8_t)(type & 0xffu);
    h_hdr[s][1] = (uint8_t)((type >> 8) & 0xffu);
    h_hdr[s][2] = (uint8_t)((type >> 16) & 0xffu);
    h_hdr[s][3] = (uint8_t)((type >> 24) & 0xffu);
    h_hdr[s][4] = h_hdr[s][5] = h_hdr[s][6] = h_hdr[s][7] = 0;
    for (int i = 0; i < 8; i++)
        h_hdr[s][8 + i] = (uint8_t)((sector >> (8 * i)) & 0xffu);
    h_status[s] = 0xff;
    d = (uint16_t)t * 3u;
    h_desc[d].addr = (uint64_t)(uintptr_t)&h_hdr[s][0];
    h_desc[d].len = 16;
    h_desc[d].flags = VRING_DESC_F_NEXT;
    h_desc[d].next = (uint16_t)(d + 1u);
    h_desc[d + 1u].addr = (uint64_t)paddr;
    h_desc[d + 1u].len = (uint32_t)len;
    h_desc[d + 1u].flags = VRING_DESC_F_NEXT | (is_write ? 0u : VRING_DESC_F_WRITE);
    h_desc[d + 1u].next = (uint16_t)(d + 2u);
    h_desc[d + 2u].addr = (uint64_t)(uintptr_t)&h_status[s];
    h_desc[d + 2u].len = 1;
    h_desc[d + 2u].flags = VRING_DESC_F_WRITE;
    h_desc[d + 2u].next = 0;
    h_owner[t] = (int)s;
    h_avail.ring[h_avail.idx % VMM_QCAP] = d;
    h_avail.idx++;
    return true;
}

/* Drain the host used ring into shadow completions (bounded). */
static void block_host_drain(void)
{
    uint32_t n = 0;
    while (h_seen != h_used.idx && n < BLK_MAX_DRAIN)
    {
        struct vring_used_elem e = h_used.ring[h_seen % VMM_QCAP];
        uint32_t id = e.id;
        if (id < (uint32_t)BLK_HOST_TRIPLES * 3u && (id % 3u) == 0u)
        {
            uint8_t t = (uint8_t)(id / 3u);
            if (t < BLK_QSIZE)
            {
                int s = h_owner[t];
                if (s >= 0 && s < (int)BLK_QSIZE && blk_q[s].in_use && !blk_q[s].done)
                {
                    blk_q[s].done = 1;
                    blk_q[s].status = h_status[s];
                    h_owner[t] = -1;
                    if (h_free_n < BLK_QSIZE)
                        h_free[h_free_n++] = t;
                }
            }
        }
        h_seen++;
        n++;
    }
}

/* Virtual device step: complete up to n owned requests through the used
 * ring (status byte per request) and raise ISTATUS. Returns completed. */
static uint16_t block_device_emulate(uint16_t n, uint8_t status)
{
    uint16_t done = 0;
    for (uint16_t i = 0; i < BLK_QSIZE && done < n; i++)
    {
        if (blk_q[i].in_use && !blk_q[i].done)
        {
            /* The triple owning this slot must still be live. */
            bool owned = false;
            for (uint16_t t = 0; t < BLK_QSIZE; t++)
            {
                if (h_owner[t] == (int)i)
                {
                    h_status[i] = status;
                    h_used.ring[h_used.idx % VMM_QCAP].id = (uint32_t)t * 3u;
                    h_used.ring[h_used.idx % VMM_QCAP].len = (uint32_t)blk_q[i].len;
                    h_used.idx++;
                    owned = true;
                    break;
                }
            }
            if (owned)
                done++;
        }
    }
    if (done > 0)
        host_blk_regs[VMM_ISTATUS / 4u] |= 1u; /* used-ring update pending */
    return done;
}
#endif

/* Report the driver's bound MMIO window as virtio-blk (or not).
 * No scan: this only touches the already-granted window in blk_regs, so it
 * never reaches outside the compartment's caps. NULL out has nowhere to
 * copy the caps, so it returns false (fail closed). On host-sim the window
 * is the host-backed identity regs programmed at init; false before init. */
bool block_probe(blk_caps_t *out)
{
    int legacy = 0;
    if (!out || !blk_regs)
        return false;
#ifdef __riscv
    if (vmm_probe(blk_regs, BLK_PROBE_DEV_BLK, &legacy) != ERR_OK)
        return false;
#else
    if (blk_regs[VMM_MAGIC / 4u] != VIRTIO_MAGIC_VAL)
        return false;
    {
        uint32_t ver = blk_regs[VMM_VERSION / 4u];
        if (ver != 1u && ver != 2u)
            return false;
    }
    if (blk_regs[VMM_DEVICE_ID / 4u] != BLK_PROBE_DEV_BLK)
        return false;
    (void)legacy;
#endif
    *out = caps;
    return true;
}

/* Scan a mem_server-minted candidate table for the virtio-blk slot.
 * Bounded linear scan (n capped to 8, the riscv-virt transport count);
 * each candidate is validated through its own cap via block_probe_slot.
 * False on NULL/empty input and on host-sim (no MMIO there). */
bool block_probe_table(const blk_caps_t *cands, uint32_t n, blk_caps_t *out)
{
    uint32_t lim;
    uint32_t i;
    if (!cands || !out || n == 0)
        return false;
    lim = n > 8u ? 8u : n;
    for (i = 0; i < lim; i++)
    {
        if (block_probe_slot(&cands[i], out))
            return true;
    }
    return false;
}

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

static bool block_transport_probe(void)
{
    volatile uint32_t *regs = blk_regs;
    int legacy = 0;
    if (vmm_probe(regs, VIRTIO_DEV_BLK, &legacy) != ERR_OK)
        return false;
    vmm_begin(regs);
    if (vmm_feat_ok(regs, legacy) != ERR_OK)
    {
        vmm_fail(regs);
        return false;
    }
    uint16_t n = 0;
    if (legacy)
        n = vmm_setup_leg(regs, 0, BLK_WANT_DESC, b_leg_mem, &b_desc, &b_avail, &b_used);
    else
        n = vmm_setup_mod(regs, 0, BLK_WANT_DESC, b_mod_desc, &b_mod_avail, &b_mod_used);
    if (n < 3u)
    {
        vmm_fail(regs);
        return false;
    }
    vmm_ready(regs);
    b_ndesc = n;
    b_ring_cap = n / 3u;
    if (b_ring_cap > BLK_QSIZE)
        b_ring_cap = BLK_QSIZE;
    b_seen = 0;
    b_desc_n = 0;
    for (uint16_t i = 0; i < b_ring_cap; i++)
    {
        b_desc_free[b_desc_n++] = (uint8_t)i;
        b_owner[i] = -1;
    }
    return true;
}

/* Program one request chain for shadow slot s (triple t already popped). */
static void block_chain_program(uint16_t s, uint8_t t, uintptr_t paddr, size_t len, uint8_t is_write)
{
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
static void block_drain_used(void)
{
    uint32_t n = 0;
    while (b_seen != b_used->idx && n < BLK_MAX_DRAIN)
    {
        struct vring_used_elem e = b_used->ring[b_seen % b_ndesc];
        vmm_fence();
        uint32_t id = e.id;
        if (id < b_ndesc && (id % 3u) == 0u)
        {
            uint8_t t = (uint8_t)(id / 3u);
            if (t < b_ring_cap)
            {
                int s = b_owner[t];
                if (s >= 0 && blk_q[s].in_use && !blk_q[s].done)
                {
                    blk_q[s].done = 1;
                    blk_q[s].status = blk_req_status[s];
                    b_owner[t] = -1;
                    if (b_desc_n < BLK_QSIZE)
                        b_desc_free[b_desc_n++] = t;
                }
            }
        }
        b_seen++;
        n++;
    }
}
#endif /* __riscv */

bool block_driver_init(blk_caps_t c, void *dma_mem, size_t dma_len)
{
    caps = c;
    if (c.mmio_len < 0x1000)
        return false;
#ifdef __CHERI_PURE_CAPABILITY__
    __capability void *cap = (void *)c.mmio_base;
    if (!__builtin_cheri_tag_get(cap))
        return false;
    if (__builtin_cheri_length_get(cap) < c.mmio_len)
        return false;
    blk_regs = (__capability volatile uint32_t *)cap;
#else
    if (c.mmio_base < 0x10000000 || c.mmio_base + c.mmio_len > 0x20000000)
        return false;
#if defined(__riscv)
    blk_regs = (volatile uint32_t *)c.mmio_base;
#else
    /* Host sim: physical MMIO is not host-valid; bind the host-backed
     * virtual-device regs (identity + rings, reset above). */
    block_host_reset();
    blk_regs = (volatile uint32_t *)host_blk_regs;
#endif
#endif
    dma_pool = (uint8_t *)dma_mem;
    dma_pool_size = dma_len;
    // IOMMU windows must be programmed before DMA - checked in kernel iommu_map()
#ifdef __riscv
    /* Production: refuse to run against an unvalidated MMIO device. */
    if (!block_transport_probe())
    {
        blk_regs = NULL;
        return false;
    }
#endif
    return true;
}

/* Bind an IOMMU window for the DMA pool. Must precede any I/O. */
bool block_set_iommu(cap_t iommu_cap, iommu_state_t *iommu, uintptr_t dev_id, uintptr_t dma_paddr, size_t dma_size)
{
    if (!iommu)
        return false;
    if (iommu_cap.type != CAP_IOMMU)
        return false;
    if (!iommu_cap.is_valid || !cheri_tag_get(iommu_cap.hw_cap))
        return false;
    if (dma_size % PAGE_SIZE || dma_paddr % PAGE_SIZE)
        return false;
    g_iommu = iommu;
    g_iommu_cap = iommu_cap;
    g_dev_id = dev_id;
    g_dma_base = dma_paddr;
    g_dma_len = dma_size;
    g_iommu_bound = false;
    kerror_t e = iommu_map(g_iommu, &g_iommu_cap, g_dev_id, dma_paddr, dma_size, CHERI_PERM_LOAD | CHERI_PERM_STORE);
    if (e != ERR_OK)
        return false;
    g_iommu_bound = true;
    return true;
}

bool block_dma_map(uintptr_t paddr, size_t size, uint32_t perms)
{
    if (!g_iommu || !g_iommu_bound)
        return false;
    if (size % PAGE_SIZE || paddr % PAGE_SIZE)
        return false;
    if (paddr < g_dma_base || size > g_dma_len || paddr + size > g_dma_base + g_dma_len)
        return false;
    if (paddr + size < paddr)
        return false;
    return iommu_map(g_iommu, &g_iommu_cap, g_dev_id, paddr, size, perms) == ERR_OK;
}

bool block_dma_unmap(uintptr_t paddr)
{
    if (!g_iommu)
        return false;
    return iommu_unmap(g_iommu, g_dev_id, paddr) == ERR_OK;
}

bool block_dma_check(uintptr_t paddr, size_t len, bool is_write)
{
    if (!g_iommu)
        return false;
    return iommu_check(g_iommu, g_dev_id, paddr, len, is_write);
}

void block_set_capacity(uint32_t nsectors)
{
    g_nsectors = nsectors;
}
uint32_t block_capacity(void)
{
    return g_nsectors;
}

void block_stats(blk_stats_t *out)
{
    if (!out)
        return;
    *out = blk_st;
    out->pending = blk_pending;
}

// Pool-membership precheck for a DMA buffer: the buffer must lie entirely
// inside the driver's DMA pool (wrap-safe). IOMMU confinement is checked
// separately via iommu_check on enqueue and IRQ drain.
bool block_map_dma(uintptr_t paddr, size_t len)
{
    if (!dma_pool)
        return false;
    if (paddr < (uintptr_t)dma_pool || len > dma_pool_size || paddr + len > (uintptr_t)dma_pool + dma_pool_size)
        return false;
    if (paddr + len < paddr)
        return false;
    return true;
}

static int blk_enqueue(uint32_t sector, uintptr_t paddr, size_t len, uint8_t is_write)
{
    if (!blk_regs || !dma_pool)
        return -1;
    if (len == 0 || len % BLK_SECTOR || len > BLK_MAX_BYTES)
        return -1;
    uint32_t nsec = (uint32_t)(len / BLK_SECTOR);
    /* Wrap-safe range check against capacity */
    if (sector >= g_nsectors || nsec > g_nsectors - sector)
        return -1;
    if (!block_map_dma(paddr, len))
        return -1;
    if (!g_iommu || !g_iommu_bound)
        return -1;
    /* Direction-appropriate IOMMU perm: read fills buf (STORE), write drains it (LOAD) */
    if (!iommu_check(g_iommu, g_dev_id, paddr, len, is_write ? false : true))
        return -1;
    if (blk_pending >= BLK_QSIZE)
        return -1;
    uint16_t slot = (uint16_t)(blk_head % BLK_QSIZE);
    for (uint16_t i = 0; i < BLK_QSIZE; i++)
    {
        uint16_t s = (uint16_t)((slot + i) % BLK_QSIZE);
        if (!blk_q[s].in_use)
        {
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
            if (b_desc_n == 0)
            {
                blk_q[s].in_use = 0;
                if (blk_pending > 0)
                    blk_pending--;
                blk_st.pending = blk_pending;
                return -1;
            }
            block_chain_program(s, b_desc_free[--b_desc_n], paddr, len, is_write);
#else
            /* Host-sim: program the virtual-device chain + queue notify.
             * Roll back the shadow alloc when the ring is full. */
            if (h_free_n == 0)
            {
                blk_q[s].in_use = 0;
                if (blk_pending > 0)
                    blk_pending--;
                blk_st.pending = blk_pending;
                return -1;
            }
            if (!block_host_chain(s, h_free[--h_free_n], paddr, len, is_write))
            {
                blk_q[s].in_use = 0;
                if (blk_pending > 0)
                    blk_pending--;
                blk_st.pending = blk_pending;
                return -1;
            }
            vmm_w((volatile uint32_t *)blk_regs, VMM_QNOTIFY, 0u);
            vmm_fence();
#endif
            return (int)len;
        }
    }
    return -1;
}

/* Derive the DMA address for a pool buffer. Bring-up identity maps the
 * pool (VA == PA) and the IOMMU window covers the same range, so the
 * address is the pointer value; on purecap it is the capability's address
 * (bounds stay on the caller's cap, ownership is proven by block_map_dma +
 * iommu_check, never by this cast alone). */
static uintptr_t block_buf_paddr(const void *buf)
{
#ifdef __CHERI_PURE_CAPABILITY__
    return cheri_address_get(buf);
#else
    return (uintptr_t)buf;
#endif
}

int block_read(uint32_t sector, void *buf, size_t len)
{
    if (!blk_regs || !buf)
        return -1;
    if (len % 512)
        return -1;
    return blk_enqueue(sector, block_buf_paddr(buf), len, VIRTIO_BLK_T_IN);
}

int block_write(uint32_t sector, const void *buf, size_t len)
{
    if (!blk_regs || !buf)
        return -1;
    if (len % 512)
        return -1;
    return blk_enqueue(sector, block_buf_paddr(buf), len, VIRTIO_BLK_T_OUT);
}

/* Device completion hooks (host-sim device step + target test hook).
 * Both go through the used ring: the device writes completions, the IRQ
 * path drains them. Returns the number completed. */
uint16_t block_sim_complete(uint16_t n)
{
#if !defined(__riscv)
    return block_device_emulate(n, 0);
#else
    uint16_t marked = 0;
    for (uint16_t i = 0; i < BLK_QSIZE && marked < n; i++)
    {
        if (blk_q[i].in_use && !blk_q[i].done)
        {
            blk_q[i].done = 1;
            blk_q[i].status = 0;
            marked++;
        }
    }
    return marked;
#endif
}

uint16_t block_sim_fail(uint16_t n)
{
#if !defined(__riscv)
    return block_device_emulate(n, 1);
#else
    uint16_t marked = 0;
    for (uint16_t i = 0; i < BLK_QSIZE && marked < n; i++)
    {
        if (blk_q[i].in_use && !blk_q[i].done)
        {
            blk_q[i].done = 1;
            blk_q[i].status = 1;
            marked++;
        }
    }
    return marked;
#endif
}

void block_driver_handle_irq(void)
{
    uint32_t status;
    if (!blk_regs)
        return;
    blk_st.irqs++;
#ifdef __riscv
    /* Real completion path: used ring -> shadow done flags. */
    (void)vmm_irq_ack(blk_regs);
    block_drain_used();
    status = 0;
#else
    /* Host-sim completion path: used ring -> shadow done flags, then ACK
     * exactly what was pending via the ISTATUS/IACK registers. */
    status = blk_regs[VMM_ISTATUS / 4u];
    block_host_drain();
#endif
    uint32_t drained = 0;
    for (uint16_t i = 0; i < BLK_QSIZE && drained < BLK_MAX_DRAIN; i++)
    {
        if (!blk_q[i].in_use || !blk_q[i].done)
            continue;
        bool confined = false;
        if (g_iommu && g_iommu_bound)
            confined = iommu_check(g_iommu, g_dev_id, blk_q[i].paddr, blk_q[i].len, blk_q[i].is_write ? false : true);
        uint8_t was_write = blk_q[i].is_write;
        size_t blen = blk_q[i].len;
        uint8_t dev_ok = blk_q[i].status;
        blk_q[i].in_use = 0;
        blk_q[i].done = 0;
        if (blk_pending > 0)
            blk_pending--;
        if (confined && dev_ok == 0)
        {
            if (was_write)
            {
                blk_st.writes++;
                blk_st.write_bytes += blen;
            }
            else
            {
                blk_st.reads++;
                blk_st.read_bytes += blen;
            }
        }
        else
        {
            blk_st.errors++;
        }
        drained++;
    }
    blk_st.pending = blk_pending;
    /* ACK exactly what was pending, via MMIO (never kernel memory). */
#ifdef __riscv
    (void)status;
#else
    if (status)
    {
        vmm_w((volatile uint32_t *)blk_regs, VMM_IACK, status);
        /* Host-sim device side effect: ACK clears the pending ISTATUS bits
         * (real devices do this in hardware; vmm_w only stores the reg). */
        host_blk_regs[VMM_ISTATUS / 4u] &= (uint32_t)~status;
        vmm_fence();
    }
#endif
}

bool block_driver_reboot(void)
{
    // Micro-reboot: clear queues, re-init with same caps, no kernel restart.
    // The driver only drops its own DMA window binding; revocation of the
    // underlying caps is the kernel/mem_server's job over IPC, re-minted
    // via mem_server before the next block_set_iommu.
    if (g_iommu && g_iommu_bound)
    {
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
    /* block_driver_init resets the transport (host rings / target probe). */
    return block_driver_init(caps, dma_pool, dma_pool_size);
}
