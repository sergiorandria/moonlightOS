/* virtio_net driver - unprivileged CHERI compartment
 * Only gets: MMIO cap (virtio regs), IRQ cap, DMA Frame caps via IOMMU. No kernel access.
 * Crash -> micro-reboot: mem_server revokes old Frame caps, re-mints new ones.
 * DMA buffers are explicitly registered via iommu_map and checked via iommu_check.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "../abi/cheri.h"
#include "../abi/cap.h"
#include "../abi/iommu.h"
#include "virtio_mmio.h"

typedef struct { uintptr_t mmio_base; size_t mmio_len; uint32_t irq; } drv_caps_t;
static drv_caps_t caps;
static volatile uint32_t *virtio_regs;

#ifdef __riscv
/* Real target transport (defined below the queue core). */
static bool net_transport_probe(void);
static void net_chain_program(int is_rx, uint16_t s, uint8_t p,
                              uintptr_t paddr, uint16_t len);
static void net_drain_queue(int is_rx);
#endif

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
#ifdef __riscv
    /* Production: refuse to run against an unvalidated MMIO device. */
    if (!net_transport_probe()) {
        virtio_regs = NULL;
        return false;
    }
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

/* --- TX/RX virtqueue layer (host-testable core, MMIO notify on target) ---
 * Split virtqueues q0=RX, q1=TX, 64 descriptors each. Descriptors live in
 * driver memory; packet buffers live in the DMA pool and are validated
 * against the IOMMU window on every enqueue AND on IRQ completion.
 * Bounded work: enqueue is O(1), IRQ drain completes at most 32 per call. */
#define NET_QSIZE 64u
#define NET_MTU 1514u
#define NET_MAX_DRAIN 32u

typedef struct {
    uintptr_t paddr;
    uint16_t len;
    uint8_t in_use;   /* descriptor owned by device */
    uint8_t done;     /* device completed, awaiting drain */
} net_desc_t;

typedef struct {
    uint64_t tx_ok;
    uint64_t tx_drop;
    uint64_t rx_ok;
    uint64_t rx_drop;
    uint64_t irqs;
    uint16_t tx_pending;
    uint16_t rx_pending;
} net_stats_t;


static net_desc_t net_txd[NET_QSIZE];
static net_desc_t net_rxd[NET_QSIZE];
static uint16_t net_tx_head, net_rx_head; /* next slot to fill (mod QSIZE) */
static uint16_t net_tx_pending, net_rx_pending;
static net_stats_t net_st;

/* --- Target virtio-mmio transport (__riscv only) ---
 * Real split virtqueues: q0=RX, q1=TX, 2 descriptors per packet
 * ([12B virtio-net header][packet]). Headers live in driver-owned static
 * memory (DMA-visible on the identity-mapped bring-up kernel; a future
 * driver compartment maps the same pages for the device via its IOMMU
 * cap). Host-sim keeps the sim hooks. */
#ifdef __riscv
#define NET_WANT_DESC 128u /* 64 packets x 2 */
#define NET_HDR_LEN 12u
static struct vring_desc *nrx_desc, *ntx_desc;
static struct vring_avail_q *nrx_avail, *ntx_avail;
static volatile struct vring_used_q *nrx_used, *ntx_used;
static uint16_t nrx_ndesc, ntx_ndesc;
static uint16_t nrx_seen, ntx_seen;
static uint16_t nrx_cap, ntx_cap;
static uint8_t nrx_leg[8192] __attribute__((aligned(4096)));
static uint8_t ntx_leg[8192] __attribute__((aligned(4096)));
static struct vring_desc nrx_mod[NET_WANT_DESC] __attribute__((aligned(16)));
static struct vring_avail_q nrx_mod_avail __attribute__((aligned(2)));
static volatile struct vring_used_q nrx_mod_used __attribute__((aligned(4096)));
static struct vring_desc ntx_mod[NET_WANT_DESC] __attribute__((aligned(16)));
static struct vring_avail_q ntx_mod_avail __attribute__((aligned(2)));
static volatile struct vring_used_q ntx_mod_used __attribute__((aligned(4096)));
static uint8_t net_rx_hdr[NET_QSIZE][NET_HDR_LEN];
static uint8_t net_tx_hdr[NET_QSIZE][NET_HDR_LEN];
/* Pair-index freelists + owner tables (pair -> shadow slot, -1 = free). */
static uint8_t nrx_free[NET_QSIZE], ntx_free[NET_QSIZE];
static uint16_t nrx_free_n, ntx_free_n;
static int nrx_owner[NET_QSIZE], ntx_owner[NET_QSIZE];

static uint16_t net_setup_one_queue(uint32_t qsel, int legacy,
                                    struct vring_desc **d,
                                    struct vring_avail_q **a,
                                    volatile struct vring_used_q **u) {
    if (legacy)
        return vmm_setup_leg(virtio_regs, qsel, NET_WANT_DESC,
                             qsel == 0u ? nrx_leg : ntx_leg, d, a, u);
    if (qsel == 0u)
        return vmm_setup_mod(virtio_regs, qsel, NET_WANT_DESC,
                             nrx_mod, &nrx_mod_avail, &nrx_mod_used);
    return vmm_setup_mod(virtio_regs, qsel, NET_WANT_DESC,
                         ntx_mod, &ntx_mod_avail, &ntx_mod_used);
}

static bool net_transport_probe(void) {
    volatile uint32_t *regs = virtio_regs;
    int legacy = 0;
    if (vmm_probe(regs, VIRTIO_DEV_NET, &legacy) != ERR_OK) return false;
    vmm_begin(regs);
    if (vmm_feat_ok(regs, legacy) != ERR_OK) { vmm_fail(regs); return false; }
    nrx_ndesc = net_setup_one_queue(0u, legacy, &nrx_desc, &nrx_avail, &nrx_used);
    if (nrx_ndesc < 2u) { vmm_fail(regs); return false; }
    ntx_ndesc = net_setup_one_queue(1u, legacy, &ntx_desc, &ntx_avail, &ntx_used);
    if (ntx_ndesc < 2u) { vmm_fail(regs); return false; }
    vmm_ready(regs);
    nrx_cap = nrx_ndesc / 2u;
    ntx_cap = ntx_ndesc / 2u;
    if (nrx_cap > NET_QSIZE) nrx_cap = NET_QSIZE;
    if (ntx_cap > NET_QSIZE) ntx_cap = NET_QSIZE;
    nrx_seen = ntx_seen = 0;
    nrx_free_n = ntx_free_n = 0;
    for (uint16_t i = 0; i < nrx_cap; i++) {
        nrx_free[nrx_free_n++] = (uint8_t)i;
        nrx_owner[i] = -1;
    }
    for (uint16_t i = 0; i < ntx_cap; i++) {
        ntx_free[ntx_free_n++] = (uint8_t)i;
        ntx_owner[i] = -1;
    }
    memset(net_rx_hdr, 0, sizeof(net_rx_hdr));
    memset(net_tx_hdr, 0, sizeof(net_tx_hdr));
    return true;
}

/* Program one packet chain on the given queue. Pair p already popped,
 * shadow slot s validated by the caller. is_rx selects direction. */
static void net_chain_program(int is_rx, uint16_t s, uint8_t p,
                              uintptr_t paddr, uint16_t len) {
    struct vring_desc *desc = is_rx ? nrx_desc : ntx_desc;
    struct vring_avail_q *avail = is_rx ? nrx_avail : ntx_avail;
    uint16_t ndesc = is_rx ? nrx_ndesc : ntx_ndesc;
    uint8_t (*hdr)[NET_HDR_LEN] = is_rx ? net_rx_hdr : net_tx_hdr;
    int *owner = is_rx ? nrx_owner : ntx_owner;
    (void)len;
    uint16_t d = (uint16_t)p * 2u;
    desc[d].addr = (uint64_t)(uintptr_t)&hdr[s][0];
    desc[d].len = NET_HDR_LEN;
    desc[d].flags = VRING_DESC_F_NEXT;
    desc[d].next = (uint16_t)(d + 1u);
    desc[d + 1].addr = (uint64_t)paddr;
    desc[d + 1].len = is_rx ? net_rxd[s].len : net_txd[s].len;
    desc[d + 1].flags = is_rx ? VRING_DESC_F_WRITE : 0u;
    desc[d + 1].next = 0;
    owner[p] = (int)s;
    vmm_fence();
    avail->ring[avail->idx % ndesc] = d;
    vmm_fence();
    avail->idx++;
    vmm_fence();
    vmm_notify(virtio_regs, is_rx ? 0u : 1u);
}

/* Drain one queue's used ring into shadow completions (bounded). */
static void net_drain_queue(int is_rx) {
    struct vring_used_q *used =
        (struct vring_used_q *)(is_rx ? nrx_used : ntx_used);
    uint16_t ndesc = is_rx ? nrx_ndesc : ntx_ndesc;
    uint16_t *seen = is_rx ? &nrx_seen : &ntx_seen;
    uint8_t *free = is_rx ? nrx_free : ntx_free;
    uint16_t *free_n = is_rx ? &nrx_free_n : &ntx_free_n;
    uint16_t cap = is_rx ? nrx_cap : ntx_cap;
    int *owner = is_rx ? nrx_owner : ntx_owner;
    net_desc_t *slots = is_rx ? net_rxd : net_txd;
    uint32_t n = 0;
    while (*seen != used->idx && n < NET_MAX_DRAIN) {
        struct vring_used_elem e = used->ring[*seen % ndesc];
        vmm_fence();
        uint32_t id = e.id;
        if (id < ndesc && (id % 2u) == 0u) {
            uint8_t p = (uint8_t)(id / 2u);
            if (p < cap) {
                int s = owner[p];
                if (s >= 0 && slots[s].in_use && !slots[s].done) {
                    if (is_rx) {
                        uint32_t paylen =
                            e.len >= NET_HDR_LEN ? e.len - NET_HDR_LEN : 0u;
                        if (paylen <= slots[s].len) {
                            slots[s].len =
                                (uint16_t)(paylen ? paylen : slots[s].len);
                            slots[s].done = 1;
                        }
                    } else {
                        slots[s].done = 1;
                    }
                    if (slots[s].done) {
                        owner[p] = -1;
                        if (*free_n < NET_QSIZE) free[(*free_n)++] = p;
                    }
                }
            }
        }
        (*seen)++;
        n++;
    }
}
#endif /* __riscv */

/* Enqueue a TX packet. Device READS the buffer -> require LOAD window. */
bool net_driver_tx(uintptr_t paddr, uint16_t len) {
    if (!virtio_regs) return false;
    if (!g_iommu || !g_iommu_bound) return false;
    if (len == 0 || len > NET_MTU) { net_st.tx_drop++; return false; }
    if (paddr < g_dma_base || len > g_dma_len ||
        paddr + len > g_dma_base + g_dma_len) { net_st.tx_drop++; return false; }
    /* Wrap-safe overflow check (paddr+len must not wrap) */
    if (paddr + len < paddr) { net_st.tx_drop++; return false; }
    if (!iommu_check(g_iommu, g_dev_id, paddr, len, false)) { net_st.tx_drop++; return false; }
    if (net_tx_pending >= NET_QSIZE) { net_st.tx_drop++; return false; }
    uint16_t slot = net_tx_head % NET_QSIZE;
    /* Linear-probe for a free slot (bounded: QSIZE steps) */
    for (uint16_t i = 0; i < NET_QSIZE; i++) {
        uint16_t s = (uint16_t)((slot + i) % NET_QSIZE);
        if (!net_txd[s].in_use) {
            net_txd[s].paddr = paddr;
            net_txd[s].len = len;
            net_txd[s].in_use = 1;
            net_txd[s].done = 0;
            net_tx_pending++;
            net_tx_head = (uint16_t)((s + 1u) % NET_QSIZE);
            net_st.tx_pending = net_tx_pending;
#ifdef __riscv
            /* Real device: program chain + notify; roll back when the
             * ring (device queue size) is full. */
            if (ntx_free_n == 0) {
                net_txd[s].in_use = 0;
                if (net_tx_pending > 0) net_tx_pending--;
                net_st.tx_pending = net_tx_pending;
                net_st.tx_drop++;
                return false;
            }
            net_chain_program(0, s, ntx_free[--ntx_free_n], paddr, len);
#else
            __asm__ volatile("" ::: "memory");
#endif
            return true;
        }
    }
    net_st.tx_drop++;
    return false;
}

/* Enqueue an RX buffer. Device WRITES the packet -> require STORE window. */
bool net_driver_rx_provide(uintptr_t paddr, uint16_t len) {
    if (!virtio_regs) return false;
    if (!g_iommu || !g_iommu_bound) return false;
    if (len == 0 || len > NET_MTU) { net_st.rx_drop++; return false; }
    if (paddr < g_dma_base || len > g_dma_len ||
        paddr + len > g_dma_base + g_dma_len) { net_st.rx_drop++; return false; }
    if (paddr + len < paddr) { net_st.rx_drop++; return false; }
    if (!iommu_check(g_iommu, g_dev_id, paddr, len, true)) { net_st.rx_drop++; return false; }
    if (net_rx_pending >= NET_QSIZE) { net_st.rx_drop++; return false; }
    uint16_t slot = net_rx_head % NET_QSIZE;
    for (uint16_t i = 0; i < NET_QSIZE; i++) {
        uint16_t s = (uint16_t)((slot + i) % NET_QSIZE);
        if (!net_rxd[s].in_use) {
            net_rxd[s].paddr = paddr;
            net_rxd[s].len = len;
            net_rxd[s].in_use = 1;
            net_rxd[s].done = 0;
            net_rx_pending++;
            net_rx_head = (uint16_t)((s + 1u) % NET_QSIZE);
            net_st.rx_pending = net_rx_pending;
#ifdef __riscv
            /* Real device: program chain + notify; roll back when the
             * ring (device queue size) is full. */
            if (nrx_free_n == 0) {
                net_rxd[s].in_use = 0;
                if (net_rx_pending > 0) net_rx_pending--;
                net_st.rx_pending = net_rx_pending;
                net_st.rx_drop++;
                return false;
            }
            net_chain_program(1, s, nrx_free[--nrx_free_n], paddr, len);
#else
            __asm__ volatile("" ::: "memory");
#endif
            return true;
        }
    }
    net_st.rx_drop++;
    return false;
}

/* Test/target hook: mark up to n owned descriptors complete (device wrote
 * used ring + raised IRQ). Returns number marked. */
uint16_t net_driver_sim_complete_tx(uint16_t n) {
    uint16_t marked = 0;
    for (uint16_t i = 0; i < NET_QSIZE && marked < n; i++) {
        if (net_txd[i].in_use && !net_txd[i].done) {
            net_txd[i].done = 1;
            marked++;
        }
    }
    return marked;
}

uint16_t net_driver_sim_recv(uint16_t n, uint16_t paylen) {
    uint16_t marked = 0;
    for (uint16_t i = 0; i < NET_QSIZE && marked < n; i++) {
        if (net_rxd[i].in_use && !net_rxd[i].done) {
            if (paylen <= net_rxd[i].len) {
                net_rxd[i].len = paylen ? paylen : net_rxd[i].len;
                net_rxd[i].done = 1;
                marked++;
            }
        }
    }
    return marked;
}

void net_driver_stats(net_stats_t *out) {
    if (!out) return;
    *out = net_st;
    out->tx_pending = net_tx_pending;
    out->rx_pending = net_rx_pending;
}

void net_driver_handle_irq(void) {
    if (!virtio_regs) return;
    uint32_t status = virtio_regs[4];
    net_st.irqs++;
#ifdef __riscv
    /* Real completion path: used rings -> shadow done flags. */
    (void)vmm_irq_ack(virtio_regs);
    net_drain_queue(1); /* TX first: frees transmit buffers promptly */
    net_drain_queue(0);
#endif
    /* Per-slot IOMMU re-validation: a revoked window turns completions
     * into drops here. No DMA memory is touched on this path (accounting
     * only), so revocation is safe without an early-out — and pending
     * slots can never leak. */
    /* Drain TX completions (bounded): re-check each buffer, then free it. */
    uint32_t drained = 0;
    for (uint16_t i = 0; i < NET_QSIZE && drained < NET_MAX_DRAIN; i++) {
        if (!net_txd[i].in_use || !net_txd[i].done) continue;
        bool ok = false;
        if (g_iommu && g_iommu_bound &&
            iommu_check(g_iommu, g_dev_id, net_txd[i].paddr, net_txd[i].len, false))
            ok = true;
        net_txd[i].in_use = 0;
        net_txd[i].done = 0;
        if (net_tx_pending > 0) net_tx_pending--;
        if (ok) net_st.tx_ok++;
        else net_st.tx_drop++;
        drained++;
    }
    /* Drain RX completions (bounded): device-filled buffers need STORE. */
    drained = 0;
    for (uint16_t i = 0; i < NET_QSIZE && drained < NET_MAX_DRAIN; i++) {
        if (!net_rxd[i].in_use || !net_rxd[i].done) continue;
        bool ok = false;
        if (g_iommu && g_iommu_bound &&
            iommu_check(g_iommu, g_dev_id, net_rxd[i].paddr, net_rxd[i].len, true))
            ok = true;
        net_rxd[i].in_use = 0;
        net_rxd[i].done = 0;
        if (net_rx_pending > 0) net_rx_pending--;
        if (ok) net_st.rx_ok++;
        else net_st.rx_drop++;
        drained++;
    }
    net_st.tx_pending = net_tx_pending;
    net_st.rx_pending = net_rx_pending;
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
    memset(net_txd, 0, sizeof(net_txd));
    memset(net_rxd, 0, sizeof(net_rxd));
    net_tx_head = net_rx_head = 0;
    net_tx_pending = net_rx_pending = 0;
    memset(&net_st, 0, sizeof(net_st));
    net_driver_init(caps);
}
