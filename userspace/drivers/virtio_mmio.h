#pragma once
/* Shared virtio-mmio transport for Moonlight userspace drivers.
 *
 * Mirrors the proven kernel/src/kbd.c pattern: probe the virtio-mmio
 * transports, validate magic/version/device-ID, negotiate features, set up
 * one split virtqueue per call (legacy MMIO v1 8K region or modern
 * descriptor/avail/used pages), handshake DRIVER_OK, notify + used-ring
 * drain with InterruptStatus ACK. All queue work is bounded.
 *
 * Ring structs and helpers are plain C and host-compilable; every MMIO
 * touch is __riscv-guarded (host-sim stubs return ERR_NO_MEM). Drivers keep
 * their own slot tables; this header only owns the transport.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "../abi/types.h"

#define VMM_MAGIC      0x000u
#define VMM_VERSION    0x004u
#define VMM_DEVICE_ID  0x008u
#define VMM_FEAT       0x010u
#define VMM_FEAT_SEL   0x014u
#define VMM_DRV_FEAT   0x020u
#define VMM_DRV_SEL    0x024u
#define VMM_GUEST_PAGE 0x028u
#define VMM_QSEL       0x030u
#define VMM_QMAX       0x034u
#define VMM_QNUM       0x038u
#define VMM_QALIGN     0x03cu
#define VMM_QPFN       0x040u
#define VMM_QREADY     0x044u
#define VMM_QNOTIFY    0x050u
#define VMM_ISTATUS    0x060u
#define VMM_IACK       0x064u
#define VMM_STATUS     0x070u
#define VMM_QDESC_LO   0x080u
#define VMM_QDESC_HI   0x084u
#define VMM_QDRV_LO    0x090u
#define VMM_QDRV_HI    0x094u
#define VMM_QDEV_LO    0x0a0u
#define VMM_QDEV_HI    0x0a4u

#define VIRTIO_MAGIC_VAL 0x74726976u
#define VIRTIO_F_VERSION_1 32u

#define VSTAT_ACK       1u
#define VSTAT_DRIVER    2u
#define VSTAT_DRIVER_OK 4u
#define VSTAT_FEAT_OK   8u
#define VSTAT_FAILED    128u

#define VRING_DESC_F_NEXT  1u
#define VRING_DESC_F_WRITE 2u

#define VMM_QCAP 256u /* max descriptors per queue handled here */

/* virtio device IDs seen on riscv-virt */
#define VIRTIO_DEV_NET 1u
#define VIRTIO_DEV_BLK 2u

struct vring_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

struct vring_avail_q {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[VMM_QCAP];
};

struct vring_used_elem {
    uint32_t id;
    uint32_t len;
};

struct vring_used_q {
    uint16_t flags;
    uint16_t idx;
    struct vring_used_elem ring[VMM_QCAP];
};

_Static_assert(sizeof(struct vring_desc) == 16, "vring_desc must be 16 bytes");
_Static_assert(sizeof(struct vring_used_elem) == 8, "vring_used_elem must be 8 bytes");

static inline void vmm_fence(void) {
#ifdef __riscv
    __asm__ volatile("fence iorw,iorw" ::: "memory");
#else
    __asm__ volatile("" ::: "memory");
#endif
}

static inline uint32_t vmm_r(volatile uint32_t *regs, uint32_t off) {
    return *(volatile uint32_t *)((uintptr_t)regs + off);
}

static inline void vmm_w(volatile uint32_t *regs, uint32_t off, uint32_t v) {
    *(volatile uint32_t *)((uintptr_t)regs + off) = v;
}

static inline void vmm_w64(volatile uint32_t *regs, uint32_t lo_off, uint64_t v) {
    vmm_w(regs, lo_off, (uint32_t)(v & 0xffffffffu));
    vmm_w(regs, lo_off + 4u, (uint32_t)(v >> 32));
    vmm_fence();
}

/* Validate one transport: magic + version (legacy 1 / modern 2) +
 * expected device ID. Returns ERR_OK and the legacy flag, else an error. */
static inline kerror_t vmm_probe(volatile uint32_t *regs, uint32_t expect_dev,
                                 int *legacy_out) {
    if (!regs || !legacy_out) return ERR_INVALID_ARG;
#ifdef __riscv
    if (vmm_r(regs, VMM_MAGIC) != VIRTIO_MAGIC_VAL) return ERR_INVALID_ARG;
    uint32_t ver = vmm_r(regs, VMM_VERSION);
    if (ver != 1u && ver != 2u) return ERR_INVALID_ARG;
    if (vmm_r(regs, VMM_DEVICE_ID) != expect_dev) return ERR_INVALID_ARG;
    *legacy_out = (ver == 1u) ? 1 : 0;
    return ERR_OK;
#else
    (void)expect_dev;
    return ERR_NO_MEM; /* host-sim: no MMIO, caller uses sim hooks */
#endif
}

static inline void vmm_begin(volatile uint32_t *regs) {
#ifdef __riscv
    vmm_w(regs, VMM_STATUS, 0u);
    vmm_fence();
    vmm_w(regs, VMM_STATUS, VSTAT_ACK | VSTAT_DRIVER);
    vmm_fence();
#else
    (void)regs;
#endif
}

static inline void vmm_fail(volatile uint32_t *regs) {
#ifdef __riscv
    vmm_w(regs, VMM_STATUS, VSTAT_ACK | VSTAT_DRIVER | VSTAT_FAILED);
    vmm_fence();
#else
    (void)regs;
#endif
}

/* We need nothing beyond VERSION_1 (bit 32 -> selector 1) on modern. */
static inline kerror_t vmm_feat_ok(volatile uint32_t *regs, int legacy) {
#ifdef __riscv
    vmm_w(regs, VMM_FEAT_SEL, 0u);
    (void)vmm_r(regs, VMM_FEAT);
    if (legacy) {
        vmm_w(regs, VMM_DRV_SEL, 0u);
        vmm_w(regs, VMM_DRV_FEAT, 0u);
    } else {
        vmm_w(regs, VMM_DRV_SEL, 1u);
        vmm_w(regs, VMM_DRV_FEAT, 1u);
        vmm_w(regs, VMM_DRV_SEL, 0u);
        vmm_w(regs, VMM_DRV_FEAT, 0u);
    }
    vmm_w(regs, VMM_STATUS, VSTAT_ACK | VSTAT_DRIVER | VSTAT_FEAT_OK);
    vmm_fence();
    if (!(vmm_r(regs, VMM_STATUS) & VSTAT_FEAT_OK)) return ERR_INVALID_ARG;
    return ERR_OK;
#else
    (void)regs; (void)legacy;
    return ERR_NO_MEM;
#endif
}

/* Modern queue setup with caller-owned pages. Returns count or 0. */
static inline uint16_t vmm_setup_mod(volatile uint32_t *regs, uint32_t qsel,
                                     uint16_t want, struct vring_desc *desc,
                                     struct vring_avail_q *avail,
                                     volatile struct vring_used_q *used) {
#ifdef __riscv
    if (!regs || !desc || !avail || !used || want == 0) return 0;
    vmm_w(regs, VMM_QSEL, qsel);
    uint32_t max = vmm_r(regs, VMM_QMAX);
    if (max == 0 || max > 1024u) return 0;
    uint16_t n = want < max ? want : (uint16_t)max;
    if (n > VMM_QCAP) n = VMM_QCAP;
    memset(desc, 0, sizeof(struct vring_desc) * n);
    memset(avail, 0, sizeof(struct vring_avail_q));
    memset((void *)used, 0, sizeof(struct vring_used_q));
    vmm_w(regs, VMM_QNUM, n);
    vmm_w64(regs, VMM_QDESC_LO, (uint64_t)(uintptr_t)desc);
    vmm_w64(regs, VMM_QDRV_LO, (uint64_t)(uintptr_t)avail);
    vmm_w64(regs, VMM_QDEV_LO, (uint64_t)(uintptr_t)used);
    vmm_w(regs, VMM_QREADY, 1u);
    vmm_fence();
    return n;
#else
    (void)regs; (void)qsel; (void)want; (void)desc; (void)avail; (void)used;
    return 0;
#endif
}

/* Legacy (MMIO v1) queue inside one 8K region: desc/avail at +0, used at
 * +4096. Outputs the split pointers. Returns count or 0. */
static inline uint16_t vmm_setup_leg(volatile uint32_t *regs, uint32_t qsel,
                                     uint16_t want, uint8_t *mem,
                                     struct vring_desc **d_out,
                                     struct vring_avail_q **a_out,
                                     volatile struct vring_used_q **u_out) {
#ifdef __riscv
    if (!regs || !mem || !d_out || !a_out || !u_out || want == 0) return 0;
    vmm_w(regs, VMM_QSEL, qsel);
    uint32_t max = vmm_r(regs, VMM_QMAX);
    if (max == 0 || max > 1024u) return 0;
    uint16_t n = want < max ? want : (uint16_t)max;
    if (n > VMM_QCAP) n = VMM_QCAP;
    /* desc(n*16) + avail(4+2n+2) must fit the first 4K page */
    if ((size_t)n * 16u + 6u + (size_t)n * 2u > 4096u)
        n = (uint16_t)((4096u - 6u) / 18u);
    if (n == 0) return 0;
    memset(mem, 0, 8192);
    vmm_w(regs, VMM_QNUM, n);
    vmm_w(regs, VMM_GUEST_PAGE, 4096u);
    vmm_w(regs, VMM_QALIGN, 4096u);
    vmm_w(regs, VMM_QPFN, (uint32_t)((uintptr_t)mem >> 12));
    vmm_fence();
    *d_out = (struct vring_desc *)mem;
    *a_out = (struct vring_avail_q *)(mem + sizeof(struct vring_desc) * n);
    *u_out = (volatile struct vring_used_q *)(mem + 4096);
    return n;
#else
    (void)regs; (void)qsel; (void)want; (void)mem;
    (void)d_out; (void)a_out; (void)u_out;
    return 0;
#endif
}

static inline void vmm_ready(volatile uint32_t *regs) {
#ifdef __riscv
    vmm_w(regs, VMM_STATUS,
          VSTAT_ACK | VSTAT_DRIVER | VSTAT_FEAT_OK | VSTAT_DRIVER_OK);
    vmm_fence();
#else
    (void)regs;
#endif
}

static inline void vmm_notify(volatile uint32_t *regs, uint32_t q) {
#ifdef __riscv
    vmm_w(regs, VMM_QNOTIFY, q);
    vmm_fence();
#else
    (void)regs; (void)q;
#endif
}

/* Returns pending interrupt status bits (0 = none); ACKs what was set. */
static inline uint32_t vmm_irq_ack(volatile uint32_t *regs) {
#ifdef __riscv
    if (!regs) return 0;
    uint32_t isr = vmm_r(regs, VMM_ISTATUS);
    if (isr) vmm_w(regs, VMM_IACK, isr);
    vmm_fence();
    return isr;
#else
    (void)regs;
    return 0;
#endif
}
