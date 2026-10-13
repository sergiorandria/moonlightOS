/* kernel/platform.h - QEMU `virt` platform constants (MMIO bases, PLIC,
 * virtio-mmio, bochs-display window). Constants only: no code, no state.
 *
 * Nothing in here is policy. The kernel maps these ranges into specific
 * threads' address spaces (kboot.c dev_leaves[]) and routes their IRQs
 * (irq.c); every driver that *uses* them lives in userspace. */
#ifndef V2_PLATFORM_H
#define V2_PLATFORM_H

/* ---- virtio-mmio: 8 transports at 0x10001000 + i*0x1000, IRQ 1+i ---- */
#define VIRTIO0_BASE 0x10001000UL
#define VIRTIO_NTRANSPORTS 8
#define VIRTIO_MAGIC 0x74726976u /* "virt" */
#define VIRTIO_VERSION_MODERN 2u
#define VIRTIO_DEV_NET 1u
#define VIRTIO_DEV_BLK 2u
#define VIRTIO_DEV_CONSOLE 3u
#define VIRTIO_DEV_RNG 4u
#define VIRTIO_DEV_INPUT 18u
#define VIRTIO_IRQ_NOT_FOUND 0xFFFFFFFFu

/* ---- PLIC, hart 0. Measured on the pinned QEMU: only the S-context set
 * delivers to S-mode; the M-context set is programmed identically as
 * defense in depth (firmware that delegates differently).
 *
 * Upstream refs: SiFive FU540-C000 PLIC (priority/enable array/threshold/
 * claim-complete) as wired on QEMU `virt`; enable registers are an array
 * of 32-bit words (word = irq/32, bit = irq%32); source 0 is reserved.
 * S-mode MMIO aliases (ENABLE_S/THRESH_S/CLAIM_S) are reachable from
 * S-mode on QEMU virt (plain MMIO, not a privileged CSR). ---- */
#define PLIC_BASE 0x0c000000UL
#define PLIC_ENABLE_M 0x0c002000UL
#define PLIC_ENABLE_S 0x0c002080UL
#define PLIC_THRESH_M 0x0c200000UL
#define PLIC_THRESH_S 0x0c201000UL
#define PLIC_CLAIM_M 0x0c200004UL
#define PLIC_CLAIM_S 0x0c201004UL
/* PLIC source-ID bound (matches userspace/drivers/plic.c PLIC_MAX_IRQ):
 * valid sources are 1..PLIC_MAX_IRQ-1; 0 is reserved/spurious. */
#define PLIC_MAX_IRQ 64u

/* ---- RISC-V S-mode interrupt-enable bits (RISC-V Privileged Spec Ch.4,
 * sie/sip: SSIE=bit1, STIE=bit5, SEIE=bit9). Single home for the fence
 * masks used by sched/syscall/irq critical sections. ---- */
#define SIE_MASK_SSIE (1UL << 1)
#define SIE_MASK_STIE (1UL << 5)
#define SIE_MASK_SEIE (1UL << 9)
#define SIE_MASK_STIE_SEIE ((1UL << 5) | (1UL << 9))

/* ---- Notify bits the IRQ router raises on the owning driver thread ---- */
#define NET_IRQ_BIT 0x1UL   /* tid 6 */
#define BLK_IRQ_BIT 0x2UL   /* tid 9 */
#define KBD_IRQ_BIT 0x4UL   /* tid 10 */
#define MOUSE_IRQ_BIT 0x8UL /* tid 10 */
/* Reserved badges: recorded on IRQ_KIND_STUB routes only. The handler
 * must not wake a thread on these until a live owner tid exists. */
#define RNG_IRQ_BIT_RESERVED 0x10UL
#define USB_IRQ_BIT_RESERVED 0x20UL
#define GPU_IRQ_BIT_RESERVED 0x40UL
#define SOUND_IRQ_BIT_RESERVED 0x80UL

/* ---- bochs-display (GUI) ---- */
#define GUI_WIDTH 800
#define GUI_HEIGHT 600
#define GUI_BPP 32                                          /* XRGB */
#define GUI_FB_MIN (GUI_WIDTH * GUI_HEIGHT * (GUI_BPP / 8)) /* smallest usable LFB */
#define GUI_ECAM_PHYS 0x30000000UL                          /* virt-machine ECAM base (fixed) */
#define GUI_LFB_PHYS 0x40000000UL                           /* kernel-assigned BAR0 (64M-aligned PCI low window) */
#define GUI_ECAM_PAGES 16                                   /* bus-0 config range: 64KB */
#define GUI_LFB_PAGES 512                                   /* one l0 table: 2MB window >= 469-page frame */
#define GUI_PCI_VEN 0x1234u
#define GUI_PCI_DEV 0x1111u
#define GUI_LFB_MAX 0x4000000u /* largest BAR the kernel assigns (64M) */

#endif /* V2_PLATFORM_H */
