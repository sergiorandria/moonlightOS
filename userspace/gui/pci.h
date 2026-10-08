/* userspace/gui/pci.h - ECAM offset + BAR validation for the
 * virt-machine PCI host bridge and the Bochs-display VGA device.
 * Portable C99, freestanding-safe: stdint.h only, static inline, no malloc,
 * no host calls. All arithmetic wrap-safe (overflow checked BEFORE compare).
 * Fail closed: invalid inputs yield a sentinel (pci_cfg_off) or 0. */

#ifndef GUI_PCI_H
#define GUI_PCI_H

#include <stdint.h>

#define PCI_ECAM_BASE 0x30000000UL
#define PCI_BUS0_ONLY 1
/* Bochs-display VGA IDs, fetched verbatim from QEMU source (never from
 * memory): include/hw/pci/pci.h defines PCI_VENDOR_ID_QEMU 0x1234 and
 * PCI_DEVICE_ID_QEMU_VGA 0x1111, and hw/display/bochs-display.c binds the
 * bochs-display device to exactly that vendor/device pair. */
#define BOCHS_VEN 0x1234
#define BOCHS_DEV 0x1111

/* Largest LFB window the GUI server accepts (64M); bigger BARs rejected. */
#define PCI_LFB_MAX 0x4000000u

/* pci_cfg_off: config-space offset of bus/dev/fn. Bus stride is one 1MB
 * ECAM window; within a bus each device owns 2KB (8 functions x 256B).
 * Fail closed: dev >= 32, fn >= 8, or bus >= 256 returns 0xFFFFFFFFu.
 * With those bounds (bus*1MB <= 255MB) the sum below cannot wrap. */
static inline uint32_t pci_cfg_off(uint32_t bus, uint32_t dev, uint32_t fn) {
    if (dev >= 32u || fn >= 8u || bus >= 256u) {
        return 0xFFFFFFFFu;
    }
    return bus * 1048576u + dev * 2048u + fn * 256u;
}

/* pci_bar_ok: base/size describe a usable 32-bit MMIO framebuffer window:
 * nonzero power-of-two size <= 64M, nonzero base aligned to size, no wrap. */
static inline int pci_bar_ok(uint32_t base, uint32_t size) {
    if (size == 0u) {
        return 0;
    }
    if (size > (uint32_t)PCI_LFB_MAX) {
        return 0;
    }
    if ((size & (size - 1u)) != 0u) {
        return 0; /* PCI BAR sizes are powers of two */
    }
    if (base == 0u) {
        return 0; /* BAR at address 0 = unprogrammed device */
    }
    if ((base & (size - 1u)) != 0u) {
        return 0; /* base must be aligned to its size */
    }
    if (base + size < base) {
        return 0; /* address wrap-around */
    }
    return 1;
}

#endif /* GUI_PCI_H */
