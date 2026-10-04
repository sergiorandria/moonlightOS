/* kernel/dev.h - Platform device identity (no driver logic).
 *
 * The kernel uses these IDs only to: (1) scan virtio transports at boot,
 * (2) map MMIO leaves into the owning driver thread, (3) bind IRQ routes.
 * Programming rings, PCI BARs (beyond the one-time bochs BAR assign),
 * and protocol all stay in userspace compartments.
 */
#ifndef V2_DEV_H
#define V2_DEV_H

#include "platform.h"

/* virtio device IDs (OASIS virtio spec). Live IDs are already in
 * platform.h; the extras are catalogued for userspace stubs. */
#ifndef VIRTIO_DEV_CONSOLE
#define VIRTIO_DEV_CONSOLE 3u
#endif
#define VIRTIO_DEV_BALLOON 5u
#define VIRTIO_DEV_SCSI 8u
#define VIRTIO_DEV_9P 9u
#define VIRTIO_DEV_GPU 16u
#define VIRTIO_DEV_VSOCK 19u
#define VIRTIO_DEV_SOUND 25u
#define VIRTIO_DEV_FS 26u

/* QEMU virt MMIO windows that are NOT mapped into any U-space today.
 * Stubs may name them; kboot must not wire a leaf until a tid owns them. */
#define UART_MMIO_PHYS 0x10000000UL
#define UART_MMIO_PAGES 1
#define RTC_MMIO_PHYS 0x00101000UL
#define POWER_MMIO_PHYS 0x00100000UL

/* Future HCI / GPIO (userspace qubes). Kernel maps nothing until spawn. */
#define USB_XHCI_PHYS_RESERVED 0x11000000UL
#define GPIO_MMIO_PHYS_RESERVED 0x10060000UL

static inline int v2_virtio_dev_known(unsigned id)
{
    switch (id)
    {
    case VIRTIO_DEV_NET:
    case VIRTIO_DEV_BLK:
    case VIRTIO_DEV_CONSOLE:
    case VIRTIO_DEV_RNG:
    case VIRTIO_DEV_BALLOON:
    case VIRTIO_DEV_SCSI:
    case VIRTIO_DEV_9P:
    case VIRTIO_DEV_GPU:
    case VIRTIO_DEV_INPUT:
    case VIRTIO_DEV_VSOCK:
    case VIRTIO_DEV_SOUND:
    case VIRTIO_DEV_FS:
        return 1;
    default:
        return 0;
    }
}

/* True iff a live driver thread owns this virtio id today. Unknown or
 * reserved devices stay kernel-unmapped (fail closed). */
static inline int v2_virtio_dev_live(unsigned id)
{
    switch (id)
    {
    case VIRTIO_DEV_NET:
    case VIRTIO_DEV_BLK:
    case VIRTIO_DEV_RNG:
    case VIRTIO_DEV_INPUT:
        return 1;
    default:
        return 0;
    }
}

#endif /* V2_DEV_H */
