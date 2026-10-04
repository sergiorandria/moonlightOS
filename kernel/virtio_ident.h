/* kernel/virtio_ident.h - Transport identity only.
 *
 * The kernel may read magic/version/device-id to decide which IRQ to
 * route and which leaf to map. It must never program virtqueues, notify
 * registers, or feature bits — that is the owning userspace driver.
 */
#ifndef V2_VIRTIO_IDENT_H
#define V2_VIRTIO_IDENT_H

#include "platform.h"

static inline int virtio_ident_match(uint32_t magic, uint32_t ver, uint32_t id,
                                     uint32_t want)
{
    return magic == VIRTIO_MAGIC && ver == VIRTIO_VERSION_MODERN && id == want;
}

static inline int virtio_ident_present(uint32_t magic, uint32_t ver)
{
    return magic == VIRTIO_MAGIC && ver == VIRTIO_VERSION_MODERN;
}

/* IRQ for virtio-mmio transport i on QEMU virt: 1+i. */
static inline uint32_t virtio_ident_irq(unsigned ti)
{
    if (ti >= (unsigned)VIRTIO_NTRANSPORTS)
        return VIRTIO_IRQ_NOT_FOUND;
    return (uint32_t)(1u + ti);
}

#endif /* V2_VIRTIO_IDENT_H */
