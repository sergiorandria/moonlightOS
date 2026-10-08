/* kernel/dev_leaves.h - Which MMIO windows exist, and who may hold them.
 *
 * Live leaves are wired in kboot.c pagetable_init. Reserved rows name
 * future devices so stubs compile against one catalog; kboot MUST NOT
 * map a leaf whose owner is DEV_LEAF_UNOWNED (no tid until a proof bump
 * of V2_CAP_THREADS). Host-testable: no MMIO, no page tables.
 */
#ifndef V2_DEV_LEAVES_H
#define V2_DEV_LEAVES_H

#include "dev.h"
#include "services.h"

#define DEV_LEAF_UNOWNED 0xFFu
#define DEV_LEAVES_MAX 16

typedef struct
{
    uint8_t owner;      /* tid, or DEV_LEAF_UNOWNED */
    uint8_t vpn1;       /* l1 index in that thread's tables; 0 if unmapped */
    uint16_t pages;     /* 4K pages in the leaf; 0 if unmapped */
    uint32_t virtio_id; /* 0 = not a virtio transport (PCI/LFB/etc.) */
} dev_leaf_desc_t;

/* Bound: DEV_LEAVES_MAX. Live rows must match kboot.c wiring. */
static const dev_leaf_desc_t v2_dev_leaves[DEV_LEAVES_MAX] = {
    {T_NET, 5, 8, VIRTIO_DEV_NET},
    {T_CRYPTBLK, 6, 8, VIRTIO_DEV_BLK},
    {T_VAULT, 5, 8, VIRTIO_DEV_RNG},
    {T_GUI, 6, 512, 0},                  /* LFB (PCI BAR0), not virtio */
    {T_GUI, 7, 16, 0},                   /* ECAM */
    {T_GUI, 9, 8, VIRTIO_DEV_INPUT},     /* keyboard transports */
    {T_GUI, 10, 8, VIRTIO_DEV_INPUT},    /* mouse transports */
    {DEV_LEAF_UNOWNED, 0, 0, VIRTIO_DEV_GPU},
    {DEV_LEAF_UNOWNED, 0, 0, VIRTIO_DEV_SOUND},
    {DEV_LEAF_UNOWNED, 0, 0, VIRTIO_DEV_9P},
    {DEV_LEAF_UNOWNED, 0, 0, VIRTIO_DEV_SCSI},
    {DEV_LEAF_UNOWNED, 0, 0, VIRTIO_DEV_CONSOLE},
    {DEV_LEAF_UNOWNED, 0, 0, VIRTIO_DEV_BALLOON},
    {DEV_LEAF_UNOWNED, 0, 0, VIRTIO_DEV_VSOCK},
    {DEV_LEAF_UNOWNED, 0, 0, VIRTIO_DEV_FS},
    {DEV_LEAF_UNOWNED, 0, 0, 0}, /* USB xHCI: USB_XHCI_PHYS_RESERVED */
};

static inline int v2_dev_leaf_mapped(const dev_leaf_desc_t *d)
{
    if (!d)
        return 0;
    if (d->owner == DEV_LEAF_UNOWNED)
        return 0;
    if (d->owner > (uint8_t)T_GUI)
        return 0;
    return d->pages != 0;
}

/* Live virtio ids get a tid; everything else stays unmapped (-1). */
static inline int v2_virtio_owner_tid(unsigned id)
{
    switch (id)
    {
    case VIRTIO_DEV_NET:
        return T_NET;
    case VIRTIO_DEV_BLK:
        return T_CRYPTBLK;
    case VIRTIO_DEV_RNG:
        return T_VAULT;
    case VIRTIO_DEV_INPUT:
        return T_GUI;
    default:
        return -1;
    }
}

static inline int v2_dev_leaves_mapped_count(void)
{
    int i, n = 0;
    for (i = 0; i < DEV_LEAVES_MAX; i++)
    { /* bound: DEV_LEAVES_MAX */
        if (v2_dev_leaf_mapped(&v2_dev_leaves[i]))
            n++;
    }
    return n;
}

_Static_assert(DEV_LEAVES_MAX == 16, "keep leaf catalog bounded");

#endif /* V2_DEV_LEAVES_H */
