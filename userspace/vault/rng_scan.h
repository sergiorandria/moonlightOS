/* userspace/vault/rng_scan.h - pure virtio-mmio scan helpers. */
#ifndef VAULT_RNG_SCAN_H
#define VAULT_RNG_SCAN_H
#include <stdint.h>
#define VIRTIO_MMIO_BASE 0x10000000UL
#define VIRTIO_MMIO_STRIDE 0x2000UL
#define VIRTIO_NTRANSPORTS 8u
#define VIRTIO_DEV_RNG 4u
#define VIRTIO_MAGIC_VAL 0x74726976u
static inline unsigned long rng_trans_off(unsigned long idx) {
    if (idx >= (unsigned long)VIRTIO_NTRANSPORTS) return 0xFFFFFFFFUL;
    return (unsigned long)VIRTIO_MMIO_BASE + idx * (unsigned long)VIRTIO_MMIO_STRIDE;
}
static inline int rng_dev_match(unsigned long dev_id) {
    return dev_id == (unsigned long)VIRTIO_DEV_RNG;
}
#endif
