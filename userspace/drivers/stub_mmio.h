/* userspace/drivers/stub_mmio.h - Shared cap check for placeholder drivers.
 * No kernel headers. Same MMIO-cap shape as uart/rtc. */
#ifndef DRV_STUB_MMIO_H
#define DRV_STUB_MMIO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uintptr_t mmio_base;
    size_t mmio_len;
    uint32_t irq;
} stub_mmio_caps_t;

typedef struct {
    uint64_t inits;
    uint64_t rejects;
    uint64_t ops;
} stub_mmio_stats_t;

static inline bool stub_mmio_caps_ok(stub_mmio_caps_t c, size_t min_len)
{
    if (c.mmio_base == 0 || c.mmio_len < min_len)
        return false;
    return true;
}

#endif
