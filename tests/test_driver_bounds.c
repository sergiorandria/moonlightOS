#include <stdint.h>
#include <stdio.h>
#include "../userspace/drivers/virtio_mmio.h"

#define CHECK(condition) do { \
    if (!(condition)) { \
        printf("FAIL line %d: %s\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)

int main(void)
{
    CHECK(vmm_range_within(0x1000u, 0x1000u, 0x1000u, 1));
    CHECK(vmm_range_within(0x1000u, 0x1000u, 0x1ff0u, 0x10u));
    CHECK(!vmm_range_within(0x1000u, 0x1000u, 0x1ff1u, 0x10u));
    CHECK(!vmm_range_within(0x1000u, 0x1000u, 0x0fffu, 1));
    CHECK(!vmm_range_within(0x1000u, 0x1000u, 0x1000u, 0));
    CHECK(!vmm_range_within(UINTPTR_MAX - 7u, 16u, UINTPTR_MAX - 3u, 8u));
    CHECK(!vmm_range_within(0x1000u, 0x1000u, UINTPTR_MAX - 3u, 8u));
    puts("PASS: test_driver_bounds");
    return 0;
}