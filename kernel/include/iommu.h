#pragma once
#include "cap.h"
#include "types.h"

#define MAX_IOMMU_WINDOWS 16

typedef struct iommu_window {
    bool valid;
    uintptr_t dev_id;      /* PCIe RID or platform device ID */
    uintptr_t paddr_base;
    size_t size;
    uint32_t perms;        /* CHERI perms subset */
    uint32_t partition_id;
    uint16_t color;
    cap_t cap;             /* sealed IOMMU cap */
} iommu_window_t;

typedef struct iommu_state {
    iommu_window_t windows[MAX_IOMMU_WINDOWS];
    uint32_t count;
} iommu_state_t;

kerror_t iommu_map(iommu_state_t *iommu, cap_t *iommu_cap, uintptr_t dev_id, uintptr_t paddr, size_t size, uint32_t perms);
kerror_t iommu_unmap(iommu_state_t *iommu, uintptr_t dev_id, uintptr_t paddr);
bool iommu_check(iommu_state_t *iommu, uintptr_t dev_id, uintptr_t paddr, size_t len, bool is_write);
void iommu_flush(iommu_state_t *iommu);
