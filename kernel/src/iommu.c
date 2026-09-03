#include "../include/iommu.h"
#include <string.h>

kerror_t iommu_map(iommu_state_t *iommu, cap_t *iommu_cap, uintptr_t dev_id, uintptr_t paddr, size_t size, uint32_t perms) {
    if (!iommu || !iommu_cap) return ERR_INVALID_ARG;
    if (iommu_cap->type != CAP_IOMMU) return ERR_INVALID_CAP;
    if (!iommu_cap->is_valid || !cheri_tag_get(iommu_cap->hw_cap)) return ERR_INVALID_CAP;
    if (size % PAGE_SIZE || paddr % PAGE_SIZE) return ERR_INVALID_ARG;
    if (iommu->count >= MAX_IOMMU_WINDOWS) return ERR_NO_MEM;
    /* Check paddr within IOMMU cap bounds - CHERI enforcement */
    uintptr_t cap_base = cheri_base_get(iommu_cap->hw_cap);
    size_t cap_len = cheri_length_get(iommu_cap->hw_cap);
    if (paddr < cap_base || paddr + size > cap_base + cap_len) return ERR_INVALID_ARG;
    if ((perms & ~iommu_cap->rights) != 0) return ERR_NO_RIGHTS;

    for (uint32_t i=0;i<MAX_IOMMU_WINDOWS;i++) {
        if (!iommu->windows[i].valid) {
            iommu->windows[i].valid = true;
            iommu->windows[i].dev_id = dev_id;
            iommu->windows[i].paddr_base = paddr;
            iommu->windows[i].size = size;
            iommu->windows[i].perms = perms;
            iommu->windows[i].partition_id = iommu_cap->u.iommu.dev_id; // proper: dev_id from cap
            iommu->windows[i].cap = *iommu_cap;
            iommu->count++;
            /* Real HW: program RISC-V IOMMU page table via CHERI-bounded register cap */
            iommu_flush(iommu);
            return ERR_OK;
        }
    }
    return ERR_NO_MEM;
}

kerror_t iommu_unmap(iommu_state_t *iommu, uintptr_t dev_id, uintptr_t paddr) {
    if (!iommu) return ERR_INVALID_ARG;
    for (uint32_t i=0;i<MAX_IOMMU_WINDOWS;i++) {
        if (iommu->windows[i].valid && iommu->windows[i].dev_id == dev_id && iommu->windows[i].paddr_base == paddr) {
            memset(&iommu->windows[i], 0, sizeof(iommu_window_t));
            iommu->count--;
            iommu_flush(iommu);
            return ERR_OK;
        }
    }
    return ERR_INVALID_ARG;
}

bool iommu_check(iommu_state_t *iommu, uintptr_t dev_id, uintptr_t paddr, size_t len, bool is_write) {
    if (!iommu) return false;
    for (uint32_t i=0;i<MAX_IOMMU_WINDOWS;i++) {
        if (!iommu->windows[i].valid || iommu->windows[i].dev_id != dev_id) continue;
        uintptr_t base = iommu->windows[i].paddr_base;
        size_t sz = iommu->windows[i].size;
        if (paddr >= base && paddr + len <= base + sz) {
            uint32_t need = is_write ? CHERI_PERM_STORE : CHERI_PERM_LOAD;
            if ((iommu->windows[i].perms & need) == 0) return false;
            return true;
        }
    }
    return false;
}

void iommu_flush(iommu_state_t *iommu) {
    (void)iommu;
#ifdef __riscv
    __asm__ volatile("fence; fence.i; sfence.vma" ::: "memory");
#endif
}
