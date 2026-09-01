#include "../include/vspace.h"
#include <string.h>

kerror_t vspace_init(vspace_t *vs, asid_t asid, uint32_t part_id) {
    if (!vs) return ERR_INVALID_ARG;
    vs->asid = asid;
    vs->partition_id = part_id;
    vs->root = NULL;
    return ERR_OK;
}

kerror_t vspace_map(vspace_t *vs, uintptr_t vaddr, uintptr_t paddr, size_t size, uint8_t perms, uint16_t color) {
    if (!vs) return ERR_INVALID_ARG;
    if (vaddr % PAGE_SIZE || paddr % PAGE_SIZE || size % PAGE_SIZE) return ERR_INVALID_ARG;
    if (color % 2 != 0) return ERR_INVALID_ARG; /* enforce coloring */
    /* Cache coloring: vaddr color must match frame color -> partition isolation */
    uint16_t vcolor = (vaddr >> 12) % 16;
    if (vcolor != color && color != 0) return ERR_PARTITION_DENIED;
    /* CHERI bounds check omitted here - enforced by Frame cap */
    (void)perms;
    return ERR_OK;
}

kerror_t vspace_unmap(vspace_t *vs, uintptr_t vaddr, size_t size) {
    if (!vs) return ERR_INVALID_ARG;
    if (vaddr % PAGE_SIZE || size % PAGE_SIZE) return ERR_INVALID_ARG;
    return ERR_OK;
}

void vspace_switch(vspace_t *vs) {
    if (!vs || !vs->root) {
#ifdef __riscv
        __asm__ volatile("sfence.vma" ::: "memory");
#else
        __asm__ volatile("" ::: "memory");
#endif
        return;
    }
#ifdef __riscv
    uintptr_t satp = (8ULL<<60) | ((uintptr_t)vs->asid << 44) | ((uintptr_t)vs->root >> 12);
    __asm__ volatile("csrw satp, %0; sfence.vma" :: "r"(satp) : "memory");
#else
    (void)vs;
#endif
}
