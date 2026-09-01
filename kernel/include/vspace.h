#pragma once
#include "cap.h"
#include "types.h"

#define PT_LEVELS 3
#define PT_ENTRIES 512

typedef struct pte {
    uint64_t ppn;
    uint64_t flags;
    uint16_t color;
} pte_t;

typedef struct vspace {
    pte_t *root;
    asid_t asid;
    uint32_t partition_id;
    uintptr_t base;
    size_t length;
} vspace_t;

#define PTE_V (1<<0)
#define PTE_R (1<<1)
#define PTE_W (1<<2)
#define PTE_X (1<<3)
#define PTE_U (1<<4)

kerror_t vspace_init(vspace_t *vs, asid_t asid, uint32_t part_id);
kerror_t vspace_map(vspace_t *vs, uintptr_t vaddr, uintptr_t paddr, size_t size, uint8_t perms, uint16_t color);
kerror_t vspace_unmap(vspace_t *vs, uintptr_t vaddr, size_t size);
bool vspace_resolve(vspace_t *vs, uintptr_t vaddr, uintptr_t *paddr_out);
void vspace_switch(vspace_t *vs);
