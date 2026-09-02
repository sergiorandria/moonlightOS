#pragma once
#include "cap.h"
#include "types.h"

#define PT_LEVELS 3
#define PT_ENTRIES 512

typedef uint64_t pte_t; /* Sv39 8-byte PTE: (ppn<<10)|flags */

typedef struct vspace {
    pte_t *root;              /* Sv39 root (512 entries, 4K) - CHERI-bounded */
    asid_t asid;
    uint32_t partition_id;
    uintptr_t base;
    size_t length;
    uint32_t pt_pages_used;   /* for bump allocator */
} vspace_t;

#define PTE_V (1<<0)
#define PTE_R (1<<1)
#define PTE_W (1<<2)
#define PTE_X (1<<3)
#define PTE_U (1<<4)
#define PTE_G (1<<5)
#define PTE_A (1<<6)
#define PTE_D (1<<7)

kerror_t vspace_init(vspace_t *vs, asid_t asid, uint32_t part_id);
kerror_t vspace_map(vspace_t *vs, uintptr_t vaddr, uintptr_t paddr, size_t size, uint8_t perms, uint16_t color);
kerror_t vspace_unmap(vspace_t *vs, uintptr_t vaddr, size_t size);
bool vspace_resolve(vspace_t *vs, uintptr_t vaddr, uintptr_t *paddr_out);
void vspace_switch(vspace_t *vs);
