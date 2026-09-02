#include "../include/vspace.h"
#include "../include/alloc.h"
#include <string.h>

/* Simple bump allocator for PT pages - 64 pages max, CHERI-bounded, placed after stack */
static uint8_t pt_pool[64 * PAGE_SIZE] __attribute__((section(".pt_pool"), aligned(PAGE_SIZE)));
static uint32_t pt_next = 0;

static pte_t *alloc_pt_page(void) {
    if (pt_next >= 64) return NULL;
    pte_t *p = (pte_t*)&pt_pool[pt_next * PAGE_SIZE];
    memset(p, 0, PAGE_SIZE);
    pt_next++;
    return p;
}

static inline uint64_t pte_encode(uint64_t ppn, uint64_t flags) {
    return (ppn << 10) | flags;
}
static inline uint64_t pte_ppn(uint64_t pte) { return pte >> 10; }

kerror_t vspace_init(vspace_t *vs, asid_t asid, uint32_t part_id) {
    if (!vs) return ERR_INVALID_ARG;
    vs->asid = asid;
    vs->partition_id = part_id;
    vs->root = alloc_pt_page();
    if (!vs->root) return ERR_NO_MEM;
    vs->pt_pages_used = 1;
    vs->base = 0;
    vs->length = 0;
    return ERR_OK;
}

/* Sv39: VPN[2]=va[38:30], VPN[1]=va[29:21], VPN[0]=va[20:12] */
kerror_t vspace_map(vspace_t *vs, uintptr_t vaddr, uintptr_t paddr, size_t size, uint8_t perms, uint16_t color) {
    if (!vs || !vs->root) return ERR_INVALID_ARG;
    if (vaddr % PAGE_SIZE || paddr % PAGE_SIZE || size % PAGE_SIZE) return ERR_INVALID_ARG;
    if (color % 2 != 0) return ERR_INVALID_ARG;
    uint16_t vcolor = (vaddr >> 12) % 16;
    if (vcolor != color && color != 0) return ERR_PARTITION_DENIED;

    uint64_t flags = PTE_V | PTE_A | PTE_D;
    if (perms & 0x1) flags |= PTE_R;
    if (perms & 0x2) flags |= PTE_W;
    if (perms & 0x4) flags |= PTE_X;
    // Production: kernel pages (partition 0 or perms with X) must not be user-accessible
    // Only set U for user partitions (partition_id != 0) and when explicitly requested
    bool is_kernel = (vs->partition_id == 0 && (perms & 0x4)); // X implies kernel code
    if (!is_kernel && vs->partition_id != 0) flags |= PTE_U;

    for (size_t off = 0; off < size; off += PAGE_SIZE) {
        uintptr_t va = vaddr + off;
        uintptr_t pa = paddr + off;
        uint64_t vpn2 = (va >> 30) & 0x1FF;
        uint64_t vpn1 = (va >> 21) & 0x1FF;
        uint64_t vpn0 = (va >> 12) & 0x1FF;
        pte_t *l2 = vs->root;
        /* L2 */
        if (!(l2[vpn2] & PTE_V)) {
            pte_t *n = alloc_pt_page();
            if (!n) return ERR_NO_MEM;
            l2[vpn2] = pte_encode((uint64_t)(uintptr_t)n >> 12, PTE_V);
            vs->pt_pages_used++;
        }
        pte_t *l1 = (pte_t*)(uintptr_t)(pte_ppn(l2[vpn2]) << 12);
        if (!(l1[vpn1] & PTE_V)) {
            pte_t *n = alloc_pt_page();
            if (!n) return ERR_NO_MEM;
            l1[vpn1] = pte_encode((uint64_t)(uintptr_t)n >> 12, PTE_V);
            vs->pt_pages_used++;
        }
        pte_t *l0 = (pte_t*)(uintptr_t)(pte_ppn(l1[vpn1]) << 12);
        if (l0[vpn0] & PTE_V) return ERR_INVALID_ARG; /* already mapped */
        l0[vpn0] = pte_encode(pa >> 12, flags);
        (void)color;
    }
    return ERR_OK;
}

kerror_t vspace_unmap(vspace_t *vs, uintptr_t vaddr, size_t size) {
    if (!vs || !vs->root) return ERR_INVALID_ARG;
    if (vaddr % PAGE_SIZE || size % PAGE_SIZE) return ERR_INVALID_ARG;
    for (size_t off = 0; off < size; off += PAGE_SIZE) {
        uintptr_t va = vaddr + off;
        uint64_t vpn2 = (va >> 30) & 0x1FF;
        uint64_t vpn1 = (va >> 21) & 0x1FF;
        uint64_t vpn0 = (va >> 12) & 0x1FF;
        pte_t *l2 = vs->root;
        if (!(l2[vpn2] & PTE_V)) continue;
        pte_t *l1 = (pte_t*)(uintptr_t)(pte_ppn(l2[vpn2]) << 12);
        if (!(l1[vpn1] & PTE_V)) continue;
        pte_t *l0 = (pte_t*)(uintptr_t)(pte_ppn(l1[vpn1]) << 12);
        l0[vpn0] = 0;
    }
#ifdef __riscv
    __asm__ volatile("sfence.vma" ::: "memory");
#else
    __asm__ volatile("" ::: "memory");
#endif
    return ERR_OK;
}

bool vspace_resolve(vspace_t *vs, uintptr_t vaddr, uintptr_t *paddr_out) {
    if (!vs || !vs->root || !paddr_out) return false;
    uint64_t vpn2 = (vaddr >> 30) & 0x1FF;
    uint64_t vpn1 = (vaddr >> 21) & 0x1FF;
    uint64_t vpn0 = (vaddr >> 12) & 0x1FF;
    pte_t *l2 = vs->root;
    if (!(l2[vpn2] & PTE_V)) return false;
    pte_t *l1 = (pte_t*)(uintptr_t)(pte_ppn(l2[vpn2]) << 12);
    if (!(l1[vpn1] & PTE_V)) return false;
    pte_t *l0 = (pte_t*)(uintptr_t)(pte_ppn(l1[vpn1]) << 12);
    if (!(l0[vpn0] & PTE_V)) return false;
    *paddr_out = (pte_ppn(l0[vpn0]) << 12) | (vaddr & 0xFFF);
    return true;
}

void vspace_switch(vspace_t *vs) {
    if (!vs || !vs->root) {
#ifdef __riscv
        __asm__ volatile("csrw satp, zero; sfence.vma" ::: "memory");
#else
        __asm__ volatile("" ::: "memory");
#endif
        return;
    }
#ifdef __riscv
    uint64_t satp = (8ULL<<60) | ((uint64_t)vs->asid << 44) | ((uint64_t)(uintptr_t)vs->root >> 12);
    __asm__ volatile("csrw satp, %0; sfence.vma" :: "r"(satp) : "memory");
#else
    (void)vs;
#endif
}
