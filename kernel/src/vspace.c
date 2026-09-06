#include "../include/vspace.h"
#include "../include/alloc.h"
#include <string.h>

#ifndef __riscv
#include <stdlib.h>
#endif

static pte_t *alloc_pt_page(vspace_t *vs) {
    if (!vs) return NULL;
    if (vs->pt_caps_count >= 64) return NULL;
    if (vs->pt_pages_used >= 64) return NULL;
    if (vs->alloc) {
        cap_t c;
        kerror_t e = alloc_frame(vs->alloc, vs->partition_id, PAGE_SIZE, &c);
        if (e != ERR_OK) return NULL;
        vs->pt_caps[vs->pt_caps_count++] = c;
        vs->pt_pages_used++;
#ifdef __riscv
        pte_t *p = (pte_t *)(uintptr_t)c.u.frame.paddr;
        memset(p, 0, PAGE_SIZE);
        return p;
#else
        /* Host simulation: paddr from alloc_frame is simulated (e.g. 0x80400000)
         * and not host-valid. Use host-backed malloc while keeping the sealed cap
         * for color isolation accounting. The PTE will contain the host address
         * so traversal stays host-valid; the cap's paddr/color proves partition
         * isolation. */
        void *ptr = NULL;
        if (posix_memalign(&ptr, PAGE_SIZE, PAGE_SIZE) != 0) return NULL;
        pte_t *p = (pte_t *)ptr;
        memset(p, 0, PAGE_SIZE);
        return p;
#endif
    } else {
        /* No allocator supplied (legacy host tests, CBMC harness). Use
         * emergency bump pool so existing tests that manually set vs.root
         * and call vspace_map still allocate new levels. Track a dummy cap. */
        static uint8_t fallback_pool[64 * PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
        static uint32_t fallback_next = 0;
        if (fallback_next >= 64) return NULL;
        pte_t *p = (pte_t *)&fallback_pool[fallback_next * PAGE_SIZE];
        memset(p, 0, PAGE_SIZE);
        fallback_next++;
        vs->pt_pages_used++;
        if (vs->pt_caps_count < 64) {
            cap_t dummy = {0};
            dummy.type = CAP_FRAME;
            dummy.is_valid = 1;
            dummy.is_sealed = 1;
            dummy.color = alloc_color_for_partition(vs->partition_id);
            dummy.u.frame.paddr = (uintptr_t)p;
            dummy.u.frame.color = dummy.color;
            dummy.hw_cap.base = (uintptr_t)p;
            dummy.hw_cap.top = (uintptr_t)p + PAGE_SIZE;
            dummy.hw_cap.addr = (uintptr_t)p;
            dummy.hw_cap.tag = 1;
            dummy.hw_cap.sealed = 1;
            vs->pt_caps[vs->pt_caps_count++] = dummy;
        }
        return p;
    }
}

static inline uint64_t pte_encode(uint64_t ppn, uint64_t flags) {
    return (ppn << 10) | flags;
}
static inline uint64_t pte_ppn(uint64_t pte) { return pte >> 10; }

kerror_t vspace_init(vspace_t *vs, asid_t asid, uint32_t part_id) {
    return vspace_init_with_alloc(vs, asid, part_id, NULL);
}

kerror_t vspace_init_with_alloc(vspace_t *vs, asid_t asid, uint32_t part_id, frame_alloc_t *alloc) {
    if (!vs) return ERR_INVALID_ARG;
    memset(vs, 0, sizeof(*vs));
    vs->asid = asid;
    vs->partition_id = part_id;
    vs->alloc = alloc;
    vs->base = 0;
    vs->length = 0;
    vs->pt_pages_used = 0;
    vs->pt_caps_count = 0;
    vs->root = alloc_pt_page(vs);
    if (!vs->root) return ERR_NO_MEM;
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
    bool is_kernel = (vs->partition_id == 0 && (perms & 0x4));
    if (!is_kernel && vs->partition_id != 0) flags |= PTE_U;

    for (size_t off = 0; off < size; off += PAGE_SIZE) {
        uintptr_t va = vaddr + off;
        uintptr_t pa = paddr + off;
        uint64_t vpn2 = (va >> 30) & 0x1FF;
        uint64_t vpn1 = (va >> 21) & 0x1FF;
        uint64_t vpn0 = (va >> 12) & 0x1FF;
        pte_t *l2 = vs->root;
        if (!(l2[vpn2] & PTE_V)) {
            pte_t *n = alloc_pt_page(vs);
            if (!n) return ERR_NO_MEM;
            l2[vpn2] = pte_encode((uint64_t)(uintptr_t)n >> 12, PTE_V);
        }
        pte_t *l1 = (pte_t*)(uintptr_t)(pte_ppn(l2[vpn2]) << 12);
        if (!(l1[vpn1] & PTE_V)) {
            pte_t *n = alloc_pt_page(vs);
            if (!n) return ERR_NO_MEM;
            l1[vpn1] = pte_encode((uint64_t)(uintptr_t)n >> 12, PTE_V);
        }
        pte_t *l0 = (pte_t*)(uintptr_t)(pte_ppn(l1[vpn1]) << 12);
        if (l0[vpn0] & PTE_V) return ERR_INVALID_ARG;
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
    __asm__ volatile("" ::: "memory");
#endif
}
