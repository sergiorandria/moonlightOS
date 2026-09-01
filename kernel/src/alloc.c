#include "../include/alloc.h"
#include "../include/cheri.h"
#include <string.h>

void alloc_init(frame_alloc_t *a, uintptr_t base, size_t size) {
    memset(a, 0, sizeof(*a));
    a->base = base;
    a->next = base;
    a->top = base + size;
}

uint16_t alloc_color_for_partition(uint32_t partition_id) {
    return (partition_id * COLORS_PER_PARTITION) % NUM_COLORS;
}

bool alloc_color_is_valid(uint32_t partition_id, uint16_t color) {
    uint16_t base = alloc_color_for_partition(partition_id);
    return color == base || color == (uint16_t)(base + 1);
}

kerror_t alloc_frame(frame_alloc_t *a, uint32_t partition_id, size_t size, cap_t *out) {
    if (!a || !out) return ERR_INVALID_ARG;
    if (size % PAGE_SIZE) return ERR_INVALID_ARG;
    if (partition_id >= 8) return ERR_INVALID_ARG;
    uint16_t color = alloc_color_for_partition(partition_id);
    /* Add offset to get desired color: color = (paddr>>12)%16 */
    uintptr_t paddr = a->next;
    /* Align to color: find next paddr with correct color */
    while (((paddr >> 12) % NUM_COLORS) != color) paddr += PAGE_SIZE;
    if (paddr + size > a->top) return ERR_NO_MEM;

    memset(out, 0, sizeof(cap_t));
    out->type = CAP_FRAME;
    out->rights = CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE_CAP;
    out->is_valid = 1;
    out->is_sealed = 1;
    out->color = color;
    out->u.frame.paddr = paddr;
    out->u.frame.color = color;
#ifdef __CHERI_PURE_CAPABILITY__
    out->hw_cap = cheri_bounds_set((CHERI_CAP)(uintptr_t)paddr, size);
    out->hw_cap = cheri_seal(out->hw_cap, OTYPE_FRAME);
#else
    out->hw_cap.base = paddr;
    out->hw_cap.top = paddr + size;
    out->hw_cap.addr = paddr;
    out->hw_cap.tag = 1;
    out->hw_cap.sealed = 1;
    out->hw_cap.otype = OTYPE_FRAME;
#endif
    a->next = paddr + size;
    if (a->frame_count < 512) a->frames[a->frame_count++] = *out;
    return ERR_OK;
}

kerror_t alloc_free(frame_alloc_t *a, cap_t *frame) {
    if (!a || !frame) return ERR_INVALID_ARG;
    if (frame->type != CAP_FRAME) return ERR_INVALID_CAP;
    /* Real kernel would push to per-color free list and clear tag */
    memset(frame, 0, sizeof(cap_t));
    return ERR_OK;
}
