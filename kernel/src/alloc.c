#include "../include/alloc.h"
#include "../include/cheri.h"
#include "../include/vspace.h"
#include <string.h>

extern frame_alloc_t g_alloc;     /* kernel pool (boot.c) */
extern vspace_t g_kernel_vspace;  /* for PT-page accounting */

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

kerror_t alloc_stats(frame_alloc_t *a, alloc_stats_t *out) {
    if (!a || !out) return ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    out->base = a->base;
    out->top = a->top;
    out->used = (a->next > a->base) ? a->next - a->base : 0;
    out->free = (a->top > a->next) ? a->top - a->next : 0;
    out->frames_carved = a->frame_count;
    for (uint32_t i = 0; i < a->frame_count && i < 512; i++) {
        uint16_t c = a->frames[i].u.frame.color;
        if (c < NUM_COLORS) out->color_used[c]++;
    }
    return ERR_OK;
}

/* --- moonsh `mem` formatting (no libc: tiny helpers, like the shell) --- */

static unsigned mem_hex(char *dst, unsigned room, uintptr_t v) {
    unsigned w = 0;
    int started = 0;
    for (int sh = (int)(sizeof(uintptr_t) * 8) - 4; sh >= 0; sh -= 4) {
        unsigned d = (unsigned)((v >> sh) & 0xFu);
        if (d || started || sh == 0) {
            if (w >= room) break;
            dst[w++] = d < 10 ? (char)('0' + d) : (char)('a' + d - 10);
            started = 1;
        }
    }
    return w;
}

static unsigned mem_dec(char *dst, unsigned room, uint32_t v) {
    char tmp[10];
    unsigned n = 0, w = 0;
    if (v == 0) { if (room) dst[0] = '0'; return room ? 1u : 0u; }
    while (v && n < sizeof(tmp)) { tmp[n++] = (char)('0' + (v % 10u)); v /= 10u; }
    while (n && w < room) dst[w++] = tmp[--n];
    return w;
}

static unsigned mem_str(char *dst, unsigned room, unsigned at, const char *s) {
    while (*s && at < room) dst[at++] = *s++;
    return at;
}

/* One-shot `mem` dump for the weak hook in shell (fits in 256B). */
int moonsh_mem_status(char *buf, unsigned len) {
    alloc_stats_t st;
    unsigned at = 0;
    if (!buf || !len) return 0;
    if (alloc_stats(&g_alloc, &st) != ERR_OK) return 0;
    at = mem_str(buf, len - 1u, at, "pool ");
    at += mem_hex(buf + at, len - 1u - at, st.base);
    at = mem_str(buf, len - 1u, at, "-");
    at += mem_hex(buf + at, len - 1u - at, st.top);
    at = mem_str(buf, len - 1u, at, " used ");
    at += mem_hex(buf + at, len - 1u - at, st.used);
    at = mem_str(buf, len - 1u, at, " free ");
    at += mem_hex(buf + at, len - 1u - at, st.free);
    at = mem_str(buf, len - 1u, at, "\nframes ");
    at += mem_dec(buf + at, len - 1u - at, st.frames_carved);
    at = mem_str(buf, len - 1u, at, "/512  colors");
    for (uint16_t c = 0; c < NUM_COLORS && at < len - 1u; c++) {
        if (!st.color_used[c]) continue;
        at = mem_str(buf, len - 1u, at, " c");
        at += mem_dec(buf + at, len - 1u - at, c);
        at = mem_str(buf, len - 1u, at, ":");
        at += mem_dec(buf + at, len - 1u - at, st.color_used[c]);
    }
    at = mem_str(buf, len - 1u, at, "\npt pages ");
    at += mem_dec(buf + at, len - 1u - at, g_kernel_vspace.pt_pages_used);
    at = mem_str(buf, len - 1u, at, "\n");
    buf[at] = '\0';
    return (int)at;
}
