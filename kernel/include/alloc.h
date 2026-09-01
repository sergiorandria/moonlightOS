#pragma once
#include "cap.h"
#include "types.h"

/* Cache-coloring frame allocator - proven color isolation
 * 16 colors, each partition gets 2 dedicated colors.
 * Host simulation tracks colors; on CHERI HW, color = physical address bits [16:12]
 */
#define NUM_COLORS 16
#define COLORS_PER_PARTITION 2

typedef struct frame_alloc {
    uintptr_t base;
    uintptr_t next;
    uintptr_t top;
    /* per-color free stacks */
    uint32_t free_head[NUM_COLORS];
    uint32_t free_count[NUM_COLORS];
    /* simple bump + free list for simulation */
    cap_t frames[512];
    uint32_t frame_count;
} frame_alloc_t;

void alloc_init(frame_alloc_t *a, uintptr_t base, size_t size);
kerror_t alloc_frame(frame_alloc_t *a, uint32_t partition_id, size_t size, cap_t *out);
kerror_t alloc_free(frame_alloc_t *a, cap_t *frame);
uint16_t alloc_color_for_partition(uint32_t partition_id);
bool alloc_color_is_valid(uint32_t partition_id, uint16_t color);
