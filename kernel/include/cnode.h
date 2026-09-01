#pragma once
#include "cap.h"
#include "types.h"

typedef struct cnode {
    cap_t slots[MAX_CAPS_PER_CNODE];
    uint32_t guard;
    uint8_t  radix;      /* bits per level */
    uint8_t  guard_size;
    uint32_t used;
} cnode_t;

kerror_t cnode_init(cnode_t *cn, uint32_t guard, uint8_t radix);
kerror_t cnode_copy(cnode_t *dst, cptr_t dst_idx, cnode_t *src, cptr_t src_idx, uint32_t rights);
kerror_t cnode_mint(cnode_t *dst, cptr_t dst_idx, cnode_t *src, cptr_t src_idx, uint32_t rights, uint32_t badge);
kerror_t cnode_move(cnode_t *dst, cptr_t dst_idx, cnode_t *src, cptr_t src_idx);
kerror_t cnode_delete(cnode_t *cn, cptr_t idx);
cap_t* cnode_lookup(cnode_t *cn, cptr_t idx);
kerror_t cnode_derive_and_insert(cnode_t *dst, cptr_t dst_idx, cap_t parent, uint32_t new_rights);
