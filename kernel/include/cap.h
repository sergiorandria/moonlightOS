#pragma once
#include "cheri.h"
#include <stdint.h>
#include <stdbool.h>

#define MAX_CAPS_PER_CNODE 256
#define CAP_RIGHTS_READ    (1u << 0)
#define CAP_RIGHTS_WRITE   (1u << 1)
#define CAP_RIGHTS_GRANT   (1u << 2)
#define CAP_RIGHTS_GRANT_REPLY (1u << 3)

typedef enum {
    CAP_NULL = 0,
    CAP_UNTYPED = 1,
    CAP_CNODE = 2,
    CAP_TCB = 3,
    CAP_VSPACE = 4,
    CAP_FRAME = 5,
    CAP_ENDPOINT = 6,
    CAP_NOTIFICATION = 7,
    CAP_IRQ = 8,
    CAP_IOMMU = 9,
    CAP_SCHED_CONTEXT = 10,
    CAP_TIME_PARTITION = 11,
} cap_type_t;

/* Unified capability - sealed CHERI cap + kernel metadata
 * Invariant proven in Isabelle: tag==1 && sealed==1 && otype matches type
 */
typedef struct {
    cap_type_t type;
    uint32_t rights;
    uint32_t badge;      /* endpoint badge for demux */
    uint8_t  is_sealed;
    uint8_t  is_valid;
    uint16_t color;      /* cache color for temporal isolation */
    union {
        struct { uintptr_t paddr; size_t size; uint16_t free_idx; } untyped;
        struct { uint32_t guard; uint8_t radix; uint8_t guard_size; } cnode;
        struct { uintptr_t tcb_ptr; } tcb;
        struct { uintptr_t root_pt; uint16_t asid; } vspace;
        struct { uintptr_t paddr; uint8_t perms; uint16_t color; } frame;
        struct { uintptr_t ep_ptr; uint32_t badge; } endpoint;
        struct { uint64_t budget_us; uint64_t period_us; uint8_t crit; } sched;
        struct { uint32_t id; uint64_t budget_us; } timepart;
    } u;
    /* CHERI sealing - hardware enforcement */
    CHERI_CAP hw_cap;
} cap_t;

static inline bool cap_has_right(cap_t c, uint32_t r) {
    return (c.rights & r) == r;
}

static inline bool cap_is_valid(const cap_t *c) {
    if (!c || !c->is_valid) return false;
    if (c->type == CAP_NULL) return false;
    /* Hardware tag check - complete mediation */
    if (!cheri_tag_get(c->hw_cap)) return false;
    return true;
}

/* Proven attenuation: derived cap rights subset of parent */
cap_t cap_derive(cap_t parent, uint32_t new_rights, uint32_t new_badge);
bool cap_can_retype(cap_t untyped, cap_type_t new_type, size_t size);
cap_t cap_retype(cap_t untyped, cap_type_t new_type, uintptr_t paddr, size_t size);
