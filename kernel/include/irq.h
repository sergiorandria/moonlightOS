#pragma once
#include "cap.h"
#include "types.h"

#define MAX_IRQS 64
#define IRQ_FLAG_EDGE  (1u<<0)
#define IRQ_FLAG_LEVEL (1u<<1)

typedef struct irq_entry {
    bool valid;
    bool bound;
    uint32_t irq_num;
    uint32_t owner_tcb;
    uint32_t notification_cap; /* which notification to signal */
    uint32_t badge;
    uint32_t partition_id;
} irq_entry_t;

typedef struct irq_state {
    irq_entry_t irqs[MAX_IRQS];
    uint64_t pending_mask[1];
} irq_state_t;

kerror_t irq_bind(irq_state_t *is, cap_t *irq_cap, uint32_t tcb_id, uint32_t ntfn_cptr, uint32_t badge);
kerror_t irq_unbind(irq_state_t *is, uint32_t irq_num);
void irq_handle(irq_state_t *is, uint32_t irq_num);
bool irq_is_pending(irq_state_t *is, uint32_t irq_num);
