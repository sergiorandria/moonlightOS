#include "../include/irq.h"
#include <string.h>

kerror_t irq_bind(irq_state_t *is, cap_t *irq_cap, uint32_t tcb_id, uint32_t ntfn_cptr, uint32_t badge) {
    if (!is || !irq_cap) return ERR_INVALID_ARG;
    if (irq_cap->type != CAP_IRQ) return ERR_INVALID_CAP;
    if (!irq_cap->is_valid) return ERR_INVALID_CAP;
    uint32_t irq = irq_cap->u.irq.irq;
    if (irq >= MAX_IRQS) return ERR_INVALID_ARG;
    if (is->irqs[irq].bound) return ERR_REVOKE_NEEDED;
    is->irqs[irq].valid = true;
    is->irqs[irq].bound = true;
    is->irqs[irq].irq_num = irq;
    is->irqs[irq].owner_tcb = tcb_id;
    is->irqs[irq].notification_cap = ntfn_cptr;
    is->irqs[irq].badge = badge;
    /* Real HW: program PLIC via CHERI-bounded MMIO cap - only this IRQ line exposed */
    return ERR_OK;
}

kerror_t irq_unbind(irq_state_t *is, uint32_t irq_num) {
    if (!is || irq_num >= MAX_IRQS) return ERR_INVALID_ARG;
    if (!is->irqs[irq_num].bound) return ERR_INVALID_ARG;
    memset(&is->irqs[irq_num], 0, sizeof(irq_entry_t));
    return ERR_OK;
}

void irq_handle(irq_state_t *is, uint32_t irq_num) {
    if (!is || irq_num >= MAX_IRQS) return;
    if (!is->irqs[irq_num].bound) return;
    /* Signal notification - kernel never touches driver memory, only badge */
    is->pending_mask[0] |= (1ULL << (irq_num % 64));
    /* Driver thread will be resumed via endpoint notification path in syscall.c */
}

bool irq_is_pending(irq_state_t *is, uint32_t irq_num) {
    if (!is || irq_num >= MAX_IRQS) return false;
    return (is->pending_mask[0] >> (irq_num % 64)) & 1ULL;
}
