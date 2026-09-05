#include "../include/tcb.h"
#include <string.h>

kerror_t tcb_configure(tcb_t *tcb, cnode_t *cspace, uintptr_t vspace_root, asid_t asid, uint32_t partition) {
    if (!tcb || !cspace) return ERR_INVALID_ARG;
    tcb->cspace = cspace;
    tcb->vspace_root = vspace_root;
    tcb->asid = asid;
    tcb->time_partition = partition;
    tcb->state = TCB_INACTIVE;
    return ERR_OK;
}

kerror_t tcb_set_regs(tcb_t *tcb, uintptr_t pc, uintptr_t sp, CHERI_CAP pcc, CHERI_CAP csp) {
    if (!tcb) return ERR_INVALID_ARG;
    if (!cheri_tag_get(pcc) || !cheri_tag_get(csp)) return ERR_INVALID_CAP;
    tcb->pc = pc;
    tcb->sp = sp;
    tcb->pcc = pcc;
    tcb->csp = csp;
    return ERR_OK;
}

void tcb_suspend(tcb_t *tcb) { if (tcb) tcb->state = TCB_INACTIVE; }
void tcb_resume(tcb_t *tcb) {
    if (!tcb) return;
    if (tcb->state == TCB_INACTIVE || tcb->state == TCB_BLOCKED_RECV ||
        tcb->state == TCB_BLOCKED_SEND || tcb->state == TCB_BLOCKED_REPLY) {
        tcb->state = TCB_RUNNABLE;
    }
}
bool tcb_is_runnable(tcb_t *tcb) { return tcb && tcb->state == TCB_RUNNABLE; }

// Explicit wake for IPC - validates transition and clears fault
kerror_t tcb_wake_from_ipc(tcb_t *tcb, uint32_t sender_id) {
    if (!tcb) return ERR_INVALID_ARG;
    if (tcb->state != TCB_BLOCKED_RECV && tcb->state != TCB_BLOCKED_REPLY) return ERR_INVALID_ARG;
    (void)sender_id;
    tcb->state = TCB_RUNNABLE;
    tcb->fault_addr = 0;
    tcb->fault_type = 0;
    return ERR_OK;
}
