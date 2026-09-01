#include "../include/process.h"
#include <string.h>

kerror_t process_create(tcb_table_t *tcbs, frame_alloc_t *alloc, sched_state_t *sched, mdb_tree_t *mdb, process_create_args_t *args, uint32_t *out_tcb_id) {
    if (!tcbs || !alloc || !sched || !mdb || !args || !out_tcb_id) return ERR_INVALID_ARG;
    if (args->partition_id >= MAX_PARTITIONS) return ERR_INVALID_ARG;
    if (args->budget_us > args->period_us || args->budget_us==0) return ERR_INVALID_ARG;
    /* Find free TCB - must be truly free (pc==0 && sp==0), INACTIVE is not free if pc!=0 */
    uint32_t id = 0xFFFF;
    for (uint32_t i=0;i<MAX_TCBS;i++) if (tcbs->threads[i].pc==0 && tcbs->threads[i].sp==0 && tcbs->threads[i].cspace==NULL) { id=i; break; }
    if (id==0xFFFF) return ERR_NO_MEM;

    /* Carve stack Frame with correct color */
    cap_t stack_cap;
    kerror_t e = alloc_frame(alloc, args->partition_id, args->stack_size, &stack_cap);
    if (e != ERR_OK) return e;

    tcb_t *tcb = &tcbs->threads[id];
    memset(tcb, 0, sizeof(*tcb));
    tcb->id = id;
    tcb->time_partition = args->partition_id;
    tcb->priority = args->priority;
    tcb->pc = args->pc;
    tcb->sp = args->sp_top;
    /* CHERI: PCC and CSP are sealed caps bounded to code/stack */
    CHERI_CAP pcc = {0}, csp = {0};
#ifndef __CHERI_PURE_CAPABILITY__
    pcc.tag=1; pcc.base=args->pc & ~0xFFF; pcc.top=pcc.base+0x10000; pcc.addr=args->pc;
    csp.tag=1; csp.base=stack_cap.u.frame.paddr; csp.top=csp.base+args->stack_size; csp.addr=args->sp_top;
#endif
    tcb->pcc = pcc;
    tcb->csp = csp;
    tcb->state = TCB_INACTIVE;

    /* Bind sched context - find free slot */
    bool bound = false;
    for (uint32_t i=0;i<MAX_SCHED_CONTEXTS;i++) if (!sched->contexts[i].bound) {
        e = sched_context_bind(sched, i, id, args->partition_id, args->budget_us, args->period_us, args->priority);
        if (e != ERR_OK) { memset(tcb,0,sizeof(*tcb)); return e; }
        tcb->sched_context = i;
        bound = true;
        break;
    }
    if (!bound) { memset(tcb,0,sizeof(*tcb)); return ERR_NO_MEM; }
    if (!sched_is_schedulable(sched)) {
        sched->contexts[tcb->sched_context].bound=false;
        memset(tcb,0,sizeof(*tcb));
        return ERR_INVALID_ARG;
    }

    /* MDB tracking */
    uint32_t mdb_idx;
    mdb_insert(mdb, 0xFFFF, id, stack_cap, &mdb_idx);

    tcbs->count++;
    *out_tcb_id = id;
    return ERR_OK;
}

kerror_t process_destroy(tcb_table_t *tcbs, sched_state_t *sched, mdb_tree_t *mdb, uint32_t tcb_id) {
    if (!tcbs || !sched || !mdb || tcb_id>=MAX_TCBS) return ERR_INVALID_ARG;
    tcb_t *t = &tcbs->threads[tcb_id];
    if (t->pc==0 && t->sp==0 && t->cspace==NULL) return ERR_INVALID_ARG;
    /* Revoke all caps derived from this process */
    uint32_t idx = mdb_lookup(mdb, 0, tcb_id);
    if (idx != 0xFFFF) { mdb_revoke(mdb, idx); mdb_delete(mdb, idx); }
    if (t->sched_context < MAX_SCHED_CONTEXTS) sched->contexts[t->sched_context].bound=false;
    memset(t, 0, sizeof(*t));
    tcbs->count--;
    return ERR_OK;
}
