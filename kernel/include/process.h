#pragma once
#include "tcb.h"
#include "cnode.h"
#include "vspace.h"
#include "sched.h"
#include "alloc.h"
#include "revoke.h"
#include "types.h"

typedef struct process_create_args {
    uint32_t parent_cnode;
    uint32_t untyped_cptr;   /* Untyped cap to carve from */
    uint32_t partition_id;
    uint64_t budget_us;
    uint64_t period_us;
    uint8_t  priority;
    uintptr_t pc;            /* entry */
    uintptr_t sp_top;        /* informational only: authoritative stack top is
                              * derived from the carved frame (frame top), so
                              * callers cannot hand us an unmapped stack */
    size_t   stack_size;
    const char *name;        /* short tag for ps (may be NULL) */
} process_create_args_t;

kerror_t process_create(tcb_table_t *tcbs, frame_alloc_t *alloc, sched_state_t *sched, mdb_tree_t *mdb, process_create_args_t *args, uint32_t *out_tcb_id);
kerror_t process_destroy(tcb_table_t *tcbs, sched_state_t *sched, mdb_tree_t *mdb, uint32_t tcb_id);
/* moonsh `kill` (weak hook in shell): op 0 destroy, 1 STOP, 2 CONT.
 * long tid: huge inputs can never wrap into a live id (checked pre-cast).
 * Returns 0 ok, -1 no such thread, -2 bad op. */
int moonsh_kill_tid(long tid, int op);
