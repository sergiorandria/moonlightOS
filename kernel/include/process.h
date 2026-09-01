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
    uintptr_t sp_top;
    size_t   stack_size;
} process_create_args_t;

kerror_t process_create(tcb_table_t *tcbs, frame_alloc_t *alloc, sched_state_t *sched, mdb_tree_t *mdb, process_create_args_t *args, uint32_t *out_tcb_id);
kerror_t process_destroy(tcb_table_t *tcbs, sched_state_t *sched, mdb_tree_t *mdb, uint32_t tcb_id);
