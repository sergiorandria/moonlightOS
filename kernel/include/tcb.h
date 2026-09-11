#pragma once
#include "types.h"
#include "cheri.h"
#include "syscall.h"
struct cnode;
typedef struct cnode cnode_t;
#include "cap.h"

typedef enum { TCB_INACTIVE=0, TCB_RUNNABLE, TCB_BLOCKED_SEND, TCB_BLOCKED_RECV, TCB_BLOCKED_REPLY } tcb_state_t;

/* Saved M-mode context for cooperative dispatch (sched_dispatch). All
 * threads share one address space/privilege, so only callee-saved regs +
 * sp/ra cross the switch (gp/tp are image-global). Layout is ABI: see
 * src/switch.S. s-array index i lives at 16+i*8. */
typedef struct {
    uintptr_t ra;
    uintptr_t sp;
    uintptr_t s[12];
} sw_ctx_t;

typedef struct tcb {
    uint32_t id;
    tcb_state_t state;
    uintptr_t pc;
    uintptr_t sp;
    sw_ctx_t ctx;          /* dispatch-saved regs; s[11] = entry pc pre-first-run */
    char name[16];         /* short tag for ps (NUL-terminated, may be "") */
    /* Preemption snapshot: full trap frame, valid iff has_frame. Written by
     * timer_handler when a quantum expires, restored when re-picked. Fresh
     * threads start cooperatively (trampoline), so the timer path only ever
     * resumes threads it previously snapshotted. */
    trap_frame_t saved;
    uint8_t has_frame;
    CHERI_CAP csp;       /* CHERI stack cap */
    CHERI_CAP pcc;       /* CHERI PCC */
    cnode_t *cspace;
    uintptr_t vspace_root;
    asid_t asid;
    uint32_t time_partition;
    uint32_t sched_context;
    uint32_t priority;
    ipc_msg_t ipc_buffer; /* per-thread IPC buffer, CHERI-bounded */
    uint32_t bound_notification;
    uint32_t bound_endpoint;
    uint64_t fault_addr;
    uint32_t fault_type;
} tcb_t;

#define MAX_TCBS 128
typedef struct { tcb_t threads[MAX_TCBS]; uint32_t count; } tcb_table_t;

kerror_t tcb_configure(tcb_t *tcb, cnode_t *cspace, uintptr_t vspace_root, asid_t asid, uint32_t partition);
kerror_t tcb_set_regs(tcb_t *tcb, uintptr_t pc, uintptr_t sp, CHERI_CAP pcc, CHERI_CAP csp);
void tcb_suspend(tcb_t *tcb);
void tcb_resume(tcb_t *tcb);
kerror_t tcb_wake_from_ipc(tcb_t *tcb, uint32_t sender_id);
bool tcb_is_runnable(tcb_t *tcb);
const char *tcb_state_name(tcb_state_t st);
const char *tcb_state_name(tcb_state_t st);
/* Cooperative switch (src/switch.S, RISC-V only): save *cur regs, load
 * *next regs, return into next. Caller-saved regs do NOT survive. */
void context_switch(sw_ctx_t *cur, sw_ctx_t *next);
void thread_trampoline(void);
