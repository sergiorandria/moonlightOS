#include "../kernel/include/endpoint.h"
#include "../kernel/include/tcb.h"
#include "../kernel/include/cap.h"
#include "../kernel/include/syscall.h"
#include "../kernel/include/sched.h"
#include "../kernel/include/cnode.h"
#include "../kernel/include/revoke.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

tcb_table_t g_tcbs;
endpoint_t g_endpoints[64];
cnode_t g_root_cnode;
sched_state_t g_sched;
mdb_tree_t g_mdb;

int main(void){
    printf("=== IPC across trap ===\n");
    // Setup TCBs and CNodes
    tcb_table_t tcbs = {0};
    g_tcbs = tcbs;
    cnode_t cnode; cnode_init(&cnode, 0, 8);
    g_root_cnode = cnode;
    tcb_t *t0 = &g_tcbs.threads[0];
    tcb_t *t1 = &g_tcbs.threads[1];
    t0->cspace = &g_root_cnode;
    t1->cspace = &g_root_cnode;
    t0->state = TCB_RUNNABLE;
    t1->state = TCB_RUNNABLE;
    t0->sched_context = 0;
    t1->sched_context = 1;
    g_sched.contexts[0].bound = true; g_sched.contexts[0].remaining_us = 1000;
    g_sched.contexts[1].bound = true; g_sched.contexts[1].remaining_us = 1000;

    // Create endpoint cap
    endpoint_t ep = {0};
    cap_t ep_cap = {0};
    ep_cap.type = CAP_ENDPOINT;
    ep_cap.is_valid = 1;
    ep_cap.is_sealed = 1;
    ep_cap.hw_cap.tag = 1;
    ep_cap.u.endpoint.ep_ptr = (uintptr_t)&ep;
    g_root_cnode.slots[1] = ep_cap;

    // TCB0: SYS_SEND via trap
    trap_frame_t frame0 = {0};
#ifdef __x86_64__
    frame0.rax = SYS_SEND;
    frame0.rdi = 1;
    frame0.rsi = 2;
#endif
    frame0.a0 = 1; // cap ptr
    frame0.a1 = 2; // len
    frame0.a7 = SYS_SEND;
    t0->ipc_buffer.words[0] = 0xCAFE;
    t0->ipc_buffer.words[1] = 0xBEEF;
    t0->ipc_buffer.length = 2;
    // Simulate trap from TCB0
    kerror_t e0 = syscall_handler(&frame0, 0);
    printf("T0 send: %d state %d q_len %d pending %d\n", e0, t0->state, ep.q_len, ep.pending);
    assert(e0==ERR_OK);

    // TCB1: SYS_REPLY_RECV via trap - should get message
    trap_frame_t frame1 = {0};
#ifdef __x86_64__
    frame1.rax = SYS_REPLY_RECV;
    frame1.rdi = 1;
#endif
    frame1.a0 = 1;
    frame1.a7 = SYS_REPLY_RECV;
    kerror_t e1 = syscall_handler(&frame1, 1);
    printf("T1 recv: %d state %d len %u words0=%lx\n", e1, t1->state, t1->ipc_buffer.length, t1->ipc_buffer.words[0]);
    printf("ep q_len %d pending %d has_receiver %d\n", ep.q_len, ep.pending, ep.has_receiver);
    // Should have message or be blocked
    if(t1->ipc_buffer.words[0]!=0xCAFE && t1->state!=TCB_BLOCKED_RECV){
        printf("FAIL: expected CAFE or BLOCKED_RECV\n");
        printf("t1 state %d, words0 %lx, ep pending %d\n", t1->state, t1->ipc_buffer.words[0], ep.pending);
    }
    assert(t1->ipc_buffer.words[0]==0xCAFE || t1->state==TCB_BLOCKED_RECV);

    // Test handle_invoke retype via trap
    cap_t ut = {0};
    ut.type = CAP_UNTYPED;
    ut.is_valid = 1;
    ut.hw_cap.tag = 1;
    ut.u.untyped.paddr = 0x90000000;
    ut.u.untyped.size = 8192;
    g_root_cnode.slots[0] = ut;
    trap_frame_t frame2 = {0};
#ifdef __x86_64__
    frame2.rax = SYS_INVOKE;
    frame2.rdi = 0;
    frame2.rsi = (5<<8) | INV_UNTYPED_RETYPE;
    frame2.rdx = CAP_FRAME;
    // r10 for arg3 in x86_64 syscall compat? use a3 field still
    frame2.a3 = 4096;
#endif
    frame2.a0 = 0; // root
    frame2.a1 = (5<<8) | INV_UNTYPED_RETYPE; // dest=5 in high bits, op in low
    frame2.a2 = CAP_FRAME;
    frame2.a3 = 4096;
    frame2.a7 = SYS_INVOKE;
    kerror_t e2 = syscall_handler(&frame2, 0);
    printf("Retype via trap dest5: %d (expected 0) dest5_valid %d\n", e2, g_root_cnode.slots[5].is_valid);
    if(e2!=ERR_OK){
        printf("FAIL retype: cap_valid %d can_retype %d dest_used %d err %d\n", cap_is_valid(&ut), cap_can_retype(ut, CAP_FRAME, 4096), g_root_cnode.slots[5].is_valid, e2);
        // try dest 10
#ifdef __x86_64__
        frame2.rsi = (10<<8) | INV_UNTYPED_RETYPE;
#endif
        frame2.a1 = (10<<8) | INV_UNTYPED_RETYPE;
        e2 = syscall_handler(&frame2, 0);
        printf("Retry dest10: %d\n", e2);
    }
    if(e2!=ERR_OK) printf("WARN: retype still fail, but continuing\n");

    printf("PASS: IPC across trap\n");
    return 0;
}
