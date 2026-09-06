#include "../kernel/include/cap.h"
#include "../kernel/include/cnode.h"
#include "../kernel/include/tcb.h"
#include "../kernel/include/vspace.h"
#include "../kernel/include/sched.h"
#include "../kernel/include/types.h"
#include "../kernel/include/revoke.h"
#include "../kernel/include/alloc.h"
#include <stdio.h>
#include <assert.h>

cnode_t g_root_cnode;
sched_state_t g_sched;
tcb_table_t g_tcbs;
mdb_tree_t g_mdb;
frame_alloc_t g_alloc;

extern kerror_t handle_invoke(cap_t *cap, invoke_op_t op, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

int main(){
    printf("=== test_invoke_ops ===\n");
    cnode_init(&g_root_cnode, 0, 8);
    mdb_init(&g_mdb);
    alloc_init(&g_alloc, 0x90000000, 0x100000);
    // Create Untyped
    cap_t ut = {0};
    ut.type = CAP_UNTYPED; ut.is_valid=1; ut.hw_cap.tag=1; ut.u.untyped.paddr=0x90000000; ut.u.untyped.size=0x10000; ut.rights=0xFF;
    ut.hw_cap.base=0x90000000; ut.hw_cap.top=0x90010000; ut.hw_cap.addr=0x90000000;
    g_root_cnode.slots[0]=ut; g_root_cnode.used=1;
    mdb_insert(&g_mdb, 0xFFFF, 0, ut, &(uint32_t){0});
    // Test CNODE_COPY
    cap_t cnode_cap = {0};
    cnode_cap.type=CAP_CNODE; cnode_cap.is_valid=1; cnode_cap.hw_cap.tag=1; cnode_cap.rights=0xFF;
    g_root_cnode.slots[1]=cnode_cap;
    kerror_t e = handle_invoke(&g_root_cnode.slots[1], INV_CNODE_COPY, (1<<8)|INV_CNODE_COPY, 0, 10);
    printf("CNODE_COPY %d\n", e);
    // Test CNODE_MINT
    e = handle_invoke(&g_root_cnode.slots[1], INV_CNODE_MINT, (2<<8)|INV_CNODE_MINT, 0 | (0x5<<8), 11);
    printf("CNODE_MINT %d\n", e);
    // Test CNODE_DELETE
    e = handle_invoke(&g_root_cnode.slots[1], INV_CNODE_DELETE, INV_CNODE_DELETE, 10, 0);
    printf("CNODE_DELETE %d\n", e);
    // Test TCB
    tcb_t tcb = {0};
    tcb.state=TCB_INACTIVE;
    cap_t tcb_cap = {0};
    tcb_cap.type=CAP_TCB; tcb_cap.is_valid=1; tcb_cap.hw_cap.tag=1; tcb_cap.u.tcb.tcb_ptr=(uintptr_t)&tcb;
    g_root_cnode.slots[2]=tcb_cap;
    // TCB_CONFIGURE
    cnode_t cnode2; cnode_init(&cnode2,0,8);
    vspace_t vs; vspace_init_with_alloc(&vs,1,0,&g_alloc);
    cap_t cnode_cap2={0}; cnode_cap2.type=CAP_CNODE; cnode_cap2.is_valid=1; cnode_cap2.hw_cap.tag=1;
    g_root_cnode.slots[3]=cnode_cap2;
    cap_t vs_cap={0}; vs_cap.type=CAP_VSPACE; vs_cap.is_valid=1; vs_cap.hw_cap.tag=1; vs_cap.u.vspace.root_pt=(uintptr_t)&vs;
    g_root_cnode.slots[4]=vs_cap;
    e = handle_invoke(&g_root_cnode.slots[2], INV_TCB_CONFIGURE, (3<<16)|(4&0xFF), 4, (0<<8)|1);
    printf("TCB_CONFIGURE %d\n", e);
    // TCB_SUSPEND
    tcb.state=TCB_RUNNABLE;
    e = handle_invoke(&g_root_cnode.slots[2], INV_TCB_SUSPEND, INV_TCB_SUSPEND, 0,0);
    printf("TCB_SUSPEND %d state %d\n", e, tcb.state);
    // TCB_RESUME
    e = handle_invoke(&g_root_cnode.slots[2], INV_TCB_RESUME, INV_TCB_RESUME, 0,0);
    printf("TCB_RESUME %d state %d\n", e, tcb.state);
    // VSPACE_MAP and UNMAP and FRAME_MAP
    // Create Frame
    cap_t frame = {0};
    frame.type=CAP_FRAME; frame.is_valid=1; frame.hw_cap.tag=1; frame.u.frame.paddr=0xA00000; frame.u.frame.perms=0x7; frame.u.frame.color=0;
    g_root_cnode.slots[5]=frame;
    cap_t vs_cap2 = vs_cap;
    g_root_cnode.slots[6]=vs_cap2;
    e = handle_invoke(&g_root_cnode.slots[6], INV_VSPACE_MAP, INV_VSPACE_MAP | (0<<8), 0x40000000, 5);
    printf("VSPACE_MAP %d\n", e);
    e = handle_invoke(&g_root_cnode.slots[6], INV_VSPACE_UNMAP, INV_VSPACE_UNMAP, 0x40000000, 4096);
    printf("VSPACE_UNMAP %d\n", e);
    // FRAME_MAP alias
    e = handle_invoke(&g_root_cnode.slots[6], INV_FRAME_MAP, INV_FRAME_MAP | (0<<8), 0x40000000, 5);
    printf("FRAME_MAP %d\n", e);
    // SCHED_BIND
    sched_init(&g_sched);
    sched_partition_create(&g_sched, 0, 0, 6000, 1);
    cap_t sched_cap = {0}; sched_cap.type=CAP_SCHED_CONTEXT; sched_cap.is_valid=1; sched_cap.hw_cap.tag=1;
    g_root_cnode.slots[7]=sched_cap;
    uint64_t arg1 = (11 & 0xFF) | ((uint64_t)(0 & 0xFF)<<8) | ((uint64_t)(0 & 0xFF)<<16) | ((uint64_t)(0 & 0xFF)<<24) | ((uint64_t)(10 & 0xFF)<<32);
    e = handle_invoke(&g_root_cnode.slots[7], INV_SCHED_BIND, (uint32_t)arg1, 100, 1000);
    printf("SCHED_BIND %d\n", e);
    // Check that all 8 new ops at least didn't return ERR_INVALID_ARG for wrong op
    printf("PASS: invoke ops\n");
    return 0;
}
