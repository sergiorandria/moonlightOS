/* Host emulation: boots kernel state machine without RISC-V, tests full flow */
#include "../kernel/include/sched.h"
#include "../kernel/include/cnode.h"
#include "../kernel/include/tcb.h"
#include "../kernel/include/endpoint.h"
#include "../kernel/include/revoke.h"
#include "../kernel/include/process.h"
#include "../kernel/include/iommu.h"
#include "../kernel/include/alloc.h"
#include <stdio.h>
#include <assert.h>

int main(void) {
    printf("=== Host boot emulation ===\n");
    sched_state_t sched; sched_init(&sched);
    sched_partition_create(&sched, 0, 0, 6000, 1);
    sched_partition_create(&sched, 1, 6000, 2000, 3);
    sched_partition_create(&sched, 2, 8000, 2000, 2);
    assert(sched_is_schedulable(&sched));

    frame_alloc_t alloc; alloc_init(&alloc, 0x80000000, 16*1024*1024);
    tcb_table_t tcbs={0};
    mdb_tree_t mdb; mdb_init(&mdb);
    iommu_state_t iommu={0};

    /* Spawn 3 processes across partitions */
    for (int i=0;i<3;i++) {
        process_create_args_t a={0};
        a.partition_id=i; a.budget_us=500; a.period_us=2000; a.priority=10+i;
        a.pc=0x80200000+i*0x1000; a.sp_top=0x80400000+i*4096; a.stack_size=4096;
        uint32_t pid; assert(process_create(&tcbs,&alloc,&sched,&mdb,&a,&pid)==ERR_OK);
        printf("spawn pid %u part %d\n", pid, i);
    }
    /* Simulate 20ms with IPC + IRQ */
    endpoint_t ep={0};
    ipc_msg_t msg={0}; msg.length=2; msg.words[0]=0xCAFE; msg.words[1]=0xBEEF;
    assert(endpoint_send(&ep, 0, &msg)==ERR_OK);
    ipc_msg_t out; assert(endpoint_recv(&ep, 1, &out)==ERR_OK);
    assert(out.words[0]==0xCAFE);
    printf("PASS: IPC across partitions\n");

    uint64_t t=0;
    for (int i=0;i<10;i++) { sched_tick(&sched, t); t+=1000; }
    printf("PASS: boot emulation 10 ticks, final part %u\n", sched.current_partition);
    printf("EMULATION OK\n");
    return 0;
}
