#include "../include/sched.h"
#include "../include/cnode.h"
#include "../include/tcb.h"
#include "../include/endpoint.h"
#include <string.h>

extern sched_state_t g_sched;
extern tcb_table_t g_tcbs;
extern cnode_t g_root_cnode;
extern endpoint_t g_endpoints[64];

void kernel_boot(void) {
    /* 1. CHERI: verify DDC and PCC tags */
    /* 2. Init scheduler with static partitions - verified schedule */
    sched_init(&g_sched);
    sched_partition_create(&g_sched, 0, 0, 6000, 1);    /* GP: 0-6ms */
    sched_partition_create(&g_sched, 1, 6000, 2000, 3); /* RT-critical: 6-8ms */
    sched_partition_create(&g_sched, 2, 8000, 2000, 2); /* Drivers: 8-10ms */
    if (!sched_is_schedulable(&g_sched)) { while(1) {
#ifdef __riscv
        __asm__ volatile("wfi");
#else
        __asm__ volatile("" ::: "memory");
#endif
    } }

    /* 3. Create root CNode and initial TCB */
    cnode_init(&g_root_cnode, 0, 8);

    /* 4. Flush microarch before enabling interrupts */
#ifdef __riscv
    __asm__ volatile("fence.i; sfence.vma; csrw 0x800, x0" ::: "memory");
#else
    __asm__ volatile("" ::: "memory");
#endif

    /* 5. Park - wait for interrupt */
    while(1) {
#ifdef __riscv
        __asm__ volatile("wfi");
#else
        __asm__ volatile("" ::: "memory"); break;
#endif
    }
}

/* Global state - placed in CHERI-bounded sections via linker.ld */
sched_state_t g_sched;
tcb_table_t g_tcbs;
cnode_t g_root_cnode;
endpoint_t g_endpoints[64];
