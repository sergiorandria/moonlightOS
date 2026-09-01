#include "../kernel/include/revoke.h"
#include "../kernel/include/process.h"
#include "../kernel/include/sched.h"
#include "../kernel/include/alloc.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    printf("=== Revoke + dynamic process test ===\n");
    mdb_tree_t mdb; mdb_init(&mdb);
    cap_t c1={0}; c1.type=CAP_FRAME; c1.is_valid=1; c1.hw_cap.tag=1;
    uint32_t i0,i1,i2;
    assert(mdb_insert(&mdb, 0xFFFF, 0, c1, &i0)==ERR_OK);
    cap_t c2=c1; c2.rights=1;
    assert(mdb_insert(&mdb, i0, 1, c2, &i1)==ERR_OK);
    assert(mdb_insert(&mdb, i1, 2, c2, &i2)==ERR_OK);
    assert(mdb_is_descendant(&mdb, i0, i2));
    assert(mdb_revoke(&mdb, i0)==ERR_OK);
    assert(!mdb.nodes[i1].valid && !mdb.nodes[i2].valid);
    assert(mdb.nodes[i0].valid); /* parent kept */
    printf("PASS: revoke tree\n");

    /* Dynamic process create/destroy with EDF admission */
    tcb_table_t tcbs={0};
    frame_alloc_t alloc; alloc_init(&alloc, 0x80000000, 0x1000000);
    sched_state_t sched; sched_init(&sched);
    sched_partition_create(&sched, 0, 0, 6000, 1);
    sched_partition_create(&sched, 1, 6000, 4000, 3);
    mdb_init(&mdb);
    process_create_args_t args={0};
    args.partition_id=1; args.budget_us=1000; args.period_us=4000; args.priority=10;
    args.pc=0x80200000; args.sp_top=0x80300000; args.stack_size=4096;
    uint32_t pid;
    assert(process_create(&tcbs, &alloc, &sched, &mdb, &args, &pid)==ERR_OK);
    printf("PASS: create pid=%u\n", pid);
    args.budget_us=3500; /* would over-utilize partition 1 (1000+3500)/4000=1.12 */
    uint32_t pid2;
    assert(process_create(&tcbs, &alloc, &sched, &mdb, &args, &pid2)==ERR_INVALID_ARG);
    printf("PASS: admission control rejects over-util\n");
    assert(process_destroy(&tcbs, &sched, &mdb, pid)==ERR_OK);
    /* Now it should admit */
    assert(process_create(&tcbs, &alloc, &sched, &mdb, &args, &pid2)==ERR_OK);
    printf("PASS: create after destroy\n");
    printf("ALL REVOCATION TESTS PASS\n");
    return 0;
}
