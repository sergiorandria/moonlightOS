#include "../kernel/include/sched.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    printf("=== Realtime partition test ===\n");
    sched_state_t s;
    sched_init(&s);
    sched_partition_create(&s, 0, 0, 6000, 1);
    sched_partition_create(&s, 1, 6000, 2000, 3);
    sched_partition_create(&s, 2, 8000, 2000, 2);

    sched_context_bind(&s, 0, 1, 1, 500, 2000, 5); /* RT task in partition 1 */
    sched_context_bind(&s, 1, 2, 1, 500, 2000, 10);
    assert(sched_is_schedulable(&s));

    /* Simulate tick across major frame: verify partition switches and budget replenish */
    uint64_t t=0;
    for (int i=0;i<20;i++) {
        sched_tick(&s, t);
        uint32_t nxt = sched_pick_next(&s, t);
        printf("t=%lu part=%u next_tcb=%u\n", t, s.current_partition, nxt);
        if (s.current_partition==1) assert(nxt==1 || nxt==2);
        t += 1000;
        /* consume */
        if (s.contexts[0].remaining_us>100) s.contexts[0].remaining_us-=100;
    }
    /* Over-utilization must be rejected */
    assert(sched_context_bind(&s, 2, 3, 1, 1500, 2000, 15)==ERR_OK);
    assert(!sched_is_schedulable(&s));
    printf("PASS: realtime scheduling\n");
    return 0;
}
