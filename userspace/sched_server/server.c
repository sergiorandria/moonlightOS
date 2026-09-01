/* sched_server - userspace policy, kernel enforces mechanism
 * Kernel only exposes SchedContext bind and partition creation. Policy lives here.
 */
#include <stdint.h>
#include <stdbool.h>

#define MAX_TASKS 64
#define MAJOR_FRAME_US 10000

typedef struct { uint32_t id, partition; uint64_t budget, period; uint8_t prio; bool rt; } task_cfg_t;
static task_cfg_t tasks[MAX_TASKS];
static uint32_t task_count;

int sched_admit(task_cfg_t *cfg) {
    /* EDF utilization test per partition, same as kernel check - defense in depth */
    double util = 0;
    for (uint32_t i=0;i<task_count;i++) if (tasks[i].partition==cfg->partition) util += (double)tasks[i].budget/(double)tasks[i].period;
    util += (double)cfg->budget/(double)cfg->period;
    if (util > 0.99) return -1; /* would break kernel sched_is_schedulable */
    if (task_count >= MAX_TASKS) return -1;
    tasks[task_count++] = *cfg;
    /* Real: invoke SchedContext_Bind via syscall */
    return 0;
}

bool sched_is_admissible(void) {
    for (uint32_t p=0;p<8;p++) {
        double u=0; for (uint32_t i=0;i<task_count;i++) if(tasks[i].partition==p) u+=(double)tasks[i].budget/(double)tasks[i].period;
        if (u>0.99) return false;
    }
    return true;
}
