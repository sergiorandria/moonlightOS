/* sched_server - userspace policy, kernel enforces mechanism
 * Kernel only exposes SchedContext bind and partition creation. Policy lives here.
 * Uses integer arithmetic (budget*100/period) like kernel's sched_is_schedulable, no float.
 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef struct { uint32_t label, length, caps; uint64_t words[30]; uint32_t cap_ptrs[3]; } ipc_msg_t;
extern int moonlight_call(uint32_t ep, ipc_msg_t *msg);
extern int moonlight_recv(uint32_t ep, ipc_msg_t *msg);

#define MAX_TASKS 64
#define MAJOR_FRAME_US 10000

typedef struct { uint32_t id, partition; uint64_t budget, period; uint8_t prio; bool rt; } task_cfg_t;
static task_cfg_t tasks[MAX_TASKS];
static uint32_t task_count;

static bool is_schedulable_for_partition(uint32_t part, task_cfg_t *new_task) {
    uint64_t sum = 0;
    for (uint32_t i=0;i<task_count;i++) if (tasks[i].partition==part) {
        sum += tasks[i].budget * 100 / tasks[i].period;
        if (sum > 99) return false;
    }
    if (new_task && new_task->partition==part) {
        sum += new_task->budget * 100 / new_task->period;
        if (sum > 99) return false;
    }
    return sum <= 99;
}

int sched_admit(task_cfg_t *cfg) {
    if (!is_schedulable_for_partition(cfg->partition, cfg)) return -1;
    if (task_count >= MAX_TASKS) return -1;
    tasks[task_count++] = *cfg;
    return 0;
}

bool sched_is_admissible(void) {
    for (uint32_t p=0;p<8;p++) {
        if (!is_schedulable_for_partition(p, NULL)) return false;
    }
    return true;
}

void sched_server_run(void) {
    ipc_msg_t msg;
    uint32_t ep = 2;
    while(1){
        moonlight_recv(ep, &msg);
        if(msg.label==1){
            task_cfg_t cfg;
            cfg.id = msg.words[0];
            cfg.partition = msg.words[1];
            cfg.budget = msg.words[2];
            cfg.period = msg.words[3];
            cfg.prio = msg.words[4];
            int err = sched_admit(&cfg);
            // Real: invoke SchedContext_Bind via syscall if admitted
            if(err==0){
                // Encode for handle_invoke SCHED_BIND: sc_id in bits 8-15, tcb in 16-23, part 24-31, prio 32-39, budget in arg2, period in arg3
                // For host testing, just call the admission check; real kernel would do moonlight_call with sched cap
            }
            msg.words[0]=err;
            msg.length=1;
            moonlight_call(ep, &msg);
        }
    }
}
