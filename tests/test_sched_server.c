#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

// Declare server functions without including the .c
typedef struct { uint32_t id, partition; uint64_t budget, period; uint8_t prio; bool rt; } task_cfg_t;
extern int sched_admit(task_cfg_t *cfg);
extern bool sched_is_admissible(void);
extern void sched_server_run(uint32_t ep);

int moonlight_call(uint32_t ep, void *msg){ (void)ep;(void)msg; return 0; }
int moonlight_recv(uint32_t ep, void *msg){ (void)ep;(void)msg; return 0; }

int main(){
    printf("=== test_sched_server ===\n");
    task_cfg_t cfg1 = {0,0,6000,10000,10,1};
    task_cfg_t cfg2 = {1,0,6000,10000,10,1};
    int err1 = sched_admit(&cfg1);
    printf("admit cfg1 %d (expected 0)\n", err1);
    assert(err1==0);
    int err2 = sched_admit(&cfg2);
    printf("admit cfg2 %d (expected -1 over-util 120>99)\n", err2);
    assert(err2==-1);
    // Test integer vs float equivalence
    uint64_t sum = 6000*100/10000 + 6000*100/10000;
    assert(sum==120);
    double fsum = 6000.0/10000.0 + 6000.0/10000.0;
    assert(fsum>0.99 && sum>99);
    printf("PASS: sched_server integer EDF\n");
    // Test that a small task would still be admissible in different partition
    task_cfg_t cfg3 = {2,1,1000,10000,10,1};
    int err3 = sched_admit(&cfg3);
    printf("admit cfg3 part1 %d (expected 0)\n", err3);
    assert(err3==0);
    assert(sched_is_admissible()==true);
    printf("PASS: sched_server\n");
    return 0;
}
