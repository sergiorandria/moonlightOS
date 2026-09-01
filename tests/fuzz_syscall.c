#include "../kernel/include/syscall.h"
#include "../kernel/include/cnode.h"
#include "../kernel/include/tcb.h"
#include "../kernel/include/sched.h"
#include "../kernel/include/endpoint.h"
#include <stdint.h>
#include <stdio.h>
/* libFuzzer-style harness: fuzz syscall_handler with arbitrary trap frames */
tcb_table_t g_tcbs;
sched_state_t g_sched;
cnode_t g_root_cnode;
endpoint_t g_endpoints[MAX_ENDPOINTS];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(trap_frame_t)) return 0;
    trap_frame_t frame;
    __builtin_memcpy(&frame, data, sizeof(frame));
    frame.a7 %= 6; /* clamp syscall num */
    /* Ensure CHERI tags valid for fuzzer */
    syscall_handler(&frame, 0);
    return 0;
}
#ifndef FUZZING
int main(void) {
    uint8_t buf[512]={0};
    for (int i=0;i<10000;i++) { buf[i%512]++; LLVMFuzzerTestOneInput(buf, sizeof(trap_frame_t)); }
    printf("fuzz smoke 10k iterations OK\n"); return 0;
}
#endif
