#ifdef CBMC
#include "include/cap.h"
#include "include/endpoint.h"
#include "include/vspace.h"
#include "include/sched.h"
#include <stdint.h>

void __CPROVER_assert(int c, const char *m);
void __CPROVER_assume(int c);

void harn_endpoint(void){
    endpoint_t ep;
    ipc_msg_t msg, out;
    __CPROVER_assume(msg.length <= IPC_MSG_MAX);
    __CPROVER_assume(msg.caps <= IPC_CAPS_MAX);
    // No overflow, no use-after-free
    kerror_t e = endpoint_send(&ep, 0, &msg);
    __CPROVER_assert(e==ERR_OK || e==ERR_OVERFLOW || e==ERR_INVALID_ARG, "endpoint_send bounds");
    e = endpoint_recv(&ep, 1, &out);
    __CPROVER_assert(e==ERR_OK, "recv ok");
}

void harn_vspace(void){
    vspace_t vs;
    pte_t *root = (pte_t*)0x1000; // dummy
    vs.root = root;
    vs.asid = 1;
    __CPROVER_assume(vs.root != 0);
    kerror_t e = vspace_map(&vs, 0x1000, 0x1000, 4096, 0x3, 0);
    __CPROVER_assert(e==ERR_OK || e==ERR_INVALID_ARG, "vspace_map bounds");
    uintptr_t pa;
    bool ok = vspace_resolve(&vs, 0x1000, &pa);
    __CPROVER_assert(!ok || pa==0x1000, "resolve");
}

void harn_sched(void){
    sched_state_t s;
    sched_init(&s);
    kerror_t e = sched_partition_create(&s, 0, 0, 6000, 1);
    __CPROVER_assert(e==ERR_OK, "partition");
    e = sched_context_bind(&s, 0, 0, 0, 100, 1000, 10);
    __CPROVER_assert(e==ERR_OK || e==ERR_INVALID_ARG, "bind");
    __CPROVER_assert(sched_is_schedulable(&s), "schedulable");
}

int main(void){
    harn_endpoint();
    harn_vspace();
    harn_sched();
    return 0;
}
#endif
