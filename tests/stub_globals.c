#include "../kernel/include/tcb.h"
#include "../kernel/include/endpoint.h"
#include "../kernel/include/cnode.h"
#include "../kernel/include/sched.h"
#include "../kernel/include/vspace.h"
#include "../kernel/include/revoke.h"
#include "../kernel/include/alloc.h"
/* Weak stubs for host unit tests - real kernel provides strong definitions in boot.c */
__attribute__((weak)) tcb_table_t g_tcbs;
__attribute__((weak)) endpoint_t g_endpoints[64];
__attribute__((weak)) cnode_t g_root_cnode;
__attribute__((weak)) sched_state_t g_sched;
__attribute__((weak)) vspace_t g_kernel_vspace;
__attribute__((weak)) mdb_tree_t g_mdb;
__attribute__((weak)) frame_alloc_t g_alloc;
/* Host cannot switch stacks (src/switch.S is RISC-V only): dispatch logic
 * still runs against this no-op. test_info.c overrides it with a recorder. */
__attribute__((weak)) void context_switch(sw_ctx_t *cur, sw_ctx_t *next) {
    (void)cur;
    (void)next;
}
