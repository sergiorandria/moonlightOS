#include "../kernel/include/tcb.h"
#include "../kernel/include/endpoint.h"
#include "../kernel/include/cnode.h"
#include "../kernel/include/sched.h"
#include "../kernel/include/vspace.h"
#include "../kernel/include/revoke.h"
/* Weak stubs for host unit tests - real kernel provides strong definitions in boot.c */
__attribute__((weak)) tcb_table_t g_tcbs;
__attribute__((weak)) endpoint_t g_endpoints[64];
__attribute__((weak)) cnode_t g_root_cnode;
__attribute__((weak)) sched_state_t g_sched;
__attribute__((weak)) vspace_t g_kernel_vspace;
__attribute__((weak)) mdb_tree_t g_mdb;
