#include "../include/process.h"
#include "../include/cnode.h"
#include "../include/endpoint.h"
#include <string.h>

extern endpoint_t g_endpoints[MAX_ENDPOINTS];
extern tcb_table_t g_tcbs;
extern sched_state_t g_sched;
extern mdb_tree_t g_mdb;

kerror_t process_create(tcb_table_t *tcbs, frame_alloc_t *alloc,
                        sched_state_t *sched, mdb_tree_t *mdb,
                        process_create_args_t *args, uint32_t *out_tcb_id) {
  if (!tcbs || !alloc || !sched || !mdb || !args || !out_tcb_id)
    return ERR_INVALID_ARG;
  if (args->partition_id >= MAX_PARTITIONS)
    return ERR_INVALID_ARG;
  if (args->budget_us > args->period_us || args->budget_us == 0)
    return ERR_INVALID_ARG;
  /* Find free TCB - must be truly free (pc==0 && sp==0), INACTIVE is not free
   * if pc!=0 */
  uint32_t id = 0xFFFF;
  for (uint32_t i = 0; i < MAX_TCBS; i++)
    if (tcbs->threads[i].pc == 0 && tcbs->threads[i].sp == 0 &&
        tcbs->threads[i].cspace == NULL) {
      id = i;
      break;
    }
  if (id == 0xFFFF)
    return ERR_NO_MEM;

  /* Carve stack Frame with correct color */
  cap_t stack_cap;
  kerror_t e =
      alloc_frame(alloc, args->partition_id, args->stack_size, &stack_cap);
  if (e != ERR_OK)
    return e;

  tcb_t *tcb = &tcbs->threads[id];
  memset(tcb, 0, sizeof(*tcb));
  tcb->id = id;
  tcb->time_partition = args->partition_id;
  tcb->priority = args->priority;
  tcb->pc = args->pc;
  /* Stack top is authoritative from the carved frame (args->sp_top is only
   * informational): this guarantees a mapped, colored backing store. */
  tcb->sp = stack_cap.u.frame.paddr + args->stack_size;
  if (args->name) {
    size_t i;
    for (i = 0; i < sizeof(tcb->name) - 1 && args->name[i]; i++)
      tcb->name[i] = args->name[i];
    tcb->name[i] = '\0';
  }
  /* First dispatch enters via the trampoline (s11 = entry pc). */
#ifdef __riscv
  tcb->ctx.ra = (uintptr_t)thread_trampoline;
#endif
  tcb->ctx.sp = tcb->sp;
  tcb->ctx.s[11] = args->pc;
  /* CHERI: PCC and CSP are sealed caps bounded to code/stack */
  CHERI_CAP pcc = {0}, csp = {0};
#ifndef __CHERI_PURE_CAPABILITY__
  pcc.tag = 1;
  pcc.base = args->pc & ~0xFFF;
  pcc.top = pcc.base + 0x10000;
  pcc.addr = args->pc;
  csp.tag = 1;
  csp.base = stack_cap.u.frame.paddr;
  csp.top = csp.base + args->stack_size;
  csp.addr = args->sp_top;
#endif
  tcb->pcc = pcc;
  tcb->csp = csp;
  tcb->state = TCB_INACTIVE;

  /* Bind sched context - find free slot */
  bool bound = false;
  for (uint32_t i = 0; i < MAX_SCHED_CONTEXTS; i++)
    if (!sched->contexts[i].bound) {
      e = sched_context_bind(sched, i, id, args->partition_id, args->budget_us,
                             args->period_us, args->priority);
      if (e != ERR_OK) {
        memset(tcb, 0, sizeof(*tcb));
        return e;
      }
      tcb->sched_context = i;
      bound = true;
      break;
    }
  if (!bound) {
    memset(tcb, 0, sizeof(*tcb));
    return ERR_NO_MEM;
  }
  if (!sched_is_schedulable(sched)) {
    sched_context_unbind(sched, tcb->sched_context);
    memset(tcb, 0, sizeof(*tcb));
    return ERR_INVALID_ARG;
  }

  /* MDB tracking */
  uint32_t mdb_idx;
  mdb_insert(mdb, 0xFFFF, id, stack_cap, &mdb_idx);

  tcbs->count++;
  *out_tcb_id = id;
  return ERR_OK;
}

static void endpoint_cleanup_for_tcb(uint32_t tcb_id) {
  for (int i = 0; i < MAX_ENDPOINTS; i++) {
    endpoint_t *ep = &g_endpoints[i];
    // If this TCB was waiting as receiver, clear it
    if (ep->has_receiver && ep->receiver_tcb == tcb_id) {
      ep->has_receiver = false;
      ep->pending = false;
      ep->receiver_tcb = 0xFFFFFFFF;
    }
    // Remove from queue if queued as sender
    for (int q = 0; q < ep->q_len;) {
      uint32_t sender = ep->queue[(ep->q_head + q) % 16];
      if (sender == tcb_id) {
        // Remove this entry by shifting
        for (int k = q; k < ep->q_len - 1; k++) {
          ep->queue[(ep->q_head + k) % 16] =
              ep->queue[(ep->q_head + k + 1) % 16];
          ep->queue_msgs[(ep->q_head + k) % 16] =
              ep->queue_msgs[(ep->q_head + k + 1) % 16];
        }
        ep->q_len--;
        ep->q_tail = (ep->q_head + ep->q_len) % 16;
        if (ep->q_len == 0)
          ep->pending = false;
        // don't increment q, check next
      } else
        q++;
    }
    // If pending_msg was from this sender, clear pending
    // (conservative: if any queue entry was this sender, pending already
    // handled)
  }
}

kerror_t process_destroy(tcb_table_t *tcbs, sched_state_t *sched,
                         mdb_tree_t *mdb, uint32_t tcb_id) {
  if (!tcbs || !sched || !mdb || tcb_id >= MAX_TCBS)
    return ERR_INVALID_ARG;
  tcb_t *t = &tcbs->threads[tcb_id];
  if (t->pc == 0 && t->sp == 0 && t->cspace == NULL)
    return ERR_INVALID_ARG;
  // 1. Clean up endpoint references to prevent cross-process injection
  endpoint_cleanup_for_tcb(tcb_id);
  // 2. Clear cspace to prevent privilege leak - zero the CNode slots
  if (t->cspace) {
    // Clear all slots in the CNode (defensive: new process must get clean
    // CNode)
    for (int i = 0; i < MAX_CAPS_PER_CNODE; i++) {
      if (t->cspace->slots[i].is_valid) {
        // Clear CHERI tag
        memset(&t->cspace->slots[i], 0, sizeof(cap_t));
      }
    }
    t->cspace->used = 0;
    // Note: cspace backing memory not freed here - caller must handle Untyped
    // reclamation For now, drop the pointer; new process will get fresh CNode
    // via alloc
    t->cspace = NULL;
  }
  // 3. Revoke all caps derived from this process (stack Frame)
  uint32_t idx = mdb_lookup(mdb, 0, tcb_id);
  if (idx != 0xFFFF) {
    mdb_revoke(mdb, idx);
    mdb_delete(mdb, idx);
  }
  if (t->sched_context < MAX_SCHED_CONTEXTS)
    sched_context_unbind(sched, t->sched_context);
  // 4. Scrub TCB - prevent ID reuse with stale data
  memset(t, 0, sizeof(*t));
  tcbs->count--;
  return ERR_OK;
}

/* moonsh `kill` (weak hook in shell). op: 0 destroy (SIGKILL-like: full
 * teardown via process_destroy), 1 STOP (suspend), 2 CONT (resume).
 * Returns 0 ok, -1 no such thread, -2 bad op. Single hart: the shell runs
 * only while no thread is executing, so teardown cannot race a live
 * context (refusing the current one anyway, defensively). */
int moonsh_kill_tid(long tid, int op) {
  tcb_t *t;
  if (op < 0 || op > 2) return -2;
  if (tid < 0 || tid >= MAX_TCBS) return -1;
  t = &g_tcbs.threads[tid];
  if (t->pc == 0 && t->sp == 0 && t->cspace == NULL) return -1;
  if (op == 0) {
    if (g_current_tcb != TCB_NONE && tid == (long)g_current_tcb) return -1;
    return process_destroy(&g_tcbs, &g_sched, &g_mdb, (uint32_t)tid) == ERR_OK
               ? 0
               : -1;
  }
  if (op == 1) {
    tcb_suspend(t);
    return 0;
  }
  tcb_resume(t);
  return 0;
}
