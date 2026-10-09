/* syscall_asend.c - Non-blocking IPC syscall: ASEND.
 *
 * Split out of syscall_ipc.c (SOLID Sprint 1b, production-ready): ASEND
 * is fire-and-forget (never blocks), used for console<->gui/tty push traffic
 * to avoid deadlocks. Queue accounting/monitoring mirrors SEND. */
#include <stdint.h>

#include "caps.h"
#include "kernel_monitor.h"
#include "kinternal.h"

#include "ipc.h"
#include "ipc_deadlock.h"
#include "ipc_monitor.h"
#include "qube.h"

/* Note: kinternal.h provides SIE_MASK_STIE_SEIE for interrupt fencing */

void sys_asend(void)
{
    unsigned long ep = (unsigned long)threads[cur].regs[10];
    uintptr_t up = (uintptr_t)threads[cur].regs[11];
    unsigned long ln = (unsigned long)threads[cur].regs[12];
    uint64_t kb[V2_MSG_MAX];
    unsigned long r;
    threads[cur].sepc += 4;
    ipc_monitor_syscall(IPC_SYSCALL_SEND);
    if (!v2_ep_ok(ep) || !v2_send_range_ok(up, ln) || ep >= (unsigned long)NTHREADS)
    {
        ipc_monitor_error(ep, IPC_ERROR_INVALID_EP);
        threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
        return;
    }
    v2_ep_t *e = &eps[ep];
    u_copy_in(kb, up, ln);
    ipc_monitor_queue_depth(ep, e->send_len);
    /* Raw gate (peek before dequeue: fail-closed, no state lost). */
    if (e->recv_len > 0)
    {
        unsigned long peek = e->recvq[e->recv_head];
        if (peek >= (unsigned long)NTHREADS ||
            !qube_raw_ok(qube_of, (unsigned long)NTHREADS, (unsigned long)cur, peek, qube_has_qx((unsigned long)cur)))
        {
            threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
            kputs("QUB: xread denied\n");
            return;
        }
    }
    if (v2_q_take_waiter(e, &r) == V2_OK && r < (unsigned long)NTHREADS)
    {
        /* Cross-qube gate (same as SEND): validate before handoff */
        if (r >= (unsigned long)NTHREADS ||
            !qube_raw_ok(qube_of, (unsigned long)NTHREADS, (unsigned long)cur, r, qube_has_qx((unsigned long)cur)))
        {
            threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
            kputs("QUB: xread denied\n");
            return;
        }
        /* Direct handoff to a waiting receiver. Unlike SEND, the caller
         * keeps running (no enter_thread): the receiver is made runnable
         * and picked up by the scheduler. */
        unsigned long cap = (unsigned long)threads[r].ipc_cap;
        unsigned long nw = ln < cap ? ln : cap;
        unsigned long ovf = ln > cap ? 1 : 0;
        u_copy_out(threads[r].ipc_ptr, kb, nw);
        threads[r].regs[10] = (uint64_t)nw;
        threads[r].regs[11] = (uint64_t)cur; /* kernel-stamped */
        threads[r].regs[12] = (uint64_t)qube_of[cur];
        threads[r].regs[13] = (uint64_t)ovf;
        asm volatile("csrc sie, %0" ::"r"(SIE_MASK_STIE_SEIE) : "memory");
        threads[r].state = T_RUNNABLE;
        threads[r].wait_kind = V2_WK_NONE;
        ipc_deadlock_wait_end(r);
        asm volatile("csrs sie, %0" ::"r"(SIE_MASK_STIE_SEIE) : "memory");
        ipc_monitor_direct_delivery();
        ipc_monitor_message_sent(ep);
        ipc_monitor_message_received(ep);
        ipc_monitor_waiter_dequeued(ep);
        threads[cur].regs[10] = (uint64_t)V2_OK;
        return;
    }
    if (v2_q_send(e, (unsigned long)cur, kb, ln) != V2_OK)
    {
        ipc_monitor_error(ep, IPC_ERROR_OVERFLOW);
        ipc_monitor_message_dropped(ep);
        threads[cur].regs[10] = (uint64_t)(long)V2_ERR_OVERFLOW;
        return;
    }
    ipc_monitor_queued_delivery();
    ipc_monitor_message_sent(ep);
    /* Wake a receiver blocked in RECV or WAIT; the sender does NOT block. */
    if (threads[ep].state == T_BLOCKED && threads[ep].wait_kind == V2_WK_RECV)
    {
        asm volatile("csrc sie, %0" ::"r"(SIE_MASK_STIE_SEIE) : "memory");
        threads[ep].state = T_RUNNABLE;
        threads[ep].wait_kind = V2_WK_NONE;
        asm volatile("csrs sie, %0" ::"r"(SIE_MASK_STIE_SEIE) : "memory");
    }
    if (threads[ep].state == T_BLOCKED && threads[ep].wait_kind == V2_WK_WAIT)
    {
        asm volatile("csrc sie, %0" ::"r"(SIE_MASK_STIE_SEIE) : "memory");
        threads[ep].notify |= (1UL << 4); /* IPC_MSG_BIT (0x10) */
        threads[ep].regs[10] = threads[ep].notify;
        threads[ep].notify = 0;
        threads[ep].state = T_RUNNABLE;
        threads[ep].wait_kind = V2_WK_NONE;
        asm volatile("csrs sie, %0" ::"r"(SIE_MASK_STIE_SEIE) : "memory");
    }
    threads[cur].regs[10] = (uint64_t)V2_OK;
    return;
}
