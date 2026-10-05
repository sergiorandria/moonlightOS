/* syscall_ipc.c - U-mode IPC syscalls: YIELD/PUTC/PARK/SEND/RECV/NOTIFY/WAIT.
 *
 * Split out of syscall.c (SOLID Sprint 1b, production-ready): the blocking
 * rendezvous IPC plane in one file; INVOKE operation classes live in
 * syscall_cap/mem/proc/qube.c (cf. seL4 src/object). */
#include <stdint.h>

#include "caps.h"
#include "kinternal.h"

#include "ipc.h"
#include "qube.h"

void sys_yield(void)
{
    threads[cur].sepc += 4;
    int n = pick_next();
    if (n < 0)
        halt_no_runnable();
    enter_thread(n);
}

void sys_putc(void)
{
    /* Forward through real SBI (M-mode): U prints via SBI. */
    sbi_putchar((char)threads[cur].regs[10]); /* a0 */
    threads[cur].sepc += 4;
    return;
}

void sys_park(void)
{
    /* Blocking primitive (mirrors V2_B UPark): park self.
     * Exit convention: a0==1 means "terminate" (Unix exit()).
     * The slot becomes T_DEAD and reusable by SPAWN/FORK/QCREATE
     * (slot selection scans on state alone); anything else parks.
     * a0 was previously ignored, so this is backward compatible.
     * WITHOUT an exit path every thread lives forever and dynamic
     * creation is dead (first SPAWN always OVERFLOWs). The exiting
     * thread's frames are NOT freed here — the reusing SPAWN (or
     * QDESTROY) reclaims them; see the reuse block in V2_INV_SPAWN.
     * qube_of is left stamped: reuse re-stamps (SPAWN/FORK inherit,
     * QCREATE mints fresh), so no stale-label window. */
    threads[cur].sepc += 4;
    if (threads[cur].regs[10] == 1)
    {
        threads[cur].state = T_DEAD;
        threads[cur].wait_kind = V2_WK_NONE;
        threads[cur].ipc_ptr = 0;
        threads[cur].ipc_cap = 0;
        threads[cur].notify = 0;
        klog("[sched] exited ");
    }
    else
    {
        threads[cur].state = T_PARKED;
        klog("[sched] parked ");
    }
    klog_char('0' + cur);
    klog_char('\n');
    int n = pick_next();
    if (n < 0)
        halt_no_runnable();
    enter_thread(n);
}

void sys_send(void)
{
    /* SEND (mirrors V2_C c_send): validate (ep -> range) -> copy
     * IN -> handoff to oldest waiter or queue + block. */
    unsigned long ep = (unsigned long)threads[cur].regs[10];
    uintptr_t up = (uintptr_t)threads[cur].regs[11];
    unsigned long ln = (unsigned long)threads[cur].regs[12];
    uint64_t kb[V2_MSG_MAX];
    unsigned long r;
    threads[cur].sepc += 4;
    if (!v2_ep_ok(ep) || !v2_send_range_ok(up, ln))
    {
        threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
        return;
    }
    if (ep >= (unsigned long)NTHREADS)
    {
        threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
        return;
    }
    v2_ep_t *e = &eps[ep];
    u_copy_in(kb, up, ln);
    /* Raw gate (peek before dequeue: fail-closed, no state lost on
     * reject). Cross-qube handoff needs QX on the sender. */
    if (e->recv_len > 0)
    {
        unsigned long peek = e->recvq[e->recv_head];
        if (peek >= (unsigned long)NTHREADS ||
            !qube_raw_ok(qube_of, (unsigned long)NTHREADS, (unsigned long)cur, peek,
                         qube_has_qx((unsigned long)cur)))
        {
            threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
            kputs("QUB: xread denied\n");
            return;
        }
    }
    if (v2_q_take_waiter(e, &r) == V2_OK && r < (unsigned long)NTHREADS)
    {
        /* Direct delivery: receiver is waiting, copy message and wake.
         * Disable interrupts during state transition to prevent race. */
        unsigned long cap = (unsigned long)threads[r].ipc_cap;
        unsigned long nw = ln < cap ? ln : cap;
        unsigned long ovf = ln > cap ? 1 : 0;
        u_copy_out(threads[r].ipc_ptr, kb, nw);
        threads[r].regs[10] = (uint64_t)nw;
        threads[r].regs[11] = (uint64_t)cur; /* kernel-stamped */
        threads[r].regs[12] = (uint64_t)qube_of[cur];
        threads[r].regs[13] = (uint64_t)ovf;
        /* Critical: atomic state transition during handoff */
        asm volatile("csrc sie, %0" ::"r"(3UL << 4) : "memory");  /* Disable STIE+SEIE */
        threads[r].state = T_RUNNABLE;
        threads[r].wait_kind = V2_WK_NONE;
        asm volatile("csrs sie, %0" ::"r"(3UL << 4) : "memory");  /* Re-enable STIE+SEIE */
        threads[cur].regs[10] = (uint64_t)V2_OK;
        static int shell_live_logged = 0;
        if (!shell_live_logged && cur == 1 && r == 4)
        {
            shell_live_logged = 1;
            kputs("[ipc] send tcb=1 -> 4\n");
        }
        else if (boot_log_enabled)
        {
            kputs("[ipc] send tcb=");
            sbi_putchar('0' + cur);
            kputs(" -> ");
            sbi_putchar('0' + (char)r);
            kputs(" ep=");
            kputdec(ep);
            kputs(" len=");
            kputdec((unsigned long)nw);
            kputs(" ovf=");
            sbi_putchar(ovf ? '1' : '0');
            sbi_putchar('\n');
        }
        enter_thread((int)r);
        return;  /* Exit SEND immediately after direct delivery */
    }
    if (v2_q_send(e, (unsigned long)cur, kb, ln) != V2_OK)
    {
        threads[cur].regs[10] = (uint64_t)(long)V2_ERR_OVERFLOW;
        return;
    }
    /* Flow control: notify sender if queue exceeds threshold */
    if (e->send_len == V2_FLOW_CONTROL_THRESHOLD + 1) {
        /* Just crossed threshold - notify sender */
        threads[cur].notify |= (1UL << 0); /* Use bit 0 for flow control */
    }
    /* If the receiving thread is waiting for notifications (V2_WK_WAIT),
     * signal that an IPC message is pending so it wakes up and can call recv.
     * Disable interrupts during state transition to prevent race. */
    if (threads[ep].state == T_BLOCKED && threads[ep].wait_kind == V2_WK_WAIT)
    {
        asm volatile("csrc sie, %0" ::"r"(3UL << 4) : "memory");  /* Disable STIE+SEIE */
        threads[ep].notify |= (1UL << 4); /* IPC_MSG_BIT (0x10) */
        threads[ep].regs[10] = threads[ep].notify;
        threads[ep].notify = 0;
        threads[ep].state = T_RUNNABLE;
        threads[ep].wait_kind = V2_WK_NONE;
        asm volatile("csrs sie, %0" ::"r"(3UL << 4) : "memory");  /* Re-enable STIE+SEIE */
    }
    /* If the receiving thread is blocked on RECV, wake it to handle the message.
     * Disable interrupts during state transition to prevent race. */
    if (threads[ep].state == T_BLOCKED && threads[ep].wait_kind == V2_WK_RECV)
    {
        asm volatile("csrc sie, %0" ::"r"(3UL << 4) : "memory");  /* Disable STIE+SEIE */
        threads[ep].state = T_RUNNABLE;
        threads[ep].wait_kind = V2_WK_NONE;
        asm volatile("csrs sie, %0" ::"r"(3UL << 4) : "memory");  /* Re-enable STIE+SEIE */
    }
    threads[cur].state = T_BLOCKED;
    threads[cur].wait_kind = V2_WK_SEND;
    klog("[ipc] send tcb=");
    klog_char('0' + cur);
    klog(" queued ep=");
    klog_dec(ep);
    klog(" len=");
    klog_dec(ln);
    klog_char('\n');
    int n = pick_next();
    if (n < 0)
        halt_no_runnable();
    enter_thread(n);
}

void sys_recv(void)
{
    /* RECV (mirrors V2_C c_recv): validate -> deliver oldest
     * queued send (resume sender, stamp sender id, flag
     * truncation) or park (ptr, cap) + block. */
    unsigned long ep = (unsigned long)threads[cur].regs[10];
    uintptr_t up = (uintptr_t)threads[cur].regs[11];
    unsigned long cap = (unsigned long)threads[cur].regs[12];
    v2_slot_t slot;
    threads[cur].sepc += 4;
    if (!v2_ep_ok(ep) || !v2_recv_range_ok(up, cap))
    {
        threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
        return;
    }
    if (ep != (unsigned long)cur)
    {
        threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
        return;
    }
    v2_ep_t *e = &eps[ep];
    /* Raw gate (peek before dequeue: fail-closed, no state lost on
     * reject). Queued sends gate at delivery: the destination is
     * unknown at send time, so the sender's qube is derived here
     * via qube_of[slot.sender] (v2_slot_t stays as-is). */
    if (e->send_len > 0)
    {
        unsigned long psrc = e->sendq[e->send_head].sender;
        if (psrc >= (unsigned long)NTHREADS ||
            !qube_raw_ok(qube_of, (unsigned long)NTHREADS, psrc,
                         (unsigned long)cur, qube_has_qx(psrc)))
        {
            threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
            kputs("QUB: xread denied\n");
            return;
        }
    }
    if (v2_q_take_send(e, &slot) == V2_OK)
    {
        unsigned long nw = slot.len < cap ? slot.len : cap;
        unsigned long ovf = slot.len > cap ? 1 : 0;
        unsigned long sq = (slot.sender < (unsigned long)NTHREADS) ?
                           (unsigned long)qube_of[slot.sender] : 0;
        u_copy_out(up, slot.words, nw);
        threads[cur].regs[10] = (uint64_t)nw;
        threads[cur].regs[11] = (uint64_t)slot.sender;
        threads[cur].regs[12] = (uint64_t)sq;
        threads[cur].regs[13] = (uint64_t)ovf;

        /* Flow control: notify sender if queue drops below threshold */
        if (e->send_len == V2_FLOW_CONTROL_THRESHOLD - 1 && slot.sender < (unsigned long)NTHREADS) {
            threads[slot.sender].notify |= (1UL << 0); /* Use bit 0 for flow control */
        }

        if (slot.sender < (unsigned long)NTHREADS)
        {
            /* Critical: atomic state transition during sender wake-up.
             * Disable interrupts to prevent race with timer/IRQ. */
            asm volatile("csrc sie, %0" ::"r"(3UL << 4) : "memory");  /* Disable STIE+SEIE */
            threads[slot.sender].state = T_RUNNABLE;
            threads[slot.sender].wait_kind = V2_WK_NONE;
            threads[slot.sender].regs[10] = (uint64_t)V2_OK;
            asm volatile("csrs sie, %0" ::"r"(3UL << 4) : "memory");  /* Re-enable STIE+SEIE */
        }
        klog("[ipc] recv tcb=");
        klog_char('0' + cur);
        klog(" from=");
        klog_char('0' + (char)slot.sender);
        klog(" len=");
        klog_dec((unsigned long)nw);
        klog(" ovf=");
        klog_char(ovf ? '1' : '0');
        klog_char('\n');
        return;
    }
    threads[cur].ipc_ptr = up;
    threads[cur].ipc_cap = cap;
    threads[cur].state = T_BLOCKED;
    threads[cur].wait_kind = V2_WK_RECV;
    if (v2_q_wait(e, (unsigned long)cur) != V2_OK)
    {
        /* Practically unreachable at NTHREADS=11 (recvq would
         * need 11 waiters on one ep); fail closed rather than
         * lose the waiter. */
        threads[cur].state = T_RUNNABLE;
        threads[cur].wait_kind = V2_WK_NONE;
        threads[cur].regs[10] = (uint64_t)(long)V2_ERR_OVERFLOW;
        return;
    }
    klog("[ipc] recv tcb=");
    klog_char('0' + cur);
    klog(" blocked ep=");
    klog_dec(ep);
    klog_char('\n');
    int n = pick_next();
    if (n < 0)
        halt_no_runnable();
    enter_thread(n);
}

void sys_notify(void)
{
    /* NOTIFY (mirrors V2_C c_notify): OR-accumulate, wake only
     * genuine waiters (wk == WAIT); rendezvous blocks untouched. */
    unsigned long t = (unsigned long)threads[cur].regs[10];
    uint64_t bits = threads[cur].regs[11];
    int woke = 0;
    threads[cur].sepc += 4;
    if (t >= (unsigned long)NTHREADS)
    {
        threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
        return;
    }
    threads[t].notify |= bits;
    /* Disable interrupts during state transition to prevent race. */
    if (threads[t].state == T_BLOCKED && threads[t].wait_kind == V2_WK_WAIT)
    {
        asm volatile("csrc sie, %0" ::"r"(3UL << 4) : "memory");  /* Disable STIE+SEIE */
        threads[t].state = T_RUNNABLE;
        threads[t].wait_kind = V2_WK_NONE;
        /* Wake-delivery: a thread woken from WAIT resumes past
         * the ecall with whatever a0 it blocked with (stale).
         * Pre-deliver the pending bits as its WAIT return
         * (UABI: a0 = bits); pending is preserved, so a
         * re-WAIT still collects — level-triggered parties
         * (admin loop) observe zero behavior change. Without
         * this, the first woken-WAIT consumer (thread A live
         * legs, Task 5) sees a stale return and parks. */
        threads[t].regs[10] = threads[t].notify;
        asm volatile("csrs sie, %0" ::"r"(3UL << 4) : "memory");  /* Re-enable STIE+SEIE */
        woke = 1;
    }
    threads[cur].regs[10] = (uint64_t)V2_OK;
    klog("[ipc] notify ");
    klog_char('0' + cur);
    klog(" -> ");
    klog_char('0' + (char)t);
    klog(" bits=");
    klog_hex(bits);
    klog(" wake=");
    klog_char(woke ? '1' : '0');
    klog_char('\n');
    return;
}

void sys_wait(void)
{
    /* WAIT (mirrors V2_C c_wait): take bits or block. */
    threads[cur].sepc += 4;
    if (threads[cur].notify != 0 || (cur < V2_NEP && eps[cur].send_len > 0))
    {
        uint64_t ret_bits = threads[cur].notify;
        if (cur < V2_NEP && eps[cur].send_len > 0)
            ret_bits |= (1UL << 4); /* IPC_MSG_BIT (0x10) */
        threads[cur].regs[10] = ret_bits;
        threads[cur].notify = 0;
        threads[cur].wait_kind = V2_WK_NONE;
        klog("[ipc] wait tcb=");
        klog_char('0' + cur);
        klog(" bits=");
        klog_hex(threads[cur].regs[10]);
        klog_char('\n');
        return;
    }
    threads[cur].state = T_BLOCKED;
    threads[cur].wait_kind = V2_WK_WAIT;
    klog("[ipc] wait tcb=");
    klog_char('0' + cur);
    klog(" blocked\n");
    int n = pick_next();
    if (n < 0)
        halt_no_runnable();
    enter_thread(n);
}
