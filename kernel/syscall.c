/* syscall.c - IPC / capability / thread-lifecycle dispatch (SRP: syscalls).
 *
 * Split out of kboot.c (SOLID Sprint 1): the s_trap_handler dispatcher
 * plus its user-copy and VSpace-sync helpers. kboot() keeps booting only. */
#include <stdint.h>

#include "../userspace/firewall/fw.h" /* S3 demo drives fw_decide (header-only, pure C) */
#include "caps.h"
#include "elf.h"
#include "initrd.h"
#include "ipc.h"
#include "kinternal.h"
#include "platform.h"
#include "qube.h"
#include "services.h"
#include "dev.h"
#include "dev_leaves.h"
#include "irq.h"
#include "virtio_ident.h"

#define TICK_DELTA 1000000UL /* 100ms @ 10MHz timebase */
#define V2_YIELD 0
#define V2_PUTC 1
#define V2_PARK 2
/* V2_GET_KBOOT_BUF removed - violates microkernel principles */
#define V2_SEND 3 /* (ep, u_ptr, len): copy IN, block unless waiter; a0 = 0 / -ERR */
#define V2_RECV                                                                                                        \
    4 /* (ep, u_buf, cap): copy OUT, block unless queued; a0 = words, a1 = sender, a2 = sender_qube, a3 = ovf */
#define V2_NOTIFY 5 /* (target, bits): OR-accumulate + wake waiters only; a0 = 0 / -ERR */
#define V2_WAIT 6   /* (): take pending bits (a0) or block; a0 = bits */
#define V2_INVOKE 7
#define V2_INV_MINT 1
#define V2_INV_GRANT 2
#define V2_INV_MAP 3
#define V2_INV_UNMAP 4
#define V2_INV_REVOKE 5
#define V2_INV_PT_ALLOC 6
#define V2_INV_ELF_CHECK 7
#define V2_INV_ELF_MAP 8
#define V2_INV_SPAWN 9
#define V2_INV_FORK 10
#define V2_INV_EXEC 11
#define V2_INV_WRITE 12
#define V2_INV_READ 13
#define V2_INV_FRAME_PA 16 /* (vpn,0,0,0): PA of the frame mapped at vpn; reserved!=0 -> INVALID */

/* ---- User copy (both directions, V2_DESIGN Sec.4): validate-then-copy.
 * S runs with SUM=0; the window is opened only for the bounded copy loop
 * after the range check passed. Raw dereference of a user pointer
 * anywhere else is a bug. SEND needs R (whole U range), RECV needs W
 * (data region: text is RX, enforced by v2_recv_range_ok). */
static void sum_on(void)
{
    asm volatile("csrs sstatus, %0" ::"r"(1UL << 18) : "memory");
}

static void sum_off(void)
{
    asm volatile("csrc sstatus, %0" ::"r"(1UL << 18) : "memory");
}

/* bound: len (caller-checked <= V2_MSG_MAX for IN; <= stored len for OUT) */
void u_copy_in(uint64_t *kd, uintptr_t us, unsigned long len)
{
    sum_on();
    for (unsigned long i = 0; i < len; i++)
        kd[i] = ((const volatile uint64_t *)us)[i];
    sum_off();
}

/* bound: n (<= stored msg len <= V2_MSG_MAX) */
void u_copy_out(uintptr_t ud, const uint64_t *ks, unsigned long n)
{
    sum_on();
    for (unsigned long i = 0; i < n; i++)
        ((volatile uint64_t *)ud)[i] = ks[i];
    sum_off();
}

/* QX grant check: does tid hold any valid cap carrying V2_RIGHT_QX?
 * Bounded scan of the thread's own cap table; fail-closed (bad tid = 0). */
int qube_has_qx(unsigned long tid)
{
    int s;
    if (tid >= (unsigned long)NTHREADS)
        return 0;
    for (s = 0; s < V2_CAP_SLOTS; s++)
    { /* bound: V2_CAP_SLOTS */
        if (caps.caps[tid][s].valid && (caps.caps[tid][s].rights & V2_RIGHT_QX))
            return 1;
    }
    return 0;
}

/* Sync hardware PTEs with the caps model for thread t: (re)install every
 * valid mapping into l0_u_t[t] and fence once. ELF loads record model
 * mappings without touching PTEs, so every load path calls this before
 * the thread can run. Reinstalling existing entries is idempotent.
 * bound: V2_VPN_SLOTS. */
void v2_pte_sync(unsigned long t)
{
    int i;
    if (t >= (unsigned long)V2_CAP_THREADS)
        return;
    for (i = 0; i < V2_VPN_SLOTS; i++)
    {
        if (caps.vm[t][i].valid)
            v2_pte_install(t, caps.vm[t][i].vpn, caps.vm[t][i].frame, caps.vm[t][i].rights);
    }
    v2_sfence_all();
}

/* satp value (mode 8 / Sv39 + root PPN) for thread t's tables. The
 * uctx_t.vspace_root_ppn field always holds this full satp encoding
 * (not a bare PPN); enter_thread loads it straight into satp. */
uint64_t v2_satp_of(unsigned long t)
{
    return (8UL << 60) | ((((uintptr_t)root_pt_t[t] >> 12) & 0xFFFFFFFFFFFUL));
}

/* Build child VSpace: wire the child's tables exactly like pagetable_init
 * wires each thread's tables (shared kernel image, shared frame window,
 * shared UART; the child's OWN l0_u for its user window), and return the
 * child's satp value (0 on bad tid). The child's l0_u starts zeroed; the
 * caller installs mappings (v2_pte_sync) afterwards.
 * bound: fixed 512-entry table loops. */
unsigned long build_child_vspace(unsigned long parent_tid, unsigned long child_tid)
{
    if (child_tid >= (unsigned long)NTHREADS || parent_tid >= (unsigned long)NTHREADS)
        return 0;

    /* Zero child's tables */
    for (int i = 0; i < 512; i++)
        l1_t[child_tid][i] = 0;
    for (int i = 0; i < 512; i++)
        l0_u_t[child_tid][i] = 0;
    for (int i = 0; i < 512; i++)
        root_pt_t[child_tid][i] = 0;

    /* Mirror pagetable_init's per-thread wiring (same indices, same
     * pte_table encoding): root[0] -> shared UART, root[2] -> own l1. */
    l1_t[child_tid][1] = l1_t[parent_tid][1];          /* l0_k: kernel image */
    l1_t[child_tid][8] = l1_t[parent_tid][8];          /* l0_frames: frame pool */
    l1_t[child_tid][4] = pte_table(l0_u_t[child_tid]); /* own user window */
    root_pt_t[child_tid][0] = pte_table(l1_m);         /* shared UART */
    root_pt_t[child_tid][2] = pte_table(l1_t[child_tid]);

    return v2_satp_of(child_tid);
}

/* COW write-protect: drop PTE_W from every W-mapping's hardware PTE in
 * BOTH parent and child tables (the caps model keeps W rights on both
 * sides and stays the authority). A later store faults (R-only PTE) and
 * the fault handler consults the model to authorize the break. No flag
 * bits are hidden in PTEs or rights, so there is nothing that can collide
 * with legitimate RX execute pages.
 * bound: V2_VPN_SLOTS. */
void v2_cow_write_protect(unsigned long parent_tid, unsigned long child_tid)
{
    for (int i = 0; i < V2_VPN_SLOTS; i++)
    {
        if (caps.vm[parent_tid][i].valid && (caps.vm[parent_tid][i].rights & V2_RIGHT_W))
        {
            unsigned long vpn = caps.vm[parent_tid][i].vpn;
            if (vpn >= (unsigned long)V2_VPN_SLOTS)
                continue;
            l0_u_t[parent_tid][vpn] &= ~(PTE_W | PTE_D);
            l0_u_t[child_tid][vpn] &= ~(PTE_W | PTE_D);
        }
    }
    v2_sfence_all();
}

/* Trap dispatch. Switch cases call u_enter (noreturn); plain cases return
 * to the trap.S epilogue which restores cur_ctx and srets.
 * TRAP_DEBUG: burst-race evidence log (spec 2026-10-04 §4.1). 1 enables a
 * per-entry (scause, SPP, SIE) print: SPP=1 means the trap was taken from
 * S-mode (nested/idle-wake, H1), SIE=1 means an interrupt window is open
 * in-handler (H2). Default 0: the log floods the transcript at burst rate.
 * Commit policy: evidence runs only; never ship with 1. */
#define TRAP_DEBUG 0
void s_trap_handler(uint64_t cause, uctx_t *ctx)
{
    int is_int = (cause >> 63) & 1;
    uint64_t code = cause & ~(1UL << 63);
    (void)ctx;
#if TRAP_DEBUG
    {
        uint64_t sstatus = 0;
        asm volatile("csrr %0, sstatus" : "=r"(sstatus));
        kputs("[trapdbg] cause=");
        kputhex(cause);
        kputs(" spp=");
        sbi_putchar((char)('0' + ((sstatus >> 8) & 1UL)));
        kputs(" sie=");
        sbi_putchar((char)('0' + ((sstatus >> 1) & 1UL)));
        sbi_putchar('\n');
    }
#endif
    if (is_int)
    {
        if (code == 5)
        { /* S-mode timer */
            /* Guard: timer interrupt during halt must never return
             * (would corrupt kernel state via trap.S epilogue with
             * zeroed sepc/sp). Schedule a woken thread or re-park. */
            if (cur_ctx == &halt_ctx)
            {
                int n = pick_next();
                if (n >= 0)
                    enter_thread(n);
                halt_no_runnable();
            }
            sbi_set_timer(rdtime() + TICK_DELTA);
            /* tick++; */ /* Unused - debug only */
            /* Timer preemption: rotate from the current TID so runnable
             * peers receive a turn before this thread is selected again. */
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            enter_thread(n);
        }
        if (code == 9)
        { /* S-mode external: virtio IRQ via PLIC claim */
            uint32_t s = *(volatile uint32_t *)PLIC_CLAIM_S;
            uint32_t m = *(volatile uint32_t *)PLIC_CLAIM_M;
            uint32_t src = 0;
            int blk = 0;
            /* Either context may carry the delivery (measured: S does);
             * one marker per trap even if both fired. Net and blk are
             * handled independently so one trap can serve both devices. */
            if (s == net_virtio_irq)
                src = s;
            else if (m == net_virtio_irq)
                src = m;
            if (s == blk_virtio_irq || m == blk_virtio_irq)
                blk = 1;
            if (src != 0)
            {
                threads[6].notify |= NET_IRQ_BIT;
                /* Wake only genuine WAIT waiters (NOTIFY discipline);
                 * unknown sources never wake anyone. 
                 * Disable interrupts during state transition to prevent race. */
                if (threads[6].state == T_BLOCKED && threads[6].wait_kind == V2_WK_WAIT)
                {
                    asm volatile("csrc sie, %0" ::"r"(3UL << 4) : "memory");  /* Disable STIE+SEIE */
                    threads[6].state = T_RUNNABLE;
                    threads[6].wait_kind = V2_WK_NONE;
                    asm volatile("csrs sie, %0" ::"r"(3UL << 4) : "memory");  /* Re-enable STIE+SEIE */
                }
                kputs("NET: irq ok\n");
            }
            if (blk)
            {
                /* No per-IRQ print: a 4K sector op raises up to 8 blk
                 * IRQs, so a print here would flood the transcript; the
                 * ELF's badge check after WAIT is the delivery proof. */
                threads[9].notify |= BLK_IRQ_BIT;
                /* Disable interrupts during state transition to prevent race. */
                if (threads[9].state == T_BLOCKED && threads[9].wait_kind == V2_WK_WAIT)
                {
                    asm volatile("csrc sie, %0" ::"r"(3UL << 4) : "memory");  /* Disable STIE+SEIE */
                    threads[9].state = T_RUNNABLE;
                    threads[9].wait_kind = V2_WK_NONE;
                    asm volatile("csrs sie, %0" ::"r"(3UL << 4) : "memory");  /* Re-enable STIE+SEIE */
                }
            }
            /* S4c VirtIO input IRQs: keyboard and mouse for GUI qube (tid 10).
             * Delivered independently; one trap can serve both if they fire
             * together (QEMU can queue IRQs). Notify bits are or'd so the
             * WAIT badge check detects either source. No per-IRQ print: typing
             * generates high-frequency IRQs that would flood the transcript;
             * the ELF's event poll after WAIT is the delivery proof. */
            int input_irq = 0;
            int input_woke = 0;
            if (s == kbd_virtio_irq || m == kbd_virtio_irq)
            {
                threads[10].notify |= KBD_IRQ_BIT;
                input_irq = 1;
            }
            if (s == mouse_virtio_irq || m == mouse_virtio_irq)
            {
                threads[10].notify |= MOUSE_IRQ_BIT;
                input_irq = 1;
            }
            if (input_irq)
            {
                /* Disable interrupts during state transition to prevent race. */
                if (threads[10].state == T_BLOCKED && threads[10].wait_kind == V2_WK_WAIT)
                {
                    asm volatile("csrc sie, %0" ::"r"(3UL << 4) : "memory");  /* Disable STIE+SEIE */
                    threads[10].state = T_RUNNABLE;
                    threads[10].wait_kind = V2_WK_NONE;
                    /* Wake-delivery (NOTIFY precedent): a thread woken
                     * from WAIT resumes past the ecall with stale a0, so
                     * pre-deliver the pending bits as its WAIT return;
                     * pending stays set, so a re-WAIT still collects. */
                    threads[10].regs[10] = threads[10].notify;
                    asm volatile("csrs sie, %0" ::"r"(3UL << 4) : "memory");  /* Re-enable STIE+SEIE */
                    input_woke = 1;
                }
            }
            if (src == 0 && !blk && !input_irq)
            {
                uint8_t kind = IRQ_KIND_NONE;
                int stub = 0;
                if (irq_lookup(s, 0, &kind, 0) && kind == IRQ_KIND_STUB)
                    stub = 1;
                else if (irq_lookup(m, 0, &kind, 0) && kind == IRQ_KIND_STUB)
                    stub = 1;
                if (!stub)
                    kputs("IRQ: unexpected\n");
            }
            if (s != 0)
                *(volatile uint32_t *)PLIC_CLAIM_S = s;
            if (m != 0)
                *(volatile uint32_t *)PLIC_CLAIM_M = m;
            /* S4c live input (Task 4): a post-halt wake leaves nobody
             * scheduled (halt is not a thread) — run the woken server
             * now (SEND-handoff precedent: enter_thread from handler).
             * Pre-park this only fires for a WAIT-blocked input server
             * and is a no-op for everyone else. */
            if (input_woke)
            {
                int n = pick_next();
                if (n >= 0)
                    enter_thread(n);
            }
            /* Halt-context return guard: if this trap was taken from
             * halt (cur_ctx == &halt_ctx: idle wfi, S-origin), the
             * trap.S epilogue would restore the zeroed halt save area
             * (sepc=0, sp=0) and sret into a fault — then re-trap from
             * S-mode and corrupt the entry swap (burst-race signature).
             * Never return from a halt entry: schedule a woken thread,
             * or re-park (halt_no_runnable re-arms the halt protocol:
             * cur_ctx, sscratch, SIE, timer-max). */
            if (cur_ctx == &halt_ctx)
            {
                int n = pick_next();
                if (n >= 0)
                    enter_thread(n);
                halt_no_runnable();
            }
            return;
        }
        kputs("[trap] unexpected interrupt\n");
        for (;;)
            asm volatile("wfi");
    }
    switch (code)
    {
    case 8: {                                 /* U-mode ecall */
        uint64_t sys = threads[cur].regs[17]; /* a7 */
        if (sys == V2_YIELD)
        {
            threads[cur].sepc += 4;
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            enter_thread(n);
        }
        else if (sys == V2_PUTC)
        {
            /* Forward through real SBI (M-mode): U prints via SBI. */
            sbi_putchar((char)threads[cur].regs[10]); /* a0 */
            threads[cur].sepc += 4;
            return;
        }
        else if (sys == V2_PARK)
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
        else if (sys == V2_SEND)
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
        else if (sys == V2_RECV)
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
        else if (sys == V2_NOTIFY)
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
        else if (sys == V2_WAIT)
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
        else if (sys == V2_INVOKE)
        {
            uint64_t op = threads[cur].regs[10]; /* a0 */
            uint64_t a1 = threads[cur].regs[11];
            uint64_t a2 = threads[cur].regs[12];
            uint64_t a3 = threads[cur].regs[13];
            threads[cur].sepc += 4;
            /* long: FRAME_PA returns a full PA (0x81000000+ exceeds int);
             * all other ops assign small ints/negatives, so the epilogue
             * regs[10] = (uint64_t)rc is bit-identical for them. */
            long rc = V2_ERR_INVALID;
            switch (op)
            {
            case V2_INV_MINT:
                rc = v2_mint(&caps, (unsigned long)cur, a1, a2, a3);
                break;
            case V2_INV_GRANT:
                rc = v2_grant(&caps, (unsigned long)cur, a1, a2, a3);
                break;
            case V2_INV_MAP: {
                /* vpn must index a real l0_u_t[t][vpn] slot: guard before
                 * the model call so rc stays V2_ERR_INVALID for vpn >=
                 * V2_VPN_SLOTS (the model itself does not bound vpn). The
                 * model call stays authoritative: on V2_OK the mapping is
                 * recorded in caps.vm, then we install the real leaf PTE. */
                int m; /* bound: vpn < V2_VPN_SLOTS (checked below) */
                if (a2 < (uint64_t)V2_VPN_SLOTS)
                    rc = v2_map(&caps, (unsigned long)cur, a1, a2);
                if (rc == V2_OK)
                {
                    m = v2_vm_find(&caps, (unsigned long)cur, a2);
                    if (m >= 0)
                    { /* model recorded it: must be findable */
                        v2_pte_install((unsigned long)cur, a2, caps.vm[cur][m].frame, caps.vm[cur][m].rights);
                        v2_sfence_all();
                    }
                }
                break;
            }
            case V2_INV_UNMAP:
                rc = v2_unmap(&caps, (unsigned long)cur, a1);
                if (rc == V2_OK)
                { /* model validated the mapping exists */
                    v2_pte_clear((unsigned long)cur, a1);
                    v2_sfence_all();
                }
                break;
            case V2_INV_REVOKE: {
                /* Revoke drops every mapping to the frame system-wide; the
                 * model clears caps.vm but not hardware PTEs. Capture the
                 * affected (t, vpn) pairs BEFORE the model destroys them,
                 * clear them only if the model approves (fail closed). */
                unsigned long f = 0;
                unsigned long npair = 0;
                int have_f = 0;
                if (a1 < (uint64_t)V2_CAP_SLOTS && caps.caps[cur][a1].valid)
                {
                    f = caps.caps[cur][a1].obj;
                    have_f = 1;
                }
                if (have_f)
                {
                    for (unsigned long u = 0; u < caps.nthreads; u++)
                        /* bound: V2_CAP_THREADS */
                        for (int i = 0; i < V2_VPN_SLOTS; i++)
                        {
                            /* bound: V2_VPN_SLOTS */
                            if (caps.vm[u][i].valid && caps.vm[u][i].frame == f &&
                                npair < (unsigned long)(V2_CAP_THREADS * V2_VPN_SLOTS))
                            {
                                v2_revoke_pairs[npair].t = u;
                                v2_revoke_pairs[npair].vpn = caps.vm[u][i].vpn;
                                npair++;
                            }
                        }
                }
                rc = v2_revoke(&caps, (unsigned long)cur, a1);
                if (rc == V2_OK)
                {
                    for (unsigned long i = 0; i < npair; i++)
                    {
                        /* bound: V2_CAP_THREADS * V2_VPN_SLOTS */
                        if (v2_revoke_pairs[i].t < (unsigned long)NTHREADS)
                            v2_pte_clear(v2_revoke_pairs[i].t, v2_revoke_pairs[i].vpn);
                    }
                    v2_sfence_all();
                }
                break;
            }
            case V2_INV_PT_ALLOC:
                rc = frame_alloc_slot(&caps, (unsigned long)cur);
                break;
            case V2_INV_ELF_CHECK:
                rc = v2_elf_ok((int)a1, (const v2_phdr_t *)a2, a3) ? V2_OK : V2_ERR_INVALID;
                break;
            case V2_INV_ELF_MAP: {
                /* ELF_MAP (a1=initrd index, a2/a3 reserved):
                 * Load an initrd ELF into the caller's VSpace.
                 * a1 = initrd index (0 = mem_server.elf, see mkinitrd.sh)
                 * a2/a3 are reserved and must be zero (unused).
                 * Returns entry point in rc (a0 on return).
                 * FAIL CLOSED: any validation error -> V2_ERR_INVALID. */
                const uint8_t *elf_data;
                uint32_t elf_size;
                uint64_t entry, brk = 0;
                if (!((a2 == 0 && a3 == 0) || v2_recv_range_ok((uintptr_t)a2, a3)))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)cur, &entry, &brk);
                if (rc == V2_OK)
                {
                    v2_pte_sync((unsigned long)cur);
                    rc = (int)entry; /* return entry point as rc */
                }
                break;
            }
            case V2_INV_SPAWN: {
                /* SPAWN (a1=initrd index, a2/a3 reserved):
                 * Create a new thread, allocate its VSpace, load an
                 * initrd ELF into it.
                 * a1 = initrd index (0 = mem_server.elf, see mkinitrd.sh)
                 * a2/a3 are reserved and must be zero (unused).
                 * Returns child tid in rc on success.
                 * FAIL CLOSED: any validation error -> V2_ERR_INVALID. */
                const uint8_t *elf_data;
                uint32_t elf_size;
                uint64_t entry, brk = 0;
                if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (!((a2 == 0 && a3 == 0) || v2_recv_range_ok((uintptr_t)a2, a3)))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                /* Find a free thread slot (threads[] has NTHREADS entries;
                 * V2_CAP_THREADS is the model's bound, not ours). */
                int child = -1;
                for (int t = 0; t < NTHREADS; t++)
                { /* bound: NTHREADS */
                    /* deferred-C: T_DEAD is distinct; state alone frees the slot */
                    if (threads[t].state == T_DEAD)
                    {
                        child = t;
                        break;
                    }
                }
                if (child < 0)
                {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                /* A reused slot may hold a previous life's caps/mappings:
                 * clear them so the load starts fresh (fail closed). The
                 * child inherits the spawner's qube: without this a slot
                 * recycled by QDESTROY (label cleared to 0) silently lands
                 * the new thread in the ambient qube — or keeps a stale
                 * non-zero label — and the raw gate decides on the wrong
                 * labels. Set before any failure break below. */
                qube_of[child] = qube_of[cur];
                /* Reclaim the previous life's frames first: dropping caps
                 * without freeing leaks the pool into OVERFLOW over spawn
                 * cycles. Snapshot-then-teardown (EXEC precedent): shared
                 * frames are unmapped on this slot's side only, never
                 * freed under a live sibling. */
                {
                    unsigned long reuse_frames[V2_VPN_SLOTS];
                    int reuse_n = 0;
                    for (int i = 0; i < V2_VPN_SLOTS; i++)
                    {
                        if (caps.vm[child][i].valid)
                            reuse_frames[reuse_n++] = caps.vm[child][i].frame;
                    }
                    for (int i = 0; i < reuse_n; i++)
                        frame_teardown_owned((unsigned long)child, reuse_frames[i]);
                }
                for (int s = 0; s < V2_CAP_SLOTS; s++)
                    caps.caps[child][s].valid = 0;
                for (int i = 0; i < V2_VPN_SLOTS; i++)
                    caps.vm[child][i].valid = 0;
                /* Build child's VSpace: copy current thread's page tables for kernel mappings,
                 * allocate fresh l0_u for user mappings */
                unsigned long child_root = build_child_vspace((unsigned long)cur, (unsigned long)child);
                if (!child_root)
                {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                threads[child].vspace_root_ppn = child_root;
                /* Fresh IPC/notify state: a reused slot must not inherit
                 * the previous life's blocked sends or pending signals. */
                threads[child].ipc_ptr = 0;
                threads[child].ipc_cap = 0;
                threads[child].notify = 0;
                threads[child].wait_kind = V2_WK_NONE;
                /* Fresh registers: no stale-word leak into the new image. */
                for (int r = 0; r < 32; r++)
                    threads[child].regs[r] = 0;
                threads[child].state = T_RUNNABLE;

                /* Load ELF into child's VSpace */
                rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)child, &entry, &brk);
                if (rc == V2_OK && entry != 0)
                {
                    v2_pte_sync((unsigned long)child);
                    threads[child].regs[2] = u_sp[child];
                    threads[child].sepc = entry;
                    rc = child; /* return child tid */
                }
                else
                {
                    threads[child].state = T_DEAD; /* cleanup on failure */
                    if (rc == V2_OK)
                        rc = V2_ERR_INVALID;
                }
                break;
            }
            case V2_INV_FORK: {
                /* FORK (no args):
                 * Create a child thread with a COW copy of the parent's
                 * VSpace and caps. The caps model keeps full rights on
                 * both sides (it stays the authority); only the hardware
                 * PTEs lose W (see v2_cow_write_protect), so the first
                 * store to a shared page faults and the handler breaks
                 * the share for the faulting thread only.
                 * Returns child tid to parent, 0 to child.
                 * FAIL CLOSED: any error -> V2_ERR_INVALID/V2_ERR_OVERFLOW. */
                int child = -1;
                for (int t = 0; t < NTHREADS; t++)
                { /* bound: NTHREADS */
                    /* deferred-C: T_DEAD is distinct; state alone frees the slot */
                    if (threads[t].state == T_DEAD)
                    {
                        child = t;
                        break;
                    }
                }
                if (child < 0)
                {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                /* The child inherits the parent's qube (same reason as
                 * SPAWN above: a recycled T_DEAD slot must not keep a
                 * cleared (0) or stale label). Set before any failure
                 * break below. */
                qube_of[child] = qube_of[cur];
                /* Reclaim the slot's previous life first (same leak as
                 * SPAWN-reuse had: overwriting caps/vm orphans frames).
                 * Shared frames are spared by teardown_owned. */
                {
                    unsigned long fork_frames[V2_VPN_SLOTS + V2_CAP_SLOTS];
                    int fork_n = 0;
                    for (int i = 0; i < V2_VPN_SLOTS; i++)
                    {
                        if (caps.vm[child][i].valid)
                            fork_frames[fork_n++] = caps.vm[child][i].frame;
                    }
                    for (int s = 0; s < V2_CAP_SLOTS; s++)
                    {
                        if (caps.caps[child][s].valid && !caps.caps[child][s].root)
                            fork_frames[fork_n++] = caps.caps[child][s].obj;
                    }
                    for (int i = 0; i < fork_n; i++)
                        frame_teardown_owned((unsigned long)child, fork_frames[i]);
                }
                /* Copy parent's caps table. The child must not inherit
                 * allocator authority: root bits stay with the parent. */
                for (int s = 0; s < V2_CAP_SLOTS; s++)
                {
                    caps.caps[child][s] = caps.caps[cur][s];
                    caps.caps[child][s].root = 0;
                }
                /* Copy parent's mappings verbatim (rights intact: the
                 * model is the COW authority, not a rights bit). */
                for (int i = 0; i < V2_VPN_SLOTS; i++)
                    caps.vm[child][i] = caps.vm[cur][i];
                /* Build child tables, install the shared mappings, then
                 * write-protect both sides in hardware. */
                unsigned long child_root = build_child_vspace((unsigned long)cur, (unsigned long)child);
                if (!child_root)
                {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                threads[child].vspace_root_ppn = child_root;
                for (int i = 0; i < V2_VPN_SLOTS; i++)
                {
                    if (caps.vm[child][i].valid)
                        v2_pte_install((unsigned long)child, caps.vm[child][i].vpn, caps.vm[child][i].frame,
                                       caps.vm[child][i].rights);
                }
                v2_cow_write_protect((unsigned long)cur, (unsigned long)child);
                /* Fresh IPC/notify state for the new life. */
                threads[child].ipc_ptr = 0;
                threads[child].ipc_cap = 0;
                threads[child].notify = 0;
                threads[child].wait_kind = V2_WK_NONE;
                threads[child].state = T_RUNNABLE;
                threads[child].regs[2] = u_sp[child];
                threads[child].sepc = threads[cur].sepc + 4; /* return after ecall */
                /* Copy registers (parent's a0..a7, sp, etc.) */
                for (int r = 0; r < 32; r++)
                    threads[child].regs[r] = threads[cur].regs[r];
                threads[child].regs[10] = 0;   /* child returns 0 in a0 */
                threads[child].regs[11] = cur; /* child gets parent tid in a1 */
                rc = child;                    /* parent returns child tid in a0 */
                break;
            }
            case V2_INV_EXEC: {
                /* EXEC (a1=initrd index, a2/a3 reserved):
                 * Replace current thread's image: unmap all user mappings, free frames,
                 * clear user caps, load a new initrd ELF.
                 * a1 = initrd index (0 = mem_server.elf, see mkinitrd.sh)
                 * a2/a3 are reserved and must be zero (unused).
                 * Returns 0 on success.
                 * FAIL CLOSED: any validation error -> V2_ERR_INVALID. */
                const uint8_t *elf_data;
                uint32_t elf_size;
                if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (!((a2 == 0 && a3 == 0) || v2_recv_range_ok((uintptr_t)a2, a3)))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                /* Tear down all user mappings and reclaim their frames.
                 * Snapshot first (teardown mutates later aliasing slots).
                 * Shared-with-sibling frames (COW fork child) are unmapped
                 * on our side only and NOT freed — a system-wide release
                 * here would destroy the sibling's live mappings. */
                unsigned long exec_frames[V2_VPN_SLOTS];
                int exec_nframes = 0;
                for (int i = 0; i < V2_VPN_SLOTS; i++)
                {
                    if (caps.vm[cur][i].valid)
                        exec_frames[exec_nframes++] = caps.vm[cur][i].frame;
                }
                for (int i = 0; i < exec_nframes; i++)
                    frame_teardown_owned((unsigned long)cur, exec_frames[i]);
                v2_sfence_all();
                /* Clear user caps (slots 0..V2_CAP_SLOTS-1, keep root caps) */
                for (int s = 0; s < V2_CAP_SLOTS; s++)
                {
                    if (!caps.caps[cur][s].root)
                        caps.caps[cur][s].valid = 0;
                }
                /* Load new ELF into current VSpace */
                {
                    uint64_t entry = 0, brk = 0;
                    rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)cur, &entry, &brk);
                    if (rc == V2_OK && entry != 0)
                    {
                        v2_pte_sync((unsigned long)cur);
                        threads[cur].regs[2] = u_sp[cur];
                        threads[cur].sepc = entry;
                        /* Reset registers to clean state */
                        for (int r = 0; r < 32; r++)
                            threads[cur].regs[r] = 0;
                        threads[cur].regs[2] = u_sp[cur];
                        rc = 0; /* return 0 on success */
                    }
                    else if (rc == V2_OK)
                    {
                        rc = V2_ERR_INVALID;
                    }
                }
                break;
            }
            case V2_INV_WRITE: {
                /* WRITE (a1=vpn, a2=u_src): one 8-byte word. Range-check +
                 * copy the user word into a kernel temp, run the model
                 * write on fdata (rights gate + shadow), then — only on
                 * V2_OK — store that same word into the real frame PA
                 * (Write-Through Mirror: real memory and fdata stay
                 * identical). FAIL CLOSED: real memory is never touched
                 * on model error. */
                uint64_t kbuf[1];
                if (a1 >= (uint64_t)V2_VPN_SLOTS)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (!v2_send_range_ok((uintptr_t)a2, 1))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                u_copy_in(kbuf, (uintptr_t)a2, 1);
                rc = v2_write(&caps, (unsigned long)cur, a1, kbuf[0]);
                if (rc == V2_OK)
                {
                    int m = v2_vm_find(&caps, (unsigned long)cur, a1);
                    if (m >= 0) /* model wrote it: mapping must be findable */
                        v2_real_write(caps.vm[cur][m].frame, (const uint8_t *)kbuf, V2_WORD_BYTES);
                }
                break;
            }
            case V2_INV_READ: {
                /* READ (a1=vpn, a2=u_dst): mirror of WRITE. Run the model
                 * read first (rights gate + shadow), then — only on V2_OK —
                 * load the real 8-byte word from the frame PA into a kernel
                 * temp and copy it out to the validated user destination.
                 * FAIL CLOSED: the user destination is touched only on
                 * model + range success. */
                uint64_t kbuf[1];
                if (a1 >= (uint64_t)V2_VPN_SLOTS)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (!v2_recv_range_ok((uintptr_t)a2, 1))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                rc = v2_read(&caps, (unsigned long)cur, a1, &kbuf[0]);
                if (rc == V2_OK)
                {
                    int m = v2_vm_find(&caps, (unsigned long)cur, a1);
                    if (m < 0)
                    { /* model read succeeded: must be findable */
                        rc = V2_ERR_INVALID;
                        break;
                    }
                    v2_real_read(caps.vm[cur][m].frame, (uint8_t *)kbuf, V2_WORD_BYTES);
                    u_copy_out((uintptr_t)a2, kbuf, 1);
                }
                break;
            }
            case V2_INV_QCREATE: {
                /* QCREATE (a1=initrd index, a2/a3 reserved=0): new thread
                 * in a fresh qube label. Mirrors SPAWN's slot setup, then
                 * stamps the fresh label. FAIL CLOSED: any validation
                 * error -> V2_ERR_INVALID/OVERFLOW with no partial state. */
                const uint8_t *elf_data;
                uint32_t elf_size;
                uint64_t entry = 0, brk = 0;
                int child = -1;
                if (!(a2 == 0 && a3 == 0))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (qube_next >= (unsigned long)V2_QUBES_MAX)
                {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                for (int t = 0; t < NTHREADS; t++)
                { /* bound: NTHREADS */
                    /* deferred-C: T_DEAD is distinct; state alone frees the slot */
                    if (threads[t].state == T_DEAD)
                    {
                        child = t;
                        break;
                    }
                }
                if (child < 0)
                {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                /* A reused slot may hold a previous life's caps/mappings:
                 * reclaim frames first (same leak SPAWN-reuse had), then
                 * clear so the load starts fresh (fail closed). Shared
                 * frames are spared by teardown_owned. */
                {
                    unsigned long qc_frames[V2_VPN_SLOTS + V2_CAP_SLOTS];
                    int qc_n = 0;
                    for (int i = 0; i < V2_VPN_SLOTS; i++)
                    {
                        if (caps.vm[child][i].valid)
                            qc_frames[qc_n++] = caps.vm[child][i].frame;
                    }
                    for (int s = 0; s < V2_CAP_SLOTS; s++)
                    {
                        if (caps.caps[child][s].valid && !caps.caps[child][s].root)
                            qc_frames[qc_n++] = caps.caps[child][s].obj;
                    }
                    for (int i = 0; i < qc_n; i++)
                        frame_teardown_owned((unsigned long)child, qc_frames[i]);
                }
                for (int s = 0; s < V2_CAP_SLOTS; s++) /* bound: V2_CAP_SLOTS */
                    caps.caps[child][s].valid = 0;
                for (int i = 0; i < V2_VPN_SLOTS; i++) /* bound: V2_VPN_SLOTS */
                    caps.vm[child][i].valid = 0;
                {
                    unsigned long child_root = build_child_vspace((unsigned long)cur, (unsigned long)child);
                    if (!child_root)
                    {
                        rc = V2_ERR_OVERFLOW;
                        break;
                    }
                    threads[child].vspace_root_ppn = child_root;
                }
                /* Fresh IPC/notify state: a reused slot must not inherit
                 * the previous life's blocked sends or pending signals. */
                threads[child].ipc_ptr = 0;
                threads[child].ipc_cap = 0;
                threads[child].notify = 0;
                threads[child].wait_kind = V2_WK_NONE;
                /* Fresh registers: no stale-word leak into the new image. */
                for (int r = 0; r < 32; r++) /* bound: 32 */
                    threads[child].regs[r] = 0;
                rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)child, &entry, &brk);
                if (rc == V2_OK && entry != 0)
                {
                    threads[child].state = T_RUNNABLE;
                    v2_pte_sync((unsigned long)child);
                    threads[child].regs[2] = u_sp[child];
                    threads[child].sepc = entry;
                    qube_of[child] = (uint8_t)qube_next++;
                    kputs("QUB: qube");
                    kputdec((unsigned long)qube_of[child]);
                    kputs(" up\n");
                    rc = V2_OK;
                }
                else
                {
                    threads[child].state = T_DEAD; /* cleanup on failure */
                    if (rc == V2_OK)
                        rc = V2_ERR_INVALID;
                }
                break;
            }
            case V2_INV_QDESTROY: {
                /* QDESTROY (a1=label, a2/a3 reserved=0): park every thread
                 * in the qube, drop their queued IPC, revoke-drain their
                 * caps + clear hardware PTEs, reclaim unshared frames.
                 * Label 0 (base system) can never be destroyed. FAIL CLOSED.
                 * POLICY (deliberate, not an oversight):
                 * - No caller-authority check: V2 has no privilege levels.
                 *   QCREATE/QDESTROY/SPAWN are all unprivileged by design;
                 *   isolation comes from qube labels on the data plane,
                 *   management is cooperative. Revisit if threat model grows.
                 * - Live BLOCKED survivors stay blocked: a live SENDer queued
                 *   for a dead waiter (or RECV waiter for dead senders) keeps
                 *   T_BLOCKED with its queue entry intact. Waking them with
                 *   an error would break open-ended rendezvous (a future
                 *   peer may still arrive), so park-forever is the policy
                 *   until timeouts/cancellation land. */
                unsigned long label = (unsigned long)a1;
                int found = 0;
                if (!(a2 == 0 && a3 == 0))
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (label == 0 || label >= (unsigned long)V2_QUBES_MAX)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                for (int t = 0; t < NTHREADS; t++)
                { /* bound: NTHREADS */
                    if (qube_of[t] == (uint8_t)label)
                        found = 1;
                }
                if (!found)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                /* Drop queued IPC entries owned by the qube (compact both
                 * queues in place; other qubes' entries are preserved). */
                {
                    for (int e = 0; e < V2_NEP; e++)
                    { /* bound: V2_NEP (11) */
                        v2_ep_t *ep = &eps[e];
                        int w = 0;
                        for (int i = 0; i < ep->send_len; i++)
                        { /* bound: V2_IPC_Q */
                            int idx = (ep->send_head + i) % V2_IPC_Q;
                            unsigned long s = ep->sendq[idx].sender;
                            if (s < (unsigned long)NTHREADS && qube_of[s] == (uint8_t)label)
                                continue; /* drop: sender dies below */
                            if (w != i)
                            {
                                int dst = (ep->send_head + w) % V2_IPC_Q;
                                ep->sendq[dst] = ep->sendq[idx];
                            }
                            w++;
                        }
                        ep->send_len = w;
                        w = 0;
                        for (int i = 0; i < ep->recv_len; i++)
                        { /* bound: V2_IPC_Q */
                            int idx = (ep->recv_head + i) % V2_IPC_Q;
                            unsigned long tid = ep->recvq[idx];
                            if (tid < (unsigned long)NTHREADS && qube_of[tid] == (uint8_t)label)
                                continue; /* drop: waiter dies below */
                            if (w != i)
                            {
                                int dst = (ep->recv_head + w) % V2_IPC_Q;
                                ep->recvq[dst] = ep->recvq[idx];
                            }
                            w++;
                        }
                        ep->recv_len = w;
                    }
                }
                /* Tear down each dying thread via frame_teardown_owned:
                 * SHARED frames (COW sibling in a live qube) lose only the
                 * dead side — the old code called v2_revoke per slot,
                 * which is system-wide and destroyed live siblings'
                 * mappings before the live-check could see them (then freed
                 * under their stale PTEs). UNSHARED frames are fully
                 * revoked + scrubbed + freed (no QCREATE/QDESTROY pool
                 * leak). Dead co-owners resolve by processing order. */
                for (int t = 0; t < NTHREADS; t++)
                { /* bound: NTHREADS */
                    unsigned long dying_frames[V2_VPN_SLOTS + V2_CAP_SLOTS];
                    int dying_n = 0;
                    int s;
                    if (qube_of[t] != (uint8_t)label)
                        continue;
                    /* Snapshot every frame this thread names (mappings +
                     * caps; teardown is idempotent so no dedupe needed). */
                    for (int i = 0; i < V2_VPN_SLOTS; i++)
                    { /* bound: V2_VPN_SLOTS */
                        if (caps.vm[t][i].valid)
                            dying_frames[dying_n++] = caps.vm[t][i].frame;
                    }
                    for (s = 0; s < V2_CAP_SLOTS; s++)
                    { /* bound: V2_CAP_SLOTS */
                        if (caps.caps[t][s].valid && !caps.caps[t][s].root)
                            dying_frames[dying_n++] = caps.caps[t][s].obj;
                    }
                    for (int i = 0; i < dying_n; i++)
                        frame_teardown_owned((unsigned long)t, dying_frames[i]);
                    for (int vpn = 0; vpn < V2_VPN_SLOTS; vpn++) /* bound: V2_VPN_SLOTS */
                        v2_pte_clear((unsigned long)t, (unsigned long)vpn);
                    threads[t].state = T_DEAD;
                    threads[t].wait_kind = V2_WK_NONE;
                    threads[t].ipc_ptr = 0;
                    threads[t].ipc_cap = 0;
                    threads[t].notify = 0;
                    qube_of[t] = 0;
                }
                v2_sfence_all();
                kputs("QUB: qube");
                kputdec(label);
                kputs(" dead\n");
                rc = V2_OK;
                break;
            }
            case V2_INV_FRAME_PA: {
                /* FRAME_PA (a1=vpn, a2/a3 reserved=0): return the physical
                 * address of the frame mapped at vpn in the caller's VSpace.
                 * Pure address math (V2_FRAME_PHYS_BASE + frame*4096): no
                 * state change, no copy. Miss or nonzero reserved -> INVALID. */
                int m; /* bound: V2_VPN_SLOTS (v2_vm_find scan) */
                if (a2 != 0 || a3 != 0)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                m = v2_vm_find(&caps, (unsigned long)cur, a1);
                if (m < 0)
                {
                    rc = V2_ERR_INVALID;
                    break;
                }
                rc = (long)(V2_FRAME_PHYS_BASE + caps.vm[cur][m].frame * 4096UL);
                break;
            }
            default:
                rc = V2_ERR_INVALID;
                break;
            }
            threads[cur].regs[10] = (uint64_t)rc;
            klog("[invoke] tcb=");
            klog_char('0' + cur);
            klog(" op=");
            klog_dec(op);
            klog(" rc=");
            klog_dec((unsigned long)rc);
            klog_char('\n');
            return;
        }
        threads[cur].sepc += 4;
        return;
    }
    case 9: /* S-mode ecall: our own SBI calls return via M, never here. */
        threads[cur].sepc += 4;
        return;
    case 13:   /* Load page fault */
    case 15: { /* Store page fault: may be a COW break */
        uint64_t fault_addr;
        asm volatile("csrr %0, stval" : "=r"(fault_addr));
        /* COW break, S-mode authority rule: the caps model is the ONLY
         * authority. A store fault inside the frame window whose model
         * mapping still carries W is a COW share (hardware PTE is R-only
         * after v2_cow_write_protect); anything else — RX execute page,
         * R-only data, unmapped address — falls through to containment.
         * PTE bits are never trusted as COW flags, so this cannot
         * misclassify a legitimate RX page. */
        if (code == 15 && fault_addr >= V2_U_END && fault_addr < V2_U_END + (uint64_t)V2_VPN_SLOTS * 4096UL)
        {
            unsigned long t = (unsigned long)cur;
            unsigned long vpn = (unsigned long)((fault_addr - V2_U_END) >> 12);
            int m = v2_vm_find(&caps, t, vpn);
            if (m >= 0 && (caps.vm[t][m].rights & V2_RIGHT_W))
            {
                unsigned long old_frame = caps.vm[t][m].frame;
                int new_frame = frame_alloc();
                if (new_frame >= 0 && old_frame != 0 && old_frame < (unsigned long)V2_FRAMES_MAX)
                {
                    /* Copy via physical addresses (S-mode, SUM=0: the
                     * faulting U VA is NOT dereferenced). */
                    volatile uint64_t *dst = (volatile uint64_t *)(V2_FRAME_PHYS_BASE + (uintptr_t)new_frame * 4096);
                    const volatile uint64_t *src =
                        (const volatile uint64_t *)(V2_FRAME_PHYS_BASE + (uintptr_t)old_frame * 4096);
                    for (int i = 0; i < 512; i++) /* bound: 4096/8 */
                        dst[i] = src[i];
                    /* The word-model shadow follows the break so later
                     * WRITE/READ word ops stay coherent with real memory. */
                    caps.fdata[new_frame] = caps.fdata[old_frame];
                    /* The new frame needs a cap: WITHOUT it v2_find_wcap
                     * fails and every later word op on this vpn returns
                     * INVALID (and fork children inherit the capless
                     * mapping). Table-full fails closed like exhaustion:
                     * give the frame back, fall through to park. */
                    if (frame_mint_slot(&caps, t, (unsigned long)new_frame) < 0)
                    {
                        /* Table full: give the frame back and fall through
                         * to default below (park offender). No break here:
                         * break would exit the switch past default and
                         * resume the faulting store into a fault loop. */
                        frame_free(new_frame);
                    }
                    else
                    {
                        caps.vm[t][m].frame = (unsigned long)new_frame;
                        /* Reinstall THIS thread's PTE only (the other sharer
                         * keeps its R-only PTE until it faults in turn). */
                        v2_pte_install(t, vpn, (unsigned long)new_frame, caps.vm[t][m].rights);
                        v2_sfence_all();
                        return; /* Resume the faulting store */
                    }
                }
            }
            /* Not a COW share (or no frame left) - fall through to default */
        }
    } /* close case 15 block: execution falls through to default */
    default: { /* fault: park the offender, keep the rest running */
        uint64_t fva;
        asm volatile("csrr %0, stval" : "=r"(fva));
        kputs("[fault] tcb=");
        sbi_putchar('0' + cur);
        kputs(" cause=");
        sbi_putchar('0' + (char)(code & 0xF));
        kputs(" epc=");
        for (int b = 60; b >= 0; b -= 4) {
            uint8_t d = (threads[cur].sepc >> b) & 0xF;
            sbi_putchar(d < 10 ? '0' + d : 'a' + d - 10);
        }
        kputs(" addr=");
        for (int b = 60; b >= 0; b -= 4) {
            uint8_t d = (fva >> b) & 0xF;
            sbi_putchar(d < 10 ? '0' + d : 'a' + d - 10);
        }
        kputs("\n parked; others continue\n");
        threads[cur].state = T_PARKED;
        int n = pick_next();
        if (n < 0)
            halt_no_runnable();
        enter_thread(n);
    }
    }
}
