/* syscall.c - trap prologue + ecall/INVOKE dispatch (SRP: syscall core).
 *
 * Split out of kboot.c (SOLID Sprint 1), operation classes factored to
 * syscall_ipc/cap/mem/proc/qube.c (Sprint 1b, production-ready). */
#include <stdint.h>

#include "caps.h"
#include "ipc.h"
#include "kinternal.h"

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
            sched_tick();
        if (code == 9)
        {
            irq_trap();
            return; /* routed (possibly spuriously); resume interrupted thread */
        }
        /* Stray interrupt: fail soft, never wedge. The only plausible
         * S-mode codes here are software (1, e.g. a stale firmware IPI —
         * the kernel never uses SSIP) or spurious arrivals; both are
         * transient, so clear-and-resume keeps the system alive. A
         * level-stuck source re-traps and re-prints here instead of
         * silently parking — diagnosable, and no worse than a wedge.
         * The code rides along so the next hunt starts with evidence. */
        if (code == 1)
            asm volatile("csrc sip, %0" ::"r"(2UL) : "memory"); /* clear SSIP */
        kputs("[trap] stray interrupt code=");
        kputhex(code);
        kputs(" sepc=");
        kputhex(threads[cur].sepc);
        kputs(" resumed\n");
        return;
    }
    switch (code)
    {
    case 8: {                                 /* U-mode ecall */
        uint64_t sys = threads[cur].regs[17]; /* a7 */
        if (sys == V2_YIELD)
        {
            sys_yield();
            return;
        }
        else if (sys == V2_PUTC)
        {
            sys_putc();
            return;
        }
        else if (sys == V2_PARK)
        {
            sys_park();
            return;
        }
        else if (sys == V2_SEND)
        {
            sys_send();
            return;
        }
        else if (sys == V2_RECV)
        {
            sys_recv();
            return;
        }
        else if (sys == V2_NOTIFY)
        {
            sys_notify();
            return;
        }
        else if (sys == V2_WAIT)
        {
            sys_wait();
            return;
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
            /* Disjoint op classes (handles() guards); unknown ops keep
             * the INVALID default, matching the old single switch. */
            if (syscall_cap_handles(op))
                rc = syscall_cap_invoke(op, a1, a2, a3);
            else if (syscall_mem_handles(op))
                rc = syscall_mem_invoke(op, a1, a2, a3);
            else if (syscall_proc_handles(op))
                rc = syscall_proc_invoke(op, a1, a2, a3);
            else if (syscall_qube_handles(op))
                rc = syscall_qube_invoke(op, a1, a2, a3);
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
