/* sched.c - thread table, scheduler, kernel object state (SRP: scheduling).
 *
 * Split out of kboot.c (SOLID Sprint 1). Owns the runnable state machine
 * and the tick preemption policy. */
#include <stdint.h>

#include "caps.h"
#include "ipc.h"
#include "kinternal.h"

uctx_t threads[NTHREADS];
uint8_t qube_of[NTHREADS];   /* qube label per thread (qube.h) */
unsigned long qube_next = 2; /* next fresh label; 0/1 taken at boot */
int cur = 0;
unsigned long tick __attribute__((unused)) = 0; /* Timer ticks (debug only) */

v2_ep_t eps[V2_NEP];
_Static_assert(V2_NEP <= V2_CAP_THREADS, "endpoint count rides the thread cap (EP i owned by tid i)");
v2_caps_t caps;

uctx_t *cur_ctx; /* read by trap.S */
uintptr_t trap_stack_top;

/* S4c live input (Task 4): post-halt IRQ traps must not save over a live
 * thread. The trap entry stores into cur_ctx unconditionally, but in halt
 * cur is a stale victim (its regs hold that thread's BLOCKED resume
 * state) — saving halt regs there would destroy it, and the woken thread
 * could never resume. So halt points cur_ctx here (cur itself stays a
 * valid tid: fault paths index threads[cur]). Zero-init BSS, written
 * only by trap entry from halt. */
uctx_t halt_ctx;

uint8_t kstack[16384] __attribute__((aligned(16)));
uint8_t *kstack_top = kstack + sizeof(kstack);
uint8_t trap_stack[4096] __attribute__((aligned(16)));

uint64_t u_sp[NTHREADS]; /* stashed pre-MMU: S must not read U pages */

int pick_next(void)
{
    for (int offset = 1; offset <= NTHREADS; offset++)
    { /* bound: NTHREADS */
        int i = (cur + offset) % NTHREADS;
        if (threads[i].state == T_RUNNABLE)
            return i;
    }
    return -1;
}

void enter_thread(int id)
{
    uint64_t active_satp;
    uint64_t target_satp = threads[id].vspace_root_ppn;
    cur = id;
    cur_ctx = &threads[id];
    /* Same-thread preemption/yield keeps its translations; flush only on
     * an actual address-space switch. Mapping changes fence at their sites. */
    asm volatile("csrr %0, satp" : "=r"(active_satp));
    if (active_satp != target_satp)
    {
        asm volatile("csrw satp, %0" ::"r"(target_satp) : "memory");
        asm volatile("sfence.vma" ::: "memory");
    }
    u_enter(&threads[id]);
    __builtin_unreachable();
}

/* Terminal park: nothing runnable and nothing can make progress: parked
 * threads never wake; blocked threads wake only via a matching IPC op,
 * which requires a runnable peer. (No timeout yet: Stage 4 time.) */
void halt_no_runnable(void)
{
    kputs("no runnable left; parking cpu\n");
    for (int t = 0; t < NTHREADS; t++) {
        sbi_putchar(' '); sbi_putchar(' ');
        sbi_putchar('t'); sbi_putchar('=');
        sbi_putchar('0' + t);
        sbi_putchar(' '); sbi_putchar('s'); sbi_putchar('=');
        sbi_putchar('0' + threads[t].state);
        sbi_putchar(' '); sbi_putchar('w'); sbi_putchar('=');
        sbi_putchar('0' + threads[t].wait_kind);
        sbi_putchar('\n');
    }
    /* Park-timer hygiene: the periodic tick is still armed, so a pending
     * timer would wake WFI, print "[tick ...]" spam after the marker, and
     * re-arm (repeating forever). Push stimecmp to the end of time and
     * clear STIE BEFORE the loop so the marker prints exactly once and
     * the CPU truly parks. */
    sbi_set_timer(~0UL);
    asm volatile("csrc sie, %0" ::"r"(1UL << 5) : "memory"); /* clear STIE */
    /* S4c live input (Task 4): traps clear sstatus.SIE on entry, so a halt
     * reached from any trap context parks with SIE=0 — post-park IRQs
     * (input) would pend forever with no trap and no wake. Re-enable SIE
     * so WFI still traps (STIE stays cleared + timer maxed: no tick spam,
     * marker still prints once per entry). Point cur_ctx at the halt
     * save area (never a live thread: entry would clobber its BLOCKED
     * resume state) and sscratch at the trap stack (stale user-sp would
     * fault the entry store under SUM=0). */
    asm volatile("csrs sstatus, %0" ::"r"(1UL << 1) : "memory"); /* SIE */
    cur_ctx = &halt_ctx;
    asm volatile("csrw sscratch, %0" ::"r"(trap_stack_top) : "memory");
    for (;;)
        asm volatile("wfi");
    __builtin_unreachable();
}

/* sched_tick: S-mode timer preemption (S-mode timer). Guard: a timer
 * interrupt during halt must never return (would corrupt kernel state
 * via the trap.S epilogue with zeroed sepc/sp). */
void sched_tick(void)
{
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
}
