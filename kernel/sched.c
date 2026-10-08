/* sched.c - thread table, scheduler, kernel object state (SRP: scheduling).
 *
 * Split out of kboot.c (SOLID Sprint 1). Owns the runnable state machine
 * and the tick preemption policy. */
#include <stdint.h>

#include "caps.h"
#include "ipc.h"
#include "ipc_deadlock.h"
#include "ipc_flow_control.h"
#include "kernel_monitor.h"
#include "kinternal.h"

/* Note: kinternal.h provides SIE_MASK_STIE and SIE_MASK_STIE_SEIE for interrupt control */

uctx_t threads[NTHREADS];
uint8_t qube_of[NTHREADS];   /* qube label per thread (qube.h) */
unsigned long qube_next = 2; /* next fresh label; 0/1 taken at boot */
int cur = 0;
unsigned long tick __attribute__((unused)) = 0; /* Timer ticks (debug only) */

/* Scheduler statistics for fairness monitoring (exported: kinternal.h). */
unsigned long sched_ticks[NTHREADS];         /* Ticks each thread has run */
unsigned long sched_switches_total = 0;      /* Total context switches */
unsigned long sched_switches_voluntary = 0;  /* Yield-induced switches */
unsigned long sched_switches_preemptive = 0; /* Timer-induced switches */

v2_ep_t eps[V2_NEP];
_Static_assert(V2_NEP <= V2_CAP_THREADS,
               "endpoint count rides the thread cap (EP i owned by tid i)");
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
#if KERNEL_MONITOR_ENABLED
    /* No runnable threads - potential deadlock or idle state */
    kernel_monitor_op_failure(KERNEL_SUBSYS_SCHED, KERNEL_ERROR_OTHER);
#endif
    return -1;
}

__attribute__((noreturn)) void enter_thread(int id)
{
    uint64_t active_satp;
    uint64_t target_satp = threads[id].vspace_root_ppn;
#if KERNEL_MONITOR_ENABLED
    uint64_t start = kernel_monitor_op_start(KERNEL_SUBSYS_SCHED);
#endif
    cur = id;
    cur_ctx = &threads[id];
    sched_ticks[id]++;
    sched_switches_total++;
    /* Same-thread preemption/yield keeps its translations; flush only on
     * an actual address-space switch. Mapping changes fence at their sites. */
    asm volatile("csrr %0, satp" : "=r"(active_satp));
    if (active_satp != target_satp)
    {
        asm volatile("csrw satp, %0" ::"r"(target_satp) : "memory");
        asm volatile("sfence.vma" ::: "memory");
    }
#if KERNEL_MONITOR_ENABLED
    kernel_monitor_op_end(KERNEL_SUBSYS_SCHED, start, 1);
#endif
    u_enter(&threads[id]);
    __builtin_unreachable();
}

/* Terminal park: nothing runnable and nothing can make progress: parked
 * threads never wake; blocked threads wake only via a matching IPC op,
 * which requires a runnable peer. (No timeout yet: Stage 4 time.) */
__attribute__((noreturn)) void halt_no_runnable(void)
{
    /* TEMP-DIAG (input-death hunt): report interrupt-mask state at halt.
     * sie should read 0x220 minus STIE (timer parked); SEIE must stay set
     * or no external IRQ can ever wake us again. */
    uint64_t sie_v = 0, sip_v = 0, sst_v = 0, sepc_v = 0, stvec_v = 0, satp_v = 0;
    asm volatile("csrr %0, sie" : "=r"(sie_v));
    asm volatile("csrr %0, sip" : "=r"(sip_v));
    asm volatile("csrr %0, sstatus" : "=r"(sst_v));
    asm volatile("csrr %0, sepc" : "=r"(sepc_v));
    asm volatile("csrr %0, stvec" : "=r"(stvec_v));
    asm volatile("csrr %0, satp" : "=r"(satp_v));
    kputs("no runnable left; parking cpu sie=");
    kputhex(sie_v);
    kputs(" sip=");
    kputhex(sip_v);
    kputs(" sstatus=");
    kputhex(sst_v);
    kputs(" sepc=");
    kputhex(sepc_v);
    kputs(" stvec=");
    kputhex(stvec_v);
    kputs(" satp=");
    kputhex(satp_v);
    kputs("\n");
    for (int t = 0; t < NTHREADS; t++)
    {
        sbi_putchar(' ');
        sbi_putchar(' ');
        sbi_putchar('t');
        sbi_putchar('=');
        sbi_putchar('0' + t);
        sbi_putchar(' ');
        sbi_putchar('s');
        sbi_putchar('=');
        sbi_putchar('0' + threads[t].state);
        sbi_putchar(' ');
        sbi_putchar('w');
        sbi_putchar('=');
        sbi_putchar('0' + threads[t].wait_kind);
        sbi_putchar(' ');
        sbi_putchar('q');
        sbi_putchar('=');
        kputdec((unsigned long)(t < V2_NEP ? eps[t].send_len : 0));
        sbi_putchar('\n');
    }
    /* SIE watchdog (input-death mitigation): SEIE must be set at park
     * or no external IRQ can ever wake WFI. If a prior critical section
     * leaked SEIE-clear (e.g. mismatched csrc/csrs masks), count it,
     * report, and repair so the hart stays reachable. This must fire
     * zero times on a healthy tree; any print here is a pairing bug. */
    {
        static unsigned long sie_watchdog_repairs = 0;
        if ((sie_v & SIE_MASK_SEIE) == 0)
        {
            sie_watchdog_repairs++;
            kputs("HALT-WDOG: SEIE clear at park, repairing n=");
            kputdec(sie_watchdog_repairs);
            kputs(" entry sie=");
            kputhex(sie_v);
            kputs("\n");
            asm volatile("csrs sie, %0" ::"r"(SIE_MASK_SEIE) : "memory");
        }
    }
    /* Park-timer hygiene: the periodic tick is still armed, so a pending
     * timer would wake WFI, print "[tick ...]" spam after the marker, and
     * re-arm (repeating forever). Push stimecmp to the end of time and
     * clear STIE BEFORE the loop so the marker prints exactly once and
     * the CPU truly parks.
     *
     * NOTE: We only clear STIE (timer), NOT SEIE (external IRQs). This
     * allows virtio IRQs (input, net, blk) to wake the CPU from halt
     * via the trap path. The pattern is:
     *   - SIE_MASK_STIE_SEIE: full disable for atomic sections (IPC, IRQ wake)
     *   - SIE_MASK_STIE only: timer-only disable (halt context, keep external IRQs) */
    sbi_set_timer(~0UL);
    asm volatile("csrc sie, %0" ::"r"(SIE_MASK_STIE)
                 : "memory"); /* clear STIE only, keep SEIE for IRQ wake */
    /* S4c live input (Task 4): traps clear sstatus.SIE on entry, so a halt
     * reached from any trap context parks with SIE=0 — post-park IRQs
     * (input) would pend forever with no trap and no wake. Re-enable SIE
     * so WFI still traps (STIE stays cleared + timer maxed: no tick spam,
     * marker still prints once per entry). Point cur_ctx at the halt
     * save area (never a live thread: entry would clobber its BLOCKED
     * resume state) and sscratch at the trap stack (stale user-sp would
     * fault the entry store under SUM=0).
     *
     * ORDER MATTERS (burst-race fix): set cur_ctx and sscratch BEFORE
     * enabling SIE. When halt runs, sscratch still holds the outer user
     * sp (the trap that led here swapped it in). If an input IRQ fires
     * after SIE is set but before sscratch is repaired, the trap entry
     * swaps sp into that U value and its first store faults under SUM=0
     * (stval=U addr, epc=trap-entry sd) — the burst-typing fault loop.
     * SIE is therefore the LAST thing enabled. */
    cur_ctx = &halt_ctx;
    asm volatile("csrw sscratch, %0" ::"r"(trap_stack_top) : "memory");
    asm volatile("csrs sstatus, %0" ::"r"(1UL << 1) : "memory"); /* SIE */
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
    /* Observability/health clocks ride the one periodic event the kernel
     * already has. All three are O(1) or O(V2_NEP) with no allocation or
     * blocking, so they are safe on the trap path (no nested trap). */
    kernel_monitor_tick();   /* kernel uptime + per-subsystem clock */
    ipc_deadlock_tick();     /* wait-for graph clock (deadlock timeouts) */
    ipc_flow_control_tick(); /* adaptive threshold / backpressure timeout */
    /* Timer preemption: rotate from the current TID so runnable
     * peers receive a turn before this thread is selected again. */
#if KERNEL_MONITOR_ENABLED
    sched_switches_preemptive++;
#endif
    int n = pick_next();
    if (n < 0)
        halt_no_runnable();
    enter_thread(n);
}
