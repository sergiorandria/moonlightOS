#pragma once
#include "types.h"
#include "cap.h"
#include "syscall.h" /* trap_frame_t for timer_handler */
#include <stdbool.h>

#define MAJOR_FRAME_US 10000  /* 10ms major frame */
#define MAX_SCHED_CONTEXTS 64
#define NSEC_PER_USEC 1000

/* Preemption quantum in rdtime ticks. QEMU virt mtime runs anywhere from
 * the spec 10MHz to 100MHz+ depending on build/host, so no tick count maps
 * to wall time portably: 100k ticks ~= 10ms @10MHz, ~1ms @100MHz. Either way
 * several quanta fit in a thread period while handler cost (~ms-scale TCG
 * work per IRQ) stays in the low single-digit percents. A 1k slice saturated
 * a fast mtime (160k IRQ/s); do not go back below ~10k without measuring. */
#define TIMER_SLICE_TICKS 100000u
extern uint64_t g_timer_ticks; /* timer IRQs serviced (ps footer proof) */
extern uint32_t g_trap_total;  /* trap entries (trap.S) */
extern uint32_t g_trap_ecall;  /* ecall-path entries */
extern uint32_t g_trap_irq;    /* irq-path entries (ack + maybe switch) */
extern uint32_t g_sched_ticks; /* sched_tick calls */
extern uint32_t g_replenish;   /* budget replenishes */
extern uint32_t g_putc_shell;  /* PUTC from shell (TCB_NONE) */
extern uint32_t g_putc_thread; /* PUTC from dispatched threads */
extern uint32_t g_yield_shell; /* YIELD from shell */
extern uint32_t g_yield_thread;/* YIELD from dispatched threads */
extern uint32_t g_loop_iter[8]; /* full user-loop iterations per tid */

/* No thread on hart (shell/idle): trap passes this as cur_tcb, and the
 * dispatcher parks here when nothing is picked. */
#define TCB_NONE 0xFFFFFFFFu
extern uint32_t g_current_tcb;

/* Time partition - ARINC-653 style, statically verified */
typedef struct {
    uint32_t id;
    const char *name;
    uint64_t offset_us;   /* offset in major frame */
    uint64_t budget_us;   /* budget in major frame */
    uint64_t used_us;
    uint8_t  criticality; /* 0 lowest .. 3 highest */
    uint16_t color_base;  /* cache color base for isolation */
    bool     active;
} time_partition_t;

/* Scheduling context - EDF + Fixed Priority within partition */
typedef struct {
    bool     bound;
    uint32_t tcb_id;
    uint32_t partition_id;
    uint64_t budget_us;   /* WCET budget */
    uint64_t period_us;   /* period */
    uint64_t remaining_us;
    uint64_t deadline;    /* absolute deadline ticks */
    uint8_t  priority;    /* 0..255, 0 highest */
    bool     is_realtime;
    uint64_t consumed_this_period;
} sched_context_t;

typedef struct {
    time_partition_t partitions[MAX_PARTITIONS];
    uint32_t num_partitions;
    uint64_t major_frame_start;
    uint32_t current_partition;
    sched_context_t contexts[MAX_SCHED_CONTEXTS];
    /* Ready hint: bit p of word (p/64) = some context MAY be pickable at
     * (this partition, prio p) on (bound, partition, priority, remaining).
     * SUPERSET ONLY: TCB-block transitions live in tcb.c/endpoint.c and do
     * not maintain this. pick_next verifies TCB-runnable in its final scan
     * and falls back to a full scan when the bitmap yields nothing, so the
     * bitmap is a pure optimization that cannot change results. Bit set on
     * bind/replenish; cleared lazily on empty scan or eagerly on unbind. */
    uint64_t ready_bits[MAX_PARTITIONS][4];
} sched_state_t;

void sched_init(sched_state_t *s);
kerror_t sched_partition_create(sched_state_t *s, uint32_t id, uint64_t offset, uint64_t budget, uint8_t crit);
kerror_t sched_context_bind(sched_state_t *s, uint32_t sc_id, uint32_t tcb_id, uint32_t part_id, uint64_t budget, uint64_t period, uint8_t prio);
void sched_context_unbind(sched_state_t *s, uint32_t sc_id); /* centralizes bound=false + bit fixup */
/* Change a bound context's priority (moonsh `nice`): fixes both bitmap bits
 * and mirrors the TCB copy. Budgets/deadlines are untouched. */
kerror_t sched_context_set_prio(sched_state_t *s, uint32_t sc_id, uint8_t prio);
void sched_tick(sched_state_t *s, uint64_t now_us);
uint32_t sched_pick_next(sched_state_t *s, uint64_t now_us);
bool sched_is_schedulable(sched_state_t *s); /* EDF utilization test proven in Isabelle */
void sched_flush_partition(sched_state_t *s, uint32_t old_part);
/* Charge elapsed rdtime ticks to a context (cooperative accounting: called
 * on every thread yield-back; exhausted contexts are skipped by pick_next
 * until sched_tick replenishes them). Saturates at 0, NULL/!bound safe. */
void sched_consume(sched_context_t *sc, uint64_t elapsed_ticks);
/* Cooperative yield via snapshot resume (the live target path): snapshot the
 * caller, install the pick (thread, or shell every 8th pick), or keep the
 * caller when idle. Every trap completes (no mid-trap suspension), so trap
 * frames can never overlap suspended C frames.
 * sched_dispatch/sched_yield_back below stay only for host unit tests. */
void sched_coop_switch(trap_frame_t *frame, uint32_t cur);
/* Legacy cooperative dispatcher (host unit tests only, context_switch
 * stubbed; dead on RISC-V target for the reason above). */
void sched_dispatch(void);
/* Thread side of the yield handshake: charge this quantum, park back in the
 * dispatcher. Resumes here when re-picked (then returns into the trap). */
void sched_yield_back(void);
/* A thread function that returns lands here: park INACTIVE, yield forever. */
void thread_exit(void);
/* Machine-timer (CLINT MTIP) driver for preemption. timer_init maps nothing
 * (boot maps the CLINT) but programs the first compare + enables MTIE;
 * threads run with MIE set (trampoline + trap restore path), the shell and
 * boot stay masked. timer_handler runs in trap context with the preempted
 * thread's full frame: snapshot, charge one slice, resume the pick (or the
 * same thread). Never touches threads without a snapshot (fresh threads
 * start cooperatively). */
void timer_init(void);
void timer_handler(trap_frame_t *frame);
/* moonsh `ps` iterator (weak hook in shell): *cursor starts 0; each call
 * fills one row (or the trailing "next:" line) and returns 1, 0 when done. */
int moonsh_ps_line(char *buf, unsigned len, unsigned *cursor);
/* moonsh `nice` (weak hook in shell): retarget a live thread's priority.
 * long tid: huge inputs can never wrap into a live id (checked pre-cast).
 * Returns 0 ok, -1 no such thread, -2 bad priority (not 0..255). */
int moonsh_nice_tid(long tid, int prio);

/* WCET enforcement - kernel preemption point */
#define WCET_KERNEL_MAX_US 5
bool wcet_check(uint64_t entry_us);
