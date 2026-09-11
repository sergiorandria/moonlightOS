#include "../include/sched.h"
#include "../include/cheri.h"
#include "../include/tcb.h"
#include <string.h>
extern tcb_table_t g_tcbs;
extern sched_state_t g_sched; /* kernel table (boot.c); stubbed weak on host */

/* Trap census for `ps` (incremented in trap.S entry/paths). */
uint32_t g_trap_total;
uint32_t g_trap_ecall;
uint32_t g_trap_irq;
uint32_t g_sched_ticks;
uint32_t g_replenish;
/* Switch census: entries vs returns (a switch that never returns = park). */
uint32_t g_sw_yield_in;
uint32_t g_sw_yield_ret;
uint32_t g_sw_disp_in;
uint32_t g_sw_disp_ret;
/* Yield-entry cause census (stale-frame detector). */
uint32_t g_yield_cause11;
uint32_t g_yield_causeOther;
/* Full user-loop iterations per tid (proves progress past yield). */
uint32_t g_loop_iter[8];
/* Syscall-class census (handler): shell vs dispatched-thread putc/yield. */
uint32_t g_putc_shell;
uint32_t g_putc_thread;
uint32_t g_yield_shell;
uint32_t g_yield_thread;

void sched_init(sched_state_t *s) {
  memset(s, 0, sizeof(*s));
  s->major_frame_start = 0;
  s->current_partition = 0;
}

/* Bitmap helpers: bit p = word p/64, bit p%64. prio 0 (highest) = LSB. */
static inline void ready_set(sched_state_t *s, uint32_t part, uint8_t prio) {
    if (part < MAX_PARTITIONS)
        s->ready_bits[part][prio >> 6] |= 1ULL << (prio & 63);
}

static inline void ready_clear(sched_state_t *s, uint32_t part, uint8_t prio) {
    if (part < MAX_PARTITIONS)
        s->ready_bits[part][prio >> 6] &= ~(1ULL << (prio & 63));
}

/* Recompute one (partition, prio) bit by 64-scan. Used on unbind (rare). */
static void ready_recompute(sched_state_t *s, uint32_t part, uint8_t prio) {
    for (uint32_t i = 0; i < MAX_SCHED_CONTEXTS; i++) {
        sched_context_t *sc = &s->contexts[i];
        if (sc->bound && sc->partition_id == part &&
            sc->priority == prio && sc->remaining_us > 0) {
            ready_set(s, part, prio);
            return;
        }
    }
    ready_clear(s, part, prio);
}

kerror_t sched_partition_create(sched_state_t *s, uint32_t id, uint64_t offset,
                                uint64_t budget, uint8_t crit) {
  if (!s || id >= MAX_PARTITIONS)
    return ERR_INVALID_ARG;
  if (offset + budget > MAJOR_FRAME_US)
    return ERR_INVALID_ARG;
  /* No overlap check - complete mediation */
  for (uint32_t i = 0; i < s->num_partitions; i++) {
    uint64_t a = s->partitions[i].offset_us;
    uint64_t b = a + s->partitions[i].budget_us;
    uint64_t c = offset;
    uint64_t d = offset + budget;
    if (!(d <= a || c >= b))
      return ERR_INVALID_ARG;
  }
  s->partitions[id].id = id;
  s->partitions[id].offset_us = offset;
  s->partitions[id].budget_us = budget;
  s->partitions[id].criticality = crit;
  s->partitions[id].color_base = id * 2; /* 2 colors per partition, 16 total */
  s->partitions[id].active = true;
  if (id >= s->num_partitions)
    s->num_partitions = id + 1;
  return ERR_OK;
}

kerror_t sched_context_bind(sched_state_t *s, uint32_t sc_id, uint32_t tcb_id,
                            uint32_t part_id, uint64_t budget, uint64_t period,
                            uint8_t prio) {
  if (!s || sc_id >= MAX_SCHED_CONTEXTS)
    return ERR_INVALID_ARG;
  if (part_id >= MAX_PARTITIONS || !s->partitions[part_id].active)
    return ERR_INVALID_ARG;
  if (budget == 0 || period == 0 || budget > period)
    return ERR_INVALID_ARG;
  if (budget > s->partitions[part_id].budget_us)
    return ERR_INVALID_ARG;
  s->contexts[sc_id].bound = true;
  s->contexts[sc_id].tcb_id = tcb_id;
  s->contexts[sc_id].partition_id = part_id;
  s->contexts[sc_id].budget_us = budget;
  s->contexts[sc_id].period_us = period;
  s->contexts[sc_id].priority = prio;
  s->contexts[sc_id].remaining_us = budget;
  s->contexts[sc_id].deadline = period;
  ready_set(s, part_id, prio); /* newly bound with full budget: candidate */
  return ERR_OK;
}

void sched_context_unbind(sched_state_t *s, uint32_t sc_id) {
  if (!s || sc_id >= MAX_SCHED_CONTEXTS)
    return;
  uint32_t part = s->contexts[sc_id].partition_id;
  uint8_t prio = s->contexts[sc_id].priority;
  s->contexts[sc_id].bound = false;
  ready_recompute(s, part, prio);
}

kerror_t sched_context_set_prio(sched_state_t *s, uint32_t sc_id, uint8_t prio) {
  sched_context_t *sc;
  if (!s || sc_id >= MAX_SCHED_CONTEXTS) return ERR_INVALID_ARG;
  sc = &s->contexts[sc_id];
  if (!sc->bound) return ERR_INVALID_ARG;
  if (sc->priority == prio) return ERR_OK;
  ready_recompute(s, sc->partition_id, sc->priority); /* fix old bit */
  sc->priority = prio;
  if (sc->remaining_us > 0) ready_set(s, sc->partition_id, prio);
  /* Mirror the TCB copy ps prints (sched owns the authoritative one). */
  if (sc->tcb_id < MAX_TCBS) g_tcbs.threads[sc->tcb_id].priority = prio;
  return ERR_OK;
}

/* moonsh `nice`: tid-born priority retarget. Bounds mirror ps_live (a slot
 * with no pc/sp/cspace is free, whatever its state word says). */
int moonsh_nice_tid(long tid, int prio) {
  tcb_t *t;
  if (prio < 0 || prio > 255) return -2;
  if (tid < 0 || tid >= MAX_TCBS) return -1;
  t = &g_tcbs.threads[tid];
  if (t->pc == 0 && t->sp == 0 && t->cspace == NULL) return -1;
  if (t->sched_context >= MAX_SCHED_CONTEXTS) return -1;
  if (sched_context_set_prio(&g_sched, t->sched_context, (uint8_t)prio) != ERR_OK)
    return -1;
  return 0;
}

void sched_tick(sched_state_t *s, uint64_t now_us) {
  uint64_t frame_offset = (now_us - s->major_frame_start) % MAJOR_FRAME_US;
  g_sched_ticks++;
  /* Deterministic partition switch - proven constant time */
  uint32_t new_part = s->current_partition;
  for (uint32_t i = 0; i < s->num_partitions; i++) {
    uint64_t off = s->partitions[i].offset_us;
    uint64_t end = off + s->partitions[i].budget_us;
    if (frame_offset >= off && frame_offset < end) {
      new_part = i;
      break;
    }
  }
  if (new_part != s->current_partition) {
    sched_flush_partition(s, s->current_partition);
    s->current_partition = new_part;
  }
  /* Replenish budgets on period */
  for (uint32_t i = 0; i < MAX_SCHED_CONTEXTS; i++) {
    if (!s->contexts[i].bound)
      continue;
    if (now_us >= s->contexts[i].deadline) {
      s->contexts[i].remaining_us = s->contexts[i].budget_us;
      s->contexts[i].deadline += s->contexts[i].period_us;
      s->contexts[i].consumed_this_period = 0;
      g_replenish++;
      ready_set(s, s->contexts[i].partition_id, s->contexts[i].priority);
    }
  }
}

void sched_flush_partition(sched_state_t *s, uint32_t old_part) {
  (void)s;
  (void)old_part;
  cheri_flush_microarch();
}

/* Full scan: authoritative definition of "pickable". The bitmap path must
 * agree with this on every state (see tests/test_sched_bitmap.c). */
static uint32_t pick_full_scan(sched_state_t *s, uint32_t part) {
  for (int prio = 0; prio < 256; prio++) {
    for (uint32_t i = 0; i < MAX_SCHED_CONTEXTS; i++) {
      sched_context_t *sc = &s->contexts[i];
      if (!sc->bound)
        continue;
      if (sc->partition_id != part)
        continue;
      if (sc->priority != prio)
        continue;
       if (sc->remaining_us == 0)
         continue;
       if (sc->tcb_id >= MAX_TCBS)
         continue; /* ill-formed context: never pickable, never fatal */
      // Production: skip blocked TCBs - prevents burning budget on non-runnable
      tcb_t *tcb = &g_tcbs.threads[sc->tcb_id];
      if (!tcb_is_runnable(tcb))
        continue;
      return sc->tcb_id;
    }
  }
  return 0xFFFFFFFF; /* idle */
}

uint32_t sched_pick_next(sched_state_t *s, uint64_t now_us) {
  (void)now_us;
  // WCET: fast path touches <=4 bitmap words + <=64 contexts at ONE prio;
  // fallback is the legacy full scan (256*64). Worst case = legacy + small
  // constant, so the old bound still holds; common case drops from 16384
  // iterations to dozens. Full O(1) needs TCB-state hooks in tcb.c/
  // endpoint.c (accepted future work, not silent debt): until then the
  // bitmap stays a superset hint and this fallback is the correctness floor.
  // MAX_SCHED_CONTEXTS=64 is kept; sched_is_schedulable keeps per-partition
  // util<=99 so bound tasks per partition <<64 in practice.
  _Static_assert(MAX_SCHED_CONTEXTS <= 64, "sched_pick_next: increase MAX_SCHED_CONTEXTS requires WCET re-analysis");
  uint32_t part = s->current_partition;
  if (part >= MAX_PARTITIONS)
    return 0xFFFFFFFF;
  for (int w = 0; w < 4; w++) {
    uint64_t word = s->ready_bits[part][w];
    while (word) {
      int b = __builtin_ctzll(word);
      word &= word - 1;
      uint8_t prio = (uint8_t)(w * 64 + b);
      for (uint32_t i = 0; i < MAX_SCHED_CONTEXTS; i++) {
        sched_context_t *sc = &s->contexts[i];
        if (!sc->bound || sc->partition_id != part || sc->priority != prio ||
            sc->remaining_us == 0 ||
            sc->tcb_id >= MAX_TCBS)
          continue;
        tcb_t *tcb = &g_tcbs.threads[sc->tcb_id];
        if (!tcb_is_runnable(tcb))
          continue;
        return sc->tcb_id;
      }
      ready_clear(s, part, prio); /* stale bit: proven empty, self-heal */
    }
  }
  return pick_full_scan(s, part);
}

bool sched_is_schedulable(sched_state_t *s) {
  for (uint32_t p = 0; p < s->num_partitions; p++) {
    uint64_t sum = 0;
    for (uint32_t i = 0; i < MAX_SCHED_CONTEXTS; i++) {
      if (!s->contexts[i].bound)
        continue;
      if (s->contexts[i].partition_id != p)
        continue;
      sum += s->contexts[i].budget_us * 100 / s->contexts[i].period_us;
    }
    if (sum > 99)
      return false;
  }
  return true;
}

bool wcet_check(uint64_t entry_us) {
  /* Kernel WCET 5us - enforced at every preemption point. MMIO clock (see
   * sched_now): a stale rdtime TB would spuriously deny yields (no dispatch
   * ever again) or putcs. */
  uint64_t now = 0;
#ifdef __riscv
  now = *(volatile uint64_t *)0x200BFF8u;
  __asm__ volatile("fence iorw,iorw" ::: "memory");
#endif
  return (now - entry_us) <= WCET_KERNEL_MAX_US * 1000;
}

/* ---- cooperative dispatch ---- */

uint32_t g_current_tcb = TCB_NONE; /* TCB_NONE: shell/idle on hart */

/* Dispatcher suspend context + quantum start (single hart: no locking). */
static sw_ctx_t disc_ctx;
static uint64_t disc_start;

static uint64_t sched_now(void) {
  uint64_t t = 0;
#ifdef __riscv
  /* MMIO mtime, NOT rdtime: QEMU TCG caches CSR reads inside hot TBs, so
   * rdtime goes stale in dispatch/tick loops (frozen scheduler, parked
   * threads) while uptime (cold path) still advances. MMIO is uncacheable
   * and always fresh. CLINT mapping comes from boot (timer_init area). */
  t = *(volatile uint64_t *)0x200BFF8u;
  __asm__ volatile("fence iorw,iorw" ::: "memory");
#endif
  return t;
}

void sched_consume(sched_context_t *sc, uint64_t elapsed_ticks) {
  if (!sc || !sc->bound) return;
  /* Timebase is rdtime ticks; virt mtime varies by build/host (spec 10MHz,
   * observed 100MHz+), so us-named budgets are really "ticks" - ratios stay
   * self-consistent (rotation works), wall mapping floats. Host-sim ticks
   * read 0 and never consume. */
  if (elapsed_ticks >= sc->remaining_us) sc->remaining_us = 0;
  else sc->remaining_us -= elapsed_ticks;
  sc->consumed_this_period += elapsed_ticks;
}

void sched_yield_back(void) {
  /* NOTE (target): dead on RISC-V — kept for host unit tests (test_info).
   * The live yield path is sched_coop_switch (snapshot resume, below):
   * suspending a trap across context_switch leaves mscratch stale, so the
   * next trap's frame lands on the suspended C frames and trips canaries. */
  uint32_t cur = g_current_tcb;
  uint64_t now;
  tcb_t *t;
  if (cur >= MAX_TCBS) return;
  t = &g_tcbs.threads[cur];
  now = sched_now();
  if (t->sched_context < MAX_SCHED_CONTEXTS)
    sched_consume(&g_sched.contexts[t->sched_context],
                  now >= disc_start ? now - disc_start : 0);
  /* NOTE: nothing below is live across the switch (caller-saved regs die);
   * on re-pick we resume right here and fall back into the trap handler. */
  g_sw_yield_in++;
  context_switch(&t->ctx, &disc_ctx);
  g_sw_yield_ret++;
}

void sched_dispatch(void) {
  /* NOTE (target): dead on RISC-V — kept for host unit tests (test_info).
   * The live yield path is sched_coop_switch (snapshot resume, below).
   * Only `n` (volatile) + globals are live across context_switch. */
  volatile int n = 0;
  for (; n < 8; n++) {
    uint64_t now = sched_now();
    uint32_t nxt;
    sched_tick(&g_sched, now);
    nxt = sched_pick_next(&g_sched, now);
    if (nxt >= MAX_TCBS || !tcb_is_runnable(&g_tcbs.threads[nxt])) {
      g_current_tcb = TCB_NONE;
      return;
    }
    g_current_tcb = nxt;
    disc_start = now;
    g_sw_disp_in++;
    context_switch(&disc_ctx, &g_tcbs.threads[nxt].ctx);
    g_sw_disp_ret++;
    /* Resumed: the thread yielded back. Charge it and repick. */
    {
      uint64_t back = sched_now();
      uint32_t cur = g_current_tcb;
      if (cur < MAX_TCBS) {
        tcb_t *t = &g_tcbs.threads[cur];
        if (t->sched_context < MAX_SCHED_CONTEXTS)
          sched_consume(&g_sched.contexts[t->sched_context],
                        back >= disc_start ? back - disc_start : 0);
      }
      g_current_tcb = TCB_NONE;
    }
  }
  /* Bound reached with live threads (e.g. instant yielders): park as idle so
   * the next yield re-dispatches fresh. Without this reset, a stale id would
   * route all later shell yields into yield-back (no dispatch ever again). */
  g_current_tcb = TCB_NONE;
}

/* ---- snapshot resume: traps never suspend across a switch ----
 *
 * Why: the old cooperative path switched stacks mid-trap (thread parked in
 * sched_yield_back inside its own syscall trap). context_switch does not
 * move mscratch, so the next trap from another context built its frame just
 * below the SUSPENDED frame — on top of the suspended C frames (locals,
 * canary). Resuming then tripped __stack_chk_fail within seconds (hart
 * parked in wfi, 100% wake-storm on the pending MTIP, all counters frozen).
 * Fix: snapshot the live trap frame into its slot (thread/shell), install
 * the pick into the live frame, mret. Every trap completes; mscratch is
 * always the live top at entry, so frames can never overlap. The timer path
 * uses the same install (true preemption), which is now safe for the same
 * reason. sched_dispatch/sched_yield_back stay only for host tests. */
static trap_frame_t shell_saved;
static int has_shell_saved;
static unsigned coop_picks; /* shell fairness: every 8th coop pick -> shell */

/* First-run frame: pc/sp from the TCB, rest zero. The trap restore path
 * advances mepc only for ecall causes, so cause 0 resumes exactly at pc. */
static void snap_synth_initial(trap_frame_t *f, const tcb_t *t) {
  memset(f, 0, sizeof(*f));
  f->pc = t->pc;
  f->sp = t->sp;
  f->cause = 0;
}

/* Charge the outgoing quantum's elapsed ticks to its context. */
static void snap_charge(uint32_t cur) {
  tcb_t *t;
  uint64_t now;
  if (cur >= MAX_TCBS) return;
  t = &g_tcbs.threads[cur];
  now = sched_now();
  if (t->sched_context < MAX_SCHED_CONTEXTS)
    sched_consume(&g_sched.contexts[t->sched_context],
                  now >= disc_start ? now - disc_start : 0);
}

/* Park the live frame into its slot (thread snapshot or shell slot). */
static void snap_save(trap_frame_t *live, uint32_t cur) {
  if (cur >= MAX_TCBS) {
    if (cur == TCB_NONE) { shell_saved = *live; has_shell_saved = 1; }
    /* Garbage cur: save nothing (recovery installs someone else below). */
  } else {
    g_tcbs.threads[cur].saved = *live;
    g_tcbs.threads[cur].has_frame = 1;
  }
}

/* Install nxt into the live frame; false = nobody runnable (live touched
 * only by the caller afterwards). A snapshot taken at an ecall resumes past
 * it (restore advances mepc for ecall causes), so complete its yield result
 * here; async snapshots keep their registers. */
static bool snap_install(trap_frame_t *live, uint32_t nxt) {
  if (nxt >= MAX_TCBS) {
    if (!has_shell_saved) return false;
    *live = shell_saved;
    if (shell_saved.cause >= 8 && shell_saved.cause < 12)
      live->a0 = (uintptr_t)ERR_OK;
    g_current_tcb = TCB_NONE;
  } else {
    tcb_t *t = &g_tcbs.threads[nxt];
    if (!tcb_is_runnable(t)) return false;
    if (!t->has_frame) { snap_synth_initial(&t->saved, t); t->has_frame = 1; }
    *live = t->saved;
    if (t->saved.cause >= 8 && t->saved.cause < 12)
      live->a0 = (uintptr_t)ERR_OK;
    g_current_tcb = nxt;
  }
  disc_start = sched_now();
  return true;
}

/* Cooperative yield via snapshot resume (called from the YIELD path with the
 * live trap frame). Snapshot the caller, install the pick (thread, or shell
 * every 8th pick for fairness), or keep the caller when idle. */
void sched_coop_switch(trap_frame_t *frame, uint32_t cur) {
  uint64_t now = sched_now();
  uint32_t nxt;
  sched_tick(&g_sched, now);
  if (cur == TCB_NONE) {
    /* Shell quantum: park the shell, run a thread when one is pickable. */
    snap_save(frame, cur);
    nxt = sched_pick_next(&g_sched, now);
    if (nxt < MAX_TCBS && tcb_is_runnable(&g_tcbs.threads[nxt]) &&
        snap_install(frame, nxt))
      return;
    /* Idle: keep the shell (advance past its yield, complete it). */
    g_current_tcb = TCB_NONE;
    frame->a0 = (uintptr_t)ERR_OK;
    return;
  }
  if (cur >= MAX_TCBS) {
    /* Garbage cur (should not happen): heal by installing anyone pickable. */
    nxt = sched_pick_next(&g_sched, now);
    if (snap_install(frame, nxt)) return;
    if (snap_install(frame, TCB_NONE)) return;
    g_current_tcb = TCB_NONE;
    return;
  }
  snap_charge(cur);
  snap_save(frame, cur);
  /* Fairness bound (mirrors the old n<8 dispatch loop): every 8th pick hands
   * the hart back to the shell so it stays interactive. */
  if (has_shell_saved && (coop_picks++ % 8) == 7 &&
      snap_install(frame, TCB_NONE))
    return;
  nxt = sched_pick_next(&g_sched, now);
  if (snap_install(frame, nxt)) return;
  if (has_shell_saved && snap_install(frame, TCB_NONE))
    return;
  /* Nothing runnable (all blocked/killed since): keep current (a yield that
   * schedules itself is a no-op: advance past it, complete it). */
  frame->a0 = (uintptr_t)ERR_OK;
}

void thread_exit(void) {
  uint32_t cur = g_current_tcb;
  if (cur < MAX_TCBS) g_tcbs.threads[cur].state = TCB_INACTIVE;
#ifdef __riscv
  /* Parked INACTIVE: the dispatcher skips us, so just keep yielding. */
  for (;;) { __asm__ volatile("li a7, 3; ecall" ::: "a7", "memory"); }
#endif
}

/* ---- machine-timer preemption (CLINT MTIP, M-mode) ---- */

uint64_t g_timer_ticks;

#ifdef __riscv
#define CLINT_MTIME    ((volatile uint64_t *)0x200BFF8u)
#define CLINT_MTIMECMP ((volatile uint64_t *)0x2004000u) /* hart 0 */

static void clint_fence(void) {
  __asm__ volatile("fence iorw,iorw" ::: "memory");
}
#endif

/* Re-arm one slice ahead. MTIP clears when compare > mtime. */
static void timer_ack(void) {
#ifdef __riscv
  *CLINT_MTIMECMP = *CLINT_MTIME + TIMER_SLICE_TICKS;
  clint_fence();
#else
  (void)0;
#endif
}

void timer_init(void) {
#ifdef __riscv
  uint64_t mie;
  timer_ack();
  /* Enable machine-timer interrupts globally; per-context MIE stays managed
   * by trap entry/exit (masked in handler, set for threads). Boot/shell run
   * masked, so a pending tick simply waits for the first thread. */
  __asm__ volatile("csrr %0, mie" : "=r"(mie));
  mie |= 0x80u; /* MTIE */
  __asm__ volatile("csrw mie, %0" :: "r"(mie));
  clint_fence();
#endif
}

/* Trap-context timer handler (trap.S irq branch, a0 = live trap frame).
 * Hardware already masked MIE on entry, so this never re-enters itself.
 * Shell/idle (TCB_NONE) is cooperative-only: ack the tick and return.
 * Preemption installs the pick into the live frame (snapshot resume, same
 * as the cooperative path); every trap completes, so this is now safe. */
void timer_handler(trap_frame_t *frame) {
  uint64_t now;
  uint32_t cur, nxt;
  tcb_t *t;
  if (!frame) return;
  g_timer_ticks++;
  timer_ack();
  now = sched_now();
  sched_tick(&g_sched, now);
  cur = g_current_tcb;
  if (cur >= MAX_TCBS) return;
  t = &g_tcbs.threads[cur];
  if (!tcb_is_runnable(t)) return;
  /* Elapsed-charge + snapshot the preempted thread. */
  snap_charge(cur);
  snap_save(frame, cur);
  /* Preempt within threads only: the shell slot may hold a mid-line state,
   * so a timer never installs it (the next yield hands back via fairness). */
  nxt = sched_pick_next(&g_sched, now);
  if (nxt >= MAX_TCBS || nxt == cur ||
      !tcb_is_runnable(&g_tcbs.threads[nxt]))
    return; /* keep current: live frame untouched, normal restore resumes it */
  snap_install(frame, nxt);
}

/* ---- moonsh `ps` ---- */

static unsigned ps_dec(char *dst, unsigned room, uint64_t v) {
  char tmp[20];
  unsigned n = 0, w = 0;
  if (v == 0) { if (room) dst[0] = '0'; return room ? 1u : 0u; }
  while (v && n < sizeof(tmp)) { tmp[n++] = (char)('0' + (v % 10u)); v /= 10u; }
  while (n && w < room) dst[w++] = tmp[--n];
  return w;
}

static unsigned ps_hex(char *dst, unsigned room, uintptr_t v) {
  unsigned w = 0;
  int started = 0;
  for (int sh = (int)(sizeof(uintptr_t) * 8) - 4; sh >= 0; sh -= 4) {
    unsigned d = (unsigned)((v >> sh) & 0xFu);
    if (d || started || sh == 0) {
      if (w >= room) break;
      dst[w++] = d < 10 ? (char)('0' + d) : (char)('a' + d - 10);
      started = 1;
    }
  }
  return w;
}

static unsigned ps_str(char *dst, unsigned room, unsigned at, const char *s) {
  while (*s && at < room) dst[at++] = *s++;
  return at;
}

/* A TCB slot is live iff process_create filled it (mirrors its predicate). */
static bool ps_live(const tcb_t *t) {
  return t && (t->pc != 0 || t->sp != 0 || t->cspace != NULL);
}

static unsigned ps_count_live(void) {
  unsigned n = 0;
  for (uint32_t i = 0; i < MAX_TCBS; i++)
    if (ps_live(&g_tcbs.threads[i])) n++;
  return n;
}

int moonsh_ps_line(char *buf, unsigned len, unsigned *cursor) {
  unsigned idx = cursor ? *cursor : 0;
  unsigned live = ps_count_live();
  unsigned at = 0, seen = 0;
  if (!buf || !len) return 0;
  if (idx < live) {
    /* idx-th live thread. */
    for (uint32_t i = 0; i < MAX_TCBS; i++) {
      const tcb_t *t = &g_tcbs.threads[i];
      uint32_t sc;
      if (!ps_live(t)) continue;
      if (seen++ != idx) continue;
      at = ps_str(buf, len - 1u, at, "  ");
      at += ps_dec(buf + at, len - 1u - at, t->id);
      at = ps_str(buf, len - 1u, at, " ");
      for (int k = 0; k < 12 && at < len - 1u; k++)
        buf[at++] = t->name[k] ? t->name[k] : ' ';
      at = ps_str(buf, len - 1u, at, " ");
      at = ps_str(buf, len - 1u, at, tcb_state_name(t->state));
      at = ps_str(buf, len - 1u, at, " pc ");
      at += ps_hex(buf + at, len - 1u - at, t->pc);
      at = ps_str(buf, len - 1u, at, " sp ");
      at += ps_hex(buf + at, len - 1u - at, t->ctx.sp);
      at = ps_str(buf, len - 1u, at, " part ");
      at += ps_dec(buf + at, len - 1u - at, t->time_partition);
      at = ps_str(buf, len - 1u, at, " prio ");
      at += ps_dec(buf + at, len - 1u - at, t->priority);
      at = ps_str(buf, len - 1u, at, " ");
      sc = t->sched_context;
      if (sc < MAX_SCHED_CONTEXTS && g_sched.contexts[sc].bound) {
        at += ps_dec(buf + at, len - 1u - at, g_sched.contexts[sc].budget_us);
        at = ps_str(buf, len - 1u, at, "/");
        at += ps_dec(buf + at, len - 1u - at, g_sched.contexts[sc].remaining_us);
      } else {
        at = ps_str(buf, len - 1u, at, "-/-");
      }
      if (t->id == g_current_tcb) at = ps_str(buf, len - 1u, at, " *");
      at = ps_str(buf, len - 1u, at, "\n");
      buf[at] = '\0';
      if (cursor) *cursor = idx + 1;
      return 1;
    }
    return 0; /* raced with destroy; end iteration */
  }
  if (idx == live) {
    uint32_t nxt;
#ifdef __riscv
    uint64_t now = sched_now();
#else
    uint64_t now = 0;
#endif
    nxt = sched_pick_next(&g_sched, now);
    at = ps_str(buf, len - 1u, at, "next: ");
    if (nxt < MAX_TCBS) {
      at = ps_str(buf, len - 1u, at, "tid ");
      at += ps_dec(buf + at, len - 1u - at, nxt);
    } else {
      at = ps_str(buf, len - 1u, at, "idle (no runnable thread)");
    }
    at = ps_str(buf, len - 1u, at, " | preempt ");
    at += ps_dec(buf + at, len - 1u - at, g_timer_ticks);
    at = ps_str(buf, len - 1u, at, "\n");
    buf[at] = '\0';
    if (cursor) *cursor = idx + 1;
    return 1;
  }
  if (idx == live + 1) {
    /* Trap census: total entries, ecall path, irq path, ticks, replenishes.
     * Plus ctx0 liveness snapshot (bound/deadline/remaining/now) so `ps`
     * doubles as a scheduler-state probe. */
    uint64_t now = sched_now();
    at = ps_str(buf, len - 1u, at, "trap ");
    at += ps_dec(buf + at, len - 1u - at, g_trap_total);
    at = ps_str(buf, len - 1u, at, " ecall ");
    at += ps_dec(buf + at, len - 1u - at, g_trap_ecall);
    at = ps_str(buf, len - 1u, at, " irq ");
    at += ps_dec(buf + at, len - 1u - at, g_trap_irq);
    at = ps_str(buf, len - 1u, at, " tick ");
    at += ps_dec(buf + at, len - 1u - at, g_sched_ticks);
    at = ps_str(buf, len - 1u, at, " repl ");
    at += ps_dec(buf + at, len - 1u - at, g_replenish);
    at = ps_str(buf, len - 1u, at, " now ");
    at += ps_dec(buf + at, len - 1u - at, now);
    at = ps_str(buf, len - 1u, at, " c0b ");
    at += ps_dec(buf + at, len - 1u - at, g_sched.contexts[0].bound);
    at = ps_str(buf, len - 1u, at, " c0d ");
    at += ps_dec(buf + at, len - 1u - at, g_sched.contexts[0].deadline);
    at = ps_str(buf, len - 1u, at, " c0r ");
    at += ps_dec(buf + at, len - 1u - at, g_sched.contexts[0].remaining_us);
    at = ps_str(buf, len - 1u, at, " swy ");
    at += ps_dec(buf + at, len - 1u - at, g_sw_yield_in);
    at = ps_str(buf, len - 1u, at, "/");
    at += ps_dec(buf + at, len - 1u - at, g_sw_yield_ret);
    at = ps_str(buf, len - 1u, at, " swd ");
    at += ps_dec(buf + at, len - 1u - at, g_sw_disp_in);
    at = ps_str(buf, len - 1u, at, "/");
    at += ps_dec(buf + at, len - 1u - at, g_sw_disp_ret);
    at = ps_str(buf, len - 1u, at, " yc11 ");
    at += ps_dec(buf + at, len - 1u - at, g_yield_cause11);
    at = ps_str(buf, len - 1u, at, " ycO ");
    at += ps_dec(buf + at, len - 1u - at, g_yield_causeOther);
    at = ps_str(buf, len - 1u, at, " lp ");
    for (int li = 0; li < 4 && at < len - 1u; li++) {
        at += ps_dec(buf + at, len - 1u - at, g_loop_iter[li]);
        if (li < 3) at = ps_str(buf, len - 1u, at, "/");
    }
    at = ps_str(buf, len - 1u, at, " cur ");
    at += ps_dec(buf + at, len - 1u - at, g_current_tcb);
    at = ps_str(buf, len - 1u, at, " dsp ");
    at += ps_hex(buf + at, len - 1u - at,
                 has_shell_saved ? (uintptr_t)shell_saved.sp : 0u);
    at = ps_str(buf, len - 1u, at, " part ");
    at += ps_dec(buf + at, len - 1u - at, g_sched.current_partition);
    at = ps_str(buf, len - 1u, at, "/");
    at += ps_dec(buf + at, len - 1u - at, g_sched.num_partitions);
    at = ps_str(buf, len - 1u, at, " ps ");
    at += ps_dec(buf + at, len - 1u - at, g_putc_shell);
    at = ps_str(buf, len - 1u, at, " pt ");
    at += ps_dec(buf + at, len - 1u - at, g_putc_thread);
    at = ps_str(buf, len - 1u, at, " ys ");
    at += ps_dec(buf + at, len - 1u - at, g_yield_shell);
    at = ps_str(buf, len - 1u, at, " yt ");
    at += ps_dec(buf + at, len - 1u - at, g_yield_thread);
    at = ps_str(buf, len - 1u, at, "\n");
    buf[at] = '\0';
    if (cursor) *cursor = idx + 1;
    return 1;
  }
  return 0;
}
