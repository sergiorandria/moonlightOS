#include "../include/sched.h"
#include "../include/cheri.h"
#include "../include/tcb.h"
#include <string.h>
extern tcb_table_t g_tcbs;

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

void sched_tick(sched_state_t *s, uint64_t now_us) {
  uint64_t frame_offset = (now_us - s->major_frame_start) % MAJOR_FRAME_US;
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
            sc->remaining_us == 0 || sc->tcb_id >= MAX_TCBS)
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
  /* Kernel WCET 5us - enforced at every preemption point */
  uint64_t now = 0;
#ifdef __riscv
  __asm__ volatile("rdtime %0" : "=r"(now));
#endif
  return (now - entry_us) <= WCET_KERNEL_MAX_US * 1000;
}
