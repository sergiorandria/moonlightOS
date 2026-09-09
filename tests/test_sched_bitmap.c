/* test_sched_bitmap - differential test: sched_pick_next (bitmap fast path
 * + full-scan fallback) must AGREE with an independent reference full scan
 * on every randomized state, including states the bitmap was never told
 * about (direct field pokes simulating TCB-state drift in tcb.c/endpoint.c,
 * stale bits, out-of-range partitions). Deterministic LCG, no libc rand. */
#include "../kernel/include/sched.h"
#include "../kernel/include/tcb.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

tcb_table_t g_tcbs;
static sched_state_t S;

static uint32_t rng_state = 0x12345678;
static uint32_t rnd(uint32_t n) {
    rng_state = rng_state * 1664525u + 1013904223u;
    return (rng_state >> 8) % (n ? n : 1);
}

/* Independent reference: the pre-bitmap algorithm, verbatim semantics. */
static uint32_t ref_pick(sched_state_t *s) {
    uint32_t part = s->current_partition;
    if (part >= MAX_PARTITIONS) return 0xFFFFFFFF;
    for (int prio = 0; prio < 256; prio++) {
        for (uint32_t i = 0; i < MAX_SCHED_CONTEXTS; i++) {
            sched_context_t *sc = &s->contexts[i];
            if (!sc->bound) continue;
            if (sc->partition_id != part) continue;
            if (sc->priority != prio) continue;
            if (sc->remaining_us == 0) continue;
            if (sc->tcb_id >= MAX_TCBS) continue;
            if (!tcb_is_runnable(&g_tcbs.threads[sc->tcb_id])) continue;
            return sc->tcb_id;
        }
    }
    return 0xFFFFFFFF;
}

static void randomize(void) {
    memset(&S, 0, sizeof(S));
    memset(&g_tcbs, 0, sizeof(g_tcbs));
    S.num_partitions = 1 + rnd(3);
    for (uint32_t p = 0; p < S.num_partitions; p++) {
        S.partitions[p].active = true;
        S.partitions[p].budget_us = 2000;
    }
    uint32_t n = rnd(10);
    for (uint32_t k = 0; k < n; k++) {
        /* Mix API binds (maintain bits) and raw pokes (bypass maintenance,
         * exactly what production external mutators do). */
        if (rnd(2)) {
            sched_context_bind(&S, rnd(MAX_SCHED_CONTEXTS), rnd(MAX_TCBS + 4),
                               rnd(S.num_partitions), 100 + rnd(900),
                               2000, rnd(256));
        } else {
            sched_context_t *c = &S.contexts[rnd(MAX_SCHED_CONTEXTS)];
            c->bound = rnd(2);
            c->partition_id = rnd(MAX_PARTITIONS + 2); /* may be OOB */
            c->priority = rnd(256);
            c->remaining_us = rnd(3) ? 100 + rnd(900) : 0;
            c->tcb_id = rnd(MAX_TCBS + 4); /* may be OOB: guard must skip */
        }
    }
    for (uint32_t t = 0; t < 8; t++) {
        g_tcbs.threads[t].state = rnd(2) ? TCB_RUNNABLE : TCB_BLOCKED_RECV;
        g_tcbs.threads[t].cspace = (void *)0x1; /* non-NULL: not free */
    }
    S.current_partition = rnd(S.num_partitions + 2); /* may be OOB-ish */
}

int main(void) {
    printf("=== sched bitmap differential ===\n");
    /* Hand cases first. */
    memset(&S, 0, sizeof(S));
    memset(&g_tcbs, 0, sizeof(g_tcbs));
    assert(sched_pick_next(&S, 0) == 0xFFFFFFFF);
    assert(sched_pick_next(&S, 0) == ref_pick(&S));
    S.current_partition = 99;
    assert(sched_pick_next(&S, 0) == 0xFFFFFFFF);
    assert(sched_pick_next(&S, 0) == ref_pick(&S));

    for (int iter = 0; iter < 3000; iter++) {
        randomize();
        uint32_t a = sched_pick_next(&S, 0);
        uint32_t b = ref_pick(&S);
        if (a != b) {
            printf("FAIL iter %d: bitmap=%u ref=%u part=%u\n",
                   iter, a, b, S.current_partition);
            assert(0);
        }
        /* Mutate through the API too: tick (replenish sets bits),
         * unbind (recomputes), rebind. */
        sched_tick(&S, rnd(20000));
        if (sched_pick_next(&S, 0) != ref_pick(&S)) {
            printf("FAIL iter %d post-tick\n", iter);
            assert(0);
        }
        uint32_t victim = rnd(MAX_SCHED_CONTEXTS);
        sched_context_unbind(&S, victim);
        if (sched_pick_next(&S, 0) != ref_pick(&S)) {
            printf("FAIL iter %d post-unbind\n", iter);
            assert(0);
        }
        /* TCB-state flip WITHOUT touching the scheduler (the hard case:
         * bitmap goes stale, fallback must still agree). */
        g_tcbs.threads[rnd(8)].state =
            rnd(2) ? TCB_RUNNABLE : TCB_BLOCKED_RECV;
        if (sched_pick_next(&S, 0) != ref_pick(&S)) {
            printf("FAIL iter %d post-tcb-flip\n", iter);
            assert(0);
        }
    }
    printf("PASS: bitmap == full scan on 3000 randomized states (+tick/unbind/tcb-flip)\n");
    return 0;
}
