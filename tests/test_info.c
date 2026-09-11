/* test_info - host-sim for scheduler dispatch + INFO queries.
 * Covers: process_create (names, derived stacks, ctx init), sched_consume
 * math, sched_dispatch pick/update/terminate (context_switch stubbed: host
 * cannot switch stacks), thread_exit parking, moonsh_ps_line iteration and
 * alloc_stats/moonsh_mem_status. The riscv switch.S path is proven on QEMU.
 */
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "../kernel/include/sched.h"
#include "../kernel/include/tcb.h"
#include "../kernel/include/process.h"
#include "../kernel/include/alloc.h"
#include "../kernel/include/revoke.h"
/* NOTE: no <string.h> here: -I kernel/include would resolve the freestanding
 * kernel header (no strstr). Declare the hosted helpers explicitly. */
extern char *strstr(const char *a, const char *b);
extern unsigned long strlen(const char *s);
extern int strcmp(const char *a, const char *b);
extern char *strcpy(char *d, const char *s);

/* Host stub: record switches, return immediately (no stack swap on host). */
static int nsw;
static void *sw_to[16];
void context_switch(sw_ctx_t *cur, sw_ctx_t *next) {
    (void)cur;
    if (nsw < 16) sw_to[nsw] = next;
    nsw++;
}

extern tcb_table_t g_tcbs;
extern sched_state_t g_sched;
extern frame_alloc_t g_alloc;
extern vspace_t g_kernel_vspace;
extern uint32_t g_current_tcb;

static int fails;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else { printf("PASS: %s\n", msg); } \
} while (0)

int main(void) {
    /* 1. process_create: names, derived stacks, ctx preset. */
    {
        tcb_table_t tcbs = {0};
        frame_alloc_t a;
        sched_state_t s;
        mdb_tree_t mdb;
        alloc_init(&a, 0x80000000, 0x100000);
        sched_init(&s);
        assert(sched_partition_create(&s, 0, 0, 6000, 1) == ERR_OK);
        mdb_init(&mdb);
        process_create_args_t args = {0};
        args.partition_id = 0; args.budget_us = 1000; args.period_us = 5000;
        args.priority = 5; args.pc = 0x80001000;
        args.sp_top = 0xDEADBEEF; /* ignored: authoritative top is derived */
        args.stack_size = 4096; args.name = "hello";
        uint32_t pid;
        assert(process_create(&tcbs, &a, &s, &mdb, &args, &pid) == ERR_OK);
        tcb_t *t = &tcbs.threads[pid];
        CHECK(t->sp == 0x80001000u, "stack top derived from carved frame");
        CHECK(t->sp != 0xDEADBEEFu, "sp_top hint ignored");
        CHECK(strcmp(t->name, "hello") == 0, "name copied");
        CHECK(t->ctx.sp == t->sp, "ctx.sp preset");
        CHECK(t->ctx.s[11] == t->pc, "ctx.s11 = entry pc");
        /* Long names truncate safely. */
        process_create_args_t b = {0};
        b.partition_id = 0; b.budget_us = 1000; b.period_us = 5000;
        b.priority = 5; b.pc = 0x80002000; b.stack_size = 4096;
        b.name = "0123456789abcdef_extra_long";
        uint32_t pid2;
        assert(process_create(&tcbs, &a, &s, &mdb, &b, &pid2) == ERR_OK);
        CHECK(strlen(tcbs.threads[pid2].name) == 15, "name truncated to 15+NUL");
        CHECK(tcbs.threads[pid2].name[15] == '\0', "name NUL-terminated");
    }

    /* 2. sched_consume math. */
    {
        sched_context_t sc = {0};
        sc.bound = true; sc.remaining_us = 100;
        sched_consume(&sc, 30);
        CHECK(sc.remaining_us == 70 && sc.consumed_this_period == 30, "consume charges");
        sched_consume(&sc, 1000);
        CHECK(sc.remaining_us == 0, "consume saturates at 0");
        sched_consume(NULL, 10);
        sc.bound = false;
        sched_consume(&sc, 10);
        CHECK(1, "consume NULL/unbound safe");
    }

    /* 3. dispatch on stub globals: picks first same-prio, terminates. */
    {
        memset(&g_tcbs, 0, sizeof(g_tcbs));
        sched_init(&g_sched);
        assert(sched_partition_create(&g_sched, 0, 0, 6000, 1) == ERR_OK);
        g_tcbs.threads[5].pc = 0x80001000; g_tcbs.threads[5].sp = 0x80002000;
        g_tcbs.threads[5].state = TCB_RUNNABLE;
        g_tcbs.threads[6].pc = 0x80003000; g_tcbs.threads[6].sp = 0x80004000;
        g_tcbs.threads[6].state = TCB_RUNNABLE;
        assert(sched_context_bind(&g_sched, 0, 5, 0, 1000, 5000, 5) == ERR_OK);
        assert(sched_context_bind(&g_sched, 1, 6, 0, 1000, 5000, 5) == ERR_OK);
        g_tcbs.threads[5].sched_context = 0;
        g_tcbs.threads[6].sched_context = 1;
        nsw = 0;
        g_current_tcb = TCB_NONE;
        sched_dispatch();
        CHECK(nsw >= 1 && nsw <= 8, "dispatch runs bounded quanta");
        CHECK(sw_to[0] == &g_tcbs.threads[5].ctx, "picks first same-prio ctx");
        CHECK(g_current_tcb == TCB_NONE, "current reset after dispatch");
    }

    /* 4. thread_exit parks INACTIVE. */
    {
        g_current_tcb = 6;
        g_tcbs.threads[6].state = TCB_RUNNABLE;
        thread_exit();
        CHECK(g_tcbs.threads[6].state == TCB_INACTIVE, "exit parks INACTIVE");
        g_current_tcb = TCB_NONE;
    }

    /* 4b. nice retargets TCB + sched context + bitmap. */
    {
        CHECK(moonsh_nice_tid(5, 2) == 0, "nice ok");
        CHECK(g_tcbs.threads[5].priority == 2, "tcb prio mirrored");
        CHECK(g_sched.contexts[0].priority == 2, "ctx prio retargeted");
        CHECK(moonsh_nice_tid(5, 2) == 0, "nice same prio ok");
        CHECK(moonsh_nice_tid(99, 2) == -1, "nice bad tid");
        CHECK(moonsh_nice_tid(-1, 2) == -1, "nice negative tid");
        CHECK(moonsh_nice_tid(5, 256) == -2, "nice prio >255");
        CHECK(moonsh_nice_tid(5, -1) == -2, "nice negative prio");
        /* STOP removes it from the pick; dispatch passes it over. */
        CHECK(moonsh_kill_tid(5, 1) == 0, "STOP ok");
        CHECK(g_tcbs.threads[5].state == TCB_INACTIVE, "STOP suspends");
        g_tcbs.threads[6].state = TCB_RUNNABLE; /* exit test parked it */
        nsw = 0;
        sched_dispatch();
        CHECK(nsw >= 1 && sw_to[0] == &g_tcbs.threads[6].ctx,
              "dispatch skips stopped thread");
        CHECK(moonsh_kill_tid(5, 2) == 0, "CONT ok");
        CHECK(g_tcbs.threads[5].state == TCB_RUNNABLE, "CONT resumes");
        /* Destroy removes it; double destroy + bad tid/op fail. */
        CHECK(moonsh_kill_tid(6, 0) == 0, "destroy ok");
        CHECK(g_tcbs.threads[6].pc == 0 && g_tcbs.threads[6].sp == 0,
              "destroy scrubs slot");
        CHECK(moonsh_kill_tid(6, 0) == -1, "double destroy fails");
        CHECK(moonsh_kill_tid(127, 0) == -1, "destroy free slot fails");
        CHECK(moonsh_kill_tid(5, 7) == -2, "bad op fails");
        CHECK(moonsh_kill_tid(5000, 0) == -1, "huge tid fails");
    }

    /* 5. ps iterator: rows + trailing next line, then done. */
    {
        char line[128];
        unsigned cur = 0;
        int n = 0;
        memset(&g_tcbs, 0, sizeof(g_tcbs));
        sched_init(&g_sched);
        assert(sched_partition_create(&g_sched, 0, 0, 6000, 1) == ERR_OK);
        strcpy(g_tcbs.threads[2].name, "mem_server");
        g_tcbs.threads[2].pc = 0x80001234; g_tcbs.threads[2].sp = 0x80005678;
        g_tcbs.threads[2].state = TCB_RUNNABLE;
        g_tcbs.threads[2].time_partition = 1;
        g_tcbs.threads[2].priority = 5;
        g_tcbs.threads[2].sched_context = 3;
        assert(sched_context_bind(&g_sched, 3, 2, 0, 1000, 5000, 5) == ERR_OK);
        g_sched.contexts[3].remaining_us = 750;
        while (moonsh_ps_line(line, sizeof(line), &cur)) {
            line[sizeof(line) - 1] = '\0';
            if (n == 0) {
                CHECK(strstr(line, "mem_server") && strstr(line, "RUNNABLE") &&
                      strstr(line, "80001234"),
                      "ps row has name/state/pc");
            }
            n++;
            assert(n < 200);
        }
        CHECK(n == 3, "ps yields row + next + stats lines");
    }

    /* 6. allocator stats + mem dump. */
    {
        frame_alloc_t a;
        alloc_stats_t st;
        cap_t f;
        alloc_init(&a, 0x90000000, 0x400000);
        assert(alloc_frame(&a, 0, 4096, &f) == ERR_OK);
        assert(alloc_frame(&a, 0, 4096, &f) == ERR_OK);
        assert(alloc_frame(&a, 1, 4096, &f) == ERR_OK);
        assert(alloc_stats(&a, &st) == ERR_OK);
        CHECK(st.base == 0x90000000u && st.top == 0x90400000u, "pool bounds");
        CHECK(st.used + st.free == 0x400000u, "used+free == size");
        CHECK(st.frames_carved == 3, "3 frames carved");
        CHECK(st.color_used[0] == 2 && st.color_used[2] == 1, "per-color counts");
        CHECK(alloc_stats(NULL, &st) == ERR_INVALID_ARG, "stats rejects NULL");
        g_alloc = a;
        memset(&g_kernel_vspace, 0, sizeof(g_kernel_vspace));
        g_kernel_vspace.pt_pages_used = 7;
        {
            char mb[256];
            int r = moonsh_mem_status(mb, sizeof(mb));
            mb[sizeof(mb) - 1] = '\0';
            CHECK(r > 0 && strstr(mb, "pool") && strstr(mb, "frames 3") &&
                  strstr(mb, "pt pages 7"),
                  "mem dump has pool/frames/pt");
        }
    }

    if (fails) {
        printf("INFO TESTS: %d FAILURES\n", fails);
        return 1;
    }
    printf("ALL INFO TESTS PASS\n");
    return 0;
}
