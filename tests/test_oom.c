/* RAM optimization + OOM killer tests (host-sim, no RISC-V needed).
 *
 * Covers:
 *  A. any-size pools: zero/tiny/unaligned/huge init never corrupts; allocs
 *     fail clean (ERR_NO_MEM) instead of wrapping.
 *  B. free-list reuse: freed single pages recycle (same paddr back), live/
 *     reclaim stats are O(1) exact, pressure 0..100 sane.
 *  C. per-process 4GB limit: oom_charge refuses past 4GB, victim pick
 *     prefers the offender, largest consumer otherwise.
 *  D. process lifecycle: destroy recycles the stack (create/destroy/create
 *     reuses the same page), >4GB stacks rejected, failed creates leak
 *     nothing.
 *  E. mem_server policy: best-fit whole-region hold, 4GB refuse, victim.
 */
#include "../kernel/include/alloc.h"
#include "../kernel/include/oom.h"
#include "../kernel/include/process.h"
#include "../kernel/include/sched.h"
#include "../kernel/include/revoke.h"
#include "../kernel/include/cap.h"
#include "../kernel/include/cnode.h"
#include "../kernel/include/vspace.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* mem_server API (userspace, linked directly). */
extern void mem_server_init(uintptr_t *bases, size_t *sizes, uint16_t *colors, uint32_t n);
extern int mem_alloc(uint32_t partition, size_t size, uintptr_t *out_paddr, uint16_t *out_color);
extern int mem_free(uintptr_t paddr);
extern uint64_t mem_usage(uint32_t partition);
extern uint32_t mem_pressure(void);
extern int mem_oom_victim(void);

/* Stubs for mem_server's kernel linkage. */
int moonlight_call(uint32_t ep, void *msg) { (void)ep; (void)msg; return 0; }
int moonlight_recv(uint32_t ep, void *msg) { (void)ep; (void)msg; return 0; }
int moonlight_retype(uint32_t cptr, uint32_t type, size_t size, uint32_t dest) {
    extern cnode_t g_root_cnode;
    cap_t *ut = cnode_lookup(&g_root_cnode, cptr);
    if (!ut) return -1;
    {
        cap_t nc = cap_retype(*ut, type, ut->u.untyped.paddr, size);
        if (!nc.is_valid) return -1;
        if (dest >= 256 || g_root_cnode.slots[dest].is_valid) return -1;
        g_root_cnode.slots[dest] = nc;
        g_root_cnode.used++;
    }
    return 0;
}
int moonlight_cnode_copy(uint32_t a, uint32_t b, uint32_t c) { (void)a; (void)b; (void)c; return 0; }

cnode_t g_root_cnode;
frame_alloc_t g_alloc;
vspace_t g_kernel_vspace;

static void test_any_size(void) {
    frame_alloc_t a;
    cap_t f;
    printf("A: any-size pools\n");
    alloc_init(&a, 0x80000000, 0);
    assert(a.base == a.top && a.next == a.top);
    assert(alloc_frame(&a, 0, PAGE_SIZE, &f) == ERR_NO_MEM);
    assert(alloc_usable_size(0x80000000, 0) == 0);
    alloc_init(&a, 0x80000001, 100); /* unaligned base, sub-page size */
    assert(a.base == 0x80001000u);
    assert(alloc_usable_size(0x80000001u, 100) == 0);
    assert(alloc_frame(&a, 0, PAGE_SIZE, &f) == ERR_NO_MEM);
    /* wrap-safe: base+size would overflow -> clamped, not wrapped */
    assert(alloc_usable_size((uintptr_t)-0x1000, (size_t)0x100000) <= 0x1000u);
    alloc_init(&a, (uintptr_t)-0x1000, (size_t)0x100000);
    assert(a.top >= a.base); /* saturated, never wrapped below base */
    /* huge (1GB + 256M): setup is pure bookkeeping, no backing touched */
    alloc_init(&a, 0x80000000u, (size_t)1536 * 1024 * 1024);
    assert(alloc_usable_size(0x80000000u, (size_t)1536 * 1024 * 1024) ==
           (size_t)1536 * 1024 * 1024);
    assert(alloc_frame(&a, 0, PAGE_SIZE, &f) == ERR_OK);
    assert(f.u.frame.paddr == 0x80000000u);
    assert(alloc_pressure(&a) == 0); /* 1 page of 393216: rounds to 0 */
    /* bad args rejected, never crash */
    assert(alloc_frame(NULL, 0, PAGE_SIZE, &f) == ERR_INVALID_ARG);
    assert(alloc_frame(&a, 0, 0, &f) == ERR_INVALID_ARG);
    assert(alloc_frame(&a, 0, 100, &f) == ERR_INVALID_ARG);
    assert(alloc_frame(&a, 99, PAGE_SIZE, &f) == ERR_INVALID_ARG);
    assert(alloc_free(NULL, &f) == ERR_INVALID_ARG);
    assert(alloc_pressure(NULL) == (uint32_t)-1);
    printf("PASS: any-size\n");
}

static void test_reuse(void) {
    frame_alloc_t a;
    cap_t f1, f2, f3;
    alloc_stats_t st;
    printf("B: free-list reuse\n");
    alloc_init(&a, 0x90000000u, 0x100000u); /* 256 pages */
    assert(alloc_frame(&a, 0, PAGE_SIZE, &f1) == ERR_OK);
    assert(alloc_frame(&a, 0, PAGE_SIZE, &f2) == ERR_OK);
    assert(f1.u.frame.paddr != f2.u.frame.paddr);
    assert(alloc_color_is_valid(0, f1.color) && alloc_color_is_valid(0, f2.color));
    assert(alloc_stats(&a, &st) == ERR_OK);
    assert(st.live_bytes == 2 * PAGE_SIZE);
    assert(st.reclaim_bytes == 0);
    /* free one: reclaim grows, live shrinks (O(1), no frames[] scan) */
    {
        cap_t tmp = f1;
        assert(alloc_free(&a, &tmp) == ERR_OK);
    }
    assert(alloc_stats(&a, &st) == ERR_OK);
    assert(st.live_bytes == PAGE_SIZE);
    assert(st.reclaim_bytes == PAGE_SIZE);
    assert(alloc_pressure(&a) == (100 * 1) / 256);
    /* realloc recycles the exact page (LIFO hot path) */
    assert(alloc_frame(&a, 0, PAGE_SIZE, &f3) == ERR_OK);
    assert(f3.u.frame.paddr == f1.u.frame.paddr);
    assert(alloc_stats(&a, &st) == ERR_OK);
    assert(st.reused_pages == 1);
    /* multi-page carve + free splits back into reusable singles */
    {
        cap_t big, r1, r2;
        cap_t t2 = f2;
        assert(alloc_frame(&a, 1, 8192, &big) == ERR_OK);
        assert(alloc_free(&a, &big) == ERR_OK);
        assert(alloc_free(&a, &t2) == ERR_OK);
        assert(alloc_stats(&a, &st) == ERR_OK);
        /* 3 reclaimable: big's 2 pages + f2's 1 (f1's page is live again
         * inside f3 — reuse pops it, so it is not counted twice). */
        assert(st.reclaim_bytes == 3 * PAGE_SIZE);
        assert(alloc_frame(&a, 1, PAGE_SIZE, &r1) == ERR_OK);
        assert(alloc_frame(&a, 1, PAGE_SIZE, &r2) == ERR_OK);
        assert(alloc_color_is_valid(1, r1.color));
        (void)r1; (void)r2;
    }
    /* foreign caps never poison the pool */
    {
        cap_t alien = {0};
        alien.type = CAP_FRAME; alien.is_valid = 1;
        alien.u.frame.paddr = 0x10000000u;
        alien.hw_cap.base = 0x10000000u; alien.hw_cap.top = 0x10001000u;
        assert(alloc_free(&a, &alien) == ERR_OK);
        assert(alloc_stats(&a, &st) == ERR_OK);
    }
    printf("PASS: reuse (reused=%llu)\n", (unsigned long long)st.reused_pages);
}

static void test_oom_ledger(void) {
    printf("C: 4GB ledger\n");
    oom_init();
    assert(oom_pick_victim() == -1);
    assert(oom_charge(3, 4096) == ERR_OK);
    assert(oom_usage(3) == 4096);
    /* Just under 4GB ok, 1 byte over refused */
    assert(oom_charge(3, (size_t)(OOM_PER_PROCESS_LIMIT - 4096)) == ERR_OK);
    assert(oom_usage(3) == OOM_PER_PROCESS_LIMIT);
    assert(oom_charge(3, 1) == ERR_NO_MEM);
    assert(oom_victim_for(3, 1) == 3); /* offender is its own victim */
    /* largest consumer otherwise */
    assert(oom_charge(5, 8192) == ERR_OK);
    assert(oom_pick_victim() == 3);
    oom_release(3, (size_t)OOM_PER_PROCESS_LIMIT);
    assert(oom_usage(3) == 0);
    assert(oom_pick_victim() == 5);
    /* single request over 4GB names the offender even untracked */
    assert(oom_victim_for(77, (size_t)OOM_PER_PROCESS_LIMIT + 1) == 77);
    oom_track_create(9);
    oom_track_destroy(9);
    assert(oom_usage(9) == 0);
    {
        uint64_t total = 0; uint32_t live = 0, kills = 0;
        oom_stats(&total, &live, &kills);
        assert(total == 8192 && live >= 1);
    }
    oom_note_kill(5);
    assert(oom_kill_count() == 1 && oom_last_victim() == 5);
    oom_track_destroy(3); oom_track_destroy(5);
    printf("PASS: ledger\n");
}

static void test_process_recycle(void) {
    /* create/destroy take the pool explicitly (no hidden global): the test
     * passes its own pool, production passes &g_alloc at the dispatch
     * sites (boot.c, linux.c, moonsh_kill_tid). */
    tcb_table_t tcbs = {0};
    frame_alloc_t *alloc = &g_alloc;
    sched_state_t sched;
    mdb_tree_t mdb;
    printf("D: process recycle + limits\n");
    oom_init();
    memset(&g_alloc, 0, sizeof(g_alloc));
    alloc_init(alloc, 0x80000000u, 0x100000u);
    sched_init(&sched);
    sched_partition_create(&sched, 0, 0, 6000, 1);
    sched_partition_create(&sched, 1, 6000, 4000, 3);
    mdb_init(&mdb);
    {
        process_create_args_t args = {0};
        uint32_t pid, pid2;
        uintptr_t first_sp;
        args.partition_id = 1; args.budget_us = 1000; args.period_us = 4000;
        args.priority = 10; args.pc = 0x80200000; args.stack_size = 4096;
        assert(process_create(&tcbs, alloc, &sched, &mdb, &args, &pid) == ERR_OK);
        first_sp = tcbs.threads[pid].sp;
        assert(oom_usage(pid) == 4096);
        /* validation: empty / unaligned / over-4GB stacks rejected */
        {
            process_create_args_t bad = args;
            uint32_t x;
            bad.stack_size = 0;
            assert(process_create(&tcbs, alloc, &sched, &mdb, &bad, &x) == ERR_INVALID_ARG);
            bad.stack_size = 100;
            assert(process_create(&tcbs, alloc, &sched, &mdb, &bad, &x) == ERR_INVALID_ARG);
            bad.stack_size = (size_t)OOM_PER_PROCESS_LIMIT + PAGE_SIZE;
            assert(process_create(&tcbs, alloc, &sched, &mdb, &bad, &x) == ERR_NO_MEM);
        }
        /* destroy recycles the page: next create reuses the same stack */
        assert(process_destroy(&tcbs, alloc, &sched, &mdb, pid) == ERR_OK);
        assert(oom_usage(pid) == 0);
        {
            alloc_stats_t st;
            assert(alloc_stats(alloc, &st) == ERR_OK);
            assert(st.reclaim_bytes == PAGE_SIZE);
        }
        assert(process_create(&tcbs, alloc, &sched, &mdb, &args, &pid2) == ERR_OK);
        assert(tcbs.threads[pid2].sp == first_sp);
        assert(process_destroy(&tcbs, alloc, &sched, &mdb, pid2) == ERR_OK);
    }
    printf("PASS: recycle\n");
}

static void test_mem_server_policy(void) {
    uintptr_t paddr; uint16_t color;
    printf("E: mem_server policy\n");
    cnode_init(&g_root_cnode, 0, 8);
    {
        cap_t ut = {0};
        ut.type = CAP_UNTYPED; ut.is_valid = 1; ut.hw_cap.tag = 1;
        ut.u.untyped.paddr = 0x90000000u; ut.u.untyped.size = 0x10000u;
        ut.rights = 0xFF;
        ut.hw_cap.base = 0x90000000u; ut.hw_cap.top = 0x90010000u;
        ut.hw_cap.addr = 0x90000000u;
        g_root_cnode.slots[0] = ut; g_root_cnode.used = 1;
    }
    {
        uintptr_t bases[1] = {0x90000000u};
        size_t sizes[1] = {0x10000u}; /* 64KB single region: any-size */
        uint16_t colors[1] = {0};
        mem_server_init(bases, sizes, colors, 1);
    }
    /* Whole-region hold: a 4K request on the 64K region holds the full
     * 64K (the retype ABI carves at the Untyped base with no offset, so a
     * sub-size retype would alias — see mem_alloc). Usage is the full
     * region; a second alloc fails until free. */
    assert(mem_alloc(0, 4096, &paddr, &color) == 0);
    assert(paddr == 0x90000000u && color == 0);
    assert(mem_usage(0) == 0x10000u);
    assert(mem_alloc(0, 4096, &paddr, &color) == -1); /* region busy */
    assert(mem_free(0x90000000u) == 0);
    assert(mem_usage(0) == 0);
    /* Freed region serves a full-size request again. */
    {
        uintptr_t p3; uint16_t c3;
        assert(mem_alloc(0, 0x10000u, &p3, &c3) == 0);
        assert(p3 == 0x90000000u);
        assert(mem_free(p3) == 0);
    }
    /* 4GB per-partition refuse (single + cumulative) */
    assert(mem_alloc(1, (size_t)OOM_PER_PROCESS_LIMIT + PAGE_SIZE, &paddr, &color) == -12);
    assert(mem_oom_victim() == -1);
    assert(mem_alloc(0, 8192, &paddr, &color) == 0);
    assert(mem_usage(0) == 0x10000u); /* whole region held */
    assert(mem_oom_victim() == 0);
    assert(mem_pressure() > 0 && mem_pressure() <= 100);
    assert(mem_free(paddr) == 0);
    printf("PASS: mem_server\n");
}

int main(void) {
    printf("=== test_oom (RAM + OOM killer) ===\n");
    test_any_size();
    test_reuse();
    test_oom_ledger();
    test_process_recycle();
    test_mem_server_policy();
    printf("ALL OOM TESTS PASS\n");
    return 0;
}
