/* tests/test_qube_destroy_auth.c - QDESTROY caller authority (C1).
 * Cross-qube destroy without membership or QX must fail closed; the
 * owner (same-qube member, or any QX holder) still succeeds. */
#include <stdint.h>
#include <stdio.h>

#include "../kernel/kinternal.h"
#include "../kernel/syscall_qube.c"

#define CHECK(c)                                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(c))                                                                                                      \
        {                                                                                                              \
            printf("FAIL line %d: %s\n", __LINE__, #c);                                                                \
            return 1;                                                                                                  \
        }                                                                                                              \
    } while (0)

/* ---- kernel globals owned by other TUs (stubs for host) ---- */
uctx_t threads[NTHREADS];
v2_ep_t eps[V2_NEP];
v2_caps_t caps;
uint8_t qube_of[NTHREADS];
unsigned long qube_next;
int cur;
uint64_t u_sp[NTHREADS];

void kputs(const char *s)
{
    (void)s;
}
void kputdec(unsigned long v)
{
    (void)v;
}
void frame_teardown_owned(unsigned long t, unsigned long f)
{
    (void)t;
    (void)f;
}
void v2_pte_clear(unsigned long t, unsigned long vpn)
{
    (void)t;
    (void)vpn;
}
void v2_pte_sync(unsigned long t)
{
    (void)t;
}
void v2_sfence_all(void)
{
}
int initrd_lookup(uint32_t idx, const uint8_t **out_ptr, uint32_t *out_size)
{
    (void)idx;
    (void)out_ptr;
    (void)out_size;
    return -1;
}
int v2_elf_load(const uint8_t *a, size_t b, v2_caps_t *c, unsigned long d, uint64_t *e, uint64_t *f)
{
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    (void)e;
    (void)f;
    return -1;
}
unsigned long build_child_vspace(unsigned long a, unsigned long b)
{
    (void)a;
    (void)b;
    return 0;
}
/* Shadows kernel/syscall.c:46 (same bounded scan over the same table);
 * syscall.c does not link on host (scheduler deps). The authority
 * OR-decision under test lives in syscall_qube.c, not here. */
int qube_has_qx(unsigned long tid)
{
    int s;
    if (tid >= (unsigned long)NTHREADS)
        return 0;
    for (s = 0; s < V2_CAP_SLOTS; s++)
    {
        if (caps.caps[tid][s].valid && (caps.caps[tid][s].rights & V2_RIGHT_QX))
            return 1;
    }
    return 0;
}

static void reset_state(void)
{
    for (int t = 0; t < NTHREADS; t++)
    {
        for (int r = 0; r < 32; r++)
            threads[t].regs[r] = 0;
        threads[t].state = T_RUNNABLE;
        threads[t].wait_kind = V2_WK_NONE;
        threads[t].ipc_ptr = 0;
        threads[t].ipc_cap = 0;
        threads[t].notify = 0;
        threads[t].vspace_root_ppn = 0;
        qube_of[t] = 0;
        u_sp[t] = 0;
        v2_ep_init(&eps[t]);
    }
    for (int t = 0; t < V2_CAP_THREADS; t++)
        for (int s = 0; s < V2_CAP_SLOTS; s++)
            caps.caps[t][s].valid = 0;
    qube_next = 2;
    cur = 0;
}

int main(void)
{
    /* Attacker in qube 3, no caps, destroys qube 2 -> must fail closed. */
    reset_state();
    qube_of[1] = 2;
    threads[1].state = T_RUNNABLE;
    qube_of[2] = 3;
    threads[2].state = T_RUNNABLE;
    cur = 2;
    CHECK(syscall_qube_invoke(V2_INV_QDESTROY, 2, 0, 0) == V2_ERR_INVALID);
    CHECK(threads[1].state == T_RUNNABLE); /* victim untouched */

    /* Owner (same-qube member) destroys own qube -> succeeds. */
    reset_state();
    qube_of[1] = 2;
    threads[1].state = T_RUNNABLE;
    qube_of[2] = 2;
    threads[2].state = T_RUNNABLE;
    cur = 2;
    CHECK(syscall_qube_invoke(V2_INV_QDESTROY, 2, 0, 0) == V2_OK);
    CHECK(threads[1].state == T_DEAD && threads[2].state == T_DEAD);

    /* QX holder in qube 3 destroys qube 2 -> succeeds. */
    reset_state();
    qube_of[1] = 2;
    threads[1].state = T_RUNNABLE;
    qube_of[2] = 3;
    threads[2].state = T_RUNNABLE;
    caps.caps[2][0].valid = 1;
    caps.caps[2][0].rights = V2_RIGHT_QX;
    cur = 2;
    CHECK(syscall_qube_invoke(V2_INV_QDESTROY, 2, 0, 0) == V2_OK);
    CHECK(threads[1].state == T_DEAD);

    /* Label 0 still rejected (existing behavior preserved). */
    reset_state();
    cur = 0;
    CHECK(syscall_qube_invoke(V2_INV_QDESTROY, 0, 0, 0) == V2_ERR_INVALID);

    printf("PASS: test_qube_destroy_auth\n");
    return 0;
}
