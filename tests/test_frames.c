/* tests/test_frames.c - host test for kernel/frames.h (pool + owners) and
 * the kernel-authority revoke in kernel/caps.h (v2_revoke_frame).
 *
 * Built with ASan/UBSan by tools/verify.sh. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../kernel/frames.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); exit(1); } } while (0)

static void test_pool(void)
{
    v2_frames_t p;
    int f, i;
    unsigned long n = 0;

    v2_frames_init(&p);
    CHECK(v2_frames_free_count(&p) == (unsigned long)(V2_FRAMES_MAX - 1));
    CHECK(p.used[0] == 1);

    /* Frame 0 is reserved: never allocated, never releasable. */
    CHECK(v2_frames_release(&p, 0) == V2_ERR_INVALID);
    CHECK(!v2_frames_is_allocated(&p, 0));
    CHECK(p.used[0] == 1);

    /* Exhaust: exactly V2_FRAMES_MAX-1 frames, each distinct, none is 0. */
    {
        uint8_t seen[V2_FRAMES_MAX];
        memset(seen, 0, sizeof seen);
        for (;;) {
            f = v2_frames_alloc(&p, (unsigned long)(n % V2_CAP_THREADS));
            if (f < 0)
                break;
            CHECK(f >= 1 && f < V2_FRAMES_MAX);
            CHECK(!seen[f]);
            seen[f] = 1;
            n++;
        }
        CHECK(f == V2_ERR_OVERFLOW);
        CHECK(n == (unsigned long)(V2_FRAMES_MAX - 1));
        CHECK(v2_frames_free_count(&p) == 0);
    }

    /* Double free and out-of-range are errors with no state change. */
    CHECK(v2_frames_release(&p, 5) == V2_OK);
    CHECK(v2_frames_release(&p, 5) == V2_ERR_INVALID);
    CHECK(v2_frames_release(&p, (unsigned long)V2_FRAMES_MAX) == V2_ERR_INVALID);
    CHECK(v2_frames_release(&p, ~0UL) == V2_ERR_INVALID);
    CHECK(v2_frames_free_count(&p) == 1);
    CHECK(p.owner[5] == V2_FRAME_NO_OWNER);

    /* A released frame is reusable and takes the new owner. */
    CHECK(v2_frames_alloc(&p, 7) == 5);
    CHECK(p.owner[5] == 7);

    /* Bad arguments. */
    CHECK(v2_frames_alloc(NULL, 0) == V2_ERR_INVALID);
    CHECK(v2_frames_alloc(&p, (unsigned long)V2_CAP_THREADS) == V2_ERR_INVALID);
    CHECK(v2_frames_release(NULL, 1) == V2_ERR_INVALID);
    (void)i;
    printf("pool: PASS\n");
}

static void test_owners(void)
{
    v2_frames_t p;
    int f, from;
    unsigned long freed = 0;

    v2_frames_init(&p);
    CHECK(v2_frames_alloc(&p, 3) == 1);
    CHECK(v2_frames_alloc(&p, 4) == 2);
    CHECK(v2_frames_alloc(&p, 3) == 3);
    CHECK(v2_frames_alloc(&p, 3) == 4);
    CHECK(v2_frames_alloc(&p, 5) == 5);

    /* The QDESTROY drain loop: free every frame owned by tid 3. */
    for (from = 1; (f = v2_frames_next_owned(&p, 3, from)) >= 0; from = f + 1) {
        CHECK(v2_frames_release(&p, (unsigned long)f) == V2_OK);
        freed++;
    }
    CHECK(freed == 3);
    CHECK(v2_frames_next_owned(&p, 3, 0) == -1);
    CHECK(v2_frames_next_owned(&p, 4, 0) == 2);  /* others untouched */
    CHECK(v2_frames_next_owned(&p, 5, 0) == 5);
    CHECK(v2_frames_next_owned(&p, 4, -7) == 2); /* negative cursor clamps */
    CHECK(v2_frames_next_owned(&p, (unsigned long)V2_CAP_THREADS, 0) == -1);
    CHECK(v2_frames_next_owned(NULL, 0, 0) == -1);
    printf("owners: PASS\n");
}

/* v2_revoke_frame: the kernel-authority revoke. Non-root caps and every
 * mapping of the frame die system-wide; roots and other frames survive;
 * the actor-checked v2_revoke behaves exactly as before. */
static void test_revoke_frame(void)
{
    v2_caps_t st;
    unsigned long t;

    v2_caps_init(&st, 4);
    /* t0 holds a root cap on frame 5 (slot 5). Hand copies to t1/t2 and map. */
    CHECK(v2_grant(&st, 0, 5, 1, 0) == V2_OK);
    CHECK(v2_grant(&st, 0, 5, 2, 0) == V2_OK);
    CHECK(v2_grant(&st, 0, 6, 1, 1) == V2_OK); /* a different frame */
    CHECK(v2_map(&st, 1, 0, 0) == V2_OK);
    CHECK(v2_map(&st, 2, 0, 0) == V2_OK);
    CHECK(v2_map(&st, 1, 1, 1) == V2_OK);

    v2_revoke_frame(&st, 5);
    for (t = 1; t <= 2; t++) {
        CHECK(!st.caps[t][0].valid);
        CHECK(v2_vm_find(&st, t, 0) < 0);
    }
    CHECK(st.caps[0][5].valid && st.caps[0][5].root); /* roots survive */
    CHECK(st.caps[1][1].valid);                       /* other frame intact */
    CHECK(v2_vm_find(&st, 1, 1) >= 0);

    /* Idempotent, and null-safe. */
    v2_revoke_frame(&st, 5);
    v2_revoke_frame(NULL, 5);

    /* Actor-checked wrapper: needs a valid cap, same effect. */
    CHECK(v2_revoke(&st, 3, 0) == V2_ERR_INVALID);
    CHECK(v2_revoke(&st, 1, 1) == V2_OK);
    CHECK(!st.caps[1][1].valid);
    CHECK(v2_vm_find(&st, 1, 1) < 0);
    printf("revoke_frame: PASS\n");
}

/* The rule the kernel relies on at QDESTROY: after revoke_frame + release,
 * a re-allocation hands the frame out clean, and the dead thread holds no
 * path back to it (no cap, no mapping), roots excepted. */
static void test_destroy_cycle(void)
{
    v2_frames_t p;
    v2_caps_t st;
    int round, from, f;
    unsigned long freed;

    v2_frames_init(&p);
    v2_caps_init(&st, 4);
    for (round = 0; round < 100; round++) {
        int a = v2_frames_alloc(&p, 2);
        int b = v2_frames_alloc(&p, 2);
        CHECK(a > 0 && b > 0);
        st.caps[2][0].valid = 1; st.caps[2][0].obj = (unsigned long)a; st.caps[2][0].rights = V2_RIGHT_RW; st.caps[2][0].root = 0;
        st.caps[3][0].valid = 1; st.caps[3][0].obj = (unsigned long)b; st.caps[3][0].rights = V2_RIGHT_R; st.caps[3][0].root = 0;
        CHECK(v2_map(&st, 2, 0, 0) == V2_OK);
        /* qube destroy of tid 2: revoke + free what it owns */
        freed = 0;
        for (from = 1; (f = v2_frames_next_owned(&p, 2, from)) >= 0; from = f + 1) {
            v2_revoke_frame(&st, (unsigned long)f);
            CHECK(v2_frames_release(&p, (unsigned long)f) == V2_OK);
            freed++;
        }
        CHECK(freed == 2);
        CHECK(!st.caps[3][0].valid);          /* granted-out copy died too */
        CHECK(v2_vm_find(&st, 2, 0) < 0);
        CHECK(v2_frames_free_count(&p) == (unsigned long)(V2_FRAMES_MAX - 1));
    }
    printf("destroy cycle x100 (no pool shrink): PASS\n");
}

int main(void)
{
    test_pool();
    test_owners();
    test_revoke_frame();
    test_destroy_cycle();
    printf("test_frames: ALL PASS\n");
    return 0;
}
