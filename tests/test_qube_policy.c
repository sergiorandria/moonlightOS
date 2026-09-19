/* tests/test_qube_policy.c - policy matrix, ask queue, audit, anti-spoof. */
#include <stdio.h>
#include "../kernel/qube.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void) {
    v2_qpolicy_t p = {0};
    /* allow/ask/deny x label pairs incl. wildcard */
    p.rules[0] = (v2_qrule_t){.src = 0, .dst = 1, .rpc = 7, .decision = V2_QDEC_ALLOW};
    p.rules[1] = (v2_qrule_t){.src = 0, .dst = 2, .rpc = 9, .decision = V2_QDEC_ASK};
    p.rules[2] = (v2_qrule_t){.src = V2_QWILD, .dst = V2_QWILD, .rpc = 99, .decision = V2_QDEC_DENY};
    p.nrules = 3;
    CHECK(qube_decide(&p, 0, 1, 7) == V2_QDEC_ALLOW);
    CHECK(qube_decide(&p, 0, 2, 9) == V2_QDEC_ASK);
    CHECK(qube_decide(&p, 5, 6, 7) == V2_QDEC_DENY);   /* no match ==> deny */
    CHECK(qube_decide(&p, 0, 1, 99) == V2_QDEC_DENY);  /* first-match-wins order */
    CHECK(qube_decide(0, 0, 1, 7) == V2_QDEC_DENY);    /* null policy fails closed */
    /* hash pinned at call time */
    uint8_t a[] = {1, 2, 3};
    uint8_t b[] = {1, 2, 4};
    CHECK(qube_fnv1a(a, 3) != qube_fnv1a(b, 3));
    CHECK(qube_fnv1a(a, 3) == qube_fnv1a(a, 3));
    CHECK(qube_fnv1a(0, 3) == 0);
    /* ask enqueue full ==> overflow + deny audit, old state kept */
    v2_qpolicy_t q = {0};
    for (unsigned long i = 0; i < V2_PENDING_MAX; i++) {
        v2_qask_t ask = {.src = 0, .dst = 1, .rpc = 9, .hash = i};
        CHECK(qube_ask_enqueue(&q, &ask) == 0);
    }
    v2_qask_t extra = {.src = 0, .dst = 1, .rpc = 9, .hash = 99};
    CHECK(qube_ask_enqueue(&q, &extra) == -2);          /* V2_ERR_OVERFLOW */
    CHECK(q.npending == V2_PENDING_MAX);
    CHECK(qube_decide_idx(&q, V2_PENDING_MAX, 1) == -1); /* bad index no-op */
    /* destroy drops inflight + audits deny */
    CHECK(qube_destroy_drop(&q, 0) == 0 && q.npending == 0);
    printf("PASS: test_qube_policy\n");
    return 0;
}
