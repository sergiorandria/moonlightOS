/* tests/test_qargs.c - ask args (frame+len) survive ask/decide/destroy. */
#include <stdio.h>
#include "../kernel/qube.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void) {
    v2_qpolicy_t q = {0};
    v2_qask_t a = {.src = 0, .dst = 4, .rpc = 3, .hash = 0xAB, .arg0 = 7, .arg1 = 64};
    v2_qask_t b = {.src = 1, .dst = 4, .rpc = 3, .hash = 0xCD, .arg0 = 9, .arg1 = 128};
    CHECK(qube_ask_enqueue(&q, &a) == 0);
    CHECK(qube_ask_enqueue(&q, &b) == 0);
    CHECK(q.pending[0].arg0 == 7 && q.pending[0].arg1 == 64);
    CHECK(q.pending[1].arg0 == 9 && q.pending[1].arg1 == 128);
    CHECK(qube_decide_idx(&q, 0, 1) == 0);       /* approve first */
    CHECK(q.npending == 1);
    CHECK(q.pending[0].arg0 == 9 && q.pending[0].arg1 == 128); /* survivor intact */
    CHECK(q.audit[0].allowed == 1);              /* hash-pinned approve audited */
    CHECK(qube_destroy_drop(&q, 4) == 0 && q.npending == 0);   /* drops dst==4 */
    printf("PASS: test_qargs\n");
    return 0;
}
