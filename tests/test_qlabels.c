/* tests/test_qlabels.c - host unit test for kernel/qube.h labels + raw gate. */
#include <assert.h>
#include <stdio.h>
#include "../kernel/qube.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void) {
    uint8_t q[8];
    unsigned long out = 99;
    qube_init(q, 8);
    CHECK(q[0] == 0 && q[7] == 0);
    CHECK(qube_label_of(q, 8, 0, &out) == 0 && out == 0);
    CHECK(qube_label_of(q, 8, 8, &out) == -1);   /* bad tid */
    CHECK(qube_label_of(q, 8, 0, 0) == -1);      /* null out */
    CHECK(qube_raw_ok(q, 8, 0, 1, 0) == 1);      /* same qube */
    q[1] = 1;
    CHECK(qube_raw_ok(q, 8, 0, 1, 0) == 0);      /* cross-qube, no grant */
    CHECK(qube_raw_ok(q, 8, 0, 1, 1) == 1);      /* cross-qube, QX grant */
    CHECK(qube_raw_ok(q, 8, 0, 9, 1) == 0);      /* bad tid fails closed */
    CHECK(V2_QUBES_MAX == 9 && V2_PENDING_MAX == 32 && V2_RIGHT_QX == 0x8UL);
    CHECK(V2_INV_QCREATE == 14 && V2_INV_QDESTROY == 15);
    printf("PASS: test_qlabels\n");
    return 0;
}
