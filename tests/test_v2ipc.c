/* tests/test_v2ipc.c — host unit test for kernel/ipc.h (Stage 2).
 * Pins validation order (ep -> length -> range), adversarial lengths,
 * kernel-stamped senders, FIFO order, truncation-with-flag, queue-full
 * fail-closed, notify-free queue ops. Mirrors kernel/isabelle/V2_C.thy. */
#include <assert.h>
#include <stdio.h>

#include "../kernel/ipc.h"

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void) {
    v2_ep_t ep;
    v2_slot_t s;
    uint64_t w[V2_MSG_MAX];
    uint64_t dst[V2_MSG_MAX];
    unsigned long tid, out_len;
    uint64_t stackbuf[4];
    uintptr_t stackaddr = (uintptr_t)stackbuf;

    /* Endpoint + length gates. */
    CHECK(v2_ep_ok(0));
    CHECK(!v2_ep_ok(99));
    CHECK(v2_len_ok(0) && v2_len_ok(4));
    CHECK(!v2_len_ok(5));
    CHECK(!v2_len_ok(0xFFFFFFFFUL));

    /* SEND range: whole U range readable, aligned, bounded. */
    CHECK(v2_send_range_ok((uintptr_t)V2_U_TEXT_BASE, 4));
    CHECK(v2_send_range_ok((uintptr_t)V2_U_DATA_BASE, 1));
    CHECK(!v2_send_range_ok(stackaddr, 1)); /* host pointer: outside U range */
    CHECK(!v2_send_range_ok((uintptr_t)V2_U_TEXT_BASE - 8, 1)); /* below range */
    CHECK(!v2_send_range_ok((uintptr_t)V2_U_END - 8, 2)); /* crosses END */
    CHECK(!v2_send_range_ok((uintptr_t)V2_U_TEXT_BASE + 1, 1)); /* unaligned */
    CHECK(!v2_send_range_ok((uintptr_t)V2_U_TEXT_BASE, 5)); /* oversize */
    CHECK(!v2_send_range_ok((uintptr_t)-8L, 1)); /* overflow-safe top */
    CHECK(!v2_send_range_ok((uintptr_t)V2_U_TEXT_BASE, 0xFFFFFFFFUL));

    /* RECV range: data region only (text is RX). */
    CHECK(v2_recv_range_ok((uintptr_t)V2_U_DATA_BASE, 4));
    CHECK(!v2_recv_range_ok((uintptr_t)V2_U_TEXT_BASE, 1)); /* text not writable */
    CHECK(!v2_recv_range_ok((uintptr_t)V2_U_TEXT_BASE + 0x1FFFF8, 1)); /* last text word */
    CHECK(!v2_recv_range_ok((uintptr_t)V2_U_DATA_BASE + 1, 1)); /* unaligned */
    CHECK(!v2_recv_range_ok((uintptr_t)V2_U_END - 8, 2)); /* crosses END */

    /* Queues: empty take fails closed. */
    v2_ep_init(&ep);
    CHECK(v2_q_take_send(&ep, &s) == V2_ERR_OVERFLOW);
    CHECK(v2_q_take_waiter(&ep, &tid) == V2_ERR_OVERFLOW);

    /* FIFO + kernel-stamped sender. */
    w[0] = 7; w[1] = 8;
    CHECK(v2_q_send(&ep, 0, w, 2) == V2_OK);
    w[0] = 9;
    CHECK(v2_q_send(&ep, 1, w, 1) == V2_OK);
    CHECK(v2_q_take_send(&ep, &s) == V2_OK);
    CHECK(s.sender == 0 && s.len == 2 && s.words[0] == 7 && s.words[1] == 8);
    CHECK(v2_q_take_send(&ep, &s) == V2_OK);
    CHECK(s.sender == 1 && s.len == 1 && s.words[0] == 9);
    CHECK(v2_q_take_send(&ep, &s) == V2_ERR_OVERFLOW);

    /* Waiter FIFO. */
    CHECK(v2_q_wait(&ep, 3) == V2_OK);
    CHECK(v2_q_wait(&ep, 5) == V2_OK);
    CHECK(v2_q_take_waiter(&ep, &tid) == V2_OK && tid == 3);
    CHECK(v2_q_take_waiter(&ep, &tid) == V2_OK && tid == 5);
    CHECK(v2_q_take_waiter(&ep, &tid) == V2_ERR_OVERFLOW);

    /* Queue-full is fail-closed, never silent drop. */
    v2_ep_init(&ep);
    w[0] = 1;
    for (int i = 0; i < V2_IPC_Q; i++) /* bound: V2_IPC_Q (now 32) */
        CHECK(v2_q_send(&ep, 0, w, 1) == V2_OK);
    CHECK(v2_q_send(&ep, 0, w, 1) == V2_ERR_OVERFLOW);
    for (int i = 0; i < V2_IPC_Q; i++) /* bound: V2_IPC_Q (now 32) */
        CHECK(v2_q_wait(&ep, 0) == V2_OK);
    CHECK(v2_q_wait(&ep, 0) == V2_ERR_OVERFLOW);

    /* Delivery: full, truncated-with-flag (never silent), zero-cap. */
    v2_ep_init(&ep);
    w[0] = 1; w[1] = 2; w[2] = 3;
    CHECK(v2_q_send(&ep, 0, w, 3) == V2_OK);
    CHECK(v2_q_take_send(&ep, &s) == V2_OK);
    CHECK(v2_deliver(&s, dst, 4, &out_len) == V2_OK && out_len == 3);
    CHECK(dst[0] == 1 && dst[2] == 3);
    CHECK(v2_deliver(&s, dst, 2, &out_len) == V2_ERR_OVERFLOW && out_len == 2);
    CHECK(dst[0] == 1 && dst[1] == 2);
    CHECK(v2_deliver(&s, dst, 0, &out_len) == V2_ERR_OVERFLOW && out_len == 0);
    CHECK(v2_deliver(0, dst, 4, &out_len) == V2_ERR_INVALID);
    CHECK(v2_deliver(&s, 0, 4, &out_len) == V2_ERR_INVALID);

    /* Zero-length message is legal (matches msg_ok []). */
    v2_ep_init(&ep);
    CHECK(v2_q_send(&ep, 1, w, 0) == V2_OK);
    CHECK(v2_q_take_send(&ep, &s) == V2_OK && s.len == 0 && s.sender == 1);

    /* Addressed EPs: gate + cross-EP isolation (Phase 1). S4a: 11 EPs. */
    CHECK(v2_ep_ok(0) && v2_ep_ok(10));
    CHECK(!v2_ep_ok(11));
    CHECK(!v2_ep_ok(99));
    {
        v2_ep_t epa, epb;
        v2_ep_init(&epa);
        v2_ep_init(&epb);
        w[0] = 41; w[1] = 42;
        CHECK(v2_q_send(&epa, 3, w, 2) == V2_OK);
        /* EP-B sees nothing: cross-EP invisibility. */
        CHECK(v2_q_take_send(&epb, &s) == V2_ERR_OVERFLOW);
        /* EP-A round-trips its own bytes, sender stamped. */
        CHECK(v2_q_take_send(&epa, &s) == V2_OK);
        CHECK(s.sender == 3 && s.len == 2 && s.words[0] == 41 && s.words[1] == 42);
        /* Waiter pairing is per-EP: oldest waiter OF THAT EP. */
        CHECK(v2_q_wait(&epa, 8) == V2_OK);
        CHECK(v2_q_wait(&epb, 9) == V2_OK);
        CHECK(v2_q_take_waiter(&epa, &tid) == V2_OK && tid == 8);
        CHECK(v2_q_take_waiter(&epb, &tid) == V2_OK && tid == 9);
        /* Queue-full on one EP leaves the other working. */
        v2_ep_init(&epa);
        v2_ep_init(&epb);
        for (int i = 0; i < V2_IPC_Q; i++) /* bound: V2_IPC_Q */
            CHECK(v2_q_send(&epa, 0, w, 1) == V2_OK);
        CHECK(v2_q_send(&epa, 0, w, 1) == V2_ERR_OVERFLOW);
        CHECK(v2_q_send(&epb, 0, w, 1) == V2_OK);
    }

    printf("test_v2ipc: ALL PASS\n");
    return 0;
}
