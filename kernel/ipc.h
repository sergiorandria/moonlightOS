/* v2 Stage 2 IPC: endpoint queues + user-range validation.
 *
 * Pure C, no asm, no SBI: host-testable (tests/test_v2ipc.c) and included
 * by kboot.c. Mirrors kernel/isabelle/V2_C.thy (max_msg_len = 4, max_ipc_q =
 * 16, kernel-stamped sender, truncation with explicit overflow flag, wk =
 * wait-kind so NOTIFY wakes only genuine waiters).
 *
 * Copy discipline (V2_DESIGN Sec.4): SEND copies IN (needs R: whole U
 * range), RECV copies OUT (needs W: data region only, text is RX),
 * NOTIFY/WAIT carry no data. Validation order per syscall: endpoint ->
 * length/capacity -> range+alignment -> copy. Anything failing any step
 * is fail-closed (V2_ERR_INVALID); a full queue is V2_ERR_OVERFLOW.
 * Both refine spec "reject" (c_send False / c_recv error shape).
 */
#ifndef V2_IPC_H
#define V2_IPC_H

#include <stdint.h>

#define V2_MSG_MAX 4
#define V2_IPC_Q 16
#define V2_EP0 0
#define V2_NEP 11 /* one endpoint per thread (EP i owned by tid i); rides V2_CAP_THREADS (S4a: 10 -> 11 for gui EP10) */
#define V2_THREADS_MAX 8

#define V2_OK 0
#define V2_ERR_INVALID (-1)
#define V2_ERR_OVERFLOW (-2)

/* U-region layout (mirrors linker.ld: .utext @0x80400000 2M, .udata @0x80600000 2M). */
#define V2_U_TEXT_BASE 0x80400000UL
#define V2_U_DATA_BASE 0x80600000UL
#define V2_U_END 0x80800000UL

/* Wait kinds (mirror V2_C wk): 0 none, 1 send, 2 recv, 3 wait. */
#define V2_WK_NONE 0
#define V2_WK_SEND 1
#define V2_WK_RECV 2
#define V2_WK_WAIT 3

typedef struct {
    uint64_t words[V2_MSG_MAX];
    unsigned long sender; /* kernel-stamped tid, never user-supplied */
    unsigned long len;
} v2_slot_t;

typedef struct {
    v2_slot_t sendq[V2_IPC_Q];
    int send_head;
    int send_len;
    unsigned long recvq[V2_IPC_Q];
    int recv_head;
    int recv_len;
} v2_ep_t;

static inline int v2_ep_ok(unsigned long ep) { return ep < (unsigned long)V2_NEP; }

static inline int v2_len_ok(unsigned long len) { return len <= (unsigned long)V2_MSG_MAX; }

/* Overflow-safe [ua, ua+nwords*8) \subseteq [lo, hi), 8-byte aligned. bound: 1 iter-free check. */
static inline int v2_range_ok(uintptr_t ua, unsigned long nwords, uintptr_t lo, uintptr_t hi)
{
    uint64_t nbytes;
    if (nwords > 262144UL)
        return 0;
    if ((ua & 7UL) != 0)
        return 0;
    nbytes = (uint64_t)nwords * 8u;
    if (ua < lo)
        return 0;
    if (ua > hi)
        return 0;
    if (nbytes > (uint64_t)(hi - ua))
        return 0;
    return 1;
}

/* SEND buffer: readable (whole U range). */
static inline int v2_send_range_ok(uintptr_t ua, unsigned long nwords)
{
    if (!v2_len_ok(nwords))
        return 0;
    return v2_range_ok(ua, nwords, (uintptr_t)V2_U_TEXT_BASE, (uintptr_t)V2_U_END);
}

/* RECV buffer: writable (data region only; text is RX). Capacity is NOT
 * capped at V2_MSG_MAX here: the copy loop is bounded by the stored
 * message length (<= V2_MSG_MAX), and oversized spans fail the range
 * check anyway. */
static inline int v2_recv_range_ok(uintptr_t ua, unsigned long nwords)
{
    return v2_range_ok(ua, nwords, (uintptr_t)V2_U_DATA_BASE, (uintptr_t)V2_U_END);
}

static inline void v2_ep_init(v2_ep_t *ep)
{
    int i;
    ep->send_head = 0;
    ep->send_len = 0;
    ep->recv_head = 0;
    ep->recv_len = 0;
    for (i = 0; i < V2_IPC_Q; i++) { /* bound: V2_IPC_Q */
        ep->sendq[i].sender = 0;
        ep->sendq[i].len = 0;
        ep->recvq[i] = 0;
    }
}

/* Queue a sender. 0 ok, V2_ERR_OVERFLOW when full (fail-closed). */
static inline int v2_q_send(v2_ep_t *ep, unsigned long sender, const uint64_t *w, unsigned long len)
{
    int tail;
    int i;
    if (!ep || !w || !v2_len_ok(len))
        return V2_ERR_INVALID;
    if (ep->send_len >= V2_IPC_Q)
        return V2_ERR_OVERFLOW;
    tail = (ep->send_head + ep->send_len) % V2_IPC_Q;
    for (i = 0; i < (int)len; i++) /* bound: V2_MSG_MAX */
        ep->sendq[tail].words[i] = w[i];
    ep->sendq[tail].sender = sender;
    ep->sendq[tail].len = len;
    ep->send_len++;
    return V2_OK;
}

/* Record a waiting receiver. 0 ok, V2_ERR_OVERFLOW when full. */
static inline int v2_q_wait(v2_ep_t *ep, unsigned long tid)
{
    int tail;
    if (!ep)
        return V2_ERR_INVALID;
    if (ep->recv_len >= V2_IPC_Q)
        return V2_ERR_OVERFLOW;
    tail = (ep->recv_head + ep->recv_len) % V2_IPC_Q;
    ep->recvq[tail] = tid;
    ep->recv_len++;
    return V2_OK;
}

/* Take the oldest waiter. 0 ok + *tid, V2_ERR_OVERFLOW(=empty) if none. */
static inline int v2_q_take_waiter(v2_ep_t *ep, unsigned long *tid)
{
    if (!ep || !tid || ep->recv_len <= 0)
        return V2_ERR_OVERFLOW;
    *tid = ep->recvq[ep->recv_head];
    ep->recv_head = (ep->recv_head + 1) % V2_IPC_Q;
    ep->recv_len--;
    return V2_OK;
}

/* Take the oldest queued send. 0 ok, V2_ERR_OVERFLOW(=empty) if none. */
static inline int v2_q_take_send(v2_ep_t *ep, v2_slot_t *out)
{
    int i;
    if (!ep || !out || ep->send_len <= 0)
        return V2_ERR_OVERFLOW;
    for (i = 0; i < (int)ep->sendq[ep->send_head].len; i++) /* bound: V2_MSG_MAX */
        out->words[i] = ep->sendq[ep->send_head].words[i];
    out->sender = ep->sendq[ep->send_head].sender;
    out->len = ep->sendq[ep->send_head].len;
    ep->send_head = (ep->send_head + 1) % V2_IPC_Q;
    ep->send_len--;
    return V2_OK;
}

/* Copy-out with explicit truncation: returns V2_OK (full) or
 * V2_ERR_OVERFLOW (partial, never silent); *out_len = words written. */
static inline int v2_deliver(const v2_slot_t *s, uint64_t *dst, unsigned long cap, unsigned long *out_len)
{
    unsigned long n;
    unsigned long i;
    if (!s || !dst || !out_len)
        return V2_ERR_INVALID;
    n = s->len < cap ? s->len : cap;
    for (i = 0; i < n; i++) /* bound: V2_MSG_MAX */
        dst[i] = s->words[i];
    *out_len = n;
    return s->len > cap ? V2_ERR_OVERFLOW : V2_OK;
}

#endif /* V2_IPC_H */
