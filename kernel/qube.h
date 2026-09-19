/* kernel/qube.h - S1/S2 qubes: labels, raw-gate, policy/pending/audit.
 * Pure C, no asm, no SBI: host-testable (tests/test_qlabels.c,
 * tests/test_qube_policy.c) and included by kboot.c. Mirrors
 * kernel/isabelle/Qubes_A.thy (first-match-wins, default-deny,
 * bounded pending, append-only audit, total transitions). */
#ifndef V2_QUBE_H
#define V2_QUBE_H

#include <stddef.h>
#include <stdint.h>

#define V2_QUBES_MAX 8
#define V2_POLICY_MAX 32
#define V2_PENDING_MAX 32
#define V2_AUDIT_MAX 64

#define V2_RIGHT_QX 0x8UL
#define V2_INV_QCREATE 14
#define V2_INV_QDESTROY 15

#define V2_QDEC_ALLOW 0
#define V2_QDEC_ASK 1
#define V2_QDEC_DENY 2

typedef struct {
    unsigned long src; /* wildcard = V2_QWILD */
    unsigned long dst;
    unsigned long rpc;
    int decision;      /* V2_QDEC_* */
} v2_qrule_t;

#define V2_QWILD 0xFFFFFFFFUL

typedef struct {
    unsigned long src;
    unsigned long dst;
    unsigned long rpc;
    uint64_t hash;
    unsigned long arg0; /* payload arg 0 (S3: frame_id) — carried, never interpreted */
    unsigned long arg1; /* payload arg 1 (S3: len) — carried, never interpreted */
} v2_qask_t;

typedef struct {
    unsigned long src;
    unsigned long dst;
    unsigned long rpc;
    int allowed;
} v2_qaudit_t;

typedef struct {
    v2_qrule_t rules[V2_POLICY_MAX];
    unsigned long nrules;
    v2_qask_t pending[V2_PENDING_MAX];
    unsigned long npending;
    v2_qaudit_t audit[V2_AUDIT_MAX];
    unsigned long naudit;
} v2_qpolicy_t;

/* Labels: qube_of[tid] valid for tid < nthreads. */
static inline void qube_init(uint8_t *qube_of, unsigned long nthreads)
{
    for (unsigned long i = 0; i < nthreads; i++) /* bound: nthreads <= V2_QUBES_MAX */
        qube_of[i] = 0;
}

static inline int qube_label_of(const uint8_t *qube_of, unsigned long nthreads,
                                unsigned long tid, unsigned long *out)
{
    if (!qube_of || !out || tid >= nthreads)
        return -1; /* V2_ERR_INVALID */
    *out = qube_of[tid];
    return 0; /* V2_OK */
}

/* Raw rendezvous gate: same qube always ok; cross-qube needs QX grant. */
static inline int qube_raw_ok(const uint8_t *qube_of, unsigned long nthreads,
                              unsigned long src_tid, unsigned long dst_tid, int has_qx)
{
    unsigned long s, d;
    if (!qube_of || src_tid >= nthreads || dst_tid >= nthreads)
        return 0;
    s = qube_of[src_tid];
    d = qube_of[dst_tid];
    if (s == d)
        return 1;
    return has_qx ? 1 : 0;
}

/* Policy: first match wins, no match ==> Deny. Wildcards via V2_QWILD. */
static inline int qube_decide(const v2_qpolicy_t *p, unsigned long s, unsigned long d,
                              unsigned long r)
{
    if (!p)
        return V2_QDEC_DENY;
    for (unsigned long i = 0; i < p->nrules; i++) { /* bound: V2_POLICY_MAX */
        if (i >= V2_POLICY_MAX)
            break;
        const v2_qrule_t *rl = &p->rules[i];
        int ms = (rl->src == V2_QWILD || rl->src == s);
        int md = (rl->dst == V2_QWILD || rl->dst == d);
        if (ms && md && rl->rpc == r)
            return rl->decision;
    }
    return V2_QDEC_DENY;
}

static inline uint64_t qube_fnv1a(const uint8_t *b, unsigned long n)
{
    uint64_t h = 1469598103934665603UL;
    if (!b)
        return 0;
    for (unsigned long i = 0; i < n; i++) { /* bound: caller len, checked <= 512 */
        h ^= (uint64_t)b[i];
        h *= 1099511628211UL;
    }
    return h;
}

/* Audit: append-only. When full the new entry is dropped and
 * V2_ERR_OVERFLOW returned; old entries are kept (fail closed). */
static inline int qube_audit(v2_qpolicy_t *q, unsigned long s, unsigned long d,
                             unsigned long r, int allowed)
{
    if (!q)
        return -1; /* V2_ERR_INVALID */
    if (q->naudit >= V2_AUDIT_MAX)
        return -2; /* V2_ERR_OVERFLOW */
    q->audit[q->naudit].src = s;
    q->audit[q->naudit].dst = d;
    q->audit[q->naudit].rpc = r;
    q->audit[q->naudit].allowed = allowed;
    q->naudit++;
    return 0; /* V2_OK */
}

/* Ask enqueue: full ==> Deny-audit + V2_ERR_OVERFLOW, old state kept. */
static inline int qube_ask_enqueue(v2_qpolicy_t *q, const v2_qask_t *ask)
{
    if (!q || !ask)
        return -1; /* V2_ERR_INVALID */
    if (q->npending >= V2_PENDING_MAX) {
        qube_audit(q, ask->src, ask->dst, ask->rpc, 0);
        return -2; /* V2_ERR_OVERFLOW */
    }
    q->pending[q->npending] = *ask;
    q->npending++;
    return 0; /* V2_OK */
}

/* Decide: bad index ==> V2_ERR_INVALID, no state change; else remove the
 * entry and audit allowed=approve. */
static inline int qube_decide_idx(v2_qpolicy_t *q, unsigned long idx, int approve)
{
    v2_qask_t a;
    unsigned long i;
    if (!q)
        return -1; /* V2_ERR_INVALID */
    if (idx >= q->npending || idx >= V2_PENDING_MAX)
        return -1; /* V2_ERR_INVALID */
    a = q->pending[idx];
    for (i = idx; i + 1 < q->npending; i++) { /* bound: V2_PENDING_MAX */
        if (i + 1 >= V2_PENDING_MAX)
            break;
        q->pending[i] = q->pending[i + 1];
    }
    q->npending--;
    return qube_audit(q, a.src, a.dst, a.rpc, approve ? 1 : 0);
}

/* Destroy: drop pending with src/dst == label, Deny-audit each. Returns
 * V2_ERR_OVERFLOW if any audit entry was dropped, else V2_OK. */
static inline int qube_destroy_drop(v2_qpolicy_t *q, unsigned long label)
{
    unsigned long r, w = 0;
    int rc = 0;
    if (!q)
        return -1; /* V2_ERR_INVALID */
    for (r = 0; r < q->npending; r++) { /* bound: V2_PENDING_MAX */
        if (r >= V2_PENDING_MAX)
            break;
        if (q->pending[r].src == label || q->pending[r].dst == label) {
            if (qube_audit(q, q->pending[r].src, q->pending[r].dst,
                           q->pending[r].rpc, 0) != 0)
                rc = -2; /* V2_ERR_OVERFLOW */
        } else {
            if (w < V2_PENDING_MAX)
                q->pending[w] = q->pending[r];
            w++;
        }
    }
    q->npending = w;
    return rc;
}

#endif /* V2_QUBE_H */
