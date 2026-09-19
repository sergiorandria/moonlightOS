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

#endif /* V2_QUBE_H */
