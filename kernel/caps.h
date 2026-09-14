/* v2 Stage 3 capabilities + memory: mint/grant/map/unmap/revoke over a
 * static frame pool, per-thread VSpaces, ELF validation/mapping.
 *
 * Pure C, no asm, no SBI: host-testable (tests/test_v2caps.c) and included
 * by kboot.c. Mirrors kernel/isabelle/V2_D.thy (max_frames = 8, max_slots =
 * 16, root-bit lineage, W^X, elf_ok/elf_map).
 *
 * Model notes (refinements vs the spec):
 * - Threads: fixed max (V2_CAP_THREADS); live count set at init. The spec's
 *   d_nthreads is the live count; ids >= it fail closed, same as spec.
 * - Mappings: per-thread linear table of V2_VPN_SLOTS entries keyed by vpn
 *   (spec: total function nat => ... option). MAP fails V2_ERR_OVERFLOW
 *   when the table is full (spec has no table-full case; fail-closed here).
 * - Failure codes: spec's False becomes V2_ERR_INVALID, except table-full
 *   which is V2_ERR_OVERFLOW. Guards are checked actor-first, in spec
 *   order; anything failing any step is fail-closed (no partial update).
 * - W^X: X (V2_RIGHT_X) is rejected in mint rights; caps and mappings can
 *   therefore never carry X (grant/map only copy). v2_vm_noexec() pins the
 *   invariant (mirrors noexec_vm). ELF rejects W+X segments (elf_ok).
 * - Data is one abstract word per frame (mirrors fdata); read/write need
 *   cap right AND mapping right (mirrors d_write/d_read).
 */
#ifndef V2_CAPS_H
#define V2_CAPS_H

#include <stddef.h>
#include <stdint.h>

#define V2_FRAMES_MAX 8
#define V2_CAP_SLOTS 16
#define V2_CAP_THREADS 8
#define V2_VPN_SLOTS 32

#define V2_RIGHT_R 0x1UL
#define V2_RIGHT_W 0x2UL
#define V2_RIGHT_X 0x4UL
#define V2_RIGHT_RW (V2_RIGHT_R | V2_RIGHT_W)

/* Error codes share ipc.h values (V2_OK/V2_ERR_INVALID/V2_ERR_OVERFLOW)
 * so kboot.c has one convention. */
#ifndef V2_OK
#define V2_OK 0
#define V2_ERR_INVALID (-1)
#define V2_ERR_OVERFLOW (-2)
#endif

typedef struct {
    int valid;
    unsigned long obj;    /* frame id (< V2_FRAMES_MAX) */
    unsigned long rights; /* subset of {R,W}; X never stored */
    int root;             /* single-level lineage: init roots only */
} v2_capslot_t;

typedef struct {
    int valid;
    unsigned long vpn;
    unsigned long frame;
    unsigned long rights; /* copied from the mapping cap (never X) */
} v2_mapslot_t;

typedef struct {
    v2_capslot_t caps[V2_CAP_THREADS][V2_CAP_SLOTS];
    uint64_t fdata[V2_FRAMES_MAX];
    v2_mapslot_t vm[V2_CAP_THREADS][V2_VPN_SLOTS];
    unsigned long nthreads;
} v2_caps_t;

typedef struct {
    unsigned long vpn;
    unsigned long len;
    int write;
    int exec;
} v2_phdr_t;

#define V2_PHDRS_MAX 4
#define V2_SEG_LEN_MAX 512

/* Cap is well-formed: object in range, rights R/W only (mirrors cap_ok). */
static inline int v2_cap_ok(unsigned long obj, unsigned long rights)
{
    if (obj >= (unsigned long)V2_FRAMES_MAX)
        return 0;
    if (rights & ~(V2_RIGHT_R | V2_RIGHT_W))
        return 0;
    return 1;
}

static inline int v2_cap_holder_ok(const v2_caps_t *st, unsigned long t)
{
    return st && t < st->nthreads && st->nthreads <= (unsigned long)V2_CAP_THREADS;
}

static inline int v2_has_cap(const v2_caps_t *st, unsigned long t, unsigned long s)
{
    const v2_capslot_t *c;
    if (!v2_cap_holder_ok(st, t))
        return 0;
    if (s >= (unsigned long)V2_CAP_SLOTS)
        return 0;
    c = &st->caps[t][s];
    return c->valid && v2_cap_ok(c->obj, c->rights);
}

/* Find a mapping for (t, vpn). Returns index or -1. bound: V2_VPN_SLOTS. */
static inline int v2_vm_find(const v2_caps_t *st, unsigned long t, unsigned long vpn)
{
    int i;
    if (!v2_cap_holder_ok(st, t))
        return -1;
    for (i = 0; i < V2_VPN_SLOTS; i++)
        if (st->vm[t][i].valid && st->vm[t][i].vpn == vpn)
            return i;
    return -1;
}

/* Init: thread 0 gets root caps on every frame (the mem_server); every
 * other table is empty; data is zero; no mappings. Mirrors init_dstate. */
static inline void v2_caps_init(v2_caps_t *st, unsigned long nthreads)
{
    unsigned long t;
    int i;
    if (!st)
        return;
    if (nthreads < 1)
        nthreads = 1;
    if (nthreads > (unsigned long)V2_CAP_THREADS)
        nthreads = (unsigned long)V2_CAP_THREADS;
    st->nthreads = nthreads;
    for (t = 0; t < (unsigned long)V2_CAP_THREADS; t++) {
        for (i = 0; i < V2_CAP_SLOTS; i++) {
            st->caps[t][i].valid = 0;
            st->caps[t][i].obj = 0;
            st->caps[t][i].rights = 0;
            st->caps[t][i].root = 0;
        }
        for (i = 0; i < V2_VPN_SLOTS; i++) {
            st->vm[t][i].valid = 0;
            st->vm[t][i].vpn = 0;
            st->vm[t][i].frame = 0;
            st->vm[t][i].rights = 0;
        }
    }
    for (i = 0; i < V2_FRAMES_MAX; i++)
        st->fdata[i] = 0;
    for (i = 0; i < V2_FRAMES_MAX && i < V2_CAP_SLOTS; i++) {
        st->caps[0][i].valid = 1;
        st->caps[0][i].obj = (unsigned long)i;
        st->caps[0][i].rights = V2_RIGHT_RW;
        st->caps[0][i].root = 1;
    }
}

/* MINT t src rights dst: attenuate own cap into an empty slot of the same
 * table. Copies never inherit the root bit. Mirrors d_mint. */
static inline int v2_mint(v2_caps_t *st, unsigned long t, unsigned long src,
                          unsigned long rights, unsigned long dst)
{
    const v2_capslot_t *c;
    if (!st || !v2_has_cap(st, t, src))
        return V2_ERR_INVALID;
    c = &st->caps[t][src];
    if ((rights & ~c->rights) != 0)
        return V2_ERR_INVALID;
    if ((rights & ~(V2_RIGHT_R | V2_RIGHT_W)) != 0)
        return V2_ERR_INVALID;
    if (dst >= (unsigned long)V2_CAP_SLOTS)
        return V2_ERR_INVALID;
    if (st->caps[t][dst].valid)
        return V2_ERR_INVALID;
    st->caps[t][dst].valid = 1;
    st->caps[t][dst].obj = c->obj;
    st->caps[t][dst].rights = rights;
    st->caps[t][dst].root = 0;
    return V2_OK;
}

/* GRANT from slot to dst_slot: copy a valid cap cross-thread (same rights,
 * root bit cleared). The only op that grows another thread. Mirrors
 * d_grant. */
static inline int v2_grant(v2_caps_t *st, unsigned long from, unsigned long slot,
                           unsigned long to, unsigned long dst)
{
    const v2_capslot_t *c;
    if (!st || !v2_has_cap(st, from, slot))
        return V2_ERR_INVALID;
    if (!v2_cap_holder_ok(st, to))
        return V2_ERR_INVALID;
    if (dst >= (unsigned long)V2_CAP_SLOTS)
        return V2_ERR_INVALID;
    if (st->caps[to][dst].valid)
        return V2_ERR_INVALID;
    c = &st->caps[from][slot];
    st->caps[to][dst].valid = 1;
    st->caps[to][dst].obj = c->obj;
    st->caps[to][dst].rights = c->rights;
    st->caps[to][dst].root = 0;
    return V2_OK;
}

/* MAP t slot vpn: map the frame through a valid cap. Mapping rights = cap
 * rights (never X: frames are data). Mirrors d_map. */
static inline int v2_map(v2_caps_t *st, unsigned long t, unsigned long slot,
                         unsigned long vpn)
{
    const v2_capslot_t *c;
    int i;
    if (!st || !v2_has_cap(st, t, slot))
        return V2_ERR_INVALID;
    if (v2_vm_find(st, t, vpn) >= 0)
        return V2_ERR_INVALID;
    for (i = 0; i < V2_VPN_SLOTS; i++) {
        if (!st->vm[t][i].valid) {
            c = &st->caps[t][slot];
            st->vm[t][i].valid = 1;
            st->vm[t][i].vpn = vpn;
            st->vm[t][i].frame = c->obj;
            st->vm[t][i].rights = c->rights;
            return V2_OK;
        }
    }
    return V2_ERR_OVERFLOW;
}

/* UNMAP t vpn: drop one mapping. Mirrors d_unmap (absent mapping is an
 * error, fail-closed). */
static inline int v2_unmap(v2_caps_t *st, unsigned long t, unsigned long vpn)
{
    int i = v2_vm_find(st, t, vpn);
    if (!st || i < 0)
        return V2_ERR_INVALID;
    st->vm[t][i].valid = 0;
    return V2_OK;
}

/* REVOKE t slot: destroy every NON-ROOT cap to the object system-wide,
 * drop every mapping to it. Roots (the allocator's caps) survive so the
 * mem_server can re-issue. Mirrors d_revoke. bound: threads x slots. */
static inline int v2_revoke(v2_caps_t *st, unsigned long t, unsigned long slot)
{
    unsigned long f, u;
    int i;
    if (!st || !v2_has_cap(st, t, slot))
        return V2_ERR_INVALID;
    f = st->caps[t][slot].obj;
    for (u = 0; u < st->nthreads; u++) {
        for (i = 0; i < V2_CAP_SLOTS; i++) {
            v2_capslot_t *c = &st->caps[u][i];
            if (c->valid && c->obj == f && !c->root)
                c->valid = 0;
        }
        for (i = 0; i < V2_VPN_SLOTS; i++) {
            v2_mapslot_t *m = &st->vm[u][i];
            if (m->valid && m->frame == f)
                m->valid = 0;
        }
    }
    return V2_OK;
}

/* Slot holding a W-cap to frame f in t's table? (mirrors the d_write/d_read
 * existential; witness is found by bounded scan). */
static inline int v2_find_wcap(const v2_caps_t *st, unsigned long t, unsigned long f)
{
    int i;
    if (!v2_cap_holder_ok(st, t))
        return 0;
    for (i = 0; i < V2_CAP_SLOTS; i++) {
        const v2_capslot_t *c = &st->caps[t][i];
        if (c->valid && (c->rights & V2_RIGHT_W) && c->obj == f &&
            v2_cap_ok(c->obj, c->rights))
            return 1;
    }
    return 0;
}

static inline int v2_find_rcap(const v2_caps_t *st, unsigned long t, unsigned long f)
{
    int i;
    if (!v2_cap_holder_ok(st, t))
        return 0;
    for (i = 0; i < V2_CAP_SLOTS; i++) {
        const v2_capslot_t *c = &st->caps[t][i];
        if (c->valid && (c->rights & V2_RIGHT_R) && c->obj == f &&
            v2_cap_ok(c->obj, c->rights))
            return 1;
    }
    return 0;
}

/* Data path: needs cap right AND mapping right. Mirrors d_write/d_read. */
static inline int v2_write(v2_caps_t *st, unsigned long t, unsigned long vpn,
                           uint64_t val)
{
    int i;
    unsigned long f;
    if (!st)
        return V2_ERR_INVALID;
    i = v2_vm_find(st, t, vpn);
    if (i < 0)
        return V2_ERR_INVALID;
    if (!(st->vm[t][i].rights & V2_RIGHT_W))
        return V2_ERR_INVALID;
    f = st->vm[t][i].frame;
    if (f >= (unsigned long)V2_FRAMES_MAX)
        return V2_ERR_INVALID;
    if (!v2_find_wcap(st, t, f))
        return V2_ERR_INVALID;
    st->fdata[f] = val;
    return V2_OK;
}

static inline int v2_read(v2_caps_t *st, unsigned long t, unsigned long vpn,
                          uint64_t *out)
{
    int i;
    unsigned long f;
    if (!st || !out)
        return V2_ERR_INVALID;
    *out = 0;
    i = v2_vm_find(st, t, vpn);
    if (i < 0)
        return V2_ERR_INVALID;
    if (!(st->vm[t][i].rights & V2_RIGHT_R))
        return V2_ERR_INVALID;
    f = st->vm[t][i].frame;
    if (f >= (unsigned long)V2_FRAMES_MAX)
        return V2_ERR_INVALID;
    if (!v2_find_rcap(st, t, f))
        return V2_ERR_INVALID;
    *out = st->fdata[f];
    return V2_OK;
}

/* W^X over mappings (mirrors noexec_vm): no mapping may carry X. */
static inline int v2_vm_noexec(const v2_caps_t *st)
{
    unsigned long t;
    int i;
    if (!st)
        return 0;
    for (t = 0; t < st->nthreads; t++) {
        for (i = 0; i < V2_VPN_SLOTS; i++) {
            if (st->vm[t][i].valid && (st->vm[t][i].rights & V2_RIGHT_X))
                return 0;
        }
    }
    return 1;
}

/* ELF validation (mirrors elf_ok): magic, 1..4 segments, each 1..512
 * pages, never W+X. */
static inline int v2_elf_ok(int magic_ok, const v2_phdr_t *ph, unsigned long n)
{
    unsigned long i;
    if (!magic_ok)
        return 0;
    if (n < 1 || n > (unsigned long)V2_PHDRS_MAX)
        return 0;
    if (!ph)
        return 0;
    for (i = 0; i < n; i++) {
        if (ph[i].len < 1 || ph[i].len > (unsigned long)V2_SEG_LEN_MAX)
            return 0;
        if (ph[i].write && ph[i].exec)
            return 0;
    }
    return 1;
}

/* Pages the loader maps (mirrors elf_map): (vpn, writable) per page. */
static inline unsigned long v2_elf_map_count(const v2_phdr_t *ph, unsigned long n)
{
    unsigned long i, total = 0;
    if (!ph)
        return 0;
    for (i = 0; i < n; i++)
        total += ph[i].len;
    return total;
}

static inline int v2_elf_map(const v2_phdr_t *ph, unsigned long n,
                             unsigned long *out_vpn, int *out_w,
                             unsigned long cap, unsigned long *out_n)
{
    unsigned long i, k, at = 0;
    if (!ph || !out_vpn || !out_w || !out_n)
        return V2_ERR_INVALID;
    *out_n = 0;
    if (v2_elf_map_count(ph, n) > cap)
        return V2_ERR_OVERFLOW;
    for (i = 0; i < n; i++) {
        for (k = 0; k < ph[i].len; k++) { /* bound: V2_SEG_LEN_MAX */
            out_vpn[at] = ph[i].vpn + k;
            out_w[at] = ph[i].write ? 1 : 0;
            at++;
        }
    }
    *out_n = at;
    return V2_OK;
}

#endif /* V2_CAPS_H */
