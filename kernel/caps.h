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
 * - W^X: X (V2_RIGHT_X) is allowed for ELF code caps/mappings; W+X together
 *   is rejected in mint/map. v2_vm_noexec() pins the W^X invariant (no
 *   mapping may carry both W and X). v2_vm_install_rights() computes
 *   Sv39 PTE flags (R/W/X) from rights, enforcing W^X in hardware PTEs.
 *   ELF rejects W+X segments (elf_ok).
 * - Data is one abstract word per frame (mirrors fdata); read/write need
 *   cap right AND mapping right (mirrors d_write/d_read).
 */
#ifndef V2_CAPS_H
#define V2_CAPS_H

#include <stddef.h>
#include <stdint.h>

/* Frame pool bound (Task 4: 16 -> 32; S4a: 32 -> 40; Task 5 owns the
 * proof impact, V2_D max_frames divergence note extended there, never
 * here).
 * Budget table (measured Task-4 exit, `llvm-readelf -l` page counts):
 *   images: mem 1 + qrexec 2 + adminvm 2 + fw 2 + net 2 + vault 3 +
 *     cryptblk 8 (6 text + rodata + bss) = 20 steady
 *   runtime: net DMA 2 + cryptblk DMA 2 + CAP 1 = 5 steady
 *   transient: key/record frames <= 2 (zeroed + revoked after use)
 *   total steady ~25-27 of 31 usable (frame 0 stays kernel-reserved).
 * Task-3 exit was exactly 15/15 usable: the pool could not fit cryptblk
 * without this bump. 32x4K = 128K fits the 0x81000000 window trivially
 * (asserted in kboot.c beside the pool).
 * S4a: gui image 2 pages (measured `llvm-readelf -l`: RX text + RW bss)
 * + headroom -> 40 (39 usable, steady ~27-29).
 * The LFB is MMIO-leaf range (l0_guifb, never pool frames). */
#define V2_FRAMES_MAX 40
#define V2_CAP_SLOTS 32
/* FDE growth (Task 3): 8 -> 10 threads (vault tid 8, cryptblk tid 9).
 * S4a growth: 10 -> 11 threads (gui tid 10).
 * Page tables (kboot root_pt_t/l1_t/l0_u_t), qube_of[], u_sp[] and the
 * thread table all size with this; NTHREADS in kboot.c must stay <= here
 * (enforced by _Static_assert at the NTHREADS definition). */
#define V2_CAP_THREADS 11
#define V2_VPN_SLOTS 32

#define V2_RIGHT_R 0x1UL
#define V2_RIGHT_W 0x2UL
#define V2_RIGHT_X 0x4UL
#define V2_RIGHT_RW (V2_RIGHT_R | V2_RIGHT_W)
/* QX (qube-cross): IPC gate bit only, never a memory right. Identical
 * value to V2_RIGHT_QX in kernel/qube.h (both headers define 0x8UL;
 * test_qlabels asserts the value). Masked out before any PTE computation. */
#define V2_RIGHT_QX 0x8UL

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
    unsigned long rights; /* subset of {R,W,X}; W^X enforced */
    int root;             /* single-level lineage: init roots only */
} v2_capslot_t;

typedef struct {
    int valid;
    unsigned long vpn;
    unsigned long frame;
    unsigned long rights; /* copied from the mapping cap (X allowed, W^X enforced) */
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

/* Cap is well-formed: object in range, rights subset of {R,W,X,QX}, W^X enforced.
 * QX is an IPC-gate bit only (never installed in a PTE; v2_map rejects it). */
static inline int v2_cap_ok(unsigned long obj, unsigned long rights)
{
    if (obj >= (unsigned long)V2_FRAMES_MAX)
        return 0;
    if (rights & ~(V2_RIGHT_R | V2_RIGHT_W | V2_RIGHT_X | V2_RIGHT_QX))
        return 0;
    if ((rights & V2_RIGHT_W) && (rights & V2_RIGHT_X))
        return 0; /* W^X: never both write and execute */
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
    for (i = 0; i < V2_FRAMES_MAX; i++) /* bound: V2_FRAMES_MAX (40) */
        st->fdata[i] = 0;
    for (i = 0; i < V2_FRAMES_MAX && i < V2_CAP_SLOTS; i++) { /* bound: V2_FRAMES_MAX (40) */
        /* Init roots: thread 0 holds a root cap on every frame the table
         * can name (40 frames, 32 slots: the first 32 frames). */
        st->caps[0][i].valid = 1;
        st->caps[0][i].obj = (unsigned long)i;
        st->caps[0][i].rights = V2_RIGHT_RW;
        st->caps[0][i].root = 1;
    }
}

/* MINT t src rights dst: attenuate own cap into an empty slot of the same
 * table. Copies never inherit the root bit. Mirrors d_mint.
 * Rights may include X (for ELF code caps) or QX (IPC cross-qube grant);
 * W^X is enforced: no W+X together. QX attenuates via the subset check. */
static inline int v2_mint(v2_caps_t *st, unsigned long t, unsigned long src,
                          unsigned long rights, unsigned long dst)
{
    const v2_capslot_t *c;
    if (!st || !v2_has_cap(st, t, src))
        return V2_ERR_INVALID;
    c = &st->caps[t][src];
    if ((rights & ~c->rights) != 0)
        return V2_ERR_INVALID;
    if (rights & ~(V2_RIGHT_R | V2_RIGHT_W | V2_RIGHT_X | V2_RIGHT_QX))
        return V2_ERR_INVALID;
    if ((rights & V2_RIGHT_W) && (rights & V2_RIGHT_X))
        return V2_ERR_INVALID; /* W^X: no write+execute together */
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
 * root bit cleared; QX flows through verbatim so a holder can delegate the
 * cross-qube grant — attenuation happens at MINT time). The only op that
 * grows another thread. Mirrors d_grant. */
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
 * rights (X allowed for ELF code, W^X enforced). Mirrors d_map. */
static inline int v2_map(v2_caps_t *st, unsigned long t, unsigned long slot,
                         unsigned long vpn)
{
    const v2_capslot_t *c;
    int i;
    if (!st || !v2_has_cap(st, t, slot))
        return V2_ERR_INVALID;
    if (v2_vm_find(st, t, vpn) >= 0)
        return V2_ERR_INVALID;
    c = &st->caps[t][slot];
    if (c->rights & V2_RIGHT_QX)
        return V2_ERR_INVALID; /* QX is an IPC-gate bit, never a memory right */
    if ((c->rights & V2_RIGHT_W) && (c->rights & V2_RIGHT_X))
        return V2_ERR_INVALID; /* W^X: mapping cannot be both writable and executable */
    for (i = 0; i < V2_VPN_SLOTS; i++) {
        if (!st->vm[t][i].valid) {
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

/* Compute Sv39 PTE flags from mapping rights (W^X enforced by model).
 * Returns flags suitable for PTE: U|A|D|R|W|X as appropriate.
 * W^X is enforced: if both W and X are set, X is dropped (should not happen if model is correct). */
static inline unsigned long v2_vm_install_rights(unsigned long rights)
{
    unsigned long flags = 0;
    rights &= 0x7UL; /* mask: QX never reaches hardware flags */
    if (rights & V2_RIGHT_R) flags |= 1UL << 1; /* PTE_R */
    if (rights & V2_RIGHT_W) flags |= (1UL << 2) | (1UL << 3); /* PTE_W | PTE_D */
    if ((rights & V2_RIGHT_X) && !(rights & V2_RIGHT_W)) flags |= 1UL << 4; /* PTE_X (only if not W) */
    flags |= (1UL << 0) | (1UL << 6); /* PTE_V | PTE_A (valid + accessed) */
    return flags;
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

/* W^X over mappings (mirrors noexec_vm): no mapping may carry both W and X.
 * QX is ignored here (never set on mappings: v2_map rejects it). */
static inline int v2_vm_noexec(const v2_caps_t *st)
{
    unsigned long t;
    int i;
    if (!st)
        return 0;
    for (t = 0; t < st->nthreads; t++) {
        for (i = 0; i < V2_VPN_SLOTS; i++) {
            if (st->vm[t][i].valid &&
                (st->vm[t][i].rights & V2_RIGHT_W) &&
                (st->vm[t][i].rights & V2_RIGHT_X))
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

/* Frame pool allocator (called from ELF loader). Mirrors kernel frame_pool_init. */
int frame_alloc_slot(v2_caps_t *caps, unsigned long tid);

#endif /* V2_CAPS_H */
