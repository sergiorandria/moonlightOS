/* vm.c - Sv39 address spaces + frame pool + PTE<->model sync (SRP: memory).
 *
 * Split out of kboot.c/syscall.c (SOLID Sprint 1b, production-ready):
 * page-table construction, the frame pool, hardware PTE install/clear,
 * and the model-sync + COW-break machinery. Matches kernel.h's vm.c. */
#include <stdint.h>

#include "caps.h"
#include "kinternal.h"
#include "platform.h"

/* ---- Sv39 ---- */

/* Pool window (Task 4): 32x4K = 128K, trivially inside both the l0_frames
 * identity map (512 pages = 2M) and the free region above the image. */
_Static_assert((unsigned long)V2_FRAMES_MAX * 4096UL <= 512UL * 4096UL,
               "frame pool must fit the l0_frames identity map");
/* Threads: 0 A, 1 B, 2 mem_server, 3 qrexec, 4 AdminVM, 5 firewall,
 * 6 net, 7 CAP stub, 8 vault, 9 cryptblk, 10 gui. Growing NTHREADS
 * forces WCET/table re-analysis: threads[], qube_of[], u_sp[] size with
 * it; root_pt_t/l1_t/l0_u_t cover V2_CAP_THREADS. NTHREADS == 11 ==
 * V2_CAP_THREADS: the thread table is full — the next thread forces a
 * V2_CAP_THREADS bump + proof replay (S4b). */
_Static_assert(NTHREADS <= V2_CAP_THREADS, "NTHREADS must fit the caps model + page tables");

/* Per-thread Sv39 VSpaces. root_pt_t = root (index VPN[2]), l1_t = level-1
 * (index VPN[1]), l0_u_t = per-thread frame window (VPN[1] of 0x80800000).
 * l1_m (UART), l0_k (kernel image) and l0_frames (frame region) are shared
 * and referenced by every thread's tables. */
uint64_t root_pt_t[V2_CAP_THREADS][512] __attribute__((aligned(4096)));
uint64_t l1_t[V2_CAP_THREADS][512] __attribute__((aligned(4096)));
uint64_t l0_u_t[V2_CAP_THREADS][512] __attribute__((aligned(4096)));
uint64_t l1_m[512] __attribute__((aligned(4096)));
uint64_t l0_k[512] __attribute__((aligned(4096)));
uint64_t l0_frames[512] __attribute__((aligned(4096)));
static uint64_t pte_leaf(uint64_t paddr, uint64_t flags)
{
    return ((paddr >> 12) << 10) | flags | PTE_V;
}

static uint64_t pte_table(uint64_t *tab)
{
    return (((uint64_t)tab >> 12) << 10) | PTE_V;
}

void pagetable_init(void)
{
    extern char _stext[], _erx[];
    uintptr_t text_start = (uintptr_t)_stext & ~0xFFFUL;
    uintptr_t text_end = ((uintptr_t)_erx + 0xFFFUL) & ~0xFFFUL;
    for (int i = 0; i < 512; i++)
    {
        uintptr_t pa = 0x80200000UL + (uintptr_t)i * 4096;
        uint64_t f = PTE_R | PTE_W | PTE_A | PTE_D;
        if (pa >= text_start && pa < text_end)
            f = PTE_R | PTE_X | PTE_A;
        l0_k[i] = pte_leaf(pa, f);
    }
    for (int i = 0; i < 512; i++) /* bound: 512 */
        l0_frames[i] = pte_leaf(V2_FRAME_PHYS_BASE + (uintptr_t)i * 4096, PTE_R | PTE_W | PTE_A | PTE_D);
    l1_m[128] = pte_leaf(0x10000000UL, PTE_R | PTE_W | PTE_A | PTE_D);
    /* Phase-2 NIC: S-only RW leaves for the PLIC region
     * (0x0c000000-0x0c3fffff: priority/pending/enable + hart-0
     * threshold/claim), mirroring the l1_m[128] UART line. */
    l1_m[96] = pte_leaf(0x0c000000UL, PTE_R | PTE_W | PTE_A | PTE_D);
    l1_m[97] = pte_leaf(0x0c200000UL, PTE_R | PTE_W | PTE_A | PTE_D);
    /* S4a GUI ECAM S-leaf: 2MB megapage at VPN[1] 384 covering
     * 0x30000000-0x301FFFFF (buses 0-1). S-only (no U bit): the kernel's
     * BAR programming below runs in S-mode post-MMU through it; the ELF
     * never sees this VA (it uses the l0_guiecam U-leaf instead). */
    l1_m[384] = pte_leaf(GUI_ECAM_PHYS, PTE_R | PTE_W | PTE_A | PTE_D);
    /* S4a GUI LFB S-leaf: 2MB megapage at VPN[1] 385 covering
     * 0x40000000-0x401FFFFF (GUI framebuffer). S-only (no U bit): the kernel
     * can write boot messages here post-MMU; the ELF uses its own l0_guifb U-leaf. */
    l1_m[385] = pte_leaf(GUI_LFB_PHYS, PTE_R | PTE_W | PTE_A | PTE_D);
    /* Bochs VBE registers: BAR2 is assigned GUI_VBE_PHYS below and reached
     * through this S-only alias. */
    l1_m[386] = pte_leaf(GUI_VBE_PHYS, PTE_R | PTE_W | PTE_A | PTE_D);
    /* Phase-2 NIC U-leaf: all 8 transport pages for tid 6 (NET_UVA +
     * i*0x1000, VPN[1] 5, VPN[0] 0..7: the driver scans for the NIC
     * because QEMU attaches backends last-first). W^X: RW, never X. */
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_netmmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    /* FDE block U-leaf: the same 8 transport pages for tid 9 (BLK_UVA
     * 0x80C00000 = VPN[1] 6, VPN[0] 0..7: the driver scans for the
     * virtio-blk device, never assuming a transport). W^X: RW, never X. */
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_blkmmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    /* RNG U-leaf: the same 8 transport pages for tid 8 (same shape as
     * NET/BLK above: the vault ELF scans for the virtio-rng device,
     * never assuming a transport). W^X: RW, never X. */
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_rngmmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    /* S4c Input U-leaves: kbd and mouse transport pages for tid 10 only.
     * Same shape as NET/BLK/RNG: 8 transport pages, RW never X. */
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_kbdmmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_mousemmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    /* S4a GUI U-leaves (contents fixed pre-MMU; the BAR programming in
     * kboot() assigns this same GUI_LFB_PHYS, so leaf and BAR agree by
     * construction). W^X: RW, never X. */
    for (int k = 0; k < GUI_LFB_PAGES; k++) /* bound: GUI_LFB_PAGES (512) */
        l0_guifb[k] = pte_leaf(GUI_LFB_PHYS + (unsigned long)k * 4096UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    for (int k = 0; k < GUI_ECAM_PAGES; k++) /* bound: GUI_ECAM_PAGES (16) */
        l0_guiecam[k] = pte_leaf(GUI_ECAM_PHYS + (unsigned long)k * 4096UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    /* Per-thread VSpaces: shared kernel/leaf/frame/UART regions are wired
     * through each thread's own l1_t; the per-thread frame window
     * (l0_u_t) stays zero until Task 3 maps frames. */
    for (int t = 0; t < NTHREADS; t++)
    { /* bound: NTHREADS */
        l1_t[t][1] = pte_table(l0_k);
        l1_t[t][2] = pte_leaf(0x80400000UL, PTE_R | PTE_X | PTE_U | PTE_A);
        l1_t[t][3] = pte_leaf(0x80600000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
        l1_t[t][4] = pte_table(l0_u_t[t]);
        l1_t[t][8] = pte_table(l0_frames);
        /* Phase-2 NIC: the transport U-leaf exists ONLY in tid 6's tables
         * (NET_UVA 0x80A00000 = VPN[1] 5). Every other l1_t[t][5] stays 0
         * except tid 8 (RNG leaf: same INDEX, different thread's tables —
         * asserted at boot: "NETMMIO: tid=6 only" + "RNGMMIO"). */
        if (t == 6)
            l1_t[t][5] = pte_table(l0_netmmio);
        /* FDE block: the transport U-leaf exists ONLY in tid 9's tables
         * (BLK_UVA 0x80C00000 = VPN[1] 6). Every other l1_t[t][6] stays 0
         * except tid 10 (GUI LFB: same INDEX, different thread's tables —
         * asserted at boot: "BLKMMIO: tid=9 only" + "GUIMMIO"). */
        if (t == 9)
            l1_t[t][6] = pte_table(l0_blkmmio);
        /* RNG: the transport U-leaf exists ONLY in tid 8's tables
         * (RNG_UVA 0x80A00000 = VPN[1] 5, fresh for tid 8: its frame
         * window is index 4, GUI/BLK use 6/7). Every other l1_t[t][5]
         * stays 0 except tid 6 (NET: same INDEX, different thread's
         * tables — asserted at boot: "RNGMMIO: tid=8 only" + "NETMMIO"). */
        if (t == 8)
            l1_t[t][5] = pte_table(l0_rngmmio);
        /* S4a GUI + S4c Input: LFB + ECAM + kbd + mouse U-leaves exist ONLY
         * in tid 10's tables (GUI_LFB_UVA 0x80C00000 = VPN[1] 6, GUI_ECAM_UVA
         * 0x80E00000 = VPN[1] 7, KBD_MMIO_UVA 0x81200000 = VPN[1] 9,
         * MOUSE_MMIO_UVA 0x81400000 = VPN[1] 10). Exclusivity asserted at
         * boot: "GUIMMIO" / "KBDMMIO" / "MOUSEMMIO" gates. */
        if (t == 10)
        {
            l1_t[t][6] = pte_table(l0_guifb);
            l1_t[t][7] = pte_table(l0_guiecam);
            l1_t[t][9] = pte_table(l0_kbdmmio);
            l1_t[t][10] = pte_table(l0_mousemmio);
        }
        root_pt_t[t][0] = pte_table(l1_m);
        root_pt_t[t][2] = pte_table(l1_t[t]);
    }
}

/* ---- Frame pool (bitmap, 1=free, 0=in-use) ----
 * Frame 0 stays kernel-reserved (its page tables live in kernel RAM, not
 * in the v2 frame region). Frames 1..V2_FRAME_TOTAL-1 map to real physical
 * pages at V2_FRAME_PHYS_BASE + f*4096. */
/* V2_FRAME_TOTAL lives in kinternal.h (shared with syscall.c). */
uint8_t frame_bitmap[V2_FRAME_TOTAL]; /* 1=free, 0=used */

/* Forward declaration for frame_free */
static void frame_zero(int f);

void frame_pool_init(void)
{
    /* Initialize all frames as free, then reserve frame 0 for kernel */
    for (int i = 0; i < V2_FRAME_TOTAL; i++) /* bound: V2_FRAME_TOTAL */
        frame_bitmap[i] = 1;
    frame_bitmap[0] = 0; /* frame 0: kernel-reserved (page tables in kernel RAM) */
}

int frame_alloc(void)
{
    /* Scan from frame 1 (skip kernel-reserved frame 0) */
    for (int i = 1; i < V2_FRAME_TOTAL; i++)
    { /* bound: V2_FRAME_TOTAL */
        if (frame_bitmap[i])
        {
            frame_bitmap[i] = 0;
            return i;
        }
    }
    /* Frame pool exhausted: diagnostic message for debugging */
    kputs("[frame_alloc] EXHAUSTED: all ");
    kputdec((unsigned long)(V2_FRAME_TOTAL - 1));
    kputs(" usable frames in use\n");
    return -1;
}

void frame_free(int f)
{
    if (f >= 0 && f < V2_FRAME_TOTAL)
    {
        /* Double-free protection: fail-closed if already free */
        if (frame_bitmap[f] != 0)
        {
            kputs("[frame_free] WARNING: double-free detected for frame ");
            kputdec((unsigned long)f);
            kputs(" (ignoring)\n");
            return;
        }
        frame_zero(f); /* Security: zero frame data before returning to pool */
        frame_bitmap[f] = 1;
    }
}

/* Zero the 4096-byte real physical page backing frame f. Runs in S-mode
 * with Sv39 on: the write hits VA == PA 0x81000000.. via the S-only
 * l0_frames identity map (l1_t[t][8]); volatile so the memset is never
 * optimized away. */
static void frame_zero(int f)
{
    volatile uint64_t *p = (volatile uint64_t *)(V2_FRAME_PHYS_BASE + (uintptr_t)f * 4096);
    for (int i = 0; i < 512; i++) /* bound: 4096/8 */
        p[i] = 0;
}

/* frame_release is defined beside the caps table below (it needs
 * caps + v2_pte_clear + v2_sfence_all): kernel-authority teardown. */

/* ---- PTE install/clear for the per-thread frame window ----
 * l0_u_t[t][vpn] is thread t's level-0 entry for the frame window at
 * user VA 0x80800000 + vpn*4096 (l1_t[t][4] -> l0_u_t[t], VPN[1]=4).
 * These are kernel-enforcement helpers: they run ONLY after the caps.h
 * model op returned V2_OK, so they never make a PTE state change on a
 * rejected op (fail closed). W^X: X is set only for execute segments;
 * W+X is rejected by the model and dropped defensively here.
 *
 * A 0-rights mapping is skipped (the slot stays 0 = unmapped), the
 * faithful hardware image of "no access": a leaf PTE with V=1 and
 * R=W=X=0 is a reserved table-pointer encoding that at level 0 can
 * never resolve and always faults (carried review finding, T3). */

/* bound: t < V2_CAP_THREADS && vpn < V2_VPN_SLOTS — defensive guard: a
 * miss here means an internal invariant has been broken, fail silently. */
void v2_pte_install(unsigned long t, unsigned long vpn,
                           unsigned long frame, unsigned long rights)
{
    uint64_t flags;
    if (t >= (unsigned long)V2_CAP_THREADS || vpn >= (unsigned long)V2_VPN_SLOTS)
        return;
    if (rights == 0)
        return;      /* R=W=X=0 leaf is the reserved table-pointer encoding */
    rights &= 0x7UL; /* mask: QX (IPC-gate bit) never reaches hardware flags */
    /* W^X: X is installed for execute segments; W+X can never arrive here
     * (rejected by mint/map/ELF validation), and is dropped defensively. */
    flags = PTE_U | PTE_A |
            ((rights & V2_RIGHT_W) ? (PTE_W | PTE_D) : 0) |
            ((rights & V2_RIGHT_R) ? PTE_R : 0) |
            (((rights & V2_RIGHT_X) && !(rights & V2_RIGHT_W)) ? PTE_X : 0);
    l0_u_t[t][vpn] = pte_leaf(V2_FRAME_PHYS_BASE + frame * 4096UL, flags);
}

/* bound: t < V2_CAP_THREADS && vpn < V2_VPN_SLOTS (see v2_pte_install) */
void v2_pte_clear(unsigned long t, unsigned long vpn)
{
    if (t >= (unsigned long)V2_CAP_THREADS || vpn >= (unsigned long)V2_VPN_SLOTS)
        return;
    l0_u_t[t][vpn] = 0;
}

void v2_sfence_all(void)
{
    asm volatile("sfence.vma" ::: "memory");
}

/* ---- Real frame backing copy (Write-Through Mirror) ----
 * WRITE/READ drive the real 4096-byte frame page at PA
 * V2_FRAME_PHYS_BASE + frame*4096, identity-mapped S-only via l0_frames
 * (l1_t[t][8]). fdata stays the caps.h model shadow: v2_write/v2_read
 * still update it first, so host-side coherence holds. These helpers run
 * ONLY after the model op returned V2_OK (fail closed), never cross the
 * pool region (frame < V2_FRAMES_MAX; len <= V2_WORD_BYTES <= 4096),
 * and are byte-accurate through volatile pointers so the copy is never
 * optimized away. */
void v2_real_write(unsigned long frame, const uint8_t *src, size_t len)
{
    volatile uint8_t *dst;
    if (frame >= (unsigned long)V2_FRAMES_MAX || !src)
        return;
    dst = (volatile uint8_t *)(V2_FRAME_PHYS_BASE + frame * 4096UL);
    for (size_t i = 0; i < len; i++) /* bound: V2_WORD_BYTES */
        dst[i] = src[i];
}

void v2_real_read(unsigned long frame, uint8_t *dst, size_t len)
{
    const volatile uint8_t *src;
    if (frame >= (unsigned long)V2_FRAMES_MAX || !dst)
        return;
    src = (const volatile uint8_t *)(V2_FRAME_PHYS_BASE + frame * 4096UL);
    for (size_t i = 0; i < len; i++) /* bound: V2_WORD_BYTES */
        dst[i] = src[i];
}

/* REVOKE capture buffer: one (thread, vpn) pair per possible mapping
 * (V2_CAP_THREADS threads x V2_VPN_SLOTS slots). The scan that fills it
 * and the drain loop that clears from it are both hard-bounded to this
 * size, so it can never overflow. */
v2_revoke_pair_t v2_revoke_pairs[V2_CAP_THREADS * V2_VPN_SLOTS];


/* PT_ALLOC: allocate a zeroed frame and mint a cap to it. Returns cap slot
 * index in a0, or V2_ERR_OVERFLOW if no frames available. */
int frame_alloc_slot(v2_caps_t *caps, unsigned long tid)
{
    int f = frame_alloc();
    if (f < 0)
        return V2_ERR_OVERFLOW;
    frame_zero(f);
    /* Find an empty cap slot and mint a RW cap to the frame */
    for (int i = 0; i < V2_CAP_SLOTS; i++)
    { /* bound: V2_CAP_SLOTS */
        if (!caps->caps[tid][i].valid)
        {
            caps->caps[tid][i].valid = 1;
            caps->caps[tid][i].obj = (unsigned long)f;
            caps->caps[tid][i].rights = V2_RIGHT_RW;
            caps->caps[tid][i].root = 0;
            return i; /* return cap slot index, not V2_OK */
        }
    }
    frame_free(f);
    return V2_ERR_OVERFLOW;
}

/* Mint a cap to an already-allocated frame for tid (COW-break path:
 * the frame came from raw frame_alloc, not frame_alloc_slot, so no cap
 * names it yet). Returns the slot, or -1 when the table is full (caller
 * fails closed: frame freed, fault becomes park-like). Mirrors the mint
 * half of frame_alloc_slot. */
int frame_mint_slot(v2_caps_t *caps, unsigned long tid, unsigned long frame)
{
    for (int i = 0; i < V2_CAP_SLOTS; i++)
    { /* bound: V2_CAP_SLOTS */
        if (!caps->caps[tid][i].valid)
        {
            caps->caps[tid][i].valid = 1;
            caps->caps[tid][i].obj = frame;
            caps->caps[tid][i].rights = V2_RIGHT_RW;
            caps->caps[tid][i].root = 0;
            return i;
        }
    }
    return -1;
}

/* Sync hardware PTEs with the caps model for thread t: (re)install every
 * valid mapping into l0_u_t[t] and fence once. ELF loads record model
 * mappings without touching PTEs, so every load path calls this before
 * the thread can run. Reinstalling existing entries is idempotent.
 * bound: V2_VPN_SLOTS. */
void v2_pte_sync(unsigned long t)
{
    int i;
    if (t >= (unsigned long)V2_CAP_THREADS)
        return;
    for (i = 0; i < V2_VPN_SLOTS; i++)
    {
        if (caps.vm[t][i].valid)
            v2_pte_install(t, caps.vm[t][i].vpn, caps.vm[t][i].frame, caps.vm[t][i].rights);
    }
    v2_sfence_all();
}

/* satp value (mode 8 / Sv39 + root PPN) for thread t's tables. The
 * uctx_t.vspace_root_ppn field always holds this full satp encoding
 * (not a bare PPN); enter_thread loads it straight into satp. */
uint64_t v2_satp_of(unsigned long t)
{
    return (8UL << 60) | ((((uintptr_t)root_pt_t[t] >> 12) & 0xFFFFFFFFFFFUL));
}

/* Build child VSpace: wire the child's tables exactly like pagetable_init
 * wires each thread's tables (shared kernel image, shared frame window,
 * shared UART; the child's OWN l0_u for its user window), and return the
 * child's satp value (0 on bad tid). The child's l0_u starts zeroed; the
 * caller installs mappings (v2_pte_sync) afterwards.
 * bound: fixed 512-entry table loops. */
unsigned long build_child_vspace(unsigned long parent_tid, unsigned long child_tid)
{
    if (child_tid >= (unsigned long)NTHREADS || parent_tid >= (unsigned long)NTHREADS)
        return 0;

    /* Zero child's tables */
    for (int i = 0; i < 512; i++)
        l1_t[child_tid][i] = 0;
    for (int i = 0; i < 512; i++)
        l0_u_t[child_tid][i] = 0;
    for (int i = 0; i < 512; i++)
        root_pt_t[child_tid][i] = 0;

    /* Mirror pagetable_init's per-thread wiring (same indices, same
     * pte_table encoding): root[0] -> shared UART, root[2] -> own l1. */
    l1_t[child_tid][1] = l1_t[parent_tid][1];          /* l0_k: kernel image */
    l1_t[child_tid][8] = l1_t[parent_tid][8];          /* l0_frames: frame pool */
    l1_t[child_tid][4] = pte_table(l0_u_t[child_tid]); /* own user window */
    root_pt_t[child_tid][0] = pte_table(l1_m);         /* shared UART */
    root_pt_t[child_tid][2] = pte_table(l1_t[child_tid]);

    return v2_satp_of(child_tid);
}

/* COW write-protect: drop PTE_W from every W-mapping's hardware PTE in
 * BOTH parent and child tables (the caps model keeps W rights on both
 * sides and stays the authority). A later store faults (R-only PTE) and
 * the fault handler consults the model to authorize the break. No flag
 * bits are hidden in PTEs or rights, so there is nothing that can collide
 * with legitimate RX execute pages.
 * bound: V2_VPN_SLOTS. */
void v2_cow_write_protect(unsigned long parent_tid, unsigned long child_tid)
{
    for (int i = 0; i < V2_VPN_SLOTS; i++)
    {
        if (caps.vm[parent_tid][i].valid && (caps.vm[parent_tid][i].rights & V2_RIGHT_W))
        {
            unsigned long vpn = caps.vm[parent_tid][i].vpn;
            if (vpn >= (unsigned long)V2_VPN_SLOTS)
                continue;
            l0_u_t[parent_tid][vpn] &= ~(PTE_W | PTE_D);
            l0_u_t[child_tid][vpn] &= ~(PTE_W | PTE_D);
        }
    }
    v2_sfence_all();
}
