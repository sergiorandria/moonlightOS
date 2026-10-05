/* v2 S-mode kernel (Stage 2): Sv39 U-bit tables, stvec traps, SBI console,
 * timer-preemptive round-robin scheduler (mirrors V2_A.sched_step),
 * two U-mode threads, blocking rendezvous IPC on addressed endpoints
 * (EP i owned by tid i) + notifications (mirrors V2_C: c_send/c_recv/c_notify/c_wait), fault
 * containment. No PMP changes (firmware owns); SUM toggled only inside
 * copy_from/to_user after range validation (S never touches U pages
 * otherwise: stacks filled pre-MMU, console via SBI-forward). */
#include "../userspace/firewall/fw.h" /* S3 demo drives fw_decide (header-only, pure C) */
#include "caps.h"
#include "elf.h"
#include "fbconsole.h" /* S4a kernel framebuffer console output */
#include "initrd.h"
#include "ipc.h"
#include "dev.h"
#include "dev_leaves.h"
#include "irq.h"
#include "blk_hal.h"  /* Block device Hardware Abstraction Layer */
#include "qube.h"
#include "services.h"
#include "virtio_ident.h"
#include "kinternal.h"
#include "uentry.h"
#include <stdint.h>

/* ---- SBI (legacy EIDs; OpenSBI serves M-mode) ---- */
#define SBI_SET_TIMER 0
#define SBI_CONSOLE_PUTCHAR 1

static long sbi_ecall(long eid, long fid, long a0, long a1, long a2)
{
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a6 asm("a6") = fid;
    register long r_a7 asm("a7") = eid;
    asm volatile("ecall" : "+r"(r_a0), "+r"(r_a1) : "r"(r_a2), "r"(r_a6), "r"(r_a7) : "memory");
    return r_a0;
}

void sbi_putchar(char c)
{
    sbi_ecall(SBI_CONSOLE_PUTCHAR, 0, (long)(unsigned char)c, 0, 0);
}

void sbi_set_timer(uint64_t stime)
{
    sbi_ecall(SBI_SET_TIMER, 0, (long)stime, (long)(stime >> 32), 0);
}

/* Boot-time logging flag: when 1, print all debug messages.
 * Set to 0 after services spawn to silence runtime IPC/invoke chatter. */
int boot_log_enabled = 1;
void kputhex(uint64_t v);
void kputdec(unsigned long v);

void kputs(const char *s)
{
    while (*s)
    {
        sbi_putchar(*s);
        s++;
    }
}

/* Debug logging (IPC, invoke, scheduler): only printed during boot */
void klog(const char *s)
{
    if (boot_log_enabled)
    {
        kputs(s);
    }
}

void klog_char(char c)
{
    if (boot_log_enabled)
    {
        sbi_putchar(c);
    }
}

void klog_dec(unsigned long v)
{
    if (boot_log_enabled)
    {
        kputdec(v);
    }
}

void klog_hex(uint64_t v)
{
    if (boot_log_enabled)
    {
        kputhex(v);
    }
}

void kputhex(uint64_t v)
{
    for (int i = 60; i >= 0; i -= 4)
    {
        int n = (v >> i) & 0xF;
        sbi_putchar(n < 10 ? '0' + n : 'a' + n - 10);
    }
}

void kputdec(unsigned long v)
{
    char buf[24];
    int i = 0;
    if (v == 0)
    {
        sbi_putchar('0');
        return;
    }
    while (v > 0 && i < 23)
    {
        buf[i++] = '0' + (v % 10);
        v /= 10;
    }
    while (i-- > 0)
        sbi_putchar(buf[i]);
}

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

uint64_t pte_table(uint64_t *tab)
{
    return (((uint64_t)tab >> 12) << 10) | PTE_V;
}

static void pagetable_init(void)
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

static void frame_pool_init(void)
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

/* frame_release: kernel-authority teardown of one frame (satisfies the
 * caps.h contract). Revoke every non-root cap + every mapping
 * system-wide, clear any hardware PTE still naming the frame, scrub the
 * page and return it to the pool. No-op on frame 0 / out-of-range /
 * already-free frames (fail-closed: never double-frees, never scrubs a
 * live frame). EVERY free path funnels through here (ELF rollback, EXEC,
 * REVOKE-adjacent teardown) so a freed frame is never reachable via a
 * stale cap, mapping, or PTE: use-after-free across fork+exec would be
 * an isolation break, while a leak would only exhaust the pool.
 * NOTE: intentionally NOT owner-checked: the kernel is the authority
 * (mirrors v2_revoke_frame, not v2_revoke). Ownership audits use
 * v2_frames_next_owned on the frames.h side.
 * ROOTS SURVIVE: v2_revoke_frame preserves thread-0 root caps by design
 * (allocator authority, so the mem_server can re-issue). A root still
 * names a freed+reallocated frame — roots are authority, NOT ownership:
 * thread 0 must never be attacker-controlled, and no path may hand a
 * root cap to an untrusted thread (MINT clears root on every copy).
 * SHARED FRAMES: frame_release is system-wide and must ONLY be called
 * for frames with no other live references (fresh loader pages). For
 * frames that may be COW-shared, use frame_teardown_owned below, which
 * drops one thread's side and frees only when unshared. */
void frame_release(unsigned long frame)
{
    unsigned long u;
    int i;
    if (frame >= (unsigned long)V2_FRAME_TOTAL)
        return;
    if (frame == 0 || frame_bitmap[frame] != 0)
        return; /* kernel-reserved / already free: no state change */
    /* Clear every hardware PTE still naming this frame BEFORE the model
     * forgets the (thread, vpn) pairs. bound: threads x vpn slots. */
    for (u = 0; u < (unsigned long)NTHREADS; u++)
    {
        for (i = 0; i < V2_VPN_SLOTS; i++)
        {
            if (caps.vm[u][i].valid && caps.vm[u][i].frame == frame)
                v2_pte_clear(u, caps.vm[u][i].vpn);
        }
    }
    v2_revoke_frame(&caps, frame); /* drops non-root caps + all mappings */
    v2_sfence_all();
    frame_free((int)frame); /* bitmap was 0 (used): zeroes, no double-free warn */
}

/* frame_teardown_owned: drop ONE thread's side of a frame, freeing the
 * frame only when nothing references it anymore. The revoke in
 * frame_release is system-wide: calling it on a COW-shared frame would
 * destroy live siblings' mappings (then free under their stale PTEs).
 * So: drop owner's mappings + PTEs + non-root caps first, then free only
 * if no valid mapping AND no valid non-root cap survives anywhere (a
 * granted-but-unmapped live cap must also block the free, or a later
 * realloc lets it map somebody else's page). Dead co-owners are handled
 * by processing order (each dead side drops in turn; the last one frees).
 * Roots are never cleared here (mirror v2_revoke). No-op on frame 0 /
 * out-of-range / already-free / bad owner (fail closed). */
void frame_teardown_owned(unsigned long owner, unsigned long frame)
{
    unsigned long u;
    int i, live;
    if (owner >= (unsigned long)NTHREADS)
        return;
    if (frame >= (unsigned long)V2_FRAME_TOTAL)
        return;
    if (frame == 0 || frame_bitmap[frame] != 0)
        return; /* kernel-reserved / already free: no state change */
    /* Drop owner's mappings + PTEs for this frame. bound: V2_VPN_SLOTS. */
    for (i = 0; i < V2_VPN_SLOTS; i++)
    {
        if (caps.vm[owner][i].valid && caps.vm[owner][i].frame == frame)
        {
            v2_pte_clear(owner, caps.vm[owner][i].vpn);
            caps.vm[owner][i].valid = 0;
        }
    }
    /* Drop owner's non-root caps for this frame. bound: V2_CAP_SLOTS. */
    for (i = 0; i < V2_CAP_SLOTS; i++)
    {
        v2_capslot_t *c = &caps.caps[owner][i];
        if (c->valid && !c->root && c->obj == frame)
            c->valid = 0;
    }
    /* Free only when no valid mapping AND no valid non-root cap survives
     * anywhere (roots exempt: allocator authority). bound: threads x slots. */
    live = 0;
    for (u = 0; u < (unsigned long)NTHREADS && !live; u++)
    {
        for (i = 0; i < V2_VPN_SLOTS; i++)
        {
            if (caps.vm[u][i].valid && caps.vm[u][i].frame == frame)
            {
                live = 1;
                break;
            }
        }
        for (i = 0; i < V2_CAP_SLOTS && !live; i++)
        {
            const v2_capslot_t *c = &caps.caps[u][i];
            if (c->valid && !c->root && c->obj == frame)
                live = 1;
        }
    }
    if (!live)
        frame_release(frame); /* full revoke (stragglers) + scrub + free */
    else
        v2_sfence_all(); /* owner's PTE clears above need fencing */
}

uint64_t rdtime(void)
{
    uint64_t t;
    asm volatile("rdtime %0" : "=r"(t));
    return t;
}
void kboot(void)
{
    irq_init();
    if (v2_dev_leaves_mapped_count() <= 0)
        kputs("DEVLEAF: none live\n");
    kputs("v2 stage2: S-mode entry (OpenSBI)\n");
    for (int e = 0; e < V2_NEP; e++) /* bound: V2_NEP (11) */
        v2_ep_init(&eps[e]);
    frame_pool_init();
    qube_init(qube_of, (unsigned long)NTHREADS); /* all threads start in qube 0 */
    initrd_init();
    v2_caps_init(&caps, NTHREADS);
    kputs("[caps] init: thread 0 has root caps to all frames\n");
    user_stacks_init(); /* pre-MMU: U stacks need no SUM games */
    u_sp[0] = (uint64_t)ustack_a_top;
    u_sp[1] = (uint64_t)ustack_b_top;
    u_sp[2] = (uint64_t)ustack_m_top;
    u_sp[3] = (uint64_t)ustack_qrexec_top; /* 8KB: policy frame (user.c) */
    u_sp[4] = (uint64_t)ustack_adminvm_top;
    u_sp[5] = (uint64_t)ustack_fw_top;
    u_sp[6] = (uint64_t)ustack_net_top;
    u_sp[7] = (uint64_t)ustack_cap_top;
    u_sp[8] = (uint64_t)ustack_vault_top;
    u_sp[9] = (uint64_t)ustack_crypt_top; /* Task 4 spawn reads it */
    u_sp[10] = (uint64_t)ustack_gui_top;  /* S4a spawn reads it */
    pagetable_init();
    uintptr_t root = (uintptr_t)root_pt_t[0];
    uint64_t satp = (8UL << 60) | ((root >> 12) & 0xFFFFFFFFFFFUL);
    asm volatile("csrw satp, %0" ::"r"(satp) : "memory");
    asm volatile("sfence.vma" ::: "memory");
    asm volatile("csrc sstatus, %0" ::"r"((1UL << 18) | (1UL << 19)) : "memory");
    /* Activate kernel framebuffer console: GUI_LFB_PHYS is now reachable via
     * the S-only l1_m[385] megapage (mapped pre-MMU in pagetable_init).
     * Every subsequent kputs() call mirrors to both UART and the display. */
    fbcon_clear();
    kputs("MoonlightOS v2 kernel\n");
    kputs("v2: satp Sv39 on, U-bit split (k U=0 / u U=1), SUM=0\n");
    device_init();

    for (int i = 0; i < NTHREADS; i++)
    { /* bound: NTHREADS */
        for (int r = 0; r < 32; r++)
            threads[i].regs[r] = 0;
        threads[i].sepc = 0;
        threads[i].state = T_PARKED;
        threads[i].ipc_ptr = 0;
        threads[i].ipc_cap = 0;
        threads[i].notify = 0;
        threads[i].wait_kind = V2_WK_NONE;
        threads[i].vspace_root_ppn = (8UL << 60) | (((uintptr_t)root_pt_t[i] >> 12) & 0xFFFFFFFFFFFUL);
    }
    /* A valid trap target must exist BEFORE interrupts are enabled: a stale
     * firmware timer can pend and fire at SIE-enable, while cur_ctx is still
     * NULL -> entry faults loading ctx -> fault loop. Parked + mapped is
     * always safe (handler prints and halts). */
    cur = 0;
    cur_ctx = &threads[0];
    trap_stack_top = (uintptr_t)(trap_stack + sizeof(trap_stack));
    asm volatile("csrw sscratch, %0" ::"r"(trap_stack_top) : "memory");
    /* Arm our timer BEFORE enabling: reprograms stimecmp, de-asserting any
     * stale firmware pending bit. */
    sbi_set_timer(rdtime() + TICK_DELTA);
    /* Phase-2 NIC PLIC setup lives in the discovery block above (priority
     * + enable for the found IRQ, threshold 0 on the claimed context). */
    asm volatile("csrs sie, %0" ::"r"((1UL << 5) | (1UL << 9)) : "memory"); /* STIE + SEIE */
    asm volatile("csrs sstatus, %0" ::"r"(1UL << 1) : "memory");            /* SIE */

    /* Thread 0: parked (was test thread A, not needed for production microkernel) */
    threads[0].regs[2] = u_sp[0];
    threads[0].sepc = (uint64_t)user_a_main;
    threads[0].state = T_PARKED;
    threads[1].regs[2] = u_sp[1];
    threads[1].sepc = (uint64_t)user_b_main;
    threads[1].state = T_RUNNABLE;
    threads[2].regs[2] = u_sp[2];
    threads[2].sepc = (uint64_t)mem_server_main;
    threads[2].state = T_RUNNABLE;
    /* Thread 7 is the scratch slot: it keeps the in-kernel capability demo
     * (CAP/OK/DU/NP markers) that thread 3 ran before the S2 brokers took
     * threads 3-4 (and the S3 packet plane takes threads 5-6). */
    threads[7].regs[2] = u_sp[7];
    threads[7].sepc = (uint64_t)test_cap_thread;
    threads[7].state = T_RUNNABLE;
    elf_loader_spawn("mem_server", 0, 2, "FAIL; stub");
    elf_loader_spawn("shell", 1, 1, "FAIL; parked");
    elf_loader_spawn("console", 3, 3, "FAIL; parked");
    elf_loader_spawn("tty", 4, 4, "FAIL; parked");
    elf_loader_spawn("vault", 8, 8, "FAIL or missing; parked");
    elf_loader_spawn("cryptblk", 9, 9, "FAIL or missing; parked");
    elf_loader_spawn("gui", 10, 10, "FAIL; parked");

    /* Production microkernel boot complete: all services loaded */

    /* Qube assignments (production microkernel - all services in qube 0):
     * For the production microkernel, all services run in qube 0 (system qube)
     * to allow free IPC communication without qube security barriers.
     * - Thread 0: kernel (qube 0)
     * - Thread 1: shell/moonsh (qube 0)
     * - Thread 2: mem_server (qube 0)
     * - Thread 3: console (qube 0)
     * - Thread 4: tty (qube 0)
     * - Thread 8: vault (qube 0)
     * - Thread 9: cryptblk (qube 0)
     * - Thread 10: gui (qube 0)
     */
    qube_of[1] = 0;  /* Shell */
    qube_of[2] = 0;  /* mem_server */
    qube_of[3] = 0;  /* console */
    qube_of[4] = 0;  /* tty */
    qube_of[8] = 0;  /* vault */
    qube_of[9] = 0;  /* cryptblk */
    qube_of[10] = 0; /* gui */
    qube_next = 1;   /* Next available qube for future isolation */

    kputs("Services: mem+console+tty+vault+cryptblk+gui up\n");

    /* Disable verbose runtime logging now that boot is complete */
    boot_log_enabled = 0;

    /* Boot complete - enter scheduler at thread 2 (mem_server) */
    kputs("v2: entering U-mode\n");
    enter_thread(2);
}

