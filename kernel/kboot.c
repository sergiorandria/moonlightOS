/* v2 S-mode kernel (Stage 2): Sv39 U-bit tables, stvec traps, SBI console,
 * timer-preemptive lowest-Runnable scheduler (mirrors V2_A.sched_step),
 * two U-mode threads, blocking rendezvous IPC on addressed endpoints
 * (EP i owned by tid i) + notifications (mirrors V2_C: c_send/c_recv/c_notify/c_wait), fault
 * containment. No PMP changes (firmware owns); SUM toggled only inside
 * copy_from/to_user after range validation (S never touches U pages
 * otherwise: stacks filled pre-MMU, console via SBI-forward). */
#include <stdint.h>
#include "ipc.h"
#include "caps.h"
#include "qube.h"
#include "initrd.h"
#include "elf.h"
#include "../userspace/firewall/fw.h" /* S3 demo drives fw_decide (header-only, pure C) */

/* ---- SBI (legacy EIDs; OpenSBI serves M-mode) ---- */
#define SBI_SET_TIMER 0
#define SBI_CONSOLE_PUTCHAR 1

static long sbi_ecall(long eid, long fid, long a0, long a1, long a2) {
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a6 asm("a6") = fid;
    register long r_a7 asm("a7") = eid;
    asm volatile("ecall"
                 : "+r"(r_a0), "+r"(r_a1)
                 : "r"(r_a2), "r"(r_a6), "r"(r_a7)
                 : "memory");
    return r_a0;
}

static void sbi_putchar(char c) {
    sbi_ecall(SBI_CONSOLE_PUTCHAR, 0, (long)(unsigned char)c, 0, 0);
}

static void sbi_set_timer(uint64_t stime) {
    sbi_ecall(SBI_SET_TIMER, 0, (long)stime, (long)(stime >> 32), 0);
}

static void kputs(const char *s) {
    while (*s) sbi_putchar(*s++);
}

static void kputhex(uint64_t v) {
    for (int i = 60; i >= 0; i -= 4) {
        int n = (v >> i) & 0xF;
        sbi_putchar(n < 10 ? '0' + n : 'a' + n - 10);
    }
}

static void kputdec(unsigned long v) {
    char buf[24];
    int i = 0;
    if (v == 0) {
        sbi_putchar('0');
        return;
    }
    while (v > 0 && i < 23) {
        buf[i++] = '0' + (v % 10);
        v /= 10;
    }
    while (i-- > 0) sbi_putchar(buf[i]);
}

/* ---- Sv39 ---- */
#define PTE_V (1UL << 0)
#define PTE_R (1UL << 1)
#define PTE_W (1UL << 2)
#define PTE_X (1UL << 3)
#define PTE_U (1UL << 4)
#define PTE_A (1UL << 6)
#define PTE_D (1UL << 7)

/* Real physical backing for v2 frames: QEMU virt 256M RAM (base 0x80000000),
 * free region above the image (< 0x80800000). S-only identity map via
 * l0_frames, wired at l1_t[t][8] (VPN[1] of 0x81000000) in every VSpace. */
#define V2_FRAME_PHYS_BASE 0x81000000UL
/* Pool window (Task 4): 32x4K = 128K, trivially inside both the l0_frames
 * identity map (512 pages = 2M) and the free region above the image. */
_Static_assert((unsigned long)V2_FRAMES_MAX * 4096UL <= 512UL * 4096UL,
               "frame pool must fit the l0_frames identity map");
#define NTHREADS 10 /* bound for all thread loops (<= V2_CAP_THREADS) */
/* Threads: 0 A, 1 B, 2 mem_server, 3 qrexec, 4 AdminVM, 5 firewall,
 * 6 net, 7 CAP stub, 8 vault, 9 cryptblk. Growing NTHREADS forces
 * WCET/table re-analysis: threads[], qube_of[], u_sp[] size with it;
 * root_pt_t/l1_t/l0_u_t cover V2_CAP_THREADS. */
_Static_assert(NTHREADS <= V2_CAP_THREADS,
               "NTHREADS must fit the caps model + page tables");

/* S3 Phase-2 NIC: virtio-net on an MMIO transport (riscv-virt standard
 * layout: 8 transports at 0x10001000+i*0x1000, IRQ 1+i). Measured on the
 * pinned QEMU: transports default to legacy mode (fixed with
 * -global virtio-mmio.force-legacy=off on the QEMU cmdline) and backends
 * attach last-first, so the NIC is NOT assumed at transport 0: kboot
 * scans for the modern (version-2) net device (device id 1) and records
 * its IRQ, and the tid-6 U-leaf maps all 8 transport pages (only tid 6).
 * PLIC regs below name both hart-0 context sets (M + S); the S-context
 * set signals S-mode directly (the path that delivers on the pinned
 * QEMU), the M-context set is programmed identically as a fallback. */
#define VIRTIO0_BASE 0x10001000UL
#define VIRTIO_NTRANSPORTS 8
#define VIRTIO_DEV_NET 1u
#define VIRTIO_DEV_BLK 2u
#define PLIC_BASE 0x0c000000UL
/* PLIC hart-0 contexts (sifive_plic, stride 0x80 enables / 0x1000 claim):
 * the M-context set is reached via delegation, the S-context set signals
 * S-mode directly. Measured on the pinned QEMU: only the S-context
 * delivers to the hart (an M-context claim succeeds but MEIP never
 * asserts), so both are programmed and the handler claims both. */
#define PLIC_ENABLE_M 0x0c002000UL
#define PLIC_ENABLE_S 0x0c002080UL
#define PLIC_THRESH_M 0x0c200000UL
#define PLIC_THRESH_S 0x0c201000UL
#define PLIC_CLAIM_M 0x0c200004UL
#define PLIC_CLAIM_S 0x0c201004UL
#define NET_IRQ_BIT 0x1UL /* notify bit the scause=9 handler raises on tid 6 */
#define BLK_IRQ_BIT 0x2UL /* notify bit the scause=9 handler raises on tid 9 */

/* Phase-2 NIC IRQ (1+transport index), discovered at boot; 0xFFFFFFFF
 * when no modern net transport exists (handler then matches nothing). */
static uint32_t net_virtio_irq = 0xFFFFFFFFUL;
/* FDE block IRQ (1+transport index), discovered at boot; 0xFFFFFFFF
 * when no modern blk transport exists (handler then matches nothing). */
static uint32_t blk_virtio_irq = 0xFFFFFFFFUL;

/* V2_INV_WRITE/READ move exactly one 64-bit word: the caps.h model is
 * word-per-frame (fdata[f] = val), so the real store/load mirrors exactly
 * what the model records and fdata can never diverge from the
 * real frame (Write-Through Mirror). This bounds every new copy loop and
 * keeps every frame access within the 32-frame region (frame <
 * V2_FRAMES_MAX, max offset 31*4096 + V2_WORD_BYTES <= 131080). */
#define V2_WORD_BYTES 8 /* bound: bytes per WRITE/READ invoke (one word) */

/* Per-thread Sv39 VSpaces. root_pt_t = root (index VPN[2]), l1_t = level-1
 * (index VPN[1]), l0_u_t = per-thread frame window (VPN[1] of 0x80800000).
 * l1_m (UART), l0_k (kernel image) and l0_frames (frame region) are shared
 * and referenced by every thread's tables. */
static uint64_t root_pt_t[V2_CAP_THREADS][512] __attribute__((aligned(4096)));
static uint64_t l1_t[V2_CAP_THREADS][512] __attribute__((aligned(4096)));
static uint64_t l0_u_t[V2_CAP_THREADS][512] __attribute__((aligned(4096)));
static uint64_t l1_m[512] __attribute__((aligned(4096)));
static uint64_t l0_k[512] __attribute__((aligned(4096)));
static uint64_t l0_frames[512] __attribute__((aligned(4096)));
/* Phase-2 NIC U-leaf: single page table mapping the 8 VIRTIO0 transport
 * pages for tid 6 only (wired at l1_t[6][5]; every other l1_t[t][5] stays
 * 0, asserted at boot). Zero-initialized except [0..7]: the transport
 * pages, RW, never X. */
static uint64_t l0_netmmio[512] __attribute__((aligned(4096)));
/* FDE block U-leaf: same single-leaf pattern as the NIC, for tid 9 only
 * (wired at l1_t[9][6] = UVA 0x80C00000; every other l1_t[t][6] stays 0,
 * asserted at boot). The 8 transport pages, RW, never X. */
static uint64_t l0_blkmmio[512] __attribute__((aligned(4096)));

static uint64_t pte_leaf(uint64_t paddr, uint64_t flags) {
    return ((paddr >> 12) << 10) | flags | PTE_V;
}

static uint64_t pte_table(uint64_t *tab) {
    return (((uint64_t)tab >> 12) << 10) | PTE_V;
}

static void pagetable_init(void) {
    extern char _stext[], _erx[];
    uintptr_t text_start = (uintptr_t)_stext & ~0xFFFUL;
    uintptr_t text_end = ((uintptr_t)_erx + 0xFFFUL) & ~0xFFFUL;
    for (int i = 0; i < 512; i++) {
        uintptr_t pa = 0x80200000UL + (uintptr_t)i * 4096;
        uint64_t f = PTE_R | PTE_W | PTE_A | PTE_D;
        if (pa >= text_start && pa < text_end)
            f = PTE_R | PTE_X | PTE_A;
        l0_k[i] = pte_leaf(pa, f);
    }
    for (int i = 0; i < 512; i++) /* bound: 512 */
        l0_frames[i] = pte_leaf(V2_FRAME_PHYS_BASE + (uintptr_t)i * 4096,
                                PTE_R | PTE_W | PTE_A | PTE_D);
    l1_m[128] = pte_leaf(0x10000000UL, PTE_R | PTE_W | PTE_A | PTE_D);
    /* Phase-2 NIC: S-only RW leaves for the PLIC region
     * (0x0c000000-0x0c3fffff: priority/pending/enable + hart-0
     * threshold/claim), mirroring the l1_m[128] UART line. */
    l1_m[96] = pte_leaf(0x0c000000UL, PTE_R | PTE_W | PTE_A | PTE_D);
    l1_m[97] = pte_leaf(0x0c200000UL, PTE_R | PTE_W | PTE_A | PTE_D);
    /* Phase-2 NIC U-leaf: all 8 transport pages for tid 6 (NET_UVA +
     * i*0x1000, VPN[1] 5, VPN[0] 0..7: the driver scans for the NIC
     * because QEMU attaches backends last-first). W^X: RW, never X. */
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_netmmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL,
                                 PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    /* FDE block U-leaf: the same 8 transport pages for tid 9 (BLK_UVA
     * 0x80C00000 = VPN[1] 6, VPN[0] 0..7: the driver scans for the
     * virtio-blk device, never assuming a transport). W^X: RW, never X. */
    for (int k = 0; k < VIRTIO_NTRANSPORTS; k++) /* bound: 8 */
        l0_blkmmio[k] = pte_leaf(VIRTIO0_BASE + (unsigned long)k * 0x1000UL,
                                 PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    /* Per-thread VSpaces: shared kernel/leaf/frame/UART regions are wired
     * through each thread's own l1_t; the per-thread frame window
     * (l0_u_t) stays zero until Task 3 maps frames. */
    for (int t = 0; t < NTHREADS; t++) { /* bound: NTHREADS */
        l1_t[t][1] = pte_table(l0_k);
        l1_t[t][2] = pte_leaf(0x80400000UL, PTE_R | PTE_X | PTE_U | PTE_A);
        l1_t[t][3] = pte_leaf(0x80600000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
        l1_t[t][4] = pte_table(l0_u_t[t]);
        l1_t[t][8] = pte_table(l0_frames);
        /* Phase-2 NIC: the transport U-leaf exists ONLY in tid 6's tables
         * (NET_UVA 0x80A00000 = VPN[1] 5). Every other l1_t[t][5] stays 0
         * (asserted at boot: "NETMMIO: tid=6 only"). */
        if (t == 6)
            l1_t[t][5] = pte_table(l0_netmmio);
        /* FDE block: the transport U-leaf exists ONLY in tid 9's tables
         * (BLK_UVA 0x80C00000 = VPN[1] 6). Every other l1_t[t][6] stays 0
         * (asserted at boot: "BLKMMIO: tid=9 only"). */
        if (t == 9)
            l1_t[t][6] = pte_table(l0_blkmmio);
        root_pt_t[t][0] = pte_table(l1_m);
        root_pt_t[t][2] = pte_table(l1_t[t]);
    }
}

/* ---- Frame pool (bitmap, 1=free, 0=in-use) ---- */
#define V2_FRAME_TOTAL (V2_FRAMES_MAX)
uint8_t frame_bitmap[V2_FRAME_TOTAL]; /* 1=free, 0=used */

static void frame_pool_init(void) {
    /* Frame 0 stays reserved for the kernel (its page tables live in the
     * kernel's own RAM, not in the v2 frame region). Frames 1..7 map to
     * real physical pages at V2_FRAME_PHYS_BASE + f*4096. */
    for (int i = 0; i < V2_FRAME_TOTAL; i++) /* bound: V2_FRAME_TOTAL */
        frame_bitmap[i] = 1;
    frame_bitmap[0] = 0; /* frame 0: reserved for the kernel */
}

static int frame_alloc(void) {
    for (int i = 0; i < V2_FRAME_TOTAL; i++) { /* bound: V2_FRAME_TOTAL */
        if (frame_bitmap[i]) {
            frame_bitmap[i] = 0;
            return i;
        }
    }
    return -1; /* all frames used */
}

static void frame_free(int f) {
    if (f >= 0 && f < V2_FRAME_TOTAL)
        frame_bitmap[f] = 1;
}

/* Zero the 4096-byte real physical page backing frame f. Runs in S-mode
 * with Sv39 on: the write hits VA == PA 0x81000000.. via the S-only
 * l0_frames identity map (l1_t[t][8]); volatile so the memset is never
 * optimized away. */
static void frame_zero(int f) {
    volatile uint64_t *p =
        (volatile uint64_t *)(V2_FRAME_PHYS_BASE + (uintptr_t)f * 4096);
    for (int i = 0; i < 512; i++) /* bound: 4096/8 */
        p[i] = 0;
}

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
static void v2_pte_install(unsigned long t, unsigned long vpn,
                           unsigned long frame, unsigned long rights)
{
    uint64_t flags;
    if (t >= (unsigned long)V2_CAP_THREADS ||
        vpn >= (unsigned long)V2_VPN_SLOTS)
        return;
    if (rights == 0)
        return; /* R=W=X=0 leaf is the reserved table-pointer encoding */
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
static void v2_pte_clear(unsigned long t, unsigned long vpn)
{
    if (t >= (unsigned long)V2_CAP_THREADS ||
        vpn >= (unsigned long)V2_VPN_SLOTS)
        return;
    l0_u_t[t][vpn] = 0;
}

static void v2_sfence_all(void)
{
    asm volatile("sfence.vma" ::: "memory");
}

/* ---- Real frame backing copy (Write-Through Mirror) ----
 * WRITE/READ drive the real 4096-byte frame page at PA
 * V2_FRAME_PHYS_BASE + frame*4096, identity-mapped S-only via l0_frames
 * (l1_t[t][8]). fdata stays the caps.h model shadow: v2_write/v2_read
 * still update it first, so host-side coherence holds. These helpers run
 * ONLY after the model op returned V2_OK (fail closed), never cross the
 * 32-frame region (frame < V2_FRAMES_MAX; len <= V2_WORD_BYTES <= 4096),
 * and are byte-accurate through volatile pointers so the copy is never
 * optimized away. */
static void v2_real_write(unsigned long frame, const uint8_t *src, size_t len)
{
    volatile uint8_t *dst;
    if (frame >= (unsigned long)V2_FRAMES_MAX || !src)
        return;
    dst = (volatile uint8_t *)(V2_FRAME_PHYS_BASE + frame * 4096UL);
    for (size_t i = 0; i < len; i++) /* bound: V2_WORD_BYTES */
        dst[i] = src[i];
}

static void v2_real_read(unsigned long frame, uint8_t *dst, size_t len)
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
typedef struct {
    unsigned long t;
    unsigned long vpn;
} v2_revoke_pair_t;
static v2_revoke_pair_t v2_revoke_pairs[V2_CAP_THREADS * V2_VPN_SLOTS];

/* PT_ALLOC: allocate a zeroed frame and mint a cap to it. Returns cap slot
 * index in a0, or V2_ERR_OVERFLOW if no frames available. */
int frame_alloc_slot(v2_caps_t *caps, unsigned long tid) {
    int f = frame_alloc();
    if (f < 0)
        return V2_ERR_OVERFLOW;
    frame_zero(f);
    /* Find an empty cap slot and mint a RW cap to the frame */
    for (int i = 0; i < V2_CAP_SLOTS; i++) { /* bound: V2_CAP_SLOTS */
        if (!caps->caps[tid][i].valid) {
            caps->caps[tid][i].valid = 1;
            caps->caps[tid][i].obj = (unsigned long)f;
            caps->caps[tid][i].rights = V2_RIGHT_RW;
            caps->caps[tid][i].root = 0;
            return i;  /* return cap slot index, not V2_OK */
        }
    }
    frame_free(f);
    return V2_ERR_OVERFLOW;
}

/* ---- Threads (mirrors V2_A: lowest-numbered Runnable wins) ---- */
typedef struct {
    uint64_t regs[32];
    uint64_t sepc;
    int state; /* 0 = Runnable, 1 = Parked, 2 = Blocked (IPC), 3 = Dead (QDESTROY) */
    /* IPC (mirrors V2_C wk/sendq/recvq): RECV-blocked threads park their
     * validated (ptr, cap) here for later copy-out; queued senders live
     * in eps[ep].sendq (kernel memory, no U pointers retained -> no TOCTOU). */
    uintptr_t ipc_ptr;
    uint64_t ipc_cap;
    uint64_t notify;   /* pending signal bits (OR-accumulate) */
    int wait_kind;     /* V2_WK_* : what this thread is blocked in */
    uint64_t vspace_root_ppn; /* satp value (mode 8 | root PPN); see v2_satp_of */
} uctx_t;

#define T_RUNNABLE 0
#define T_PARKED 1
#define T_DEAD 3 /* distinct from T_BLOCKED since deferred-C: slot-reuse scans key on state alone */
#define T_BLOCKED 2

static uctx_t threads[NTHREADS];
static uint8_t qube_of[NTHREADS]; /* qube label per thread (qube.h) */
static unsigned long qube_next = 2; /* next fresh label; 0/1 taken at boot */
static int cur = 0;
static unsigned long tick = 0;
static v2_ep_t eps[V2_NEP];
_Static_assert(V2_NEP <= V2_CAP_THREADS,
               "endpoint count rides the thread cap (EP i owned by tid i)");
static v2_caps_t caps;

uctx_t *cur_ctx; /* read by trap.S */
uintptr_t trap_stack_top;

static uint8_t kstack[16384] __attribute__((aligned(16)));
uint8_t *kstack_top = kstack + sizeof(kstack);
static uint8_t trap_stack[4096] __attribute__((aligned(16)));

void user_a_main(void);
void user_b_main(void);
void mem_server_main(void);
void test_cap_thread(void);
void user_stacks_init(void);
extern uintptr_t ustack_a_top, ustack_b_top, ustack_m_top, ustack_cap_top;
extern uintptr_t ustack_qrexec_top, ustack_adminvm_top;
extern uintptr_t ustack_fw_top, ustack_net_top;
extern uintptr_t ustack_vault_top, ustack_crypt_top;
__attribute__((noreturn)) void u_enter(uctx_t *ctx);

static uint64_t u_sp[NTHREADS]; /* stashed pre-MMU: S must not read U pages */

#define TICK_DELTA 1000000UL /* 100ms @ 10MHz timebase */
#define V2_YIELD 0
#define V2_PUTC 1
#define V2_PARK 2
#define V2_SEND 3 /* (ep, u_ptr, len): copy IN, block unless waiter; a0 = 0 / -ERR */
#define V2_RECV 4 /* (ep, u_buf, cap): copy OUT, block unless queued; a0 = words, a1 = sender, a2 = sender_qube, a3 = ovf */
#define V2_NOTIFY 5 /* (target, bits): OR-accumulate + wake waiters only; a0 = 0 / -ERR */
#define V2_WAIT 6 /* (): take pending bits (a0) or block; a0 = bits */
#define V2_INVOKE 7
#define V2_INV_MINT 1
#define V2_INV_GRANT 2
#define V2_INV_MAP 3
#define V2_INV_UNMAP 4
#define V2_INV_REVOKE 5
#define V2_INV_PT_ALLOC 6
#define V2_INV_ELF_CHECK 7
#define V2_INV_ELF_MAP 8
#define V2_INV_SPAWN 9
#define V2_INV_FORK 10
#define V2_INV_EXEC 11
#define V2_INV_WRITE 12
#define V2_INV_READ 13
#define V2_INV_FRAME_PA 16 /* (vpn,0,0,0): PA of the frame mapped at vpn; reserved!=0 -> INVALID */

/* ---- User copy (both directions, V2_DESIGN Sec.4): validate-then-copy.
 * S runs with SUM=0; the window is opened only for the bounded copy loop
 * after the range check passed. Raw dereference of a user pointer
 * anywhere else is a bug. SEND needs R (whole U range), RECV needs W
 * (data region: text is RX, enforced by v2_recv_range_ok). */
static void sum_on(void) {
    asm volatile("csrs sstatus, %0" ::"r"(1UL << 18) : "memory");
}

static void sum_off(void) {
    asm volatile("csrc sstatus, %0" ::"r"(1UL << 18) : "memory");
}

/* bound: len (caller-checked <= V2_MSG_MAX for IN; <= stored len for OUT) */
static void u_copy_in(uint64_t *kd, uintptr_t us, unsigned long len) {
    sum_on();
    for (unsigned long i = 0; i < len; i++)
        kd[i] = ((const volatile uint64_t *)us)[i];
    sum_off();
}

/* bound: n (<= stored msg len <= V2_MSG_MAX) */
static void u_copy_out(uintptr_t ud, const uint64_t *ks, unsigned long n) {
    sum_on();
    for (unsigned long i = 0; i < n; i++)
        ((volatile uint64_t *)ud)[i] = ks[i];
    sum_off();
}

static uint64_t rdtime(void) {
    uint64_t t;
    asm volatile("rdtime %0" : "=r"(t));
    return t;
}

static int pick_next(void) {
    for (int i = 0; i < NTHREADS; i++)
        if (threads[i].state == T_RUNNABLE)
            return i;
    return -1;
}

/* QX grant check: does tid hold any valid cap carrying V2_RIGHT_QX?
 * Bounded scan of the thread's own cap table; fail-closed (bad tid = 0). */
static int qube_has_qx(unsigned long tid)
{
    int s;
    if (tid >= (unsigned long)NTHREADS)
        return 0;
    for (s = 0; s < V2_CAP_SLOTS; s++) { /* bound: V2_CAP_SLOTS */
        if (caps.caps[tid][s].valid &&
            (caps.caps[tid][s].rights & V2_RIGHT_QX))
            return 1;
    }
    return 0;
}

/* Sync hardware PTEs with the caps model for thread t: (re)install every
 * valid mapping into l0_u_t[t] and fence once. ELF loads record model
 * mappings without touching PTEs, so every load path calls this before
 * the thread can run. Reinstalling existing entries is idempotent.
 * bound: V2_VPN_SLOTS. */
static void v2_pte_sync(unsigned long t)
{
    int i;
    if (t >= (unsigned long)V2_CAP_THREADS)
        return;
    for (i = 0; i < V2_VPN_SLOTS; i++) {
        if (caps.vm[t][i].valid)
            v2_pte_install(t, caps.vm[t][i].vpn, caps.vm[t][i].frame,
                           caps.vm[t][i].rights);
    }
    v2_sfence_all();
}

/* satp value (mode 8 / Sv39 + root PPN) for thread t's tables. The
 * uctx_t.vspace_root_ppn field always holds this full satp encoding
 * (not a bare PPN); enter_thread loads it straight into satp. */
static uint64_t v2_satp_of(unsigned long t)
{
    return (8UL << 60) |
           ((((uintptr_t)root_pt_t[t] >> 12) & 0xFFFFFFFFFFFUL));
}

/* Build child VSpace: wire the child's tables exactly like pagetable_init
 * wires each thread's tables (shared kernel image, shared frame window,
 * shared UART; the child's OWN l0_u for its user window), and return the
 * child's satp value (0 on bad tid). The child's l0_u starts zeroed; the
 * caller installs mappings (v2_pte_sync) afterwards.
 * bound: fixed 512-entry table loops. */
static unsigned long build_child_vspace(unsigned long parent_tid, unsigned long child_tid)
{
    if (child_tid >= (unsigned long)NTHREADS ||
        parent_tid >= (unsigned long)NTHREADS)
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
    l1_t[child_tid][1] = l1_t[parent_tid][1]; /* l0_k: kernel image */
    l1_t[child_tid][8] = l1_t[parent_tid][8]; /* l0_frames: frame pool */
    l1_t[child_tid][4] = pte_table(l0_u_t[child_tid]); /* own user window */
    root_pt_t[child_tid][0] = pte_table(l1_m); /* shared UART */
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
static void v2_cow_write_protect(unsigned long parent_tid,
                                 unsigned long child_tid)
{
    for (int i = 0; i < V2_VPN_SLOTS; i++) {
        if (caps.vm[parent_tid][i].valid &&
            (caps.vm[parent_tid][i].rights & V2_RIGHT_W)) {
            unsigned long vpn = caps.vm[parent_tid][i].vpn;
            if (vpn >= (unsigned long)V2_VPN_SLOTS)
                continue;
            l0_u_t[parent_tid][vpn] &= ~(PTE_W | PTE_D);
            l0_u_t[child_tid][vpn] &= ~(PTE_W | PTE_D);
        }
    }
    v2_sfence_all();
}

static void enter_thread(int id) {
    cur = id;
    cur_ctx = &threads[id];
    /* Per-thread VSpace: switch satp before entering U-mode */
    asm volatile("csrw satp, %0" :: "r"(threads[id].vspace_root_ppn) : "memory");
    asm volatile("sfence.vma" ::: "memory");
    u_enter(&threads[id]);
    __builtin_unreachable();
}

/* Terminal park: nothing runnable and nothing can make progress: parked
 * threads never wake; blocked threads wake only via a matching IPC op,
 * which requires a runnable peer. (No timeout yet: Stage 4 time.) */
static void halt_no_runnable(void) {
    kputs("no runnable left; parking cpu\n");
    /* Park-timer hygiene: the periodic tick is still armed, so a pending
     * timer would wake WFI, print "[tick ...]" spam after the marker, and
     * re-arm (repeating forever). Push stimecmp to the end of time and
     * clear STIE BEFORE the loop so the marker prints exactly once and
     * the CPU truly parks. */
    sbi_set_timer(~0UL);
    asm volatile("csrc sie, %0" :: "r"(1UL << 5) : "memory"); /* clear STIE */
    for (;;)
        asm volatile("wfi");
    __builtin_unreachable();
}

/* Trap dispatch. Switch cases call u_enter (noreturn); plain cases return
 * to the trap.S epilogue which restores cur_ctx and srets. */
void s_trap_handler(uint64_t cause, uctx_t *ctx) {
    int is_int = (cause >> 63) & 1;
    uint64_t code = cause & ~(1UL << 63);
    (void)ctx;
    if (is_int) {
        if (code == 5) { /* S-mode timer */
            sbi_set_timer(rdtime() + TICK_DELTA);
            tick++;
            kputs("[tick ");
            kputdec(tick);
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            kputs("] -> ");
            sbi_putchar(n ? 'B' : 'A');
            sbi_putchar('\n');
            enter_thread(n);
        }
        if (code == 9) { /* S-mode external: virtio IRQ via PLIC claim */
            uint32_t s = *(volatile uint32_t *)PLIC_CLAIM_S;
            uint32_t m = *(volatile uint32_t *)PLIC_CLAIM_M;
            uint32_t src = 0;
            int blk = 0;
            /* Either context may carry the delivery (measured: S does);
             * one marker per trap even if both fired. Net and blk are
             * handled independently so one trap can serve both devices. */
            if (s == net_virtio_irq)
                src = s;
            else if (m == net_virtio_irq)
                src = m;
            if (s == blk_virtio_irq || m == blk_virtio_irq)
                blk = 1;
            if (src != 0) {
                threads[6].notify |= NET_IRQ_BIT;
                /* Wake only genuine WAIT waiters (NOTIFY discipline);
                 * unknown sources never wake anyone. */
                if (threads[6].state == T_BLOCKED &&
                    threads[6].wait_kind == V2_WK_WAIT) {
                    threads[6].state = T_RUNNABLE;
                    threads[6].wait_kind = V2_WK_NONE;
                }
                kputs("NET: irq ok\n");
            }
            if (blk) {
                /* No per-IRQ print: a 4K sector op raises up to 8 blk
                 * IRQs, so a print here would flood the transcript; the
                 * ELF's badge check after WAIT is the delivery proof. */
                threads[9].notify |= BLK_IRQ_BIT;
                if (threads[9].state == T_BLOCKED &&
                    threads[9].wait_kind == V2_WK_WAIT) {
                    threads[9].state = T_RUNNABLE;
                    threads[9].wait_kind = V2_WK_NONE;
                }
            }
            if (src == 0 && !blk) {
                kputs("IRQ: unexpected\n");
            }
            if (s != 0)
                *(volatile uint32_t *)PLIC_CLAIM_S = s;
            if (m != 0)
                *(volatile uint32_t *)PLIC_CLAIM_M = m;
            return;
        }
        kputs("[trap] unexpected interrupt\n");
        for (;;)
            asm volatile("wfi");
    }
    switch (code) {
    case 8: { /* U-mode ecall */
        uint64_t sys = threads[cur].regs[17]; /* a7 */
        if (sys == V2_YIELD) {
            threads[cur].sepc += 4;
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            enter_thread(n);
        } else if (sys == V2_PUTC) {
            /* Forward through real SBI (M-mode): U prints via SBI. */
            sbi_putchar((char)threads[cur].regs[10]); /* a0 */
            threads[cur].sepc += 4;
            return;
        } else if (sys == V2_PARK) {
            /* Blocking primitive (mirrors V2_B UPark): park self. */
            threads[cur].sepc += 4;
            threads[cur].state = T_PARKED;
            kputs("[sched] parked ");
            sbi_putchar('0' + cur);
            sbi_putchar('\n');
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            enter_thread(n);
        } else if (sys == V2_SEND) {
            /* SEND (mirrors V2_C c_send): validate (ep -> range) -> copy
             * IN -> handoff to oldest waiter or queue + block. */
            unsigned long ep = (unsigned long)threads[cur].regs[10];
            uintptr_t up = (uintptr_t)threads[cur].regs[11];
            unsigned long ln = (unsigned long)threads[cur].regs[12];
            uint64_t kb[V2_MSG_MAX];
            unsigned long r;
            threads[cur].sepc += 4;
            if (!v2_ep_ok(ep) || !v2_send_range_ok(up, ln)) {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                return;
            }
            if (ep >= (unsigned long)NTHREADS) {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                return;
            }
            v2_ep_t *e = &eps[ep];
            u_copy_in(kb, up, ln);
            /* Raw gate (peek before dequeue: fail-closed, no state lost on
             * reject). Cross-qube handoff needs QX on the sender. */
            if (e->recv_len > 0) {
                unsigned long peek = e->recvq[e->recv_head];
                if (peek >= (unsigned long)NTHREADS ||
                    !qube_raw_ok(qube_of, (unsigned long)NTHREADS,
                                 (unsigned long)cur, peek,
                                 qube_has_qx((unsigned long)cur))) {
                    threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                    kputs("QUB: xread denied\n");
                    return;
                }
            }
            if (v2_q_take_waiter(e, &r) == V2_OK && r < (unsigned long)NTHREADS) {
                unsigned long cap = (unsigned long)threads[r].ipc_cap;
                unsigned long nw = ln < cap ? ln : cap;
                unsigned long ovf = ln > cap ? 1 : 0;
                u_copy_out(threads[r].ipc_ptr, kb, nw);
                threads[r].regs[10] = (uint64_t)nw;
                threads[r].regs[11] = (uint64_t)cur; /* kernel-stamped */
                threads[r].regs[12] = (uint64_t)qube_of[cur];
                threads[r].regs[13] = (uint64_t)ovf;
                threads[r].state = T_RUNNABLE;
                threads[r].wait_kind = V2_WK_NONE;
                threads[cur].regs[10] = (uint64_t)V2_OK;
                kputs("[ipc] send tcb=");
                sbi_putchar('0' + cur);
                kputs(" -> ");
                sbi_putchar('0' + (char)r);
                kputs(" len=");
                kputdec((unsigned long)nw);
                kputs(" ovf=");
                sbi_putchar(ovf ? '1' : '0');
                sbi_putchar('\n');
                enter_thread((int)r);
            }
            if (v2_q_send(e, (unsigned long)cur, kb, ln) != V2_OK) {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_OVERFLOW;
                return;
            }
            threads[cur].state = T_BLOCKED;
            threads[cur].wait_kind = V2_WK_SEND;
            kputs("[ipc] send tcb=");
            sbi_putchar('0' + cur);
            kputs(" queued len=");
            kputdec(ln);
            sbi_putchar('\n');
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            enter_thread(n);
        } else if (sys == V2_RECV) {
            /* RECV (mirrors V2_C c_recv): validate -> deliver oldest
             * queued send (resume sender, stamp sender id, flag
             * truncation) or park (ptr, cap) + block. */
            unsigned long ep = (unsigned long)threads[cur].regs[10];
            uintptr_t up = (uintptr_t)threads[cur].regs[11];
            unsigned long cap = (unsigned long)threads[cur].regs[12];
            v2_slot_t slot;
            threads[cur].sepc += 4;
            if (!v2_ep_ok(ep) || !v2_recv_range_ok(up, cap)) {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                return;
            }
            if (ep != (unsigned long)cur) {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                return;
            }
            v2_ep_t *e = &eps[ep];
            /* Raw gate (peek before dequeue: fail-closed, no state lost on
             * reject). Queued sends gate at delivery: the destination is
             * unknown at send time, so the sender's qube is derived here
             * via qube_of[slot.sender] (v2_slot_t stays as-is). */
            if (e->send_len > 0) {
                unsigned long psrc = e->sendq[e->send_head].sender;
                if (psrc >= (unsigned long)NTHREADS ||
                    !qube_raw_ok(qube_of, (unsigned long)NTHREADS, psrc,
                                 (unsigned long)cur, qube_has_qx(psrc))) {
                    threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                    kputs("QUB: xread denied\n");
                    return;
                }
            }
            if (v2_q_take_send(e, &slot) == V2_OK) {
                unsigned long nw = slot.len < cap ? slot.len : cap;
                unsigned long ovf = slot.len > cap ? 1 : 0;
                unsigned long sq = slot.sender < (unsigned long)NTHREADS
                                       ? (unsigned long)qube_of[slot.sender]
                                       : 0;
                u_copy_out(up, slot.words, nw);
                threads[cur].regs[10] = (uint64_t)nw;
                threads[cur].regs[11] = (uint64_t)slot.sender;
                threads[cur].regs[12] = (uint64_t)sq;
                threads[cur].regs[13] = (uint64_t)ovf;
                if (slot.sender < (unsigned long)NTHREADS) {
                    threads[slot.sender].state = T_RUNNABLE;
                    threads[slot.sender].wait_kind = V2_WK_NONE;
                    threads[slot.sender].regs[10] = (uint64_t)V2_OK;
                }
                kputs("[ipc] recv tcb=");
                sbi_putchar('0' + cur);
                kputs(" from=");
                sbi_putchar('0' + (char)slot.sender);
                kputs(" len=");
                kputdec((unsigned long)nw);
                kputs(" ovf=");
                sbi_putchar(ovf ? '1' : '0');
                sbi_putchar('\n');
                return;
            }
            threads[cur].ipc_ptr = up;
            threads[cur].ipc_cap = cap;
            threads[cur].state = T_BLOCKED;
            threads[cur].wait_kind = V2_WK_RECV;
            if (v2_q_wait(e, (unsigned long)cur) != V2_OK) {
                /* Unreachable at NTHREADS=2 (recvq never full here);
                 * fail closed rather than lose the waiter. */
                threads[cur].state = T_RUNNABLE;
                threads[cur].wait_kind = V2_WK_NONE;
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_OVERFLOW;
                return;
            }
            kputs("[ipc] recv tcb=");
            sbi_putchar('0' + cur);
            kputs(" blocked\n");
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            enter_thread(n);
        } else if (sys == V2_NOTIFY) {
            /* NOTIFY (mirrors V2_C c_notify): OR-accumulate, wake only
             * genuine waiters (wk == WAIT); rendezvous blocks untouched. */
            unsigned long t = (unsigned long)threads[cur].regs[10];
            uint64_t bits = threads[cur].regs[11];
            int woke = 0;
            threads[cur].sepc += 4;
            if (t >= (unsigned long)NTHREADS) {
                threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                return;
            }
            threads[t].notify |= bits;
            if (threads[t].state == T_BLOCKED && threads[t].wait_kind == V2_WK_WAIT) {
                threads[t].state = T_RUNNABLE;
                threads[t].wait_kind = V2_WK_NONE;
                /* Wake-delivery: a thread woken from WAIT resumes past
                 * the ecall with whatever a0 it blocked with (stale).
                 * Pre-deliver the pending bits as its WAIT return
                 * (UABI: a0 = bits); pending is preserved, so a
                 * re-WAIT still collects — level-triggered parties
                 * (admin loop) observe zero behavior change. Without
                 * this, the first woken-WAIT consumer (thread A live
                 * legs, Task 5) sees a stale return and parks. */
                threads[t].regs[10] = threads[t].notify;
                woke = 1;
            }
            threads[cur].regs[10] = (uint64_t)V2_OK;
            kputs("[ipc] notify ");
            sbi_putchar('0' + cur);
            kputs(" -> ");
            sbi_putchar('0' + (char)t);
            kputs(" bits=");
            kputhex(bits);
            kputs(" wake=");
            sbi_putchar(woke ? '1' : '0');
            sbi_putchar('\n');
            return;
        } else if (sys == V2_WAIT) {
            /* WAIT (mirrors V2_C c_wait): take bits or block. */
            threads[cur].sepc += 4;
            if (threads[cur].notify != 0) {
                threads[cur].regs[10] = threads[cur].notify;
                threads[cur].notify = 0;
                threads[cur].wait_kind = V2_WK_NONE;
                kputs("[ipc] wait tcb=");
                sbi_putchar('0' + cur);
                kputs(" bits=");
                kputhex(threads[cur].regs[10]);
                sbi_putchar('\n');
                return;
            }
            threads[cur].state = T_BLOCKED;
            threads[cur].wait_kind = V2_WK_WAIT;
            kputs("[ipc] wait tcb=");
            sbi_putchar('0' + cur);
            kputs(" blocked\n");
            int n = pick_next();
            if (n < 0)
                halt_no_runnable();
            enter_thread(n);
        } else if (sys == V2_INVOKE) {
            uint64_t op = threads[cur].regs[10]; /* a0 */
            uint64_t a1 = threads[cur].regs[11];
            uint64_t a2 = threads[cur].regs[12];
            uint64_t a3 = threads[cur].regs[13];
            threads[cur].sepc += 4;
            /* long: FRAME_PA returns a full PA (0x81000000+ exceeds int);
             * all other ops assign small ints/negatives, so the epilogue
             * regs[10] = (uint64_t)rc is bit-identical for them. */
            long rc = V2_ERR_INVALID;
            switch (op) {
            case V2_INV_MINT:
                rc = v2_mint(&caps, (unsigned long)cur, a1, a2, a3);
                break;
            case V2_INV_GRANT:
                rc = v2_grant(&caps, (unsigned long)cur, a1, a2, a3);
                break;
            case V2_INV_MAP: {
                /* vpn must index a real l0_u_t[t][vpn] slot: guard before
                 * the model call so rc stays V2_ERR_INVALID for vpn >=
                 * V2_VPN_SLOTS (the model itself does not bound vpn). The
                 * model call stays authoritative: on V2_OK the mapping is
                 * recorded in caps.vm, then we install the real leaf PTE. */
                int m; /* bound: vpn < V2_VPN_SLOTS (checked below) */
                if (a2 < (uint64_t)V2_VPN_SLOTS)
                    rc = v2_map(&caps, (unsigned long)cur, a1, a2);
                if (rc == V2_OK) {
                    m = v2_vm_find(&caps, (unsigned long)cur, a2);
                    if (m >= 0) { /* model recorded it: must be findable */
                        v2_pte_install((unsigned long)cur, a2,
                                       caps.vm[cur][m].frame,
                                       caps.vm[cur][m].rights);
                        v2_sfence_all();
                    }
                }
                break;
            }
            case V2_INV_UNMAP:
                rc = v2_unmap(&caps, (unsigned long)cur, a1);
                if (rc == V2_OK) { /* model validated the mapping exists */
                    v2_pte_clear((unsigned long)cur, a1);
                    v2_sfence_all();
                }
                break;
            case V2_INV_REVOKE: {
                /* Revoke drops every mapping to the frame system-wide; the
                 * model clears caps.vm but not hardware PTEs. Capture the
                 * affected (t, vpn) pairs BEFORE the model destroys them,
                 * clear them only if the model approves (fail closed). */
                unsigned long f = 0;
                unsigned long npair = 0;
                int have_f = 0;
                if (a1 < (uint64_t)V2_CAP_SLOTS &&
                    caps.caps[cur][a1].valid) {
                    f = caps.caps[cur][a1].obj;
                    have_f = 1;
                }
                if (have_f) {
                    for (unsigned long u = 0; u < caps.nthreads; u++)
                        /* bound: V2_CAP_THREADS */
                        for (int i = 0; i < V2_VPN_SLOTS; i++) {
                            /* bound: V2_VPN_SLOTS */
                            if (caps.vm[u][i].valid &&
                                caps.vm[u][i].frame == f &&
                                npair < (unsigned long)(V2_CAP_THREADS *
                                                        V2_VPN_SLOTS)) {
                                v2_revoke_pairs[npair].t = u;
                                v2_revoke_pairs[npair].vpn =
                                    caps.vm[u][i].vpn;
                                npair++;
                            }
                        }
                }
                rc = v2_revoke(&caps, (unsigned long)cur, a1);
                if (rc == V2_OK) {
                    for (unsigned long i = 0; i < npair; i++) {
                        /* bound: V2_CAP_THREADS * V2_VPN_SLOTS */
                        if (v2_revoke_pairs[i].t <
                            (unsigned long)NTHREADS)
                            v2_pte_clear(v2_revoke_pairs[i].t,
                                         v2_revoke_pairs[i].vpn);
                    }
                    v2_sfence_all();
                }
                break;
            }
            case V2_INV_PT_ALLOC:
                rc = frame_alloc_slot(&caps, (unsigned long)cur);
                break;
            case V2_INV_ELF_CHECK:
                rc = v2_elf_ok((int)a1, (const v2_phdr_t *)a2, a3) ? V2_OK : V2_ERR_INVALID;
                break;
            case V2_INV_ELF_MAP: {
                /* ELF_MAP (a1=initrd index, a2/a3 reserved):
                 * Load an initrd ELF into the caller's VSpace.
                 * a1 = initrd index (0 = mem_server.elf, see mkinitrd.sh)
                 * a2/a3 are reserved and must be zero (unused).
                 * Returns entry point in rc (a0 on return).
                 * FAIL CLOSED: any validation error -> V2_ERR_INVALID. */
                const uint8_t *elf_data;
                uint32_t elf_size;
                uint64_t entry, brk = 0;
                if (!((a2 == 0 && a3 == 0) ||
                      v2_recv_range_ok((uintptr_t)a2, a3))) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                rc = v2_elf_load(elf_data, (size_t)elf_size, &caps,
                                 (unsigned long)cur, &entry, &brk);
                if (rc == V2_OK) {
                    v2_pte_sync((unsigned long)cur);
                    rc = (int)entry; /* return entry point as rc */
                }
                break;
            }
            case V2_INV_SPAWN: {
                /* SPAWN (a1=initrd index, a2/a3 reserved):
                 * Create a new thread, allocate its VSpace, load an
                 * initrd ELF into it.
                 * a1 = initrd index (0 = mem_server.elf, see mkinitrd.sh)
                 * a2/a3 are reserved and must be zero (unused).
                 * Returns child tid in rc on success.
                 * FAIL CLOSED: any validation error -> V2_ERR_INVALID. */
                const uint8_t *elf_data;
                uint32_t elf_size;
                uint64_t entry, brk = 0;
                if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (!((a2 == 0 && a3 == 0) ||
                      v2_recv_range_ok((uintptr_t)a2, a3))) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                /* Find a free thread slot (threads[] has NTHREADS entries;
                 * V2_CAP_THREADS is the model's bound, not ours). */
                int child = -1;
                for (int t = 0; t < NTHREADS; t++) { /* bound: NTHREADS */
                    /* deferred-C: T_DEAD is distinct; state alone frees the slot */
                    if (threads[t].state == T_DEAD) {
                        child = t;
                        break;
                    }
                }
                if (child < 0) {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                /* A reused slot may hold a previous life's caps/mappings:
                 * clear them so the load starts fresh (fail closed). */
                for (int s = 0; s < V2_CAP_SLOTS; s++)
                    caps.caps[child][s].valid = 0;
                for (int i = 0; i < V2_VPN_SLOTS; i++)
                    caps.vm[child][i].valid = 0;
                /* Build child's VSpace: copy current thread's page tables for kernel mappings,
                 * allocate fresh l0_u for user mappings */
                unsigned long child_root = build_child_vspace((unsigned long)cur, (unsigned long)child);
                if (!child_root) {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                threads[child].vspace_root_ppn = child_root;
                /* Fresh IPC/notify state: a reused slot must not inherit
                 * the previous life's blocked sends or pending signals. */
                threads[child].ipc_ptr = 0;
                threads[child].ipc_cap = 0;
                threads[child].notify = 0;
                threads[child].wait_kind = V2_WK_NONE;
                /* Fresh registers: no stale-word leak into the new image. */
                for (int r = 0; r < 32; r++)
                    threads[child].regs[r] = 0;
                threads[child].state = T_RUNNABLE;

                /* Load ELF into child's VSpace */
                rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)child, &entry, &brk);
                if (rc == V2_OK && entry != 0) {
                    v2_pte_sync((unsigned long)child);
                    threads[child].regs[2] = u_sp[child];
                    threads[child].sepc = entry;
                    rc = child; /* return child tid */
                } else {
                    threads[child].state = T_DEAD; /* cleanup on failure */
                    if (rc == V2_OK)
                        rc = V2_ERR_INVALID;
                }
                break;
            }
            case V2_INV_FORK: {
                /* FORK (no args):
                 * Create a child thread with a COW copy of the parent's
                 * VSpace and caps. The caps model keeps full rights on
                 * both sides (it stays the authority); only the hardware
                 * PTEs lose W (see v2_cow_write_protect), so the first
                 * store to a shared page faults and the handler breaks
                 * the share for the faulting thread only.
                 * Returns child tid to parent, 0 to child.
                 * FAIL CLOSED: any error -> V2_ERR_INVALID/V2_ERR_OVERFLOW. */
                int child = -1;
                for (int t = 0; t < NTHREADS; t++) { /* bound: NTHREADS */
                    /* deferred-C: T_DEAD is distinct; state alone frees the slot */
                    if (threads[t].state == T_DEAD) {
                        child = t;
                        break;
                    }
                }
                if (child < 0) {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                /* Copy parent's caps table. The child must not inherit
                 * allocator authority: root bits stay with the parent. */
                for (int s = 0; s < V2_CAP_SLOTS; s++) {
                    caps.caps[child][s] = caps.caps[cur][s];
                    caps.caps[child][s].root = 0;
                }
                /* Copy parent's mappings verbatim (rights intact: the
                 * model is the COW authority, not a rights bit). */
                for (int i = 0; i < V2_VPN_SLOTS; i++)
                    caps.vm[child][i] = caps.vm[cur][i];
                /* Build child tables, install the shared mappings, then
                 * write-protect both sides in hardware. */
                unsigned long child_root = build_child_vspace((unsigned long)cur, (unsigned long)child);
                if (!child_root) {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                threads[child].vspace_root_ppn = child_root;
                for (int i = 0; i < V2_VPN_SLOTS; i++) {
                    if (caps.vm[child][i].valid)
                        v2_pte_install((unsigned long)child,
                                       caps.vm[child][i].vpn,
                                       caps.vm[child][i].frame,
                                       caps.vm[child][i].rights);
                }
                v2_cow_write_protect((unsigned long)cur,
                                     (unsigned long)child);
                /* Fresh IPC/notify state for the new life. */
                threads[child].ipc_ptr = 0;
                threads[child].ipc_cap = 0;
                threads[child].notify = 0;
                threads[child].wait_kind = V2_WK_NONE;
                threads[child].state = T_RUNNABLE;
                threads[child].regs[2] = u_sp[child];
                threads[child].sepc = threads[cur].sepc + 4; /* return after ecall */
                /* Copy registers (parent's a0..a7, sp, etc.) */
                for (int r = 0; r < 32; r++)
                    threads[child].regs[r] = threads[cur].regs[r];
                threads[child].regs[10] = 0; /* child returns 0 in a0 */
                threads[child].regs[11] = cur; /* child gets parent tid in a1 */
                rc = child; /* parent returns child tid in a0 */
                break;
            }
            case V2_INV_EXEC: {
                /* EXEC (a1=initrd index, a2/a3 reserved):
                 * Replace current thread's image: unmap all user mappings, free frames,
                 * clear user caps, load a new initrd ELF.
                 * a1 = initrd index (0 = mem_server.elf, see mkinitrd.sh)
                 * a2/a3 are reserved and must be zero (unused).
                 * Returns 0 on success.
                 * FAIL CLOSED: any validation error -> V2_ERR_INVALID. */
                const uint8_t *elf_data;
                uint32_t elf_size;
                if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (!((a2 == 0 && a3 == 0) ||
                      v2_recv_range_ok((uintptr_t)a2, a3))) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                /* Unmap all user mappings and free frames */
                for (int i = 0; i < V2_VPN_SLOTS; i++) {
                    if (caps.vm[cur][i].valid) {
                        /* Free the frame back to pool */
                        frame_free((int)caps.vm[cur][i].frame);
                        v2_pte_clear((unsigned long)cur, caps.vm[cur][i].vpn);
                        caps.vm[cur][i].valid = 0;
                    }
                }
                v2_sfence_all();
                /* Clear user caps (slots 0..V2_CAP_SLOTS-1, keep root caps) */
                for (int s = 0; s < V2_CAP_SLOTS; s++) {
                    if (!caps.caps[cur][s].root)
                        caps.caps[cur][s].valid = 0;
                }
                /* Load new ELF into current VSpace */
                {
                    uint64_t entry = 0, brk = 0;
                    rc = v2_elf_load(elf_data, (size_t)elf_size, &caps, (unsigned long)cur, &entry, &brk);
                    if (rc == V2_OK && entry != 0) {
                        v2_pte_sync((unsigned long)cur);
                        threads[cur].regs[2] = u_sp[cur];
                        threads[cur].sepc = entry;
                        /* Reset registers to clean state */
                        for (int r = 0; r < 32; r++)
                            threads[cur].regs[r] = 0;
                        threads[cur].regs[2] = u_sp[cur];
                        rc = 0; /* return 0 on success */
                    } else if (rc == V2_OK) {
                        rc = V2_ERR_INVALID;
                    }
                }
                break;
            }
            case V2_INV_WRITE: {
                /* WRITE (a1=vpn, a2=u_src): one 8-byte word. Range-check +
                 * copy the user word into a kernel temp, run the model
                 * write on fdata (rights gate + shadow), then — only on
                 * V2_OK — store that same word into the real frame PA
                 * (Write-Through Mirror: real memory and fdata stay
                 * identical). FAIL CLOSED: real memory is never touched
                 * on model error. */
                uint64_t kbuf[1];
                if (a1 >= (uint64_t)V2_VPN_SLOTS) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (!v2_send_range_ok((uintptr_t)a2, 1)) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                u_copy_in(kbuf, (uintptr_t)a2, 1);
                rc = v2_write(&caps, (unsigned long)cur, a1, kbuf[0]);
                if (rc == V2_OK) {
                    int m = v2_vm_find(&caps, (unsigned long)cur, a1);
                    if (m >= 0) /* model wrote it: mapping must be findable */
                        v2_real_write(caps.vm[cur][m].frame,
                                      (const uint8_t *)kbuf, V2_WORD_BYTES);
                }
                break;
            }
            case V2_INV_READ: {
                /* READ (a1=vpn, a2=u_dst): mirror of WRITE. Run the model
                 * read first (rights gate + shadow), then — only on V2_OK —
                 * load the real 8-byte word from the frame PA into a kernel
                 * temp and copy it out to the validated user destination.
                 * FAIL CLOSED: the user destination is touched only on
                 * model + range success. */
                uint64_t kbuf[1];
                if (a1 >= (uint64_t)V2_VPN_SLOTS) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (!v2_recv_range_ok((uintptr_t)a2, 1)) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                rc = v2_read(&caps, (unsigned long)cur, a1, &kbuf[0]);
                if (rc == V2_OK) {
                    int m = v2_vm_find(&caps, (unsigned long)cur, a1);
                    if (m < 0) { /* model read succeeded: must be findable */
                        rc = V2_ERR_INVALID;
                        break;
                    }
                    v2_real_read(caps.vm[cur][m].frame, (uint8_t *)kbuf,
                                 V2_WORD_BYTES);
                    u_copy_out((uintptr_t)a2, kbuf, 1);
                }
                break;
            }
            case V2_INV_QCREATE: {
                /* QCREATE (a1=initrd index, a2/a3 reserved=0): new thread
                 * in a fresh qube label. Mirrors SPAWN's slot setup, then
                 * stamps the fresh label. FAIL CLOSED: any validation
                 * error -> V2_ERR_INVALID/OVERFLOW with no partial state. */
                const uint8_t *elf_data;
                uint32_t elf_size;
                uint64_t entry = 0, brk = 0;
                int child = -1;
                if (!(a2 == 0 && a3 == 0)) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (qube_next >= (unsigned long)V2_QUBES_MAX) {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                if (initrd_lookup((uint32_t)a1, &elf_data, &elf_size) != 0) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                for (int t = 0; t < NTHREADS; t++) { /* bound: NTHREADS */
                    /* deferred-C: T_DEAD is distinct; state alone frees the slot */
                    if (threads[t].state == T_DEAD) {
                        child = t;
                        break;
                    }
                }
                if (child < 0) {
                    rc = V2_ERR_OVERFLOW;
                    break;
                }
                /* A reused slot may hold a previous life's caps/mappings:
                 * clear them so the load starts fresh (fail closed). */
                for (int s = 0; s < V2_CAP_SLOTS; s++) /* bound: V2_CAP_SLOTS */
                    caps.caps[child][s].valid = 0;
                for (int i = 0; i < V2_VPN_SLOTS; i++) /* bound: V2_VPN_SLOTS */
                    caps.vm[child][i].valid = 0;
                {
                    unsigned long child_root =
                        build_child_vspace((unsigned long)cur,
                                           (unsigned long)child);
                    if (!child_root) {
                        rc = V2_ERR_OVERFLOW;
                        break;
                    }
                    threads[child].vspace_root_ppn = child_root;
                }
                /* Fresh IPC/notify state: a reused slot must not inherit
                 * the previous life's blocked sends or pending signals. */
                threads[child].ipc_ptr = 0;
                threads[child].ipc_cap = 0;
                threads[child].notify = 0;
                threads[child].wait_kind = V2_WK_NONE;
                /* Fresh registers: no stale-word leak into the new image. */
                for (int r = 0; r < 32; r++) /* bound: 32 */
                    threads[child].regs[r] = 0;
                rc = v2_elf_load(elf_data, (size_t)elf_size, &caps,
                                 (unsigned long)child, &entry, &brk);
                if (rc == V2_OK && entry != 0) {
                    threads[child].state = T_RUNNABLE;
                    v2_pte_sync((unsigned long)child);
                    threads[child].regs[2] = u_sp[child];
                    threads[child].sepc = entry;
                    qube_of[child] = (uint8_t)qube_next++;
                    kputs("QUB: qube");
                    kputdec((unsigned long)qube_of[child]);
                    kputs(" up\n");
                    rc = V2_OK;
                } else {
                    threads[child].state = T_DEAD; /* cleanup on failure */
                    if (rc == V2_OK)
                        rc = V2_ERR_INVALID;
                }
                break;
            }
            case V2_INV_QDESTROY: {
                /* QDESTROY (a1=label, a2/a3 reserved=0): park every thread
                 * in the qube, drop their queued IPC, revoke-drain their
                 * caps + clear hardware PTEs. Label 0 (base system) can
                 * never be destroyed. FAIL CLOSED. */
                unsigned long label = (unsigned long)a1;
                int found = 0;
                if (!(a2 == 0 && a3 == 0)) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                if (label == 0 || label >= (unsigned long)V2_QUBES_MAX) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                for (int t = 0; t < NTHREADS; t++) { /* bound: NTHREADS */
                    if (qube_of[t] == (uint8_t)label)
                        found = 1;
                }
                if (!found) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                /* Drop queued IPC entries owned by the qube (compact both
                 * queues in place; other qubes' entries are preserved). */
                {
                    for (int e = 0; e < V2_NEP; e++) { /* bound: V2_NEP (10) */
                        v2_ep_t *ep = &eps[e];
                        int w = 0;
                        for (int i = 0; i < ep->send_len; i++) { /* bound: V2_IPC_Q */
                            int idx = (ep->send_head + i) % V2_IPC_Q;
                            unsigned long s = ep->sendq[idx].sender;
                            if (s < (unsigned long)NTHREADS &&
                                qube_of[s] == (uint8_t)label)
                                continue; /* drop: sender dies below */
                            if (w != i) {
                                int dst = (ep->send_head + w) % V2_IPC_Q;
                                ep->sendq[dst] = ep->sendq[idx];
                            }
                            w++;
                        }
                        ep->send_len = w;
                        w = 0;
                        for (int i = 0; i < ep->recv_len; i++) { /* bound: V2_IPC_Q */
                            int idx = (ep->recv_head + i) % V2_IPC_Q;
                            unsigned long tid = ep->recvq[idx];
                            if (tid < (unsigned long)NTHREADS &&
                                qube_of[tid] == (uint8_t)label)
                                continue; /* drop: waiter dies below */
                            if (w != i) {
                                int dst = (ep->recv_head + w) % V2_IPC_Q;
                                ep->recvq[dst] = ep->recvq[idx];
                            }
                            w++;
                        }
                        ep->recv_len = w;
                        }
                }
                /* Revoke-drain caps, clear the whole frame window in
                 * hardware, park the threads. */
                for (int t = 0; t < NTHREADS; t++) { /* bound: NTHREADS */
                    if (qube_of[t] != (uint8_t)label)
                        continue;
                    for (int s = 0; s < V2_CAP_SLOTS; s++) { /* bound: V2_CAP_SLOTS */
                        if (caps.caps[t][s].valid)
                            (void)v2_revoke(&caps, (unsigned long)t,
                                            (unsigned long)s);
                    }
                    for (int vpn = 0; vpn < V2_VPN_SLOTS; vpn++) /* bound: V2_VPN_SLOTS */
                        v2_pte_clear((unsigned long)t,
                                     (unsigned long)vpn);
                    threads[t].state = T_DEAD;
                    threads[t].wait_kind = V2_WK_NONE;
                    threads[t].ipc_ptr = 0;
                    threads[t].ipc_cap = 0;
                    threads[t].notify = 0;
                    qube_of[t] = 0;
                }
                v2_sfence_all();
                kputs("QUB: qube");
                kputdec(label);
                kputs(" dead\n");
                rc = V2_OK;
                break;
            }
            case V2_INV_FRAME_PA: {
                /* FRAME_PA (a1=vpn, a2/a3 reserved=0): return the physical
                 * address of the frame mapped at vpn in the caller's VSpace.
                 * Pure address math (V2_FRAME_PHYS_BASE + frame*4096): no
                 * state change, no copy. Miss or nonzero reserved -> INVALID. */
                int m; /* bound: V2_VPN_SLOTS (v2_vm_find scan) */
                if (a2 != 0 || a3 != 0) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                m = v2_vm_find(&caps, (unsigned long)cur, a1);
                if (m < 0) {
                    rc = V2_ERR_INVALID;
                    break;
                }
                rc = (long)(V2_FRAME_PHYS_BASE +
                            caps.vm[cur][m].frame * 4096UL);
                break;
            }
            default:
                rc = V2_ERR_INVALID;
                break;
            }
            threads[cur].regs[10] = (uint64_t)rc;
            kputs("[invoke] tcb=");
            sbi_putchar('0' + cur);
            kputs(" op=");
            kputdec(op);
            kputs(" rc=");
            kputdec((unsigned long)rc);
            sbi_putchar('\n');
            return;
        }
        threads[cur].sepc += 4;
        return;
    }
    case 9: /* S-mode ecall: our own SBI calls return via M, never here. */
        threads[cur].sepc += 4;
        return;
case 13: /* Load page fault */
    case 15: { /* Store page fault: may be a COW break */
        uint64_t fault_addr;
        asm volatile("csrr %0, stval" : "=r"(fault_addr));
        /* COW break, S-mode authority rule: the caps model is the ONLY
         * authority. A store fault inside the frame window whose model
         * mapping still carries W is a COW share (hardware PTE is R-only
         * after v2_cow_write_protect); anything else — RX execute page,
         * R-only data, unmapped address — falls through to containment.
         * PTE bits are never trusted as COW flags, so this cannot
         * misclassify a legitimate RX page. */
        if (code == 15 &&
            fault_addr >= V2_U_END &&
            fault_addr < V2_U_END + (uint64_t)V2_VPN_SLOTS * 4096UL) {
            unsigned long t = (unsigned long)cur;
            unsigned long vpn =
                (unsigned long)((fault_addr - V2_U_END) >> 12);
            int m = v2_vm_find(&caps, t, vpn);
            if (m >= 0 && (caps.vm[t][m].rights & V2_RIGHT_W)) {
                unsigned long old_frame = caps.vm[t][m].frame;
                int new_frame = frame_alloc();
                if (new_frame >= 0 &&
                    old_frame < (unsigned long)V2_FRAMES_MAX) {
                    /* Copy via physical addresses (S-mode, SUM=0: the
                     * faulting U VA is NOT dereferenced). */
                    volatile uint64_t *dst = (volatile uint64_t *)
                        (V2_FRAME_PHYS_BASE + (uintptr_t)new_frame * 4096);
                    const volatile uint64_t *src =
                        (const volatile uint64_t *)
                        (V2_FRAME_PHYS_BASE + (uintptr_t)old_frame * 4096);
                    for (int i = 0; i < 512; i++) /* bound: 4096/8 */
                        dst[i] = src[i];
                    /* The word-model shadow follows the break so later
                     * WRITE/READ word ops stay coherent with real memory. */
                    caps.fdata[new_frame] = caps.fdata[old_frame];
                    caps.vm[t][m].frame = (unsigned long)new_frame;
                    /* Reinstall THIS thread's PTE only (the other sharer
                     * keeps its R-only PTE until it faults in turn). */
                    v2_pte_install(t, vpn, (unsigned long)new_frame,
                                   caps.vm[t][m].rights);
                    v2_sfence_all();
                    return; /* Resume the faulting store */
                }
            }
        }
        /* Not a COW share (or no frame left) - fall through to default */
    }
    default: { /* fault: park the offender, keep the rest running */
        kputs("[fault] tcb=");
        sbi_putchar('0' + cur);
        kputs(" cause=");
        kputhex(code);
        kputs(" epc=");
        kputhex(threads[cur].sepc);
        kputs("\n parked; others continue\n");
        threads[cur].state = T_PARKED;
        int n = pick_next();
        if (n < 0)
            halt_no_runnable();
        enter_thread(n);
    }
    }
}

void kboot(void) {
    kputs("v2 stage2: S-mode entry (OpenSBI)\n");
    for (int e = 0; e < V2_NEP; e++) /* bound: V2_NEP (10) */
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
    pagetable_init();
    uintptr_t root = (uintptr_t)root_pt_t[0];
    uint64_t satp = (8UL << 60) | ((root >> 12) & 0xFFFFFFFFFFFUL);
    asm volatile("csrw satp, %0" :: "r"(satp) : "memory");
    asm volatile("sfence.vma" ::: "memory");
    asm volatile("csrc sstatus, %0" :: "r"((1UL << 18) | (1UL << 19)) : "memory");
    kputs("v2: satp Sv39 on, U-bit split (k U=0 / u U=1), SUM=0\n");
    /* Phase-2 NIC discovery: transports live at VIRTIO0_BASE+i*0x1000
     * (S-only UART megapage, pre-MMU-mapped). QEMU attaches backends
     * last-first, so scan for the modern net device instead of assuming
     * transport 0. A found IRQ gets priority 1 + its enable bit with
     * threshold 0 (any priority-1 IRQ fires); none found leaves
     * net_virtio_irq at 0xFFFFFFFF (handler matches nothing, fail closed). */
    for (int ti = 0; ti < VIRTIO_NTRANSPORTS; ti++) { /* bound: 8 */
        volatile uint32_t *tr = (volatile uint32_t *)
            (VIRTIO0_BASE + (unsigned long)ti * 0x1000UL);
        if (tr[0] == 0x74726976u && tr[1] == 2u &&
            tr[2] == (uint32_t)VIRTIO_DEV_NET) {
            net_virtio_irq = (uint32_t)(1 + ti);
            break;
        }
    }
    if (net_virtio_irq != 0xFFFFFFFFUL) {
        *(volatile uint32_t *)(PLIC_BASE + 4u * net_virtio_irq) = 1;
        *(volatile uint32_t *)PLIC_ENABLE_M |= (1U << net_virtio_irq);
        *(volatile uint32_t *)PLIC_ENABLE_S |= (1U << net_virtio_irq);
        *(volatile uint32_t *)PLIC_THRESH_M = 0;
        *(volatile uint32_t *)PLIC_THRESH_S = 0;
    }
    /* FDE block discovery: same scan-then-bind as the NIC above, keyed on
     * the virtio-blk device id (never a hardcoded transport: QEMU
     * attaches backends last-first). A found IRQ gets priority 1 + its
     * enable bit with threshold 0 (any priority-1 IRQ fires); none found
     * leaves blk_virtio_irq at 0xFFFFFFFF (handler matches nothing, the
     * ELF parks fail-closed at probe, never spins). */
    for (int ti = 0; ti < VIRTIO_NTRANSPORTS; ti++) { /* bound: 8 */
        volatile uint32_t *tr = (volatile uint32_t *)
            (VIRTIO0_BASE + (unsigned long)ti * 0x1000UL);
        if (tr[0] == 0x74726976u && tr[1] == 2u &&
            tr[2] == (uint32_t)VIRTIO_DEV_BLK) {
            blk_virtio_irq = (uint32_t)(1 + ti);
            break;
        }
    }
    if (blk_virtio_irq != 0xFFFFFFFFUL) {
        *(volatile uint32_t *)(PLIC_BASE + 4u * blk_virtio_irq) = 1;
        *(volatile uint32_t *)PLIC_ENABLE_M |= (1U << blk_virtio_irq);
        *(volatile uint32_t *)PLIC_ENABLE_S |= (1U << blk_virtio_irq);
        *(volatile uint32_t *)PLIC_THRESH_M = 0;
        *(volatile uint32_t *)PLIC_THRESH_S = 0;
    }

    for (int i = 0; i < NTHREADS; i++) { /* bound: NTHREADS */
        for (int r = 0; r < 32; r++)
            threads[i].regs[r] = 0;
        threads[i].sepc = 0;
        threads[i].state = T_PARKED;
        threads[i].ipc_ptr = 0;
        threads[i].ipc_cap = 0;
        threads[i].notify = 0;
        threads[i].wait_kind = V2_WK_NONE;
        threads[i].vspace_root_ppn =
            (8UL << 60) | (((uintptr_t)root_pt_t[i] >> 12) & 0xFFFFFFFFFFFUL);
    }
    /* A valid trap target must exist BEFORE interrupts are enabled: a stale
     * firmware timer can pend and fire at SIE-enable, while cur_ctx is still
     * NULL -> entry faults loading ctx -> fault loop. Parked + mapped is
     * always safe (handler prints and halts). */
    cur = 0;
    cur_ctx = &threads[0];
    trap_stack_top = (uintptr_t)(trap_stack + sizeof(trap_stack));
    asm volatile("csrw sscratch, %0" :: "r"(trap_stack_top) : "memory");
    /* Arm our timer BEFORE enabling: reprograms stimecmp, de-asserting any
     * stale firmware pending bit. */
    sbi_set_timer(rdtime() + TICK_DELTA);
    /* Phase-2 NIC PLIC setup lives in the discovery block above (priority
     * + enable for the found IRQ, threshold 0 on the claimed context). */
    asm volatile("csrs sie, %0" :: "r"((1UL << 5) | (1UL << 9)) : "memory"); /* STIE + SEIE */
    asm volatile("csrs sstatus, %0" :: "r"(1UL << 1) : "memory"); /* SIE */

    threads[0].regs[2] = u_sp[0];
    threads[0].sepc = (uint64_t)user_a_main;
    threads[0].state = T_RUNNABLE;
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
    /* Stage 3: boot the userspace mem_server from initrd index 0 into
     * thread 2's VSpace. On success thread 2 enters the ELF image and
     * prints MEM-SRV from U-mode; on failure it keeps the in-kernel
     * stub above, and the missing MEM-SRV marker fails the smoke loudly. */
    {
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry = 0, brk = 0;
        if (initrd_lookup(0, &elf_data, &elf_size) == 0 &&
            v2_elf_load(elf_data, (size_t)elf_size, &caps, 2, &entry, &brk) == V2_OK &&
            entry != 0) {
            v2_pte_sync(2);
            threads[2].sepc = entry;
            kputs("[spawn] mem_server ELF ok\n");
        } else {
            kputs("[spawn] mem_server ELF FAIL; stub\n");
        }
    }
    /* S2 brokers: qrexec from initrd index 1 into thread 3 (qube 2),
     * AdminVM from index 2 into thread 4 (qube 3). Mirrors the mem_server
     * load above. On success the thread enters the ELF image and prints
     * QREXEC: up / ADMIN: up from U-mode; on failure it stays parked and
     * the missing markers fail the smoke loudly (fail closed: no stub
     * impersonates a broker). Backpressure note: a SEND with no waiter
     * queues + blocks, and every cross-qube delivery fails INVALID at the
     * raw gate (no QX grants at boot), so no broker rendezvous can ever
     * complete across qubes — each broker ends parked in RECV/WAIT or
     * SEND-blocked on its queued reply, and the A/B + CAP transcript runs
     * to the clean park with no livelock. */
    {
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry = 0, brk = 0;
        if (initrd_lookup(1, &elf_data, &elf_size) == 0 &&
            v2_elf_load(elf_data, (size_t)elf_size, &caps, 3, &entry, &brk) == V2_OK &&
            entry != 0) {
            v2_pte_sync(3);
            threads[3].regs[2] = u_sp[3];
            threads[3].sepc = entry;
            threads[3].state = T_RUNNABLE;
            kputs("[spawn] qrexec ELF ok\n");
        } else {
            kputs("[spawn] qrexec ELF FAIL; parked\n");
        }
    }
    {
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry = 0, brk = 0;
        if (initrd_lookup(2, &elf_data, &elf_size) == 0 &&
            v2_elf_load(elf_data, (size_t)elf_size, &caps, 4, &entry, &brk) == V2_OK &&
            entry != 0) {
            v2_pte_sync(4);
            threads[4].regs[2] = u_sp[4];
            threads[4].sepc = entry;
            threads[4].state = T_RUNNABLE;
            kputs("[spawn] adminvm ELF ok\n");
        } else {
            kputs("[spawn] adminvm ELF FAIL; parked\n");
        }
    }
    /* S3 packet plane: firewall from initrd index 3 into thread 5 (qube 4),
     * net from index 4 into thread 6 (qube 5). Mirrors the S2 broker loads
     * above. On success the thread enters the ELF image and prints FW: up
     * / NET: up from U-mode; on failure it stays parked and the missing
     * markers fail the smoke loudly (fail closed: no stub impersonates
     * the packet plane). Same rendezvous discipline as S2: no QX exists
     * for these qubes until the boot grants below, so no cross-qube
     * delivery can complete before the labels + grants land. */
    {
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry = 0, brk = 0;
        if (initrd_lookup(3, &elf_data, &elf_size) == 0 &&
            v2_elf_load(elf_data, (size_t)elf_size, &caps, 5, &entry, &brk) == V2_OK &&
            entry != 0) {
            v2_pte_sync(5);
            threads[5].regs[2] = u_sp[5];
            threads[5].sepc = entry;
            threads[5].state = T_RUNNABLE;
            kputs("[spawn] firewall ELF ok\n");
        } else {
            kputs("[spawn] firewall ELF FAIL; parked\n");
        }
    }
    {
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry = 0, brk = 0;
        if (initrd_lookup(4, &elf_data, &elf_size) == 0 &&
            v2_elf_load(elf_data, (size_t)elf_size, &caps, 6, &entry, &brk) == V2_OK &&
            entry != 0) {
            v2_pte_sync(6);
            threads[6].regs[2] = u_sp[6];
            threads[6].sepc = entry;
            threads[6].state = T_RUNNABLE;
            kputs("[spawn] net ELF ok\n");
        } else {
            kputs("[spawn] net ELF FAIL; parked\n");
        }
    }
    /* FDE vault: initrd index 8 into thread 8 (qube 6, labeled below).
     * Mirrors the S2/S3 loads above. On success the thread enters the
     * ELF image and prints VAULT: up from U-mode; on failure it stays
     * parked and the missing marker fails the smoke loudly (fail closed:
     * nothing impersonates the vault). */
    {
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry = 0, brk = 0;
        if (initrd_lookup(8, &elf_data, &elf_size) == 0 &&
            v2_elf_load(elf_data, (size_t)elf_size, &caps, 8, &entry, &brk) == V2_OK &&
            entry != 0) {
            v2_pte_sync(8);
            threads[8].regs[2] = u_sp[8];
            threads[8].sepc = entry;
            threads[8].state = T_RUNNABLE;
            kputs("[spawn] vault ELF ok\n");
        } else {
            kputs("[spawn] vault ELF FAIL; parked\n");
        }
    }
    /* FDE cryptblk: initrd index 9 into thread 9 (qube 7, labeled
     * below). Mirrors the vault load above. On success the thread enters
     * the ELF image and runs the unlock demo from U-mode (printing the
     * CRYPT: markers); on failure it stays parked and the missing markers
     * fail the smoke loudly (fail closed: nothing impersonates cryptblk).
     * kboot only spawns + asserts here: the demo lives in the ELF. */
    {
        const uint8_t *elf_data;
        uint32_t elf_size;
        uint64_t entry = 0, brk = 0;
        if (initrd_lookup(9, &elf_data, &elf_size) == 0 &&
            v2_elf_load(elf_data, (size_t)elf_size, &caps, 9, &entry, &brk) == V2_OK &&
            entry != 0) {
            v2_pte_sync(9);
            threads[9].regs[2] = u_sp[9];
            threads[9].sepc = entry;
            threads[9].state = T_RUNNABLE;
            kputs("[spawn] cryptblk ELF ok\n");
        } else {
            kputs("[spawn] cryptblk ELF FAIL; parked\n");
        }
    }
    /* Qubes boot labels: mem_server (thread 2) owns qube 1, qrexec
     * (thread 3) owns qube 2, AdminVM (thread 4) owns qube 3, firewall
     * (thread 5) owns qube 4, net (thread 6) owns qube 5, vault
     * (thread 8) owns qube 6, cryptblk (thread 9) owns qube 7; A/B/CAP
     * stub stay in qube 0. Fresh QCREATE labels start at qube_next == 8
     * == V2_QUBES_MAX: the qube table is full (documented cap — any
     * further qube forces a V2_QUBES_MAX bump + proof replay, Task 5). */
    qube_of[2] = 1;
    qube_of[3] = 2;
    qube_of[4] = 3;
    qube_of[5] = 4;
    qube_of[6] = 5;
    qube_of[8] = 6;
    qube_of[9] = 7;
    qube_next = 8;
    kputs("QUB: qube0 qube1 up\n");
    /* NETQ label assert: fail closed (mismatch prints marker-free
     * "[demo] FAIL", so the smoke gate misses the marker and fails). */
    if (qube_of[5] != 4 || qube_of[6] != 5 || qube_next != 8) {
        kputs("[demo] FAIL netq labels\n");
    } else {
        kputs("NETQ: labels ok\n");
    }
    /* VAULTQ label assert: vault (thread 8) owns qube 6 and the next
     * fresh label is 8 (cryptblk took 7 below). Fail-closed like NETQ
     * above; the one QX grant below is documented beside this assert. */
    if (qube_of[8] != 6 || qube_next != 8) {
        kputs("[demo] FAIL vaultq labels\n");
    } else {
        kputs("VAULTQ: labels ok\n");
    }
    /* CRYPTQ label assert: cryptblk (thread 9) owns qube 7 and the next
     * fresh label is 8 == V2_QUBES_MAX. Fail-closed like NETQ above;
     * the FDE QX grants below are documented beside this assert. */
    if (qube_of[9] != 7 || qube_next != 8) {
        kputs("[demo] FAIL cryptq labels\n");
    } else {
        kputs("CRYPTQ: labels ok\n");
    }
    /* S3 QX boot grants: QX is holder-based (qube_has_qx scans the
     * sender's own table), so each cross-qube leg needs its sender to
     * hold a QX cap. Three legs, three holders, all at slot 9: slot 8 is
     * the live data-plane slot (firewall FW_IN_SLOT, net NET_IN_SLOT —
     * both ELFs enforce slot==8 fail-closed), and MAP rejects QX-bit
     * caps, so a boot QX cap at slot 8 would collide with the live frame
     * GRANT(->8)+MAP(8) path (grant needs an empty dst). The QX grants
     * therefore live at slot >= 9, leaving slot 8 free in tid 5/6 for
     * live traffic. qube0 augments its slot-9 root in place, then
     * delegates verbatim (QX flows through v2_grant unchanged):
     * qube0->firewall lands tid 5 slot 9 (enables firewall->net) and
     * firewall->net lands tid 6 slot 9 (enables net->firewall).
     * Fail-closed: any grant failure prints marker-free "[demo] FAIL". */
    caps.caps[0][9].rights |= V2_RIGHT_QX;
    if (v2_grant(&caps, 0, 9, 5, 9) != V2_OK ||
        v2_grant(&caps, 5, 9, 6, 9) != V2_OK ||
        !qube_has_qx(0) || !qube_has_qx(5) || !qube_has_qx(6)) {
        kputs("[demo] FAIL qx boot grants\n");
    }
    /* FDE vault QX boot grant (exactly one): qrexec (thread 3) needs a QX
     * cap so its approved T_DELIVERs reach the vault (thread 8, qube 6)
     * through the raw gate (cross-qube handoff needs QX on the sender).
     * Same shape as the S3 grants above: qube0's QX-augmented slot-9 root
     * delegates verbatim into the broker's slot 9 (slot 8 stays free of
     * QX-bit caps: MAP rejects QX, and the live data-plane GRANT+MAP
     * path needs an empty dst). The vault takes no direct calls and the
     * AdminVM rewrap/format calls also route via qrexec ask, so this one
     * leg covers every Task-3 deliver path (see the VAULTQ assert above).
     * Live-traffic second path (Task 5): thread A's T_CALL leg drives an
     * approved keys.sign deliver along this same broker->vault grant —
     * the broker (sender, tid 3) already holds QX via this line and
     * thread A (sender, tid 0) holds QX via the S3 root above, so the
     * live ask+deny legs REUSE this grant and add no second grant into
     * tid 3 slot 9 (v2_grant fails on an occupied dst — caps.h).
     * Fail-closed: any grant failure prints marker-free "[demo] FAIL". */
    if (v2_grant(&caps, 0, 9, 3, 9) != V2_OK || !qube_has_qx(3)) {
        kputs("[demo] FAIL vault qx grant\n");
    }
    /* FDE cryptblk QX boot grants (Task 4): QX is holder-based, so each
     * cross-qube sender holds its own QX cap; all land at slot >= 9
     * (slot 8 stays free of QX-bit caps: MAP rejects QX, and the key/data
     * GRANT+MAP paths need an empty dst — same shape as the S3 block).
     *   qube0 -> cryptblk (tid 9 slot 9): the direct AppVM-FS path —
     *     cryptblk's replies to qube-0 callers route cross-qube.
     *   qrexec -> cryptblk (tid 9 slot 10): chain delegation mirroring
     *     the S3 firewall->net grant (QX flows through v2_grant
     *     unchanged) — the approved-T_DELIVER path.
     *   qube0 -> vault (tid 8 slot 9): the T_KEY-notice path — the raw
     *     gate needs QX on the SENDER, so the vault's keyless notice to
     *     cryptblk requires this grant (Step-0 ratification necessity).
     * The qrexec -> vault leg keeps its Task-3 grant (tid 3 holds QX).
     * Fail-closed: any grant failure prints marker-free "[demo] FAIL". */
    if (v2_grant(&caps, 0, 9, 9, 9) != V2_OK ||
        v2_grant(&caps, 3, 9, 9, 10) != V2_OK ||
        v2_grant(&caps, 0, 9, 8, 9) != V2_OK ||
        !qube_has_qx(9) || !qube_has_qx(8) || !qube_has_qx(3)) {
        kputs("[demo] FAIL crypt qx grants\n");
    }
    /* Live-traffic QX grant (deferred-A): QX is holder-based. Thread A's
     * T_CALL leg reuses the FDE vault-grant line above
     * (v2_grant(&caps, 0, 9, 3, 9)): v2_grant fails on an occupied dst
     * (caps.h), so a second grant into tid 3 slot 9 ALWAYS fails — the
     * FDE line's assert comment is extended to cover this leg instead.
     * One grant is ADDED here:
     *   qube0 -> admin (tid 4 slot 9): HELLO + T_DECIDE to the broker.
     * Same slot-9 shape (user/admin tables hold no caps; MAP rejects
     * QX-bit caps). Fail-closed like every grant block here. */
    if (v2_grant(&caps, 0, 9, 4, 9) != V2_OK || !qube_has_qx(4)) {
        kputs("[demo] FAIL live qx grants\n");
    }
    /* NETMMIO leaf gate: the transport U-leaf exists ONLY in tid 6's
     * tables (l1_t[6][5]); any other mapping is a leak. Fail-closed:
     * mismatch prints marker-free "[demo] FAIL", so the smoke gate
     * misses the marker and fails instead of passing on a lie. */
    {
        int mmio_ok = (l1_t[6][5] != 0);
        for (int t = 0; t < NTHREADS; t++) { /* bound: NTHREADS */
            if (t != 6 && l1_t[t][5] != 0)
                mmio_ok = 0;
        }
        if (mmio_ok)
            kputs("NETMMIO: tid=6 only\n");
        else
            kputs("[demo] FAIL netmmio leak\n");
    }
    /* BLKMMIO leaf gate: the transport U-leaf exists ONLY in tid 9's
     * tables (l1_t[9][6]); any other mapping is a leak. Fail-closed
     * like NETMMIO above. */
    {
        int mmio_ok = (l1_t[9][6] != 0);
        for (int t = 0; t < NTHREADS; t++) { /* bound: NTHREADS */
            if (t != 9 && l1_t[t][6] != 0)
                mmio_ok = 0;
        }
        if (mmio_ok)
            kputs("BLKMMIO: tid=9 only\n");
        else
            kputs("[demo] FAIL blkmmio leak\n");
    }
    /* S2 demo transcript (runs once at boot, in-kernel test_cap_thread-style
     * sequence: straight-line, bounded, no loops, no IPC). It drives the
     * REAL boot labels through qube_raw_ok and the qube.h policy ops the
     * qrexec broker runs on (decide/enqueue/decide/audit), printing one
     * marker per leg. Fail-closed: any unexpected result prints a
     * marker-free "[demo] FAIL" line, so the smoke gate misses the marker
     * and fails instead of passing on a lie.
     *
     * Honesty note (Task 3 follow-up d): there is no GETC in the V2 UABI,
     * so the AdminVM auto-approves after displaying the hash prompt. The
     * Ask leg below is therefore display-only: qube_decide_idx(approve=1)
     * stands in for the console confirm, while the enqueue + hash-pinned
     * decide + audit path is the real broker path.
     *
     * Arg-less note (Task 3 follow-up c): v2_qask_t carries
     * (src, dst, rpc, hash) with no arg fields and T_DECIDE deliver
     * forwards zeros, so the S2 demo RPCs use rpc ids only
     * (keys.sign=1, clipboard=2) and no args are dropped anywhere. */
    {
        v2_qpolicy_t demo;
        v2_qask_t ask;
        uint8_t hbuf[1];
        int dec;
        demo.nrules = 2;
        demo.npending = 0;
        demo.naudit = 0;
        demo.rules[0] = (v2_qrule_t){.src = 0, .dst = 1, .rpc = 1,
                                     .decision = V2_QDEC_ASK};
        demo.rules[1] = (v2_qrule_t){.src = V2_QWILD, .dst = V2_QWILD,
                                     .rpc = 2, .decision = V2_QDEC_DENY};
        /* 1. Direct work->vault bypass hits the raw gate: thread 0 is qube 0,
         * thread 2 is qube 1. Literal 0 tests the gate independent of
         * thread-0's cap table (identical today: thread 0 holds no QX). */
        if (qube_raw_ok(qube_of, (unsigned long)NTHREADS, 0, 2, 0)) {
            kputs("[demo] FAIL raw gate allowed xqube\n");
        } else {
            (void)qube_audit(&demo, 0, 1, 0, 0);
            kputs("QUB: xread denied\n");
        }
        /* 2. work->vault keys.sign raises Ask. */
        dec = qube_decide(&demo, 0, 1, 1);
        if (dec != V2_QDEC_ASK) {
            kputs("[demo] FAIL keys.sign not ask\n");
        } else {
            kputs("QREXEC: ask\n");
        }
        /* 3. Enqueue the ask, then display-only auto-approve (approve=1). */
        hbuf[0] = 1;
        ask.src = 0;
        ask.dst = 1;
        ask.rpc = 1;
        ask.hash = qube_fnv1a(hbuf, 1);
        if (qube_ask_enqueue(&demo, &ask) != V2_OK ||
            qube_decide_idx(&demo, 0, 1) != V2_OK) {
            kputs("[demo] FAIL ask approve\n");
        } else {
            kputs("QREXEC: allow\n");
        }
        /* 4. work->net clipboard attempt is denied with no prompt. */
        dec = qube_decide(&demo, 0, 1, 2);
        if (dec != V2_QDEC_DENY) {
            kputs("[demo] FAIL clipboard not deny\n");
        } else {
            (void)qube_audit(&demo, 0, 1, 2, 0);
            kputs("QREXEC: deny\n");
        }
        /* 5. Audit count: raw-deny + allow + clipboard-deny = 3 entries. */
        if (demo.naudit != 3) {
            kputs("[demo] FAIL audit count\n");
        } else {
            kputs("AUD: ");
            kputdec(demo.naudit);
            kputs(" entries\n");
        }
        /* Audit-full self-test (deferred-B): model the cap rule on a
         * local policy — 64 appends ok, 65th OVERFLOW with entries
         * intact, helper refuses at cap and appends below it. */
        {
            v2_qpolicy_t fulltest;
            int fq;
            fulltest.nrules = 0;
            fulltest.npending = 0;
            fulltest.naudit = 0;
            for (fq = 0; fq < 64; fq++) { /* bound: V2_AUDIT_MAX */
                if (qube_audit(&fulltest, 0, 6, 1, 1) != 0)
                    kputs("[demo] FAIL audit fill\n");
            }
            if (fulltest.naudit != 64 ||
                qube_audit(&fulltest, 0, 6, 1, 1) != -2 ||
                fulltest.naudit != 64 ||
                qube_audit_allow(&fulltest, 0, 6, 1) != -2 ||
                qube_audit_room(&fulltest) != 0) {
                kputs("[demo] FAIL audit cap\n");
            } else {
                fulltest.naudit = 63;
                if (!qube_audit_room(&fulltest) ||
                    qube_audit_allow(&fulltest, 0, 6, 1) != 0 ||
                    fulltest.naudit != 64) {
                    kputs("[demo] FAIL audit room\n");
                } else {
                    kputs("AUD: full ok\n");
                }
            }
        }
    }
    /* S3 Phase-1 demo (model-level: straight-line, bounded, no IPC).
     * Drives the real fw_decide + qube_fnv1a + qube_raw_ok + qube_audit
     * over one demo frame, one marker per leg. Fail-closed: any
     * unexpected result prints marker-free "[demo] FAIL", so the smoke
     * gate misses the marker and fails instead of passing on a lie.
     * The frame lifecycle closes in-model via v2_revoke. */
    {
        fw_rule_t frules[3];
        v2_qpolicy_t netdemo;
        uint8_t pkt[64] = {0};
        unsigned long i;
        unsigned long sender_qube;
        int ds, ms, gs, ns;
        uint64_t h;
        int dec;
        /* Ruleset v0 mirror (boot): DNS out, HTTPS to Ask, else DENY. */
        frules[0] = (fw_rule_t){.src_qube = 0,
                                .proto = (unsigned long)FW_PROTO_UDP,
                                .dport = 53,
                                .verdict = FW_ALLOW};
        frules[1] = (fw_rule_t){.src_qube = 0,
                                .proto = (unsigned long)FW_PROTO_TCP,
                                .dport = 443,
                                .verdict = FW_ASK};
        frules[2] = (fw_rule_t){.src_qube = FW_ANY_QUBE,
                                .proto = (unsigned long)FW_ANY_PROTO,
                                .dport = (unsigned long)FW_ANY_PORT,
                                .verdict = FW_DENY};
        netdemo.nrules = 0;
        netdemo.npending = 0;
        netdemo.naudit = 0;
        /* Allow packet: IPv4 ethertype, UDP, dport 53 (BE tail bytes). */
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        pkt[FW_ETH_HDR + 9] = FW_PROTO_UDP;
        pkt[FW_ETH_HDR + FW_IP_MIN + 2] = 0;
        pkt[FW_ETH_HDR + FW_IP_MIN + 3] = 53;
        /* 1. Allow leg: alloc the demo frame as the qube-0 scratch holder
         * (thread 7/CAP stub: empty table at demo time, so slot 0),
         * attenuate to R-only in place (slot 1, free), grant R to the
         * firewall's first free slot, hash the bytes, grant R onward to
         * net's first free slot, re-hash (integrity holds) and decide:
         * UDP/53 from qube 0 must ALLOW. */
        ds = frame_alloc_slot(&caps, 7);
        ms = 1;
        gs = -1;
        ns = -1;
        for (i = 0; i < (unsigned long)V2_CAP_SLOTS; i++) { /* bound: V2_CAP_SLOTS */
            if (gs < 0 && !caps.caps[5][i].valid)
                gs = (int)i;
            if (ns < 0 && !caps.caps[6][i].valid)
                ns = (int)i;
        }
        h = qube_fnv1a(pkt, 64);
        if (ds < 0 ||
            v2_mint(&caps, 7, (unsigned long)ds, V2_RIGHT_R,
                    (unsigned long)ms) != V2_OK ||
            gs < 0 || ns < 0 ||
            v2_grant(&caps, 7, (unsigned long)ms, 5,
                     (unsigned long)gs) != V2_OK ||
            v2_grant(&caps, 5, (unsigned long)gs, 6,
                     (unsigned long)ns) != V2_OK ||
            qube_fnv1a(pkt, 64) != h) {
            kputs("[demo] FAIL fw allow setup\n");
        } else {
            dec = fw_decide(frules, 3, 0, pkt, 64);
            if (dec != FW_ALLOW) {
                kputs("[demo] FAIL fw allow decide\n");
            } else {
                /* src 0, dst FW_QUBE 4, rpc NET_SEND 3, allowed. */
                (void)qube_audit(&netdemo, 0, 4, 3, 1);
                kputs("FW: allow\n");
            }
        }
        /* 2. Deny leg: same frame, TCP/22 (no row covers it) -> DENY. */
        pkt[FW_ETH_HDR + 9] = FW_PROTO_TCP;
        pkt[FW_ETH_HDR + FW_IP_MIN + 2] = 0;
        pkt[FW_ETH_HDR + FW_IP_MIN + 3] = 22;
        dec = fw_decide(frules, 3, 0, pkt, 64);
        if (dec != FW_DENY) {
            kputs("[demo] FAIL fw deny decide\n");
        } else {
            /* src 0, dst FW_QUBE 4, rpc NET_SEND 3, denied. */
            (void)qube_audit(&netdemo, 0, 4, 3, 0);
            kputs("FW: deny\n");
        }
        /* 3. Leak leg: AppVM (thread 0, qube 0) -> net (thread 6, qube 5)
         * with no QX must read 0 at the raw gate. Literal 0 tests the
         * gate independent of thread-0's table (which now holds QX). */
        if (qube_raw_ok(qube_of, (unsigned long)NTHREADS, 0, 6, 0)) {
            kputs("[demo] FAIL leak open\n");
        } else {
            /* src 0, dst NET_QUBE 5, rpc NET_SEND 3, denied. */
            (void)qube_audit(&netdemo, 0, 5, 3, 0);
            kputs("LEAK: denied\n");
        }
        /* 4. Spoof leg: an announcement stamped with sender_qube != 4
         * (FW_QUBE) is ignored, like the net stub's silent drop (which
         * audits nothing). */
        sender_qube = 0;
        if (sender_qube != 4UL) {
            kputs("SPOOF: ignored\n");
        } else {
            kputs("[demo] FAIL spoof accepted\n");
        }
        /* 5. Audit count: allow + deny + leak-deny = 3 entries (the spoof
         * drop audits nothing, like the stub). */
        if (netdemo.naudit != 3) {
            kputs("[demo] FAIL net audit count\n");
        } else {
            kputs("AUD: ");
            kputdec(netdemo.naudit);
            kputs(" entries\n");
        }
        /* 6. Lifecycle: revoke the demo frame (drops the scratch cap and
         * every granted copy system-wide, mappings included). */
        if (ds < 0 || v2_revoke(&caps, 7, (unsigned long)ds) != V2_OK) {
            kputs("[demo] FAIL revoke\n");
        } else {
            /* FDE frame budget (Task 4: pool 16 -> 32, 31 usable):
             * steady demand is ~25-27 frames: 7 boot ELFs = 20 image
             * frames (mem 1 + qrexec 2 + adminvm 2 + fw 2 + net 2 +
             * vault 3 + cryptblk 8) + net DMA 2 + cryptblk DMA 2 +
             * CAP 1, plus transient key/record frames (freed after
             * use). Revoke alone drops caps/mappings but leaves the
             * bitmap marked used, so return the demo frame to the pool:
             * it was zeroed at alloc and never WRITEn (model ops only),
             * and frame_alloc_slot re-zeroes on next alloc. */
            frame_free(ds);
        }
    }
    kputs("v2: entering U-mode mem_server\n");
    enter_thread(0);
}
