/* v2 S-mode kernel (Stage 2): Sv39 U-bit tables, stvec traps, SBI console,
 * timer-preemptive lowest-Runnable scheduler (mirrors V2_A.sched_step),
 * two U-mode threads, blocking rendezvous IPC on one static endpoint EP0
 * + notifications (mirrors V2_C: c_send/c_recv/c_notify/c_wait), fault
 * containment. No PMP changes (firmware owns); SUM toggled only inside
 * copy_from/to_user after range validation (S never touches U pages
 * otherwise: stacks filled pre-MMU, console via SBI-forward). */
#include <stdint.h>
#include "ipc.h"
#include "caps.h"
#include "qube.h"
#include "initrd.h"
#include "elf.h"

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
#define NTHREADS 6 /* bound for all thread loops (<= V2_CAP_THREADS) */
/* Growing NTHREADS forces WCET/table re-analysis: threads[], qube_of[],
 * u_sp[] size with it; root_pt_t/l1_t/l0_u_t cover V2_CAP_THREADS. */
_Static_assert(NTHREADS <= V2_CAP_THREADS,
               "NTHREADS must fit the caps model + page tables");

/* V2_INV_WRITE/READ move exactly one 64-bit word: the caps.h model is
 * word-per-frame (fdata[f] = val), so the real store/load mirrors exactly
 * what the model records and fdata can never diverge from the
 * real frame (Write-Through Mirror). This bounds every new copy loop and
 * keeps every frame access within the 8-frame region (frame <
 * V2_FRAMES_MAX, max offset 7*4096 + V2_WORD_BYTES <= 32768). */
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
    /* Per-thread VSpaces: shared kernel/leaf/frame/UART regions are wired
     * through each thread's own l1_t; the per-thread frame window
     * (l0_u_t) stays zero until Task 3 maps frames. */
    for (int t = 0; t < NTHREADS; t++) { /* bound: NTHREADS */
        l1_t[t][1] = pte_table(l0_k);
        l1_t[t][2] = pte_leaf(0x80400000UL, PTE_R | PTE_X | PTE_U | PTE_A);
        l1_t[t][3] = pte_leaf(0x80600000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
        l1_t[t][4] = pte_table(l0_u_t[t]);
        l1_t[t][8] = pte_table(l0_frames);
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
 * 8-frame region (frame < V2_FRAMES_MAX; len <= V2_WORD_BYTES <= 4096),
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
    int state; /* 0 = Runnable, 1 = Parked, 2 = Blocked (IPC) */
    /* IPC (mirrors V2_C wk/sendq/recvq): RECV-blocked threads park their
     * validated (ptr, cap) here for later copy-out; queued senders live
     * in ep0.sendq (kernel memory, no U pointers retained -> no TOCTOU). */
    uintptr_t ipc_ptr;
    uint64_t ipc_cap;
    uint64_t notify;   /* pending signal bits (OR-accumulate) */
    int wait_kind;     /* V2_WK_* : what this thread is blocked in */
    uint64_t vspace_root_ppn; /* satp value (mode 8 | root PPN); see v2_satp_of */
} uctx_t;

#define T_RUNNABLE 0
#define T_PARKED 1
#define T_DEAD 2
#define T_BLOCKED 2

static uctx_t threads[NTHREADS];
static uint8_t qube_of[NTHREADS]; /* qube label per thread (qube.h) */
static unsigned long qube_next = 2; /* next fresh label; 0/1 taken at boot */
static int cur = 0;
static unsigned long tick = 0;
static v2_ep_t ep0;
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
            u_copy_in(kb, up, ln);
            /* Raw gate (peek before dequeue: fail-closed, no state lost on
             * reject). Cross-qube handoff needs QX on the sender. */
            if (ep0.recv_len > 0) {
                unsigned long peek = ep0.recvq[ep0.recv_head];
                if (peek >= (unsigned long)NTHREADS ||
                    !qube_raw_ok(qube_of, (unsigned long)NTHREADS,
                                 (unsigned long)cur, peek,
                                 qube_has_qx((unsigned long)cur))) {
                    threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                    kputs("QUB: xread denied\n");
                    return;
                }
            }
            if (v2_q_take_waiter(&ep0, &r) == V2_OK && r < (unsigned long)NTHREADS) {
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
            if (v2_q_send(&ep0, (unsigned long)cur, kb, ln) != V2_OK) {
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
            /* Raw gate (peek before dequeue: fail-closed, no state lost on
             * reject). Queued sends gate at delivery: the destination is
             * unknown at send time, so the sender's qube is derived here
             * via qube_of[slot.sender] (v2_slot_t stays as-is). */
            if (ep0.send_len > 0) {
                unsigned long psrc = ep0.sendq[ep0.send_head].sender;
                if (psrc >= (unsigned long)NTHREADS ||
                    !qube_raw_ok(qube_of, (unsigned long)NTHREADS, psrc,
                                 (unsigned long)cur, qube_has_qx(psrc))) {
                    threads[cur].regs[10] = (uint64_t)(long)V2_ERR_INVALID;
                    kputs("QUB: xread denied\n");
                    return;
                }
            }
            if (v2_q_take_send(&ep0, &slot) == V2_OK) {
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
            if (v2_q_wait(&ep0, (unsigned long)cur) != V2_OK) {
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
            int rc = V2_ERR_INVALID;
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
                    /* T_DEAD aliases T_BLOCKED (both 2): a rendezvous-blocked
                     * thread parks (ptr, cap) + wait_kind, so all three must
                     * read clear before the slot is reusable (fail closed). */
                    if (threads[t].state == T_DEAD &&
                        threads[t].wait_kind == V2_WK_NONE &&
                        threads[t].ipc_ptr == 0 && threads[t].ipc_cap == 0) {
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
                    /* T_DEAD aliases T_BLOCKED (both 2): a rendezvous-blocked
                     * thread parks (ptr, cap) + wait_kind, so all three must
                     * read clear before the slot is reusable (fail closed). */
                    if (threads[t].state == T_DEAD &&
                        threads[t].wait_kind == V2_WK_NONE &&
                        threads[t].ipc_ptr == 0 && threads[t].ipc_cap == 0) {
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
                    /* T_DEAD aliases T_BLOCKED (both 2): see SPAWN scan. */
                    if (threads[t].state == T_DEAD &&
                        threads[t].wait_kind == V2_WK_NONE &&
                        threads[t].ipc_ptr == 0 && threads[t].ipc_cap == 0) {
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
                    int w = 0;
                    for (int i = 0; i < ep0.send_len; i++) { /* bound: V2_IPC_Q */
                        int idx = (ep0.send_head + i) % V2_IPC_Q;
                        unsigned long s = ep0.sendq[idx].sender;
                        if (s < (unsigned long)NTHREADS &&
                            qube_of[s] == (uint8_t)label)
                            continue; /* drop: sender dies below */
                        if (w != i) {
                            int dst = (ep0.send_head + w) % V2_IPC_Q;
                            ep0.sendq[dst] = ep0.sendq[idx];
                        }
                        w++;
                    }
                    ep0.send_len = w;
                    w = 0;
                    for (int i = 0; i < ep0.recv_len; i++) { /* bound: V2_IPC_Q */
                        int idx = (ep0.recv_head + i) % V2_IPC_Q;
                        unsigned long tid = ep0.recvq[idx];
                        if (tid < (unsigned long)NTHREADS &&
                            qube_of[tid] == (uint8_t)label)
                            continue; /* drop: waiter dies below */
                        if (w != i) {
                            int dst = (ep0.recv_head + w) % V2_IPC_Q;
                            ep0.recvq[dst] = ep0.recvq[idx];
                        }
                        w++;
                    }
                    ep0.recv_len = w;
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
    v2_ep_init(&ep0);
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
    u_sp[5] = (uint64_t)ustack_cap_top;
    pagetable_init();
    uintptr_t root = (uintptr_t)root_pt_t[0];
    uint64_t satp = (8UL << 60) | ((root >> 12) & 0xFFFFFFFFFFFUL);
    asm volatile("csrw satp, %0" :: "r"(satp) : "memory");
    asm volatile("sfence.vma" ::: "memory");
    asm volatile("csrc sstatus, %0" :: "r"((1UL << 18) | (1UL << 19)) : "memory");
    kputs("v2: satp Sv39 on, U-bit split (k U=0 / u U=1), SUM=0\n");

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
    asm volatile("csrs sie, %0" :: "r"(1UL << 5) : "memory");   /* STIE */
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
    /* Thread 5 is the scratch slot: it keeps the in-kernel capability demo
     * (CAP/OK/DU/NP markers) that thread 3 ran before the S2 brokers took
     * threads 3-4, and stays free for a future QCREATE demo. */
    threads[5].regs[2] = u_sp[5];
    threads[5].sepc = (uint64_t)test_cap_thread;
    threads[5].state = T_RUNNABLE;
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
    /* Qubes boot labels: mem_server (thread 2) owns qube 1, qrexec
     * (thread 3) owns qube 2, AdminVM (thread 4) owns qube 3; A/B/CAP stub
     * stay in qube 0. Fresh QCREATE labels start at qube_next == 4. */
    qube_of[2] = 1;
    qube_of[3] = 2;
    qube_of[4] = 3;
    qube_next = 4;
    kputs("QUB: qube0 qube1 up\n");
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
    }
    kputs("v2: entering U-mode mem_server\n");
    enter_thread(0);
}
