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

static uint64_t root_pt[512] __attribute__((aligned(4096)));
static uint64_t l1_k[512] __attribute__((aligned(4096)));
static uint64_t l1_m[512] __attribute__((aligned(4096)));
static uint64_t l0_k[512] __attribute__((aligned(4096)));

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
    l1_k[1] = pte_table(l0_k);
    l1_k[2] = pte_leaf(0x80400000UL, PTE_R | PTE_X | PTE_U | PTE_A);
    l1_k[3] = pte_leaf(0x80600000UL, PTE_R | PTE_W | PTE_U | PTE_A | PTE_D);
    l1_m[128] = pte_leaf(0x10000000UL, PTE_R | PTE_W | PTE_A | PTE_D);
    root_pt[2] = pte_table(l1_k);
    root_pt[0] = pte_table(l1_m);
}

/* ---- Frame pool (bitmap, 1=free, 0=in-use) ---- */
#define V2_FRAME_TOTAL (V2_FRAMES_MAX)
static uint8_t frame_bitmap[V2_FRAME_TOTAL]; /* 1=free, 0=used */

static void frame_pool_init(void) {
    /* All frames start free except frame 0 (kernel's own page tables live
     * there — keep it used). Frames 1..7 available for allocation. */
    for (int i = 0; i < V2_FRAME_TOTAL; i++) /* bound: V2_FRAME_TOTAL */
        frame_bitmap[i] = 1;
    frame_bitmap[0] = 0; /* frame 0: kernel PT (in use) */
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

/* PT_ALLOC: allocate a zeroed frame and mint a cap to it. Returns frame id
 * in a0, or V2_ERR_OVERFLOW if no frames available. */
static __attribute__((unused)) int frame_alloc_slot(v2_caps_t *caps, unsigned long tid) {
    int f = frame_alloc();
    if (f < 0)
        return V2_ERR_OVERFLOW;
    /* Find an empty cap slot and mint a RW cap to the frame */
    for (int i = 0; i < V2_CAP_SLOTS; i++) { /* bound: V2_CAP_SLOTS */
        if (!caps->caps[tid][i].valid) {
            caps->caps[tid][i].valid = 1;
            caps->caps[tid][i].obj = (unsigned long)f;
            caps->caps[tid][i].rights = V2_RIGHT_RW;
            caps->caps[tid][i].root = 0;
            return V2_OK;
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
    uint64_t vspace_root_ppn; /* PPN of thread's root page table */
} uctx_t;

#define NTHREADS 4
#define T_RUNNABLE 0
#define T_PARKED 1
#define T_BLOCKED 2

static uctx_t threads[NTHREADS];
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
__attribute__((noreturn)) void u_enter(uctx_t *ctx);

static uint64_t u_sp[NTHREADS]; /* stashed pre-MMU: S must not read U pages */

#define TICK_DELTA 1000000UL /* 100ms @ 10MHz timebase */
#define V2_YIELD 0
#define V2_PUTC 1
#define V2_PARK 2
#define V2_SEND 3 /* (ep, u_ptr, len): copy IN, block unless waiter; a0 = 0 / -ERR */
#define V2_RECV 4 /* (ep, u_buf, cap): copy OUT, block unless queued; a0 = words, a1 = sender, a2 = ovf */
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
#define V2_INV_WRITE 8
#define V2_INV_READ 9

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
            if (v2_q_take_waiter(&ep0, &r) == V2_OK && r < (unsigned long)NTHREADS) {
                unsigned long cap = (unsigned long)threads[r].ipc_cap;
                unsigned long nw = ln < cap ? ln : cap;
                unsigned long ovf = ln > cap ? 1 : 0;
                u_copy_out(threads[r].ipc_ptr, kb, nw);
                threads[r].regs[10] = (uint64_t)nw;
                threads[r].regs[11] = (uint64_t)cur; /* kernel-stamped */
                threads[r].regs[12] = (uint64_t)ovf;
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
            if (v2_q_take_send(&ep0, &slot) == V2_OK) {
                unsigned long nw = slot.len < cap ? slot.len : cap;
                unsigned long ovf = slot.len > cap ? 1 : 0;
                u_copy_out(up, slot.words, nw);
                threads[cur].regs[10] = (uint64_t)nw;
                threads[cur].regs[11] = (uint64_t)slot.sender;
                threads[cur].regs[12] = (uint64_t)ovf;
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
            case V2_INV_MAP:
                rc = v2_map(&caps, (unsigned long)cur, a1, a2);
                break;
            case V2_INV_UNMAP:
                rc = v2_unmap(&caps, (unsigned long)cur, a1);
                break;
            case V2_INV_REVOKE:
                rc = v2_revoke(&caps, (unsigned long)cur, a1);
                break;
            case V2_INV_PT_ALLOC:
                rc = frame_alloc_slot(&caps, (unsigned long)cur);
                break;
            case V2_INV_ELF_CHECK:
                rc = v2_elf_ok((int)a1, (const v2_phdr_t *)a2, a3) ? V2_OK : V2_ERR_INVALID;
                break;
            case V2_INV_WRITE:
                rc = v2_write(&caps, (unsigned long)cur, a1, a2);
                break;
            case V2_INV_READ: {
                uint64_t val = 0;
                rc = v2_read(&caps, (unsigned long)cur, a1, &val);
                if (rc == V2_OK) {
                    sum_on();
                    *(volatile uint64_t *)a2 = val;
                    sum_off();
                }
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
    v2_caps_init(&caps, NTHREADS);
    kputs("[caps] init: thread 0 has root caps to all frames\n");
    user_stacks_init(); /* pre-MMU: U stacks need no SUM games */
    u_sp[0] = (uint64_t)ustack_a_top;
    u_sp[1] = (uint64_t)ustack_b_top;
    u_sp[2] = (uint64_t)ustack_m_top;
    u_sp[3] = (uint64_t)ustack_cap_top;
    pagetable_init();
    uintptr_t root = (uintptr_t)root_pt;
    uint64_t satp = (8UL << 60) | ((root >> 12) & 0xFFFFFFFFFFFUL);
    asm volatile("csrw satp, %0" :: "r"(satp) : "memory");
    asm volatile("sfence.vma" ::: "memory");
    asm volatile("csrc sstatus, %0" :: "r"((1UL << 18) | (1UL << 19)) : "memory");
    kputs("v2: satp Sv39 on, U-bit split (k U=0 / u U=1), SUM=0\n");

    uint64_t initial_vspace = (8UL << 60) | (((uintptr_t)root_pt >> 12) & 0xFFFFFFFFFFFUL);
    for (int i = 0; i < NTHREADS; i++) {
        for (int r = 0; r < 32; r++)
            threads[i].regs[r] = 0;
        threads[i].sepc = 0;
        threads[i].state = T_PARKED;
        threads[i].ipc_ptr = 0;
        threads[i].ipc_cap = 0;
        threads[i].notify = 0;
        threads[i].wait_kind = V2_WK_NONE;
        threads[i].vspace_root_ppn = initial_vspace;
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
    threads[3].regs[2] = u_sp[3];
    threads[3].sepc = (uint64_t)test_cap_thread;
    threads[3].state = T_RUNNABLE;
    kputs("v2: entering U-mode mem_server\n");
    enter_thread(0);
}
