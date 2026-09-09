/* v2 S-mode kernel (Stage 1): Sv39 U-bit tables, stvec traps, SBI console,
 * timer-preemptive lowest-Runnable scheduler (mirrors V2_A.sched_step),
 * two U-mode threads, fault containment. No PMP changes (firmware owns);
 * no SUM (S never touches U pages: stacks filled pre-MMU, console via
 * SBI-forward or SBI-direct). */
#include <stdint.h>

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

/* ---- Threads (mirrors V2_A: lowest-numbered Runnable wins) ---- */
typedef struct {
    uint64_t regs[32];
    uint64_t sepc;
    int state; /* 0 = Runnable, 1 = Parked */
} uctx_t;

#define NTHREADS 2
#define T_RUNNABLE 0
#define T_PARKED 1

static uctx_t threads[NTHREADS];
static int cur = 0;
static unsigned long tick = 0;

uctx_t *cur_ctx; /* read by trap.S */
uintptr_t trap_stack_top;

static uint8_t kstack[16384] __attribute__((aligned(16)));
uint8_t *kstack_top = kstack + sizeof(kstack);
static uint8_t trap_stack[4096] __attribute__((aligned(16)));

void user_a_main(void);
void user_b_main(void);
void user_stacks_init(void);
extern uintptr_t ustack_a_top, ustack_b_top;
__attribute__((noreturn)) void u_enter(uctx_t *ctx);

static uint64_t u_sp[NTHREADS]; /* stashed pre-MMU: S must not read U pages */

#define TICK_DELTA 1000000UL /* 100ms @ 10MHz timebase */
#define V2_YIELD 0
#define V2_PUTC 1
#define V2_PARK 2

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
    u_enter(&threads[id]);
    __builtin_unreachable();
}

/* Terminal park: nothing runnable and (Stage 1) nothing can make progress.
 * IPC wakeups arrive in a later stage; for now this is a dead end by design. */
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
    kputs("v2 stage1: S-mode entry (OpenSBI)\n");
    user_stacks_init(); /* pre-MMU: U stacks need no SUM games */
    u_sp[0] = (uint64_t)ustack_a_top;
    u_sp[1] = (uint64_t)ustack_b_top;
    pagetable_init();
    uintptr_t root = (uintptr_t)root_pt;
    uint64_t satp = (8UL << 60) | ((root >> 12) & 0xFFFFFFFFFFFUL);
    asm volatile("csrw satp, %0" :: "r"(satp) : "memory");
    asm volatile("sfence.vma" ::: "memory");
    asm volatile("csrc sstatus, %0" :: "r"((1UL << 18) | (1UL << 19)) : "memory");
    kputs("v2: satp Sv39 on, U-bit split (k U=0 / u U=1), SUM=0\n");

    for (int i = 0; i < NTHREADS; i++) {
        for (int r = 0; r < 32; r++)
            threads[i].regs[r] = 0;
        threads[i].sepc = 0;
        threads[i].state = T_PARKED;
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
    kputs("v2: entering U-mode thread A\n");
    enter_thread(0);
}
