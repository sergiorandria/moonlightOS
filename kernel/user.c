/* v2 U-mode threads (Stage 2). Freestanding, linked into .utext/.udata.
 * CONSTRAINT (Stage-1, documented): no string literals, no globals here.
 * Literals would land in kernel .rodata (U=0, fault on U access) and gp
 * points at the kernel small-data area. Everything below is immediates +
 * stack locals, so code runs with any gp. Stage 3 (ELF loader) lifts this
 * with per-process gp + private rodata.
 *
 * Demo (mirrors V2_C ipc_demo_ping/pong/notify): A SENDs ping, B RECVs
 * and prints it, B NOTIFYs A then SENDs pong, A RECVs, prints, WAITs
 * (takes the earlier notify), both park. Message bytes travel only via
 * the kernel endpoint (copy IN + copy OUT); the two threads share no
 * writable memory (separate stacks; text is RX). */
#include <stdint.h>

#define V2_YIELD 0
#define V2_PUTC 1
#define V2_PARK 2
#define V2_SEND 3
#define V2_RECV 4
#define V2_NOTIFY 5
#define V2_WAIT 6
#define V2_INVOKE 7

/* mem_server IPC protocol */
#define REQ_ALLOC 1
#define REQ_MAP 2
#define REQ_UNMAP 3
#define RESP_ERR -1

/* V2_INVOKE sub-operations (must match kernel kboot.c) */
#define V2_INV_PT_ALLOC 6
#define V2_INV_ELF_CHECK 7
#define V2_INV_ELF_MAP 8
#define V2_INV_SPAWN 9
#define V2_INV_FORK 10
#define V2_INV_EXEC 11
#define V2_INV_WRITE 12
#define V2_INV_READ 13

#define V2_INV_MAP 3
#define V2_INV_UNMAP 4
#define V2_INV_REVOKE 5

static long u_ecall3(long sys, long a0, long a1, long a2) {
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall"
                 : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2)
                 : "r"(r_a7)
                 : "memory");
    return r_a0;
}

static long u_ecall4(long sys, long a0, long a1, long a2, long a3) {
    register long r_a0 asm("a0") = a0;
    register long r_a1 asm("a1") = a1;
    register long r_a2 asm("a2") = a2;
    register long r_a3 asm("a3") = a3;
    register long r_a7 asm("a7") = sys;
    asm volatile("ecall"
                 : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2), "+r"(r_a3)
                 : "r"(r_a7)
                 : "memory");
    return r_a0;
}

static void uputc(char c) {
    u_ecall3(V2_PUTC, (long)(unsigned char)c, 0, 0);
}

static void upark(void) {
    u_ecall3(V2_PARK, 0, 0, 0);
    for (;;)
        u_ecall3(V2_YIELD, 0, 0, 0); /* unreachable: park never returns */
}

static long usend(unsigned long ep, const uint64_t *p, unsigned long n) {
    return u_ecall3(V2_SEND, (long)ep, (long)p, (long)n);
}

/* RECV returns words-written in a0, kernel-stamped sender in a1,
 * sender qube in a2, truncation flag in a3 (explicit, never silent). */
static long urecv(unsigned long ep, uint64_t *buf, unsigned long cap,
                  unsigned long *sender, unsigned long *qube,
                  unsigned long *ovf) {
    register long r_a0 asm("a0") = (long)ep;
    register long r_a1 asm("a1") = (long)buf;
    register long r_a2 asm("a2") = (long)cap;
    register long r_a3 asm("a3") = 0;
    register long r_a7 asm("a7") = V2_RECV;
    asm volatile("ecall"
                 : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2), "+r"(r_a3)
                 : "r"(r_a7)
                 : "memory");
    *sender = (unsigned long)r_a1;
    *qube = (unsigned long)r_a2;
    *ovf = (unsigned long)r_a3;
    return r_a0;
}

static long unotify(unsigned long t, unsigned long bits) {
    return u_ecall3(V2_NOTIFY, (long)t, (long)bits, 0);
}

static long uwait(void) {
    return u_ecall3(V2_WAIT, 0, 0, 0);
}

/* Single invoke path: all four args forwarded (a3 reaches the kernel;
 * MINT/GRANT/ELF_CHECK-style dst args are no longer dropped). */
static long u_invoke(long op, long a1, long a2, long a3) {
    return u_ecall4(V2_INVOKE, op, a1, a2, a3);
}

/* Print low bytes of w[0..n): immediates only, no literals. */
static void uputs_n(const uint64_t *w, long n) {
    for (long i = 0; i < n; i++)
        uputc((char)(w[i] & 0xFF));
    uputc('\n');
}

/* Decimal print (immediates only, no literals). */
__attribute__((section(".utext"), noinline)) static void uputdec(long v) {
    if (v < 0) {
        uputc('-');
        v = -v;
    }
    if (v >= 10)
        uputdec(v / 10);
    uputc((char)('0' + (v % 10)));
}

/* Thread A: ping -> recv pong -> wait notify -> park. */
__attribute__((section(".utext"), noinline)) void user_a_main(void) {
    uint64_t ping[2];
    uint64_t out[4];
    unsigned long snd;
    unsigned long qb;
    unsigned long ovf;
    long n;
    long bits;
    ping[0] = 'p';
    ping[1] = 'n';
    uputc('A');
    uputc('\n');
    usend(0, ping, 2);
    n = urecv(0, out, 4, &snd, &qb, &ovf);
    uputc('A');
    uputc((char)('0' + snd)); /* kernel-stamped sender: must be 1 */
    uputc((char)('0' + ovf)); /* must be 0: pong fits */
    uputs_n(out, n);
    bits = uwait(); /* takes B's earlier notify */
    uputc('W');
    uputc((char)('0' + bits)); /* must be 1 */
    uputc('\n');
    upark();
}

/* Thread B: recv ping -> notify A -> reply pong -> park. */
__attribute__((section(".utext"), noinline)) void user_b_main(void) {
    uint64_t buf[4];
    uint64_t pong[2];
    unsigned long snd;
    unsigned long qb;
    unsigned long ovf;
    long n;
    pong[0] = 'p';
    pong[1] = 'g';
    n = urecv(0, buf, 4, &snd, &qb, &ovf);
    uputc('B');
    uputc((char)('0' + snd)); /* kernel-stamped sender: must be 0 */
    uputc((char)('0' + ovf)); /* must be 0: ping fits */
    uputs_n(buf, n);
    unotify(0, 1);
    usend(0, pong, 2);
    upark();
}

/* mem_server_main: receives root caps at boot, handles frame allocation
 * IPC. Main loop: wait for requests, handle them, reply. */
__attribute__((section(".utext"), noinline)) void mem_server_main(void) {
    uint64_t buf[4];
    unsigned long snd;
    unsigned long qb;
    unsigned long ovf;
    long n;

    uputc('M'); uputc('E'); uputc('M'); uputc('\n');

    /* Main loop: wait for requests, handle them, reply */
    for (;;) { /* bound: ∞ — service loop */
        n = urecv(0, buf, 4, &snd, &qb, &ovf);
        if (n < 1) {
            /* Empty or invalid: reply error */
            uint64_t resp[1] = { (uint64_t)RESP_ERR };
            usend(0, resp, 1);
            continue;
        }

        long req = (long)buf[0];
        long rc = RESP_ERR;

        switch (req) {
        case REQ_ALLOC: {
            /* Allocate a frame: kernel V2_INV_PT_ALLOC does the work */
            rc = (long)u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
            break;
        }
        case REQ_MAP: {
            /* Map: args = cap_slot, vpn */
            if (n >= 3) {
                rc = (long)u_invoke(V2_INV_MAP, buf[1], buf[2], 0);
            }
            break;
        }
        case REQ_UNMAP: {
            /* Unmap: args = vpn */
            if (n >= 2) {
                rc = (long)u_invoke(V2_INV_UNMAP, buf[1], 0, 0);
            }
            break;
        }
        default:
            rc = RESP_ERR;
            break;
        }

        uint64_t resp[1] = { (uint64_t)rc };
        usend(0, resp, 1);
    }
}

/* test_cap_thread: exercises the capability system end-to-end
 * PT_ALLOC → MAP → WRITE (real frame) → DIRECT read of the mapped VA
 * (no syscall) → READ invoke → CAP OK. vpn 0 maps VA 0x80800000 (the
 * frame window base, kernel/ipc.h V2_U_FRAME_BASE). Pattern bytes are
 * built from a runtime variable: a 64-bit literal loaded by U-mode code
 * would pull a literal pool into kernel .rodata (U=0) and fault. */
__attribute__((section(".utext"), noinline)) void test_cap_thread(void) {
    long i;
    int n_ok;
    uputc('C'); uputc('A'); uputc('P'); uputc('\n');

    /* Step 1: PT_ALLOC — allocate a frame, get a cap in our table */
    long rc = u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
    if (rc != 0) {
        uputc('F'); uputc('A'); uputc('I'); uputc('L');
        upark();
    }

    /* Step 2: MAP — map the frame at VPN 0. (vpn 0x200 >= V2_VPN_SLOTS
     * is now correctly rejected by the kernel since Task 3.) */
    rc = u_invoke(V2_INV_MAP, 0, 0, 0);
    if (rc != 0) {
        uputc('F'); uputc('A'); uputc('I'); uputc('L');
        upark();
    }

    /* Step 3: WRITE — the invoke copies this 8-byte pattern word (two
     * 0xcafebeef uint32 lanes) into the REAL frame backing vpn 0. The
     * pattern bytes are built from a runtime value x: the compiler would
     * otherwise constant-fold past the FAIL/PARK branches (rc is provably
     * 0 there) and pool the 8-byte pattern into kernel .text, where U-mode
     * cannot read it (load page fault). Feeding the stack address of pat
     * into x makes the value genuinely runtime and defeats the fold. */
    uint64_t pat = 0;
    uint32_t x = 0xcafebeefUL ^ (uint32_t)(uintptr_t)&pat;
    volatile uint8_t *pb = (volatile uint8_t *)&pat;
    for (i = 0; i < 8; i++) /* bound: 8 (pattern bytes) */
        pb[i] = (uint8_t)(x >> (((uint32_t)i & 3) * 8));
    rc = u_invoke(V2_INV_WRITE, 0, (long)&pat, 0);
    if (rc != 0) {
        uputc('F'); uputc('A'); uputc('I'); uputc('L');
        upark();
    }

    /* Step 4: DIRECT read of the mapped VA 0x80800000 (vpn 0) — no
     * syscall. The CPU walks the real leaf PTE installed by MAP, so the
     * 2 matching uint32 lanes prove the mapping is real hardware. */
    volatile uint32_t *va = (volatile uint32_t *)0x80800000UL;
    n_ok = 0;
    for (i = 0; i < 2; i++) /* bound: 2 (pattern uint32 lanes) */
        if (va[i] == x)
            n_ok++;
    if (n_ok != 2) {
        uputc('F'); uputc('A'); uputc('I'); uputc('L');
        upark();
    }
    /* DU marker: every word matched through the real leaf PTE */
    uputc('D'); uputc('U'); uputc(':'); uputc(' ');
    uputc('v'); uputc('p'); uputc('n'); uputc('0');
    uputc(' '); uputc('m'); uputc('i'); uputc('r'); uputc('r');
    uputc('o'); uputc('r'); uputc('e'); uputc('d');
    uputc(' ');
    uputdec(n_ok);
    uputc('/'); uputc('2');
    uputc('\n');

    /* Step 5: READ — the invoke copies the 8-byte word back from the real
     * frame into the user buffer; the pattern bytes must still match. */
    uint64_t rb = 0;
    rc = u_invoke(V2_INV_READ, 0, (long)&rb, 0);
    if (rc != 0) {
        uputc('F'); uputc('A'); uputc('I'); uputc('L');
        upark();
    }
    {
        const volatile uint8_t *rbb = (const volatile uint8_t *)&rb;
        for (i = 0; i < 8; i++) /* bound: 8 (read-back bytes) */
            if (rbb[i] != (uint8_t)(x >> (((uint32_t)i & 3) * 8))) {
                uputc('F'); uputc('A'); uputc('I'); uputc('L');
                upark();
            }
    }

    uputc('O'); uputc('K'); uputc('\n');

    /* ---- Negative tests: prove fail-closed behavior (Task 8) ----
     * Each test expects rc<0. A 'P' is printed on each success. */

    /* 1. MAP bad slot: slot V2_CAP_SLOTS (out of bounds) must be rejected. */
    rc = u_invoke(V2_INV_MAP, 0, 0, 0x200);
    if (rc >= 0) { uputc('F'); uputc('A'); uputc('I'); uputc('L'); upark(); }
    uputc('P');

    /* 2. READ to a pointer inside the text region (0x80400000..0x80600000)
     *    must fail the data-range check (hardening proof). */
    volatile uint64_t *text_ptr = (volatile uint64_t *)0x80400000UL;
    rc = u_invoke(V2_INV_READ, 0, (long)text_ptr, 0);
    if (rc >= 0) { uputc('F'); uputc('A'); uputc('I'); uputc('L'); upark(); }
    uputc('P');

    /* 3. UNMAP vpn 0, then READ must fail (mapping gone). */
    rc = u_invoke(V2_INV_UNMAP, 0, 0, 0);
    if (rc != 0) { uputc('F'); uputc('A'); uputc('I'); uputc('L'); upark(); }
    rc = u_invoke(V2_INV_READ, 0, (long)&rb, 0);
    if (rc >= 0) { uputc('F'); uputc('A'); uputc('I'); uputc('L'); upark(); }
    uputc('P');

    /* 4. READ to a pointer past the data region (0x80800000+) must fail. */
    volatile uint64_t *oob_ptr = (volatile uint64_t *)0x80800000UL;
    rc = u_invoke(V2_INV_READ, 0, (long)oob_ptr, 0);
    if (rc >= 0) { uputc('F'); uputc('A'); uputc('I'); uputc('L'); upark(); }
    uputc('P');

    uputc('N'); uputc('P'); uputc('\n'); /* negative-passed */
    upark();
}

static uint8_t ustack_a[4096] __attribute__((section(".ustack"), aligned(16)));
static uint8_t ustack_b[4096] __attribute__((section(".ustack"), aligned(16)));
static uint8_t ustack_m[4096] __attribute__((section(".ustack"), aligned(16)));
static uint8_t ustack_cap[4096] __attribute__((section(".ustack"), aligned(16)));
/* S2 broker stacks: qrexec holds a v2_qpolicy_t (~4.1KB) plus its service
 * frame on-stack, so it gets an 8KB window; AdminVM's frame is small. */
static uint8_t ustack_qrexec[8192] __attribute__((section(".ustack"), aligned(16)));
static uint8_t ustack_adminvm[4096] __attribute__((section(".ustack"), aligned(16)));

/* Boot assertion (Task 4 follow-up b): the qrexec U-stack window must fit
 * the policy frame with headroom; a short window fails the build, never
 * boots into a stack overflow. */
_Static_assert(sizeof(ustack_qrexec) >= 8192,
               "qrexec U-stack must be >= 8KB (v2_qpolicy_t ~4.1KB)");

uintptr_t ustack_a_top __attribute__((section(".udata"))) = 0;
uintptr_t ustack_b_top __attribute__((section(".udata"))) = 0;
uintptr_t ustack_m_top __attribute__((section(".udata"))) = 0;
uintptr_t ustack_cap_top __attribute__((section(".udata"))) = 0;
uintptr_t ustack_qrexec_top __attribute__((section(".udata"))) = 0;
uintptr_t ustack_adminvm_top __attribute__((section(".udata"))) = 0;

__attribute__((section(".utext"))) void user_stacks_init(void) {
    ustack_a_top = (uintptr_t)(ustack_a + sizeof(ustack_a));
    ustack_b_top = (uintptr_t)(ustack_b + sizeof(ustack_b));
    ustack_m_top = (uintptr_t)(ustack_m + sizeof(ustack_m));
    ustack_cap_top = (uintptr_t)(ustack_cap + sizeof(ustack_cap));
    ustack_qrexec_top = (uintptr_t)(ustack_qrexec + sizeof(ustack_qrexec));
    ustack_adminvm_top = (uintptr_t)(ustack_adminvm + sizeof(ustack_adminvm));
}
