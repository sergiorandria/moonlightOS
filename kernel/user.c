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
#define V2_INV_MAP 3
#define V2_INV_UNMAP 4
#define V2_INV_WRITE 8
#define V2_INV_READ 9

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

static long __attribute__((unused)) u_ecall4(long sys, long a0, long a1, long a2, long a3) {
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
 * truncation flag in a2 (explicit, never silent). */
static long urecv(unsigned long ep, uint64_t *buf, unsigned long cap,
                  unsigned long *sender, unsigned long *ovf) {
    register long r_a0 asm("a0") = (long)ep;
    register long r_a1 asm("a1") = (long)buf;
    register long r_a2 asm("a2") = (long)cap;
    register long r_a7 asm("a7") = V2_RECV;
    asm volatile("ecall"
                 : "+r"(r_a0), "+r"(r_a1), "+r"(r_a2)
                 : "r"(r_a7)
                 : "memory");
    *sender = (unsigned long)r_a1;
    *ovf = (unsigned long)r_a2;
    return r_a0;
}

static long unotify(unsigned long t, unsigned long bits) {
    return u_ecall3(V2_NOTIFY, (long)t, (long)bits, 0);
}

static long uwait(void) {
    return u_ecall3(V2_WAIT, 0, 0, 0);
}

static long u_invoke(long op, long a1, long a2, long a3) {
    (void)a3;
    return u_ecall3(V2_INVOKE, op, a1, a2);
}

static long __attribute__((unused)) u_invoke4(long op, long a1, long a2, long a3) {
    return u_ecall4(V2_INVOKE, op, a1, a2, a3);
}

/* Print low bytes of w[0..n): immediates only, no literals. */
static void uputs_n(const uint64_t *w, long n) {
    for (long i = 0; i < n; i++)
        uputc((char)(w[i] & 0xFF));
    uputc('\n');
}

/* Thread A: ping -> recv pong -> wait notify -> park. */
__attribute__((section(".utext"), noinline)) void user_a_main(void) {
    uint64_t ping[2];
    uint64_t out[4];
    unsigned long snd;
    unsigned long ovf;
    long n;
    long bits;
    ping[0] = 'p';
    ping[1] = 'n';
    uputc('A');
    uputc('\n');
    usend(0, ping, 2);
    n = urecv(0, out, 4, &snd, &ovf);
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
    unsigned long ovf;
    long n;
    pong[0] = 'p';
    pong[1] = 'g';
    n = urecv(0, buf, 4, &snd, &ovf);
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
    unsigned long ovf;
    long n;

    uputc('M'); uputc('E'); uputc('M'); uputc('\n');

    /* Main loop: wait for requests, handle them, reply */
    for (;;) { /* bound: ∞ — service loop */
        n = urecv(0, buf, 4, &snd, &ovf);
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

/* test_cap_thread: exercises capability system end-to-end
 * PT_ALLOC → MAP → WRITE → READ */
__attribute__((section(".utext"), noinline)) void test_cap_thread(void) {
    uputc('C'); uputc('A'); uputc('P'); uputc('\n');

    /* Step 1: PT_ALLOC — allocate a frame, get a cap in our table */
    long rc = u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
    if (rc != 0) {
        uputc('F'); uputc('A'); uputc('I'); uputc('L');
        upark();
    }

    /* Step 2: MAP — map the frame at VPN 0x200 */
    rc = u_invoke(V2_INV_MAP, 0, 0x200, 0);
    if (rc != 0) {
        uputc('F'); uputc('A'); uputc('I'); uputc('L');
        upark();
    }

    /* Step 3: WRITE — write 0xDEADBEEF via V2_INVOKE */
    rc = u_invoke(V2_INV_WRITE, 0x200, 0xDEADBEEF, 0);
    if (rc != 0) {
        uputc('F'); uputc('A'); uputc('I'); uputc('L');
        upark();
    }

    /* Step 4: READ — read back and verify */
    uint64_t rd_val = 0;
    rc = u_invoke(V2_INV_READ, 0x200, (long)&rd_val, 0);
    if (rc != 0 || rd_val != 0xDEADBEEF) {
        uputc('F'); uputc('A'); uputc('I'); uputc('L');
        upark();
    }

    uputc('O'); uputc('K'); uputc('\n');
    upark();
}

static uint8_t ustack_a[4096] __attribute__((section(".ustack"), aligned(16)));
static uint8_t ustack_b[4096] __attribute__((section(".ustack"), aligned(16)));
static uint8_t ustack_m[4096] __attribute__((section(".ustack"), aligned(16)));
static uint8_t ustack_cap[4096] __attribute__((section(".ustack"), aligned(16)));

uintptr_t ustack_a_top __attribute__((section(".udata"))) = 0;
uintptr_t ustack_b_top __attribute__((section(".udata"))) = 0;
uintptr_t ustack_m_top __attribute__((section(".udata"))) = 0;
uintptr_t ustack_cap_top __attribute__((section(".udata"))) = 0;

__attribute__((section(".utext"))) void user_stacks_init(void) {
    ustack_a_top = (uintptr_t)(ustack_a + sizeof(ustack_a));
    ustack_b_top = (uintptr_t)(ustack_b + sizeof(ustack_b));
    ustack_m_top = (uintptr_t)(ustack_m + sizeof(ustack_m));
    ustack_cap_top = (uintptr_t)(ustack_cap + sizeof(ustack_cap));
}
