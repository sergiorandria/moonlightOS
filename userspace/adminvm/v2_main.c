/* userspace/adminvm/v2_main.c - S2 AdminVM console approver (U-mode ELF).
 *
 * Freestanding rv64, V2 UABI only (ecalls 0..7, see kernel/kboot.c). Linked
 * at the frame-window base via userspace/v2_user.ld; entry is _v2_start
 * (adminvm/adminvm_start.S) which sets gp and calls adminvm_main.
 *
 * Role: the human confirm path for Ask-gated calls. Registers with the
 * qrexec broker via T_HELLO (the broker learns our kernel-stamped tid and
 * NOTIFYs it per ask), then runs a WAIT loop: on wake, RECV the queued
 * T_ASK record, print the pinned hash, show the y/n prompt via PUTC, and
 * SEND the T_DECIDE verdict back. There is no GETC in the V2 UABI, so this
 * stage auto-approves after displaying the prompt (the decision bytes
 * still travel the full SEND/RECV + hash re-check path in the broker).
 *
 * Non-ASK messages taken by accident are re-SENT (cooperative
 * addressed-EP sharing with the broker). All state is stack-local; string
 * literals are private rodata (U-mapped).
 */
#include <stdint.h>

#define V2_PUTC 1
#define V2_PARK 2
#define V2_SEND 3
#define V2_RECV 4
#define V2_NOTIFY 5
#define V2_WAIT 6

#define T_DECIDE 2
#define T_ASK 3
#define T_HELLO 4

static long u_ecall3(long sys, long a0, long a1, long a2)
{
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

static void u_putc(char c)
{
    u_ecall3(V2_PUTC, (long)(unsigned char)c, 0, 0);
}

static void u_puts(const char *s)
{
    while (*s)
        u_putc(*s++);
}

static void u_putdec(long v)
{
    if (v < 0) {
        u_putc('-');
        v = -v;
    }
    if (v >= 10)
        u_putdec(v / 10);
    u_putc((char)('0' + (v % 10)));
}

static void u_puthex64(uint64_t v)
{
    int i;
    u_putc('0');
    u_putc('x');
    for (i = 15; i >= 0; i--) { /* bound: 16 (hex digits) */
        unsigned d = (unsigned)((v >> (unsigned)(i * 4)) & 0xFUL);
        u_putc((char)(d < 10 ? '0' + d : 'a' + (d - 10)));
    }
}

static long u_send(unsigned long ep, const uint64_t *p, unsigned long n)
{
    return u_ecall3(V2_SEND, (long)ep, (long)p, (long)n);
}

/* RECV returns words-written in a0, kernel-stamped sender in a1,
 * sender qube in a2, truncation flag in a3 (explicit, never silent). */
static long u_recv(unsigned long ep, uint64_t *buf, unsigned long cap,
                   unsigned long *sender, unsigned long *qube,
                   unsigned long *ovf)
{
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

static long u_wait(void)
{
    return u_ecall3(V2_WAIT, 0, 0, 0);
}

/* Wake the live client (kernel thread A, tid 0) once the broker HELLO
 * reply proves the broker is live. ADMIN_LIVE_BIT 2 is distinct from
 * thread B's bit-1 ping notify, already consumed by A's first WAIT. */
#define ADMIN_LIVE_BIT 2
#define LIVE_CLIENT_TID 0

static long u_notify(unsigned long t, unsigned long bits)
{
    return u_ecall3(V2_NOTIFY, (long)t, (long)bits, 0);
}

void adminvm_main(void)
{
    uint64_t hello[1];

    u_puts("ADMIN: up\n");

    /* Register with the broker, then wake the live client. SEND pairs
     * with the broker's EP3 RECV (queues + blocks otherwise); the
     * broker's [R_OK] reply needs THIS RECV — without it the reply
     * SEND wedges the broker while we WAIT below. On [0] the broker
     * is live, so notify the live client (thread 0, ADMIN_LIVE_BIT 2
     * — distinct from thread B's bit-1 ping notify, already consumed
     * by A's first WAIT); else fall into WAIT without notifying and
     * the gate fails on the missing markers. */
    hello[0] = T_HELLO;
    if (u_send(3, hello, 1) == 0) {
        uint64_t rep[4];
        unsigned long s = 0, q = 0, o = 0;
        if (u_recv(4, rep, 4, &s, &q, &o) >= 1 && rep[0] == 0)
            u_notify(LIVE_CLIENT_TID, ADMIN_LIVE_BIT);
    }

    for (;;) { /* bound: inf - WAIT loop */
        uint64_t buf[4];
        unsigned long snd = 0;
        unsigned long sqb = 0;
        unsigned long ovf = 0;
        long n;

        (void)u_wait(); /* wake on broker NOTIFY (bits carry no hash) */
        (void)snd;
        (void)sqb;
        (void)ovf;

        n = u_recv(4, buf, 4, &snd, &sqb, &ovf);
        if (n < 4 || buf[0] != (uint64_t)T_ASK) {
            /* Not ours: put it back for the broker (cooperative addressed EPs).
             * Short/empty takes have nothing to return. */
            if (n >= 1)
                u_send(3, buf, (unsigned long)n);
            continue;
        }

        {
            unsigned long idx = (unsigned long)buf[1];
            unsigned long rpc = (unsigned long)buf[2];
            uint64_t h = buf[3];
            uint64_t dec[4];

            u_puts("ADMIN: ask idx=");
            u_putdec((long)idx);
            u_puts(" rpc=");
            u_putdec((long)rpc);
            u_puts(" hash=");
            u_puthex64(h);
            u_putc('\n');
            /* Console y/n prompt via PUTC; no GETC in the V2 UABI, so
             * this stage auto-approves after showing the prompt. */
            u_puts("ADMIN: approve? [y/n] y\n");

            dec[0] = T_DECIDE;
            dec[1] = idx;
            dec[2] = 1; /* approve */
            dec[3] = h; /* pinned hash: broker re-checks */
            u_send(3, dec, 4);

            u_puts("ADMIN: decided idx=");
            u_putdec((long)idx);
            u_putc('\n');
        }
    }
}
