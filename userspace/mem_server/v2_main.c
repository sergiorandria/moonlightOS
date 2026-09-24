/* userspace/mem_server/v2_main.c - Stage 3 mem_server as a v2 userspace process.
 *
 * Freestanding rv64, V2 UABI only (ecalls 0..7, see kernel/kboot.c). Linked
 * at the frame-window base via userspace/v2_user.ld; entry is _v2_start
 * (userspace/lib/v2_start.S) which sets gp and calls mem_server_main.
 *
 * Boots from initrd: tools/mkinitrd.sh packs this ELF first (index 0) and
 * the kernel SPAWNs initrd index 0 into thread 2's VSpace at boot, jumping
 * to _v2_start in U-mode. The MEM-SRV banner below therefore proves
 * userspace execution from the initrd image (not the in-kernel stub).
 *
 * Service loop mirrors the in-kernel stub (kernel/user.c mem_server_main):
 * REQ_ALLOC -> V2_INV_PT_ALLOC in our own table, REQ_MAP/UNMAP forwarded.
 * String literals are fine here (private rodata, U-mapped); stack buffers
 * live in the shared .udata stacks (0x806xxxxx, inside the IPC data range).
 * No globals: everything is stack-local so the image stays stateless.
 */
#include <stdint.h>

#define V2_PUTC 1
#define V2_PARK 2
#define V2_SEND 3
#define V2_RECV 4
#define V2_INVOKE 7

#define V2_INV_MAP 3
#define V2_INV_UNMAP 4
#define V2_INV_PT_ALLOC 6

#define REQ_ALLOC 1
#define REQ_MAP 2
#define REQ_UNMAP 3
#define RESP_ERR (-1L)

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

static long u_ecall4(long sys, long a0, long a1, long a2, long a3)
{
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

static void u_putc(char c)
{
    u_ecall3(V2_PUTC, (long)(unsigned char)c, 0, 0);
}

static void u_puts(const char *s)
{
    while (*s)
        u_putc(*s++);
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

static long u_invoke(long op, long a1, long a2, long a3)
{
    return u_ecall4(V2_INVOKE, op, a1, a2, a3);
}

void mem_server_main(void)
{
    u_puts("MEM-SRV\n");

    /* Service loop: wait for requests, handle them, reply. Runs after the
     * A/B ping-pong has parked, so EP0 is quiet (no message stealing). */
    for (;;) {
        uint64_t buf[4];
        unsigned long snd = 0;
        unsigned long qb = 0;
        unsigned long ovf = 0;
        long n = u_recv(2, buf, 4, &snd, &qb, &ovf);
        long req;
        long rc = RESP_ERR;

        if (n < 1) {
            uint64_t resp[1];
            resp[0] = (uint64_t)RESP_ERR;
            u_send(snd, resp, 1);
            continue;
        }

        req = (long)buf[0];
        if (req == REQ_ALLOC) {
            rc = u_invoke(V2_INV_PT_ALLOC, 0, 0, 0);
        } else if (req == REQ_MAP) {
            if (n >= 3)
                rc = u_invoke(V2_INV_MAP, (long)buf[1], (long)buf[2], 0);
        } else if (req == REQ_UNMAP) {
            if (n >= 2)
                rc = u_invoke(V2_INV_UNMAP, (long)buf[1], 0, 0);
        }

        {
            uint64_t resp[1];
            resp[0] = (uint64_t)rc;
            u_send(snd, resp, 1);
        }
    }
}
