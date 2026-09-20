/* userspace/net/v2_main.c - S3 net stub ELF (U-mode, phase 1).
 *
 * Freestanding rv64, V2 UABI only (ecalls 0..7, see kernel/kboot.c). Linked
 * at the frame-window base via userspace/v2_user.ld; entry is _v2_start
 * (net/net_start.S) which sets gp and calls net_main.
 *
 * Role: receive forwarded packets from the firewall (qube 4) and verify
 * byte integrity. Only one message is honored:
 *   T_FWD [6, slot, len, h] from sender_qube == FW_QUBE
 * with slot == NET_IN_SLOT and len <= 1514. The slot names the granted cap
 * in our own table (the firewall GRANTed it before announcing); we MAP it
 * at the scratch vpn, recompute qube_fnv1a over len bytes, and compare to
 * h. Mismatch: UNMAP + silent drop (no reply, no marker -- a corrupt or
 * raced announcement is indistinguishable from noise). Match: print
 * "NET: fwd ok", UNMAP, and SEND [T_DONE, slot, 0, 0] back to the
 * firewall, closing the audit trail. All other tags (including T_CALL,
 * T_DELIVER, stray T_DONE) are silently ignored: nothing ever waits on a
 * net reply, so no reply is ever sent.
 *
 * Phase-2 TX/link logic appends here; this loop stays as the fallback when
 * the link is down. All state is stack-local; string literals are private
 * rodata (U-mapped).
 */
#include <stdint.h>

#include "../../kernel/qube.h"

#define V2_PUTC 1
#define V2_SEND 3
#define V2_RECV 4
#define V2_INVOKE 7

#define V2_INV_MAP 3
#define V2_INV_UNMAP 4

#define T_FWD 6
#define T_DONE 7

#define FW_QUBE 4

#define NET_IN_SLOT 8
#define NET_SCRATCH_MAP_VPN 8

/* Frame-window base (kernel/ipc.h V2_U_FRAME_BASE): vpn N maps VA
 * base + N*4096. Scratch vpn 8 -> 0x80808000 (ELF image occupies the low
 * vpns only; verified < 8 pages at build). */
#define NET_U_FRAME_BASE 0x80800000UL
#define NET_SCRATCH_VA (NET_U_FRAME_BASE + (NET_SCRATCH_MAP_VPN * 4096UL))

/* Wire bound: max Ethernet frame, matches fw.h FW_PKT_MAX. */
#define NET_PKT_MAX 1514UL

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
    while (*s) /* bound: NUL-terminated rodata literal */
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

void net_main(void)
{
    u_puts("NET: up\n");

    for (;;) { /* bound: inf - service loop */
        uint64_t buf[4];
        unsigned long snd = 0;
        unsigned long sqb = 0;
        unsigned long ovf = 0;
        long n = u_recv(0, buf, 4, &snd, &sqb, &ovf);

        /* Only a full T_FWD from the firewall qube is actionable.
         * Everything else (short takes, other tags, spoofed sender)
         * is a silent drop: no reply is ever sent. */
        if (n < 4 || (unsigned long)buf[0] != (unsigned long)T_FWD ||
            sqb != (unsigned long)FW_QUBE)
            continue;

        {
            unsigned long slot = (unsigned long)buf[1];
            unsigned long len = (unsigned long)buf[2];
            uint64_t h = buf[3];
            const uint8_t *pkt;
            uint64_t done[4];
            if (slot != (unsigned long)NET_IN_SLOT || len < 1 ||
                len > (unsigned long)NET_PKT_MAX)
                continue;
            /* Live-grant check: INVALID means no granted cap behind the
             * announcement (grant-without-announcement race) -> drop. */
            if (u_invoke(V2_INV_MAP, (long)slot,
                         (long)NET_SCRATCH_MAP_VPN, 0) != 0)
                continue;
            pkt = (const uint8_t *)NET_SCRATCH_VA;
            if (qube_fnv1a(pkt, len) != h) {
                u_invoke(V2_INV_UNMAP, (long)NET_SCRATCH_MAP_VPN, 0, 0);
                continue; /* corrupt/raced bytes: UNMAP + silent drop */
            }
            u_puts("NET: fwd ok\n");
            u_invoke(V2_INV_UNMAP, (long)NET_SCRATCH_MAP_VPN, 0, 0);
            done[0] = (uint64_t)T_DONE;
            done[1] = (uint64_t)slot;
            done[2] = 0;
            done[3] = 0;
            /* Completion handoff: blocks until the firewall RECVs.
             * Cross-qube gate needs our QX (Step-5 boot grant); without
             * it SEND fails INVALID here, fail closed, loop continues. */
            u_send(0, done, 4);
        }
    }
}
