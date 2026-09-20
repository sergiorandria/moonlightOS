/* userspace/qrexec_server/v2_main.c - S2 qrexec policy broker (U-mode ELF).
 *
 * Freestanding rv64, V2 UABI only (ecalls 0..7, see kernel/kboot.c). Linked
 * at the frame-window base via userspace/v2_user.ld; entry is _v2_start
 * (qrexec_server/qrexec_start.S) which sets gp and calls qrexec_main.
 *
 * Role: every cross-qube call arrives on EP0 as T_CALL. The kernel stamps
 * the sender tid (a1) and sender qube label (a2) into RECV results, so the
 * client label is unforgable: policy matches on the stamped qube, never on
 * client-supplied bytes (anti-spoof). The payload hash is pinned at call
 * time with qube_fnv1a over the received words; the AdminVM decision must
 * present the same hash or the decide is dropped (re-checked, never
 * trusted).
 *
 * EP0 protocol (all messages <= V2_MSG_MAX = 4 words):
 *   T_CALL    [1, rpc, arg0, arg1]      client -> qrexec
 *   T_DECIDE  [2, idx, approve, hash]   adminvm -> qrexec (hash = pinned)
 *   T_ASK     [3, idx, rpc, hash]       qrexec -> adminvm (queued ask)
 *   T_HELLO   [4, 0, 0, 0]              adminvm -> qrexec (register tid)
 *   T_DELIVER [5, rpc, arg0, arg1]      qrexec -> dst service (approved)
 *   reply     [0] = OK, [1] = PENDING, [-1] = INVALID/DENY
 *
 * Backpressure is explicit rendezvous: SEND queues + blocks the sender
 * until a RECV takes the message (kernel IPC). The broker therefore never
 * drops; a missing AdminVM stalls Ask delivery, it does not bypass it
 * (fail closed). String literals are private rodata (U-mapped); all policy
 * state is stack-local (no globals cross qubes).
 */
#include <stdint.h>

#include "../../kernel/qube.h"

#define V2_PUTC 1
#define V2_PARK 2
#define V2_SEND 3
#define V2_RECV 4
#define V2_NOTIFY 5
#define V2_WAIT 6

#define T_CALL 1
#define T_DECIDE 2
#define T_ASK 3
#define T_HELLO 4
#define T_DELIVER 5

#define R_OK 0L
#define R_PENDING 1L
#define R_DENY (-1L)

#define RPC_KEYS_SIGN 1
#define RPC_CLIPBOARD 2
#define RPC_NET_SEND 3
#define RPC_NET_FWD 4
#define RPC_FILTER_RELOAD 5
#define RPC_NET_DONE 6

#define FW_QUBE 4
#define NET_QUBE 5

#define QREXEC_QUBE 1

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
    while (*s) /* bound: NUL-terminated rodata literal */
        u_putc(*s++);
}

static void u_putdec(long v)
{
    if (v < 0) {
        u_putc('-');
        v = -v;
    }
    if (v >= 10)
        u_putdec(v / 10); /* bound: <=20 digits */
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

static long u_notify(unsigned long t, unsigned long bits)
{
    return u_ecall3(V2_NOTIFY, (long)t, (long)bits, 0);
}

static void u_reply(long v)
{
    uint64_t resp[1];
    resp[0] = (uint64_t)v;
    u_send(0, resp, 1);
}

void qrexec_main(void)
{
    /* Explicit field init: `= {0}` on this multi-KB struct would emit a
     * memset call, which does not exist freestanding (-nostdlib). Only
     * slots below nrules/npending/naudit are ever read. */
    v2_qpolicy_t pol;
    unsigned long admin_tid = 0;
    int admin_known = 0;

    /* Boot policy table: keys.sign ASK, clipboard DENY, net.send ASK
     * (AppVM->firewall), net.fwd ALLOW (firewall->net), net.send catch-all
     * DENY, filter.reload ASK (AdminVM->firewall). First match wins. */
    pol.nrules = 6;
    pol.npending = 0;
    pol.naudit = 0;
    pol.rules[0] = (v2_qrule_t){.src = 0, .dst = QREXEC_QUBE,
                                .rpc = RPC_KEYS_SIGN,
                                .decision = V2_QDEC_ASK};
    pol.rules[1] = (v2_qrule_t){.src = V2_QWILD, .dst = V2_QWILD,
                                .rpc = RPC_CLIPBOARD,
                                .decision = V2_QDEC_DENY};
    pol.rules[2] = (v2_qrule_t){.src = 0, .dst = FW_QUBE,
                                .rpc = RPC_NET_SEND,
                                .decision = V2_QDEC_ASK};
    pol.rules[3] = (v2_qrule_t){.src = FW_QUBE, .dst = NET_QUBE,
                                .rpc = RPC_NET_FWD,
                                .decision = V2_QDEC_ALLOW};
    pol.rules[4] = (v2_qrule_t){.src = V2_QWILD, .dst = V2_QWILD,
                                .rpc = RPC_NET_SEND,
                                .decision = V2_QDEC_DENY};
    pol.rules[5] = (v2_qrule_t){.src = 3, .dst = FW_QUBE,
                                .rpc = RPC_FILTER_RELOAD,
                                .decision = V2_QDEC_ASK};

    u_puts("QREXEC: up\n");
    u_puts("AUD: boot nrules=6\n");

    for (;;) { /* bound: inf - service loop */
        uint64_t buf[4];
        unsigned long snd = 0;
        unsigned long sqb = 0;
        unsigned long ovf = 0;
        long n = u_recv(0, buf, 4, &snd, &sqb, &ovf);

        if (n < 1) {
            u_reply(R_DENY);
            continue;
        }

        if (buf[0] == (uint64_t)T_HELLO) {
            /* AdminVM registration: kernel-stamped sender tid is the
             * notify target for future asks. */
            admin_tid = snd;
            admin_known = 1;
            u_puts("QREXEC: admin registered\n");
            u_reply(R_OK);
            continue;
        }

        if (buf[0] == (uint64_t)T_DECIDE) {
            /* Decide path: re-check the pinned hash, then deliver.
             * The decider is not waiting, so no reply is sent. */
            if (n >= 4) {
                unsigned long idx = (unsigned long)buf[1];
                int approve = buf[2] ? 1 : 0;
                uint64_t h = buf[3];
                if (idx < pol.npending && idx < (unsigned long)V2_PENDING_MAX &&
                    pol.pending[idx].hash == h) {
                    unsigned long rpc = pol.pending[idx].rpc;
                    unsigned long a0 = pol.pending[idx].arg0;
                    unsigned long a1 = pol.pending[idx].arg1;
                    int arc = qube_decide_idx(&pol, idx, approve);
                    (void)arc;
                    if (approve) {
                        uint64_t fwd[4];
                        fwd[0] = T_DELIVER;
                        fwd[1] = rpc;
                        fwd[2] = a0;
                        fwd[3] = a1;
                        /* Backpressure: blocks until a service RECVs. */
                        u_send(0, fwd, 4);
                        u_puts("AUD: allow rpc=");
                        u_putdec((long)rpc);
                        u_putc('\n');
                    } else {
                        u_puts("AUD: deny rpc=");
                        u_putdec((long)rpc);
                        u_putc('\n');
                    }
                } else {
                    /* Hash mismatch or bad index: drop, deny-audit,
                     * no state change to the pending entry. */
                    u_puts("AUD: deny spoofed-decide\n");
                }
            } else {
                u_puts("AUD: deny short-decide\n");
            }
            continue;
        }

        if (buf[0] != (uint64_t)T_CALL || n < 2) {
            u_puts("QREXEC: drop unknown\n");
            u_reply(R_DENY);
            continue;
        }

        {
            unsigned long rpc = (unsigned long)buf[1];
            /* Pin the hash over the received words at call time
             * (24 bytes max, within the <= 512 caller-len bound). */
            uint64_t h = qube_fnv1a((const uint8_t *)&buf[1],
                                    (unsigned long)(n - 1) * 8UL);
            int dec = qube_decide(&pol, sqb, QREXEC_QUBE, rpc);

            u_puts("QREXEC: call src=");
            u_putdec((long)sqb);
            u_puts(" rpc=");
            u_putdec((long)rpc);
            u_putc('\n');

            if (dec == V2_QDEC_ALLOW) {
                uint64_t fwd[4];
                int k;
                for (k = 0; k < 4; k++) /* bound: 4 (message words) */
                    fwd[k] = k < n ? buf[k] : 0;
                fwd[0] = T_DELIVER;
                qube_audit(&pol, sqb, QREXEC_QUBE, rpc, 1);
                /* Forward first (backpressure), then reply to caller. */
                u_send(0, fwd, 4);
                u_puts("AUD: allow rpc=");
                u_putdec((long)rpc);
                u_putc('\n');
                u_reply(R_OK);
            } else if (dec == V2_QDEC_ASK) {
                v2_qask_t ask;
                int erc;
                ask.src = sqb;
                ask.dst = QREXEC_QUBE;
                ask.rpc = rpc;
                ask.hash = h;
                ask.arg0 = n >= 3 ? (unsigned long)buf[2] : 0;
                ask.arg1 = n >= 4 ? (unsigned long)buf[3] : 0;
                erc = qube_ask_enqueue(&pol, &ask);
                if (erc == 0) {
                    uint64_t na[4];
                    na[0] = T_ASK;
                    na[1] = pol.npending - 1;
                    na[2] = rpc;
                    na[3] = h;
                    u_puts("QREXEC: ask queued hash=");
                    u_puthex64(h);
                    u_putc('\n');
                    if (admin_known)
                        u_notify(admin_tid, pol.npending);
                    /* Blocks until the AdminVM RECVs the ask. */
                    u_send(0, na, 4);
                    u_reply(R_PENDING);
                } else {
                    /* Queue full: ask_enqueue already deny-audited. */
                    u_puts("AUD: deny ask-overflow\n");
                    u_reply(R_DENY);
                }
            } else {
                qube_audit(&pol, sqb, QREXEC_QUBE, rpc, 0);
                u_puts("AUD: deny rpc=");
                u_putdec((long)rpc);
                u_putc('\n');
                u_reply(R_DENY);
            }
        }
    }
}
